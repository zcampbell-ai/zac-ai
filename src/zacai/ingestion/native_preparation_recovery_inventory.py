"""Exact native preparation recovery metadata, never recovery/access authority.

Uses current canonical loaders and complete own+dependency rows. No backup,
crypto, receipt, model, credential, commit or capture. Caller owns permission,
READ COMMITTED session and rollback after a hold; trusted callbacks are not a
sandbox and cannot undo their own durable SQL. BaseException propagates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore
from zacai.ingestion.native_batch_inventory import (
    NativeBatchRecoverySelection,
    load_native_batch_inventory,
    prepare_native_batch_recovery_selection,
)
from zacai.ingestion.native_contextual_preparation_retention import (
    PairedNativePreparationReferences,
    RetainedNativeContextualPreparation,
    _CurrentPreparationStore,
    _decode,
    _external,
    _header_external,
    _pairs,
    load_retained_native_contextual_preparation,
)
from zacai.ingestion.native_proposal_retention import (
    _clean,
    _time,
    _valid,
    load_retained_native_proposal,
)
from zacai.intelligence import native_contextual_assembly as assembly
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation


class NativePreparationRecoveryInventoryError(ValueError):
    """Fixed hold outside private exception context; no inferred readiness."""


@dataclass(frozen=True, repr=False)
class NativePreparationRecoveryInventory:
    retained: RetainedNativeContextualPreparation
    native: NativeBatchRecoverySelection
    references: tuple[EvidenceReference, ...]
    hashes: tuple[tuple[UUID, str], ...]
    source_fingerprints: tuple[tuple[UUID, str], ...]
    source_rows: tuple[tuple[tuple[str, object], ...], ...]
    artifact_hashes: frozenset[str]
    original_observed_at: datetime
    retained_at: datetime
    checked_at: datetime
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    access_authorized: Literal[False] = field(default=False, init=False)
    capture_authorized: Literal[False] = field(default=False, init=False)


def _references(saved: RetainedNativeContextualPreparation) -> tuple[EvidenceReference, ...]:
    if type(saved) is not RetainedNativeContextualPreparation:
        raise ValueError("exact retained preparation")
    declared = saved.request.context.task.event.provenance
    own = (saved.reference, saved.dependency_reference)
    if len({ref.source_id for ref in (*declared, *own)}) != len(declared) + 2:
        raise ValueError("distinct paired own retained Sources required")
    refs = (*declared, *own)
    if not 1 <= len(refs) <= assembly.MAX_REFERENCES or len({ref.source_id for ref in refs}) != len(
        refs
    ):
        raise ValueError("bounded distinct complete recovery union")
    if any(
        type(ref) is not EvidenceReference
        or ref.trust_boundary is not B.BRAINSTORM
        or ref.effective_classification is not C.CONFIDENTIAL
        for ref in refs
    ):
        raise ValueError("fixed exact declared current read scope")
    return tuple(sorted(refs, key=lambda ref: str(ref.source_id)))


def _rows(
    session: Session, refs: tuple[EvidenceReference, ...], as_of: datetime
) -> tuple[tuple[tuple[str, object], ...], ...]:
    _clean(session)
    expected = {ref.source_id: ref for ref in refs}
    effective = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(SourceClassificationElevation.elevated_at.desc())
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    with session.no_autoflush:
        rows = list(
            session.execute(
                select(
                    *Source.__table__.columns,
                    func.coalesce(effective, Source.data_classification).label("effective"),
                )
                .where(Source.id.in_(tuple(expected)))
                .order_by(Source.id)
                .limit(assembly.MAX_REFERENCES + 1)
            ).mappings()
        )
    if len(rows) != len(refs) or {row["id"] for row in rows} != set(expected):
        raise ValueError("complete selected Source rows required")
    for row in rows:
        ref = expected[row["id"]]
        if (
            row["trust_boundary"] is not B.BRAINSTORM
            or row["data_classification"] is not C.CONFIDENTIAL
            or row["effective"] is not C.CONFIDENTIAL
            or row["content_hash"] != ref.content_hash
            or type(row["content_location"]) is not str
            or not 0 < len(row["content_location"]) <= 2048
            or _time(row["captured_at"]) > as_of
        ):
            raise ValueError("selected current metadata/ACL changed")
    return tuple(tuple((str(key), value) for key, value in row.items()) for row in rows)


def _fingerprints(rows: tuple[tuple[tuple[str, object], ...], ...]) -> dict[UUID, str]:
    result = {}
    for values in rows:
        row = dict(values)
        sid = row["id"]
        if type(sid) is not UUID:
            raise ValueError("exact Source UUID")
        result[sid] = assembly._fingerprint(row)
    return result


def _own_rows(
    saved: RetainedNativeContextualPreparation,
    rows: tuple[tuple[tuple[str, object], ...], ...],
    now: datetime,
) -> None:
    by_id = {dict(values)["id"]: dict(values) for values in rows}
    own = (saved.reference, saved.dependency_reference)
    fingerprints = dict(saved.own_source_fingerprints)
    if len(saved.own_source_fingerprints) != 2 or set(fingerprints) != {
        ref.source_id for ref in own
    }:
        raise ValueError("exact loaded own Source fingerprints")
    expected = (_external(saved.request), _header_external(saved.request.context.task.task_id))
    for ref, external in zip(own, expected, strict=True):
        row = by_id[ref.source_id]
        _valid(row, ref.content_hash, now)
        captured = row["captured_at"]
        if type(captured) is not datetime:
            raise ValueError("actual own capture timestamp")
        if (
            row["external_ref"] != external
            or _time(captured) != saved.captured_at
            or row["excerpt"] is not None
            or assembly._fingerprint(row) != fingerprints[ref.source_id]
        ):
            raise ValueError("loaded own Source metadata changed")


def prepare_retained_native_contextual_recovery_inventory(
    session: Session,
    *,
    factory: sessionmaker[Session],
    artifacts: ArtifactStore,
    reference: PairedNativePreparationReferences,
    as_of: datetime,
) -> NativePreparationRecoveryInventory:
    """Read complete own+ancestor inventory. False flags never change on success."""
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        session.connection()  # Composite identity starts before its private loader.
        outer, nested = session.get_transaction(), session.get_nested_transaction()
        if outer is None or not outer.is_active:
            raise ValueError("actual live entry transaction")
        now = _time(as_of)
        saved = load_retained_native_contextual_preparation(
            session, factory=factory, artifacts=artifacts, reference=reference, as_of=now
        )
        if (
            session.get_transaction() is not outer
            or not outer.is_active
            or session.get_nested_transaction() is not nested
            or (nested is not None and not nested.is_active)
        ):
            raise ValueError("loader replaced caller transaction")
        refs = _references(saved)
        before = _rows(session, refs, now)
        _own_rows(saved, before, now)
        fingerprints = _fingerprints(before)
        selection, request, value = _decode(saved.binding_bytes)
        declared_fingerprints = _pairs(value["source_fingerprints"])
        if any(
            fingerprints[sid] != fingerprint for sid, fingerprint in declared_fingerprints.items()
        ):
            raise ValueError("retained declared full Source snapshot changed")
        scoped = _CurrentPreparationStore(
            session, artifacts, refs, fingerprints, now, outer, nested
        )
        proposal = load_retained_native_proposal(
            session,
            artifacts=scoped,
            proposal_reference=selection.proposal_reference,
            batch_id=selection.batch_id,
            expected_proposal_hash=selection.approved_proposal_hash,
            as_of=now,
        )
        native = load_native_batch_inventory(
            session,
            artifacts=scoped,
            batch_reference=selection.batch_reference,
            approval_reference=selection.intake_instruction_reference,
            approved_proposal_raw=proposal,
            as_of=now,
        )
        if (
            native.batch_id != selection.batch_id
            or native.batch_reference != selection.batch_reference
            or native.approval_reference != selection.intake_instruction_reference
            or native.artifact_references != request.artifact_references
        ):
            raise ValueError("exact native batch/intake/artifact role join")
        complete = prepare_native_batch_recovery_selection(
            session,
            artifacts=scoped,
            inventory=native,
            proposal_reference=selection.proposal_reference,
            approved_proposal_raw=proposal,
            as_of=now,
        )
        hashes = {ref.source_id: ref.content_hash for ref in refs}
        native_hashes = dict(complete.hashes)
        declared = {
            ref.source_id: ref.content_hash for ref in request.context.task.event.provenance
        }
        if not set(native_hashes) < set(declared) or any(
            declared.get(sid) != digest for sid, digest in native_hashes.items()
        ):
            raise ValueError("exact native prerequisite subset required")
        if (
            session.get_transaction() is not outer
            or not outer.is_active
            or session.get_nested_transaction() is not nested
            or (nested is not None and not nested.is_active)
        ):
            raise ValueError("private callback changed caller transaction")
        _clean(session)
        # Final combined all-Source scalar snapshot after every private callback.
        final = _rows(session, refs, now)
        _own_rows(saved, final, now)
        if (
            assembly._base_relationships(session, selection) != value["relationship_fingerprint"]
            or final != before
        ):
            raise ValueError("final complete own/dependency inventory changed")
        result = NativePreparationRecoveryInventory(
            saved,
            complete,
            refs,
            tuple(sorted(hashes.items(), key=lambda item: str(item[0]))),
            tuple(sorted(fingerprints.items(), key=lambda item: str(item[0]))),
            before,
            frozenset(hashes.values()),
            request.context.task.event.observed_at,
            saved.captured_at,
            now,
        )
    except Exception:  # noqa: BLE001,S110 - private hold outside handler
        pass
    if result is None:
        raise NativePreparationRecoveryInventoryError("native preparation recovery inventory held")
    return result
