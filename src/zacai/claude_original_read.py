"""Canonical custody read mechanics only; host owns live identity and recovery gates.

Read-only, clean caller READ COMMITTED transaction with no assigned write transaction ID. Roll back on any database
error/hold. Static supplied scopes are not live authentication or revocation.
No capture, artifact writes/sync, protection, repair, or processing permission.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zacai.claude_custody_selection import inspect_claude_custody_selection
from zacai.claude_history_index import index_claude_member_history
from zacai.claude_message_projection import ClaudeMessageProjection, extract_claude_selected_message
from zacai.claude_original_capture import (
    MAX_ORIGINAL_REVISIONS,
    ClaudeArtifactRootIdentity,
    ClaudeCustodyProposal,
    _bounded_read,
    _clean,
    _envelope,
    _integer,
    _io,
    _number,
    _original_lineage,
    _pairs,
    _root_check,
    _SourceRow,
    _validated,
)
from zacai.history_manifest import MAX_MANIFEST_BYTES
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference, classification_covers
from zacai.policy import AccessRequest, Destination, evaluate_access
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import source_classification_elevation_strength


class ClaudeOriginalReadError(ValueError):
    """Fixed cause-free diagnostics; hosts must suppress traceback locals."""


@dataclass(frozen=True, repr=False)
class ReadClaudeCustody:
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    proposal_hash: str
    proposal: ClaudeCustodyProposal
    original_raw: bytes
    companion_raw: bytes
    captured_at: datetime
    original_binding_reference: EvidenceReference
    companion_binding_reference: EvidenceReference
    envelope_raw: bytes
    joint_output_classification: C
    original_tip_id: UUID
    superseded_at_read: bool
    original_within_legacy_byte_limit: bool
    reported_dates_after_acquired_at: bool
    date_semantics: Literal["HOST_DECLARED_AND_EXPORT_REPORTED"] = field(
        default="HOST_DECLARED_AND_EXPORT_REPORTED", init=False
    )
    recovery_verified: Literal[False] = field(default=False, init=False)
    owner_authenticated: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)

    @property
    def current_original_reference(self) -> EvidenceReference:
        return self.original_reference

    @property
    def current_companion_reference(self) -> EvidenceReference:
        return self.companion_reference


def _rows(
    session: Session,
    *,
    external: str | None = None,
    ids: tuple[UUID, ...] = (),
    externals: tuple[str, str] | None = None,
) -> tuple[_SourceRow, ...]:
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(
            source_classification_elevation_strength().desc(),
            SourceClassificationElevation.elevated_at.desc(),
        )
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    names = (
        "id",
        "trust_boundary",
        "data_classification",
        "system",
        "external_ref",
        "captured_at",
        "excerpt",
        "content_hash",
        "content_location",
        "supersedes_source_id",
    )
    query = select(
        *(getattr(Source, name) for name in names),
        func.coalesce(latest, Source.data_classification).label("effective"),
    )
    if externals is not None:
        if external is not None or ids or len(set(externals)) != 2:
            raise ValueError("exact pair namespaces required")
        query = query.where(Source.external_ref.in_(externals))
        cap = MAX_ORIGINAL_REVISIONS + 1  # original max plus unique companion
    else:
        query = (
            query.where(Source.external_ref == external)
            if external is not None
            else query.where(Source.id.in_(ids))
        )
        cap = MAX_ORIGINAL_REVISIONS
    rows = tuple(
        _SourceRow.model_validate(dict(row))
        for row in session.execute(query.order_by(Source.id).limit(cap + 1)).mappings()
    )
    if len(rows) > cap:
        raise ValueError("lineage capacity")
    return rows


def _pair_rows(
    session: Session, original: str, companion: str
) -> tuple[tuple[_SourceRow, ...], tuple[_SourceRow, ...]]:
    """Both complete namespace lineages from ONE READ COMMITTED statement."""
    rows = _rows(session, externals=(original, companion))
    originals = tuple(row for row in rows if row.external_ref == original)
    companions = tuple(row for row in rows if row.external_ref == companion)
    if len(originals) > MAX_ORIGINAL_REVISIONS or len(companions) != 1:
        raise ValueError("lineage capacity or companion ambiguity")
    return originals, companions


def _read_only(session: Session) -> None:
    if session.get_nested_transaction() is not None:
        raise ValueError("read transaction is nested")
    if session.scalar(select(func.txid_current_if_assigned())) is not None:
        raise ValueError("read transaction has writes")


def _selected_own_date_conflict(proposal: ClaudeCustodyProposal, original_raw: bytes) -> bool:
    """Selected records own created/updated claims, not nested conversation dates."""
    index = index_claude_member_history(original_raw, expected_file_hash=proposal.original_hash)
    selected_ids = {choice.original_id for choice in proposal.selections}
    selected_reported_dates = [choice.reported_at for choice in proposal.selections]
    selected_reported_dates.extend(
        conversation.reported_updated_at
        for conversation in index.conversations
        if str(conversation.original_id) in selected_ids
    )
    selected_reported_dates.extend(
        message.reported_updated_at
        for conversation in index.conversations
        for message in conversation.messages
        if str(message.original_id) in selected_ids
    )
    return any(
        value is not None and value > proposal.acquired_at for value in selected_reported_dates
    )


def _access(rows: tuple[_SourceRow, ...], boundaries: frozenset[B], classes: frozenset[C]) -> None:
    for row in rows:
        if (
            not classification_covers(row.effective, row.data_classification)
            or row.system != SourceSystem.MANUAL
            or row.trust_boundary not in boundaries
            or row.data_classification not in classes
            or row.effective not in classes
            or not evaluate_access(
                AccessRequest(
                    data_boundary=row.trust_boundary,
                    data_classification=row.effective,
                    requestor_boundaries=boundaries,
                    destination=Destination.LOCAL,
                )
            ).allowed
        ):
            raise ValueError("current source unavailable")


def load_claude_original(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
    requestor_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> ReadClaudeCustody:
    result = None
    try:
        _clean(session)
        outer = session.get_transaction()
        if outer is None or not outer.is_active:
            raise ValueError("existing transaction required")
        _assert_ledger_isolation(session)
        _read_only(session)
        _root_check(artifacts, expected_root)
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(original_reference) is not EvidenceReference
            or type(companion_reference) is not EvidenceReference
            or original_reference.source_id == companion_reference.source_id
            or type(expected_account_ref) is not str
            or not expected_account_ref
            or (
                expected_exported_at is not None
                and (
                    type(expected_exported_at) is not datetime
                    or expected_exported_at.tzinfo is None
                    or expected_exported_at.utcoffset() is None
                )
            )
            or type(requestor_boundaries) is not frozenset
            or type(allowed_classifications) is not frozenset
            or any(type(x) is not B for x in requestor_boundaries)
            or any(type(x) is not C for x in allowed_classifications)
        ):
            raise ValueError("exact read inputs required")
        original_reference = EvidenceReference.model_validate(original_reference)
        companion_reference = EvidenceReference.model_validate(companion_reference)
        if original_reference.source_id.int == 0 or companion_reference.source_id.int == 0:
            raise ValueError("nonzero canonical identities required")
        selected = _rows(session, ids=(original_reference.source_id, companion_reference.source_id))
        _access(selected, requestor_boundaries, allowed_classifications)
        by_id = {row.id: row for row in selected}
        if len(selected) != 2:
            raise ValueError("exact sources required")
        original, companion = (
            by_id[original_reference.source_id],
            by_id[companion_reference.source_id],
        )
        for row, ref in ((original, original_reference), (companion, companion_reference)):
            if (
                row.content_hash != ref.content_hash
                or row.trust_boundary != ref.trust_boundary
                or row.effective != ref.effective_classification
                or row.content_location is None
                or row.excerpt is not None
            ):
                raise ValueError("source snapshot differs")
        if original.external_ref is None or not original.external_ref.startswith(
            "claude-original/"
        ):
            raise ValueError("original namespace required")
        custody = UUID(original.external_ref.removeprefix("claude-original/"))
        if original.external_ref != f"claude-original/{custody}" or custody.int == 0:
            raise ValueError("exact original namespace required")
        prefix = f"claude-original-companion/{custody}/"
        if companion.external_ref is None or not companion.external_ref.startswith(prefix):
            raise ValueError("companion namespace required")
        proposal_hash = companion.external_ref.removeprefix(prefix)
        if len(proposal_hash) != 64 or any(x not in "0123456789abcdef" for x in proposal_hash):
            raise ValueError("exact proposal digest required")
        original_namespace, companion_namespace = original.external_ref, companion.external_ref
        originals, companions = _pair_rows(session, original_namespace, companion_namespace)
        _original_lineage(originals)
        if any(row.trust_boundary != original.trust_boundary for row in originals + companions):
            raise ValueError("lineage boundary differs")
        _access(originals + companions, requestor_boundaries, allowed_classifications)
        if (
            original not in originals
            or companions != (companion,)
            or companion.supersedes_source_id is not None
        ):
            raise ValueError("unique canonical provenance required")

        def read(row: _SourceRow, cap: int) -> bytes:
            _read_only(session)
            _root_check(artifacts, expected_root)
            before = _pair_rows(session, original_namespace, companion_namespace)
            if before != (originals, companions):
                raise ValueError("source observation changed")
            _access(before[0] + before[1], requestor_boundaries, allowed_classifications)
            location = row.content_location
            if location is None:
                raise ValueError("location required")
            raw = _io(
                session,
                lambda: _bounded_read(
                    artifacts,
                    expected_root,
                    row.trust_boundary,
                    location,
                    max_bytes=cap,
                ),
            )
            _read_only(session)
            _root_check(artifacts, expected_root)
            after = _pair_rows(session, original_namespace, companion_namespace)
            if after != before or content_hash_of(raw) != row.content_hash:
                raise ValueError("read observation differs")
            _access(after[0] + after[1], requestor_boundaries, allowed_classifications)
            return raw

        envelope_raw = read(companion, MAX_MANIFEST_BYTES)
        envelope = json.loads(
            envelope_raw,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_number,
            parse_constant=_number,
        )
        proposal_raw = canonical_bytes(envelope["proposal"])
        if content_hash_of(proposal_raw) != proposal_hash:
            raise ValueError("proposal differs")
        proposal = ClaudeCustodyProposal.model_validate(envelope["proposal"])
        if (
            proposal.custody_id != custody
            or proposal.account_ref != expected_account_ref
            or proposal.exported_at != expected_exported_at
            or proposal.captured_at != original.captured_at
            or companion.captured_at != original.captured_at
            or proposal.original_hash != original.content_hash
            or proposal.boundary != original.trust_boundary
            or proposal.boundary != companion.trust_boundary
            or proposal.classification != original.data_classification
            or proposal.classification != companion.data_classification
        ):
            raise ValueError("canonical custody declaration differs")
        original_raw = read(original, proposal.original_bytes)
        proposal = _validated(proposal_raw, original_raw)
        if _envelope(proposal, str(original.id)) != envelope_raw:
            raise ValueError("exact derivation differs")
        companion_raw = canonical_bytes(envelope["companion"])
        original_binding_reference = EvidenceReference(
            source_id=original.id,
            content_hash=proposal.original_hash,
            trust_boundary=proposal.boundary,
            effective_classification=proposal.classification,
        )
        companion_binding_reference = EvidenceReference(
            source_id=companion.id,
            content_hash=content_hash_of(envelope_raw),
            trust_boundary=proposal.boundary,
            effective_classification=proposal.classification,
        )
        inspection = inspect_claude_custody_selection(
            companion_raw,
            original_raw,
            expected_companion_hash=content_hash_of(companion_raw),
            expected_original_reference=original_binding_reference,
            expected_account_ref=expected_account_ref,
            expected_exported_at=expected_exported_at,
        )
        reported_date_conflict = _selected_own_date_conflict(proposal, original_raw)
        # Last external work is finished: root check, complete scalar union, no IO afterward.
        _root_check(artifacts, expected_root)
        final = _pair_rows(session, original_namespace, companion_namespace)
        if final != (originals, companions):
            raise ValueError("final source union differs")
        _access(final[0] + final[1], requestor_boundaries, allowed_classifications)
        _clean(session)
        _read_only(session)
        if session.get_transaction() is not outer or not outer.is_active:
            raise ValueError("caller transaction changed")
        result = ReadClaudeCustody(
            original_reference,
            companion_reference,
            proposal_hash,
            proposal,
            original_raw,
            companion_raw,
            original.captured_at,
            original_binding_reference,
            companion_binding_reference,
            envelope_raw,
            original.effective
            if classification_covers(original.effective, companion.effective)
            else companion.effective,
            next(
                row.id
                for row in originals
                if row.id not in {item.supersedes_source_id for item in originals}
            ),
            any(row.supersedes_source_id == original.id for row in originals),
            inspection.original_within_legacy_byte_limit,
            reported_date_conflict,
        )
    except Exception:  # noqa: BLE001,S110 - private errors held without retained causes
        pass
    if result is None:
        raise ClaudeOriginalReadError("Claude original unavailable")
    return result


@dataclass(frozen=True, repr=False)
class ReadClaudeMessage:
    """Prepared projection, not current owner, recovery or model permission."""

    capture_binding_projection: ClaudeMessageProjection
    current_original_reference: EvidenceReference
    current_companion_reference: EvidenceReference
    joint_output_classification: C
    captured_at: datetime
    date_semantics: Literal["HOST_DECLARED_AND_EXPORT_REPORTED"]
    reported_dates_after_acquired_at: bool
    superseded_at_read: bool
    original_tip_id: UUID
    projection_reference_semantics: Literal["IMMUTABLE_CAPTURE_BINDING_ONLY"] = field(
        default="IMMUTABLE_CAPTURE_BINDING_ONLY", init=False
    )
    owner_authenticated: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)


def project_claude_read_message(
    read: ReadClaudeCustody, *, character_start: int, character_end: int
) -> ReadClaudeMessage:
    result = None
    try:
        if (
            type(read) is not ReadClaudeCustody
            or read.captured_at != read.proposal.captured_at
            or type(read.reported_dates_after_acquired_at) is not bool
            or type(read.superseded_at_read) is not bool
            or type(read.original_tip_id) is not UUID
            or read.original_tip_id.int == 0
            or read.superseded_at_read
            != (read.original_tip_id != read.original_reference.source_id)
            or read.date_semantics != "HOST_DECLARED_AND_EXPORT_REPORTED"
            or read.reported_dates_after_acquired_at
            != _selected_own_date_conflict(read.proposal, read.original_raw)
        ):
            raise ValueError("exact read observations required")
        for current, binding in (
            (read.original_reference, read.original_binding_reference),
            (read.companion_reference, read.companion_binding_reference),
        ):
            EvidenceReference.model_validate(current)
            EvidenceReference.model_validate(binding)
            if (
                current.source_id != binding.source_id
                or current.content_hash != binding.content_hash
                or current.trust_boundary != binding.trust_boundary
                or not classification_covers(
                    current.effective_classification, binding.effective_classification
                )
            ):
                raise ValueError("base/current reference differs")
        if (
            content_hash_of(read.envelope_raw) != read.companion_reference.content_hash
            or _envelope(read.proposal, str(read.original_reference.source_id)) != read.envelope_raw
            or canonical_bytes(json.loads(read.envelope_raw)["companion"]) != read.companion_raw
        ):
            raise ValueError("exact retained envelope differs")
        for binding in (read.original_binding_reference, read.companion_binding_reference):
            if (
                binding.trust_boundary != read.proposal.boundary
                or binding.effective_classification != read.proposal.classification
            ):
                raise ValueError("immutable declaration differs")
        expected_joint = (
            read.original_reference.effective_classification
            if classification_covers(
                read.original_reference.effective_classification,
                read.companion_reference.effective_classification,
            )
            else read.companion_reference.effective_classification
        )
        if read.joint_output_classification != expected_joint:
            raise ValueError("joint sensitivity differs")
        projection = extract_claude_selected_message(
            read.companion_raw,
            read.original_raw,
            expected_companion_hash=content_hash_of(read.companion_raw),
            expected_original_reference=read.original_binding_reference,
            expected_account_ref=read.proposal.account_ref,
            expected_exported_at=read.proposal.exported_at,
            character_start=character_start,
            character_end=character_end,
        )
        result = ReadClaudeMessage(
            projection,
            read.original_reference,
            read.companion_reference,
            expected_joint,
            read.captured_at,
            read.date_semantics,
            read.reported_dates_after_acquired_at,
            read.superseded_at_read,
            read.original_tip_id,
        )
    except Exception:  # noqa: BLE001,S110 - private diagnostic suppression
        pass
    if result is None:
        raise ClaudeOriginalReadError("Claude original unavailable")
    return result
