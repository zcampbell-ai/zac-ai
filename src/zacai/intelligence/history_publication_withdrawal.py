"""Observed complete-purpose cancellation in the existing consumed namespace.

Cancellation reads the own historical declaration only, not expired generation
input eligibility. No processing/recovery grant, repair, deletion or new ledger.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime
from sqlalchemy.orm import Session, sessionmaker

from zacai import contextual_authorization as auth
from zacai.backup_artifacts import _assert_personal_custody_append_capacity
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_publication_generation import (
    _same_output_commit_transaction as _same_commit,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.fragment_review_withdrawal import _withdrawal_ids, _withdrawal_namespace
from zacai.intelligence.history_generation_review_declaration import (
    MAX_DECLARATION_BYTES,
    HistoryGenerationReviewDeclarationV1,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_review_retention import (
    _ids,
    _namespace,
    _parts,
)
from zacai.interfaces.history_publication_action import _consume_history_post, _PostedHistoryAction
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import SourceSystem
from zacai.state_repository import record_source

_NATIVE_MONOTONIC = time.monotonic
MAX_WITHDRAWAL_BYTES = 8192


class HistoryWithdrawalError(ValueError):
    """Fixed held cancellation, possibly committed; never safe retry proof."""


class HistoryPublicationWithdrawalV1(Contract):
    format: Literal["zac-personal-complete-publication-withdrawal-v1"] = (
        "zac-personal-complete-publication-withdrawal-v1"
    )
    generation_id: UUID
    publication_reference: EvidenceReference
    publication_digest: Digest
    request_digest: Digest
    generation_wire_digest: Digest
    owner_issuer: str
    owner_subject: str
    current_session_binding: Digest
    current_session_issued_at: AwareDatetime
    current_session_expires_at: AwareDatetime
    observed_at: AwareDatetime


@dataclass(frozen=True, repr=False)
class RetainedHistoryWithdrawal:
    reference: EvidenceReference
    value: HistoryPublicationWithdrawalV1

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False


def _raw(value: HistoryPublicationWithdrawalV1) -> bytes:
    result = canonical_bytes(value.model_dump(mode="json"))
    if len(result) > MAX_WITHDRAWAL_BYTES:
        raise ValueError("bounded cancellation required")
    return result


def _target_current(
    session: Session,
    reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    raw, g, _ = _parts(declaration)
    if (
        reference.content_hash != content_hash_of(raw)
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
    ):
        raise ValueError("exact historical complete target required")
    rows = _fragment_rows(session, (reference,), auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    if _ids(session, g.id) != (reference.source_id,):
        raise ValueError("unique own complete publication required")
    row = dict(rows[0])
    if (
        row["system"] is not SourceSystem.MANUAL
        or row["external_ref"] != _namespace(declaration)
        or row["data_classification"] is not C.HIGHLY_RESTRICTED
        or row["lineage_id"] != reference.source_id
        or row["supersedes_source_id"] is not None
    ):
        raise ValueError("exact historical target metadata required")
    return rows


def _load_history_withdrawal_target(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> None:
    """Own exact historical body/current ACL; no old input/request admission."""
    entry = _physical(session)
    before = _target_current(session, reference, declaration)
    row = dict(before[0])
    location = row["content_location"]
    if type(location) is not str:
        raise ValueError("bounded target location required")
    if (
        artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_DECLARATION_BYTES)
        != _parts(declaration)[0]
    ):
        raise ValueError("exact own historical body required")
    _same(session, entry)
    if _target_current(session, reference, declaration) != before:
        raise ValueError("historical target changed during own read")
    _same(session, entry)


def _event_current(
    session: Session,
    reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    _, g, _ = _parts(declaration)
    target = _target_current(session, reference, declaration)
    ids = _withdrawal_ids(session, g.id)
    if len(ids) != 1:
        raise ValueError("one complete withdrawal required")
    from zacai.state import Source

    row = session.get(Source, ids[0])
    if row is None:
        raise ValueError("complete withdrawal unavailable")
    event_ref = EvidenceReference(
        source_id=row.id,
        content_hash=row.content_hash,
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    rows = _fragment_rows(session, (event_ref,), auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    item = dict(rows[0])
    if (
        item["system"] is not SourceSystem.USER_INSTRUCTION
        or item["external_ref"] != _withdrawal_namespace(g.id)
        or item["data_classification"] is not C.HIGHLY_RESTRICTED
        or item["lineage_id"] != row.id
        or item["supersedes_source_id"] is not None
    ):
        raise ValueError("exact committed cancellation metadata required")
    return (*target, *rows)


def _load_history_publication_withdrawal(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    publication_reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> RetainedHistoryWithdrawal:
    entry = _physical(session)
    before = _event_current(session, publication_reference, declaration)
    load_history_withdrawal_target(
        session, artifacts=artifacts, reference=publication_reference, declaration=declaration
    )
    if _event_current(session, publication_reference, declaration) != before:
        raise ValueError("cancellation changed after target callback")
    row = dict(before[-1])
    if type(row["content_location"]) is not str:
        raise ValueError("bounded cancellation location required")
    raw = artifacts.get_bounded(B.PERSONAL, row["content_location"], max_bytes=MAX_WITHDRAWAL_BYTES)
    value = HistoryPublicationWithdrawalV1.model_validate_json(raw)
    _, g, _ = _parts(declaration)
    if (
        raw != _raw(value)
        or content_hash_of(raw) != row["content_hash"]
        or value.publication_reference != publication_reference
        or value.publication_digest != history_generation_review_declaration_digest(declaration)
        or value.generation_id != g.id
        or value.request_digest != g.request_digest
        or value.generation_wire_digest != g.generation_wire_digest
        or (value.owner_issuer, value.owner_subject) != (g.owner_issuer, g.owner_subject)
        or not value.current_session_issued_at
        <= value.observed_at
        < value.current_session_expires_at
        or row["captured_at"] != value.observed_at
    ):
        raise ValueError("exact complete cancellation binding required")
    _same(session, entry)
    if _event_current(session, publication_reference, declaration) != before:
        raise ValueError("cancellation changed after own callback")
    _same(session, entry)
    identifier, digest = row["id"], row["content_hash"]
    if type(identifier) is not UUID or type(digest) is not str:
        raise ValueError("exact cancellation reference metadata required")
    return RetainedHistoryWithdrawal(
        EvidenceReference(
            source_id=identifier,
            content_hash=digest,
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        ),
        value,
    )


def withdraw_history_publication(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    action: _PostedHistoryAction,
) -> RetainedHistoryWithdrawal:
    result = None
    started = _NATIVE_MONOTONIC()
    interrupted: KeyboardInterrupt | SystemExit | None = None
    try:
        if type(factory) is not sessionmaker or type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("actual canonical cancellation graph required")
        observation = _consume_history_post(action, purpose="WITHDRAW")
        _, g, _ = _parts(observation.publication)

        def owner() -> datetime:
            operation = observation.operation
            operation.host_clock()
            current = operation.recheck(observation.current_session.binding_digest)
            with operation.host_clock._lock:
                now = operation.host_clock._last
            if (
                current != observation.current_session
                or now is None
                or not current.issued_at <= now < current.effective_expires_at
            ):
                raise ValueError("current cancellation actor/window changed")
            return now

        now = owner()
        deadline = (
            started + (observation.current_session.effective_expires_at - now).total_seconds()
        )
        with factory() as session, session.begin():
            _lock(session, g.id)
            load_history_withdrawal_target(
                session,
                artifacts=artifacts,
                reference=observation.reference,
                declaration=observation.publication,
            )
            baseline = _target_current(session, observation.reference, observation.publication)
            prior = _withdrawal_ids(session, g.id)
            if len(prior) > 1:
                raise ValueError("cancellation conflict")
            if prior:
                load_history_publication_withdrawal(
                    session,
                    artifacts=artifacts,
                    publication_reference=observation.reference,
                    declaration=observation.publication,
                )
        if not prior:
            current = observation.current_session
            value = HistoryPublicationWithdrawalV1(
                generation_id=g.id,
                publication_reference=observation.reference,
                publication_digest=history_generation_review_declaration_digest(
                    observation.publication
                ),
                request_digest=g.request_digest,
                generation_wire_digest=g.generation_wire_digest,
                owner_issuer=g.owner_issuer,
                owner_subject=g.owner_subject,
                current_session_binding=current.binding_digest,
                current_session_issued_at=current.issued_at,
                current_session_expires_at=current.effective_expires_at,
                observed_at=observation.observed_at,
            )
            raw = _raw(value)
            location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            if artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_WITHDRAWAL_BYTES) != raw:
                raise ValueError("stored cancellation differs")
        owner()
        with factory() as session:
            session.begin()
            _lock(session, g.id)
            entry = _physical(session)
            if (
                _target_current(session, observation.reference, observation.publication) != baseline
                or _withdrawal_ids(session, g.id) != prior
            ):
                raise ValueError("cancellation target changed before write")
            if not prior:
                _assert_personal_custody_append_capacity(session, 1)
                row, new = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.USER_INSTRUCTION,
                    external_ref=_withdrawal_namespace(g.id),
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    captured_at=observation.observed_at,
                )
                if not new:
                    raise ValueError("unexpected cancellation replay")
                ids: tuple[UUID, ...] = (row.id,)
            else:
                ids = prior
            if (
                _withdrawal_ids(session, g.id) != ids
                or _target_current(session, observation.reference, observation.publication)
                != baseline
            ):
                raise ValueError("cancellation changed before commit")
            _same(session, entry)
            if _NATIVE_MONOTONIC() >= deadline:
                raise ValueError("current cancellation window expired")
            _same_commit(session, entry)
            session.commit()
        owner()
        with factory() as session, session.begin():
            reopened = load_history_publication_withdrawal(
                session,
                artifacts=artifacts,
                publication_reference=observation.reference,
                declaration=observation.publication,
            )
            final = _event_current(session, observation.reference, observation.publication)
        owner()
        with factory() as session, session.begin():
            entry = _physical(session)
            if _event_current(session, observation.reference, observation.publication) != final:
                raise ValueError("final cancellation became stale")
            _same(session, entry)
        if _NATIVE_MONOTONIC() >= deadline:
            raise ValueError("cancellation acknowledgment expired")
        result = reopened
    except (KeyboardInterrupt, SystemExit) as error:
        interrupted = error
    except Exception:  # noqa: BLE001,S110 - possibly committed hold, no automatic retry
        pass
    if interrupted is not None:
        raise type(interrupted)() from None
    if result is None:
        raise HistoryWithdrawalError("complete cancellation unavailable; stop and reconcile")
    return result


def load_history_withdrawal_target(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> None:
    """Fixed private-safe own-target read, with no processing reapproval."""
    success = False
    try:
        _load_history_withdrawal_target(
            session, artifacts=artifacts, reference=reference, declaration=declaration
        )
        success = True
    except Exception:  # noqa: BLE001,S110
        pass
    if not success:
        raise HistoryWithdrawalError("complete cancellation target unavailable")


def load_history_publication_withdrawal(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    publication_reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> RetainedHistoryWithdrawal:
    """Existing exact event only; no write, repair, recovery or authority."""
    result = None
    try:
        result = _load_history_publication_withdrawal(
            session,
            artifacts=artifacts,
            publication_reference=publication_reference,
            declaration=declaration,
        )
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryWithdrawalError("complete cancellation record unavailable")
    return result
