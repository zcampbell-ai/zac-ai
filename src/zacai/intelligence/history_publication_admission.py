"""Canonical browser-observed history publication, never dispatch permission.

Only the concrete HTTP controller's consumed POST observation can reach the
writer. MANUAL publication custody, caller declarations and encoded constructors
cannot mint this observation. Only the completed writer issues an in-process
acknowledgment capability; a loader returns custody and can never issue or renew
it. A failed acknowledgment after commit is terminal possibly-committed HOLD,
never permission to resume or re-POST. Trusted host code is not a callback sandbox.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from threading import RLock
from time import monotonic as _NATIVE_MONOTONIC
from typing import TYPE_CHECKING, Literal, Self, SupportsIndex
from uuid import UUID
from weakref import ReferenceType, ref

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai import contextual_authorization as auth
from zacai.backup_artifacts import _assert_personal_custody_append_capacity
from zacai.claude_original_capture import _artifact_profile, _root_check
from zacai.host_clock import HostObservedClock
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
from zacai.intelligence.fragment_review_withdrawal import _withdrawal_ids
from zacai.intelligence.history_generation_review_declaration import (
    HistoryGenerationReviewDeclarationV1,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_review_retention import (
    HistoryDeclarationContext,
    _parts,
    history_declaration_owner,
    load_history_review_declaration,
)
from zacai.intelligence.history_review_retention import (
    _ids as _publication_ids,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

if TYPE_CHECKING:
    from zacai.interfaces.history_publication_action import _PostedHistoryAction
    from zacai.interfaces.named_session_binding import NamedSessionOperation

MAX_ADMISSION_BYTES = 16000


class HistoryPublicationAdmissionError(ValueError):
    """Fixed safe acknowledgment error; no approval inferred from failure."""


class HistoryPublicationAdmissionUncertain(HistoryPublicationAdmissionError):
    """Possibly committed custody, terminal no-retry and no processing capability."""


class HistoryPublicationAdmissionV1(Contract):
    format: Literal["zac-history-complete-publication-admission-v1"] = (
        "zac-history-complete-publication-admission-v1"
    )
    action: Literal["approve_history_generation_and_review"] = (
        "approve_history_generation_and_review"
    )
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    generation_id: UUID
    task_id: UUID
    builder_id: UUID
    request_digest: Digest
    generation_wire_digest: Digest
    review_profile_digest: Digest
    actor_issuer: str = Field(strict=True, min_length=1, max_length=500, repr=False)
    actor_subject: str = Field(strict=True, min_length=1, max_length=500, repr=False)
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    original_approved_at: AwareDatetime
    expires_at: AwareDatetime
    observed_action_at: AwareDatetime

    @model_validator(mode="after")
    def exact_window(self) -> Self:
        r = self.publication_reference
        if (
            r.source_id.int == 0
            or r.trust_boundary is not B.PERSONAL
            or r.effective_classification is not C.HIGHLY_RESTRICTED
            or any(x.int == 0 for x in (self.generation_id, self.task_id, self.builder_id))
            or not self.original_session_issued_at
            <= self.original_approved_at
            <= self.observed_action_at
            < self.expires_at
            <= self.original_session_expires_at
        ):
            raise ValueError("exact original browser action window required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def encode_history_publication_admission(value: HistoryPublicationAdmissionV1) -> bytes:
    result = None
    try:
        if type(value) is not HistoryPublicationAdmissionV1:
            raise ValueError("exact action family required")
        raw = canonical_bytes(
            HistoryPublicationAdmissionV1.model_validate(value).model_dump(mode="json")
        )
        if len(raw) > MAX_ADMISSION_BYTES:
            raise ValueError("bounded action required")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationAdmissionError("history publication action unavailable")
    return result


def decode_history_publication_admission(raw: bytes) -> HistoryPublicationAdmissionV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ADMISSION_BYTES:
            raise ValueError("bounded action required")

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in items:
                if key in out:
                    raise ValueError("duplicate field")
                out[key] = value
            return out

        result = HistoryPublicationAdmissionV1.model_validate_json(
            canonical_bytes(json.loads(raw, object_pairs_hook=pairs)), strict=True
        )
        if encode_history_publication_admission(result) != raw:
            raise ValueError("canonical action required")
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryPublicationAdmissionError("history publication action unavailable")
    return result


def _binding(
    value: HistoryPublicationAdmissionV1, publication: HistoryGenerationReviewDeclarationV1
) -> None:
    _, g, _ = _parts(publication)
    raw = encode_history_publication_admission(value)
    if (
        value.publication_digest != history_generation_review_declaration_digest(publication)
        or value.publication_reference.content_hash != content_hash_of(_parts(publication)[0])
        or (
            value.generation_id,
            value.task_id,
            value.builder_id,
            value.request_digest,
            value.generation_wire_digest,
            value.review_profile_digest,
        )
        != (
            g.id,
            g.task_id,
            g.builder_id,
            g.request_digest,
            g.generation_wire_digest,
            publication.review_profile_digest,
        )
        or (
            value.actor_issuer,
            value.actor_subject,
            value.original_session_binding,
            value.original_session_issued_at,
            value.original_session_expires_at,
            value.original_approved_at,
            value.expires_at,
        )
        != (
            g.owner_issuer,
            g.owner_subject,
            g.original_session_binding,
            g.original_session_issued_at,
            g.original_session_expires_at,
            g.approved_at,
            g.expires_at,
        )
        or not raw
        or publication.review is None
    ):
        raise ValueError("full original publication action differs")


def _prefix(value: HistoryPublicationAdmissionV1) -> str:
    return f"personal-history-complete-publication-admission/{value.generation_id}/"


def _namespace(value: HistoryPublicationAdmissionV1) -> str:
    return (
        _prefix(value)
        + value.publication_digest
        + "/"
        + content_hash_of(encode_history_publication_admission(value))
    )


def _ids(
    session: Session, prefix: str, *, system: SourceSystem = SourceSystem.USER_INSTRUCTION
) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == system,
                Source.external_ref.like(prefix + "%"),
            )
            .limit(2)
        )
    )


def _not_withdrawn(session: Session, generation_id: UUID) -> None:
    # Reuse the canonical existing withdrawal locator. No complete-family
    # cancellation writer or processing authority is implied.
    if _withdrawal_ids(session, generation_id):
        raise ValueError("publication withdrawn or cancellation state ambiguous")


@dataclass(frozen=True, repr=False)
class RetainedHistoryPublicationAdmission:
    """Canonical custody comparison only, including unacknowledged commit rows."""

    reference: EvidenceReference
    admission: HistoryPublicationAdmissionV1 = field(repr=False)
    captured_at: datetime


def _history_admission_current(
    session: Session,
    *,
    reference: EvidenceReference,
    expected_admission: HistoryPublicationAdmissionV1,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    """Current exact full-union/namespace scalars; no owner or artifact callback.

    Caller retains its physical transaction guard. This is not an authority
    capability and does not replace the actual complete original reader.
    """
    _binding(expected_admission, expected_declaration)
    raw = encode_history_publication_admission(expected_admission)
    if (
        type(reference) is not EvidenceReference
        or reference.source_id.int == 0
        or reference.content_hash != content_hash_of(raw)
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
    ):
        raise ValueError("exact admission locator required")
    _, g, _ = _parts(expected_declaration)
    selected = (*g.provenance, expected_admission.publication_reference, reference)
    if len(selected) > 95 or len({r.source_id for r in selected}) != len(selected):
        raise ValueError("bounded distinct complete action union required")
    rows = _fragment_rows(session, selected, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    _not_withdrawn(session, g.id)
    if _publication_ids(session, g.id) != (
        expected_admission.publication_reference.source_id,
    ) or _ids(session, _prefix(expected_admission)) != (reference.source_id,):
        raise ValueError("unique complete publication and action required")
    row = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
    if (
        row["system"] is not SourceSystem.USER_INSTRUCTION
        or row["external_ref"] != _namespace(expected_admission)
        or row["supersedes_source_id"] is not None
        or row["lineage_id"] != reference.source_id
        or row["captured_at"] != expected_admission.observed_action_at
    ):
        raise ValueError("exact canonical action metadata required")
    return rows


def load_history_publication_admission(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    expected_admission: HistoryPublicationAdmissionV1,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    context: HistoryDeclarationContext,
) -> RetainedHistoryPublicationAdmission:
    result = None
    try:
        _binding(expected_admission, expected_declaration)
        raw = encode_history_publication_admission(expected_admission)
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(reference) is not EvidenceReference
            or reference.content_hash != content_hash_of(raw)
            or reference.trust_boundary is not B.PERSONAL
            or reference.effective_classification is not C.HIGHLY_RESTRICTED
        ):
            raise ValueError("exact action Source required")
        entry = _physical(session)
        rows = _history_admission_current(
            session,
            reference=reference,
            expected_admission=expected_admission,
            expected_declaration=expected_declaration,
        )
        _same(session, entry)
        row = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
        load_history_review_declaration(
            session,
            artifacts=artifacts,
            context=context,
            reference=expected_admission.publication_reference,
            expected_declaration=expected_declaration,
        )
        _same(session, entry)
        if (
            _history_admission_current(
                session,
                reference=reference,
                expected_admission=expected_admission,
                expected_declaration=expected_declaration,
            )
            != rows
        ):
            raise ValueError("full action union changed during parent read")
        _same(session, entry)
        location, captured = row["content_location"], row["captured_at"]
        if (
            type(location) is not str
            or not isinstance(captured, datetime)
            or captured.utcoffset() is None
        ):
            raise ValueError("bounded Source location/time required")
        returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_ADMISSION_BYTES)
        _same(session, entry)
        if returned != raw or decode_history_publication_admission(returned) != expected_admission:
            raise ValueError("exact action bytes required")
        if (
            _history_admission_current(
                session,
                reference=reference,
                expected_admission=expected_admission,
                expected_declaration=expected_declaration,
            )
            != rows
        ):
            raise ValueError("full action union changed")
        _same(session, entry)
        result = RetainedHistoryPublicationAdmission(reference, expected_admission, captured)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationAdmissionError("history publication action unavailable")
    return result


_ACK_SEAL = object()


@dataclass(frozen=True, init=False, repr=False)
class AcknowledgedHistoryPublicationAdmission:
    """Writer-success identity only; loaded custody cannot issue this capability.

    A concrete consumer must consume once, then independently recheck original
    canonical inputs/recovery and burn its claim. This is not dispatch authority.
    """

    retained: RetainedHistoryPublicationAdmission
    _operation: NamedSessionOperation
    _clock: HostObservedClock
    _declaration: HistoryGenerationReviewDeclarationV1
    _deadline: float
    _seal: object
    _issued_ref: ReferenceType[AcknowledgedHistoryPublicationAdmission]
    _lock: RLock
    _used: bool

    def __init__(self) -> None:
        raise HistoryPublicationAdmissionError("acknowledged history action unavailable")

    def __copy__(self) -> Self:
        raise HistoryPublicationAdmissionError("acknowledged history action unavailable")

    def __deepcopy__(self, memo: dict[int, object]) -> Self:
        raise HistoryPublicationAdmissionError("acknowledged history action unavailable")

    def __reduce_ex__(self, protocol: SupportsIndex) -> tuple[object, ...]:
        raise HistoryPublicationAdmissionError("acknowledged history action unavailable")

    @property
    def original_deadline_monotonic(self) -> float:
        return self._deadline

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reference(self) -> EvidenceReference:
        return self.retained.reference

    @property
    def admission(self) -> HistoryPublicationAdmissionV1:
        return self.retained.admission

    @property
    def captured_at(self) -> datetime:
        return self.retained.captured_at


def _consume_history_admission_acknowledgment(
    capability: AcknowledgedHistoryPublicationAdmission,
    *,
    operation: NamedSessionOperation,
    clock: HostObservedClock,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
) -> RetainedHistoryPublicationAdmission:
    """Concrete consumer entry only, outside SQL; no loader issues permission."""
    from zacai.interfaces.named_session_binding import NamedSessionOperation

    result = None
    try:
        if (
            type(capability) is not AcknowledgedHistoryPublicationAdmission
            or capability._seal is not _ACK_SEAL
            or type(capability._issued_ref) is not ReferenceType
            or capability._issued_ref() is not capability
            or type(operation) is not NamedSessionOperation
            or capability._operation is not operation
            or capability._clock is not clock
            or operation.host_clock is not clock
            or capability._declaration != expected_declaration
        ):
            raise ValueError("exact successful original action required")
        with capability._lock:
            if capability._used:
                raise ValueError("successful action already consumed")
            object.__setattr__(capability, "_used", True)
        _, generation, _ = _parts(expected_declaration)
        history_declaration_owner(operation, clock, generation)
        if _NATIVE_MONOTONIC() >= capability._deadline:
            raise ValueError("original action deadline expired")
        result = capability.retained
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationAdmissionError("acknowledged history action unavailable")
    return result


def _record_posted_history_admission(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    action: _PostedHistoryAction,
    clock: HostObservedClock,
    context: HistoryDeclarationContext,
) -> AcknowledgedHistoryPublicationAdmission:
    from zacai.interfaces.history_publication_action import _consume_history_post

    result = None
    possibly_committed = False
    try:
        if (
            type(factory) is not sessionmaker
            or type(artifacts) is not LocalFilesystemArtifactStore
            or type(context) is not HistoryDeclarationContext
        ):
            raise ValueError("concrete canonical action dependencies required")
        native_started = _NATIVE_MONOTONIC()
        observed = _consume_history_post(action, purpose="APPROVE")
        publication, reference, operation = (
            observed.publication,
            observed.reference,
            observed.operation,
        )
        _, g, _ = _parts(publication)
        if len(g.provenance) + 2 > 95:
            raise ValueError("complete action union capacity exceeded")
        history_declaration_owner(operation, clock, g)
        with clock._lock:
            original_observed = clock._last
        if original_observed is None:
            raise ValueError("actual original clock observation required")
        original_deadline = native_started + (g.expires_at - original_observed).total_seconds()
        value = HistoryPublicationAdmissionV1(
            publication_reference=reference,
            publication_digest=history_generation_review_declaration_digest(publication),
            generation_id=g.id,
            task_id=g.task_id,
            builder_id=g.builder_id,
            request_digest=g.request_digest,
            generation_wire_digest=g.generation_wire_digest,
            review_profile_digest=publication.review_profile_digest,
            actor_issuer=g.owner_issuer,
            actor_subject=g.owner_subject,
            original_session_binding=g.original_session_binding,
            original_session_issued_at=g.original_session_issued_at,
            original_session_expires_at=g.original_session_expires_at,
            original_approved_at=g.approved_at,
            expires_at=g.expires_at,
            observed_action_at=observed.observed_at,
        )
        _binding(value, publication)
        raw = encode_history_publication_admission(value)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            auth._assert_fragment_generation_unconsumed(session, g.id)
            _same(session, entry)
            _not_withdrawn(session, g.id)
            before = _fragment_rows(
                session,
                (*g.provenance, reference),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            load_history_review_declaration(
                session,
                artifacts=artifacts,
                context=context,
                reference=reference,
                expected_declaration=publication,
            )
            _same(session, entry)
            if _ids(session, _prefix(value)):
                raise ValueError("existing action cannot be renewed or redispatched")
            if (
                _fragment_rows(
                    session,
                    (*g.provenance, reference),
                    auth._FRAGMENT_BOUNDARIES,
                    auth._FRAGMENT_LABELS,
                )
                != before
            ):
                raise ValueError("publication union changed during clean preparation")
            if _publication_ids(session, g.id) != (reference.source_id,):
                raise ValueError("publication identity changed during clean preparation")
            _same(session, entry)
        _root_check(artifacts, context.expected_root)
        location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
        returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_ADMISSION_BYTES)
        _artifact_profile(artifacts, B.PERSONAL, location)
        _root_check(artifacts, context.expected_root)
        if returned != raw or location != artifacts.location_for(content_hash_of(raw)):
            raise ValueError("exact prepared action artifact required")
        history_declaration_owner(operation, clock, g)
        if _NATIVE_MONOTONIC() >= original_deadline:
            raise ValueError("original action expired during preparation")
        with factory() as session:
            session.begin()
            _lock(session, g.id)
            entry = _physical(session)
            _not_withdrawn(session, g.id)
            auth._assert_fragment_generation_unconsumed(session, g.id)
            if (
                _ids(session, _prefix(value))
                or _publication_ids(session, g.id) != (reference.source_id,)
                or _fragment_rows(
                    session,
                    (*g.provenance, reference),
                    auth._FRAGMENT_BOUNDARIES,
                    auth._FRAGMENT_LABELS,
                )
                != before
            ):
                raise ValueError("prepared original action union or namespace changed")
            _assert_personal_custody_append_capacity(session, 7)
            _same(session, entry)
            row, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=_namespace(value),
                content_hash=content_hash_of(raw),
                content_location=location,
                captured_at=value.observed_action_at,
            )
            if not new:
                raise ValueError("original action required")
            own = EvidenceReference(
                source_id=row.id,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            pending = _fragment_rows(
                session,
                (*g.provenance, reference, own),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            own_row = next(dict(v) for v in pending if dict(v)["id"] == own.source_id)
            if (
                own_row["system"] is not SourceSystem.USER_INSTRUCTION
                or own_row["external_ref"] != _namespace(value)
                or own_row["content_hash"] != own.content_hash
                or own_row["content_location"] != location
                or own_row["captured_at"] != value.observed_action_at
                or own_row["supersedes_source_id"] is not None
                or own_row["lineage_id"] != own.source_id
                or own_row["data_classification"] is not C.HIGHLY_RESTRICTED
                or _ids(session, _prefix(value)) != (own.source_id,)
                or _publication_ids(session, g.id) != (reference.source_id,)
                or _fragment_rows(
                    session,
                    (*g.provenance, reference),
                    auth._FRAGMENT_BOUNDARIES,
                    auth._FRAGMENT_LABELS,
                )
                != before
            ):
                raise ValueError("pending exact action metadata changed")
            _same(session, entry)
            auth._assert_fragment_generation_unconsumed(session, g.id)
            _assert_personal_custody_append_capacity(session, 6)
            _same(session, entry)
            if _NATIVE_MONOTONIC() >= original_deadline:
                raise ValueError("original action expiry crossed before commit")
            _same_commit(session, entry)
            possibly_committed = True
            session.commit()
        history_declaration_owner(operation, clock, g)
        with factory() as session:
            session.begin()
            saved = load_history_publication_admission(
                session,
                artifacts=artifacts,
                reference=own,
                expected_admission=value,
                expected_declaration=publication,
                context=context,
            )
            baseline = _fragment_rows(
                session,
                (*g.provenance, reference, own),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
        history_declaration_owner(operation, clock, g)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            final = _fragment_rows(
                session,
                (*g.provenance, reference, own),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            if final != baseline or _publication_ids(session, g.id) != (reference.source_id,):
                raise ValueError("full publication/union changed before acknowledgment")
            _not_withdrawn(session, g.id)
            auth._assert_fragment_generation_unconsumed(session, g.id)
            if _ids(session, _prefix(value)) != (own.source_id,):
                raise ValueError("final action identity changed")
            _same(session, entry)
            if _NATIVE_MONOTONIC() >= original_deadline:
                raise ValueError("original action expiry crossed before acknowledgment")
        # Issued here only after this original writer's successful terminal
        # acknowledgment. No helper/loader accepts supplied custody to issue it.
        acknowledged = object.__new__(AcknowledgedHistoryPublicationAdmission)
        for name, item in (
            ("retained", saved),
            ("_operation", operation),
            ("_clock", clock),
            ("_declaration", publication),
            ("_deadline", original_deadline),
            ("_seal", _ACK_SEAL),
            ("_issued_ref", ref(acknowledged)),
            ("_lock", RLock()),
            ("_used", False),
        ):
            object.__setattr__(acknowledged, name, item)
        result = acknowledged
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        if possibly_committed:
            raise HistoryPublicationAdmissionUncertain(
                "history publication custody possibly committed; action held without acknowledgment"
            )
        raise HistoryPublicationAdmissionError("history publication action not acknowledged")
    return result
