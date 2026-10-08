"""Canonical one-shot contextual consent ledger, outside agents.

Trusted operator records a real human decision only after independent recovery
checks. No endpoint, message parser, automatic grant or enabled operator exists.
Distinct formats/prefixes prevent reuse of compact-review approvals. Authority
is serialized under the existing canonical ledger lock and backup inventory.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, TypeAdapter, field_validator, model_validator
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contextual_generation import (
    ContextualRequest,
    ContextualRequestV2,
    encode_native_contextual_request,
    prepare_contextual_request,
)
from zacai.intelligence.contextual_host import ContextualRunScope, contextual_request_digest
from zacai.intelligence.contracts import Contract, Digest, ModelRoute
from zacai.intelligence.research_context import ResearchReviewSelection
from zacai.intelligence.review_context import _unique_pairs
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_freshness import review_evidence_digest
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes, _find, _lock, _write
from zacai.state import Source, SourceSystem

if TYPE_CHECKING:
    from sqlalchemy.orm import SessionTransaction

    from zacai.contextual_protection import (
        PersonalFragmentAuthorityReceiptV1,
        PersonalHistoryFragmentProtector,
    )
    from zacai.intelligence.local_contextual_runtime import (
        FragmentContextualDispatchDescriptor,
        FragmentLocalContextualRuntime,
    )
    from zacai.review_recovery import BrainstormReviewRecoveryGate


class ContextualAuthorizationError(RuntimeError):
    """Fixed diagnostic, no chained private inputs or backend exceptions."""


class ContextualConsent(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-contextual-consent-v1"] = "zac-contextual-consent-v1"
    id: UUID
    builder_id: UUID
    selection: ReviewSelection | ResearchReviewSelection
    authorized_boundaries: frozenset[B]
    allowed_classifications: frozenset[C]
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL
    route: ModelRoute
    model_digest: Digest
    prepared_digest: Digest
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_reference: str = Field(min_length=1, max_length=500, strict=True)
    state_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)
    artifact_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)
    credential_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)

    @field_validator("selection", mode="before")
    @classmethod
    def exact_selection(cls, value: object) -> object:
        if isinstance(value, dict):
            if "format" in value:
                return ResearchReviewSelection.model_validate(value)
            if set(value) - {"selected", "earlier", "projects"}:
                raise ValueError("unknown selection fields")
        return value

    @model_validator(mode="after")
    def bounded_scope(self) -> Self:
        if (
            self.authorized_boundaries != frozenset({B.BRAINSTORM})
            or self.allowed_classifications != frozenset({C.CONFIDENTIAL})
            or self.route.destination != Destination.LOCAL
            or "contextual_meeting_review" not in self.route.capabilities
            or "compact_meeting_review" in self.route.capabilities
            or not timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=15)
            or len(self.selection.earlier) > 7
            or len(self.selection.projects) > 3
            or any(
                not value.strip()
                for value in (
                    self.human_reference,
                    self.state_recovery_reference,
                    self.artifact_recovery_reference,
                    self.credential_recovery_reference,
                )
            )
        ):
            raise ValueError("invalid bounded contextual consent")
        return self


class ContextualRecoveryGate(Protocol):
    def preflight(self, consent: ContextualConsent) -> None:
        """Verify actual current checkpoint/key evidence, not reference strings."""
        ...


def prepared_contextual_digest(request: ContextualRequest | ContextualRequestV2) -> str:
    """Bind reviewed content/schema/limits across fresh task/event identities.

    Only host-generated ID namespaces are normalized, never passage text. The
    actual claim separately binds all actual identities and the exact request.
    """
    if type(request) is ContextualRequestV2:
        return prepared_native_contextual_digest(request)
    result: str | None = None
    try:
        if type(request) is not ContextualRequest:
            raise ValueError("unsupported contextual request family")
        if request != prepare_contextual_request(request.context):
            raise ValueError("modified request")
        namespace = review_context_digest(request.context)[:32] + ":"
        passages = json.loads(request.evidence_json)
        for passage in passages:
            if not passage["id"].startswith(namespace):
                raise ValueError("invalid host evidence namespace")
            passage["id"] = passage["id"][len(namespace) :]
        raw = canonical_bytes(
            {
                "evidence": review_evidence_digest(request.context),
                # This instruction is host-built and contains no passage text.
                "instruction": request.instruction.replace(namespace, ""),
                "passages": passages,
                "schema": request.schema_json,
            }
        )
        result = hashlib.sha256(raw).hexdigest()
    except Exception:  # noqa: BLE001, S110 - suppress private diagnostics
        pass
    if result is None:
        raise ContextualAuthorizationError("contextual prepared scope unavailable")
    return result


def _consent_bytes(consent: ContextualConsent) -> bytes:
    data = consent.model_dump(mode="json")
    data["authorized_boundaries"] = sorted(data["authorized_boundaries"])
    data["allowed_classifications"] = sorted(data["allowed_classifications"])
    data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    raw = canonical_bytes(data)
    if len(raw) > 32_000:
        raise ValueError("bounded authority metadata required")
    return raw


def _decode_consent(raw: bytes) -> ContextualConsent:
    value = ContextualConsent.model_validate(json.loads(raw, object_pairs_hook=_unique_pairs))
    if raw != _consent_bytes(value):
        raise ValueError("noncanonical consent")
    return value


def _scope_digest(scope: ContextualRunScope) -> str:
    data = TypeAdapter(ContextualRunScope).dump_python(scope, mode="json")
    data["authorized_boundaries"] = sorted(data["authorized_boundaries"])
    data["allowed_classifications"] = sorted(data["allowed_classifications"])
    data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    return content_hash_of(canonical_bytes(data))


def record_contextual_consent(
    session: Session,
    *,
    store: ArtifactStore,
    consent: ContextualConsent,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> UUID:
    """Trusted host only AFTER an authenticated human decision/recovery checks.

    Caller commits. This attestation alone cannot authenticate a chat approval,
    replace actual recovery checks or override gateway policy.
    """
    result: UUID | None = None
    try:
        consent = ContextualConsent.model_validate(consent)
        recorded_at = clock()
        if (
            recorded_at.utcoffset() is None
            or not consent.approved_at <= recorded_at < consent.expires_at
        ):
            raise ValueError("consent is not currently active")
        _lock(session, consent.id)
        result = _write(
            session,
            store,
            f"contextual-consent/{consent.id}",
            SourceSystem.USER_INSTRUCTION,
            _consent_bytes(consent),
            recorded_at,
        )
    except Exception:  # noqa: BLE001, S110 - suppress private ledger diagnostics
        pass
    if result is None:
        raise ContextualAuthorizationError("contextual consent unavailable or mismatched")
    return result


def _load(session: Session, store: ArtifactStore, approval_id: UUID) -> ContextualConsent:
    _assert_ledger_isolation(session)
    source = session.get(Source, approval_id)
    if (
        source is None
        or source.trust_boundary != B.BRAINSTORM
        or source.system != SourceSystem.USER_INSTRUCTION
    ):
        raise ValueError("authority unavailable")
    consent = _decode_consent(_bytes(session, store, source))
    if source.external_ref != f"contextual-consent/{consent.id}":
        raise ValueError("authority identity mismatch")
    return consent


def _active(
    session: Session, store: ArtifactStore, approval_id: UUID, now: datetime
) -> ContextualConsent:
    consent = _load(session, store, approval_id)
    if (
        now.utcoffset() is None
        or not consent.approved_at <= now < consent.expires_at
        or _find(session, f"contextual-revocation/{approval_id}", SourceSystem.USER_INSTRUCTION)
        is not None
    ):
        raise ValueError("authority inactive")
    return consent


def revoke_contextual_consent(
    session: Session,
    *,
    store: ArtifactStore,
    approval_id: UUID,
    human_reference: str,
    revoked_at: datetime,
) -> UUID:
    """Append human revocation under the same claim lock; caller commits."""
    result: UUID | None = None
    try:
        if (
            revoked_at.utcoffset() is None
            or type(human_reference) is not str
            or not human_reference.strip()
            or len(human_reference) > 500
        ):
            raise ValueError("invalid revocation")
        _lock(session, approval_id)
        _load(session, store, approval_id)
        prior = _find(
            session, f"contextual-revocation/{approval_id}", SourceSystem.USER_INSTRUCTION
        )
        if prior is not None:
            _bytes(session, store, prior)
            return prior.id
        raw = canonical_bytes(
            {
                "format": "zac-contextual-revocation-v1",
                "approval_id": str(approval_id),
                "human_reference": human_reference,
                "revoked_at": revoked_at.isoformat(),
            }
        )
        result = _write(
            session,
            store,
            f"contextual-revocation/{approval_id}",
            SourceSystem.USER_INSTRUCTION,
            raw,
            revoked_at,
        )
    except Exception:  # noqa: BLE001, S110 - suppress private authority diagnostics
        pass
    if result is None:
        raise ContextualAuthorizationError("contextual revocation unavailable")
    return result


def _scope_matches(consent: ContextualConsent, scope: ContextualRunScope) -> bool:
    return (
        scope.selection == consent.selection
        and scope.builder_id == consent.builder_id
        and scope.authorized_boundaries == consent.authorized_boundaries
        and scope.allowed_classifications == consent.allowed_classifications
        and scope.route == consent.route
        and scope.model_digest == consent.model_digest
    )


def _request_matches(consent: ContextualConsent, request: ContextualRequest) -> bool:
    if type(request) is not ContextualRequest:
        return False  # V2 needs its own actual selected scope/approval/recovery.
    selected = consent.selection.selected
    related = {item.source_id for item in consent.selection.earlier} | {
        item.source_id for item in consent.selection.projects
    }
    if isinstance(consent.selection, ResearchReviewSelection):
        related |= {item.source_id for item in consent.selection.research}
    meetings = {selected.meeting_id} | {item.meeting_id for item in consent.selection.earlier}
    actual = {
        e.entity_id
        for e in request.context.task.event.related_entities
        if e.entity_type == "Meeting"
    }
    return (
        request.context.meeting_source_id == selected.source_id
        and request.context.related_source_ids == related
        and actual == meetings
        and request.context.task.event.trust_boundary == consent.boundary
        and request.context.task.event.data_classification == consent.classification
        and prepared_contextual_digest(request) == consent.prepared_digest
    )


def contextual_claim_bytes(
    consent: ContextualConsent,
    approval_id: UUID,
    scope: ContextualRunScope,
    request_digest: str,
    context_digest: str,
) -> bytes:
    """Exact existing claim serialization; no authority or state writes."""
    return canonical_bytes(
        {
            "format": "zac-contextual-claim-v1",
            "approval_id": str(approval_id),
            "run_id": str(scope.run_id),
            "builder_id": str(scope.builder_id),
            "scope_digest": _scope_digest(scope),
            "request_digest": request_digest,
            "context_digest": context_digest,
            "prepared_digest": consent.prepared_digest,
            "consent_digest": content_hash_of(_consent_bytes(consent)),
        }
    )


class CanonicalContextualAuthorization:
    """Concrete one-shot Source ledger; wire only through the contextual host.

    PostgreSQL advisory locking serializes trusted claim/revocation. Recovery gate
    is mandatory and separately verifies actual prerequisites. Not a sandbox
    against hostile in-process code or database administrators.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        store: ArtifactStore,
        approval_id: UUID,
        recovery: ContextualRecoveryGate,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._factory, self._store, self._approval = factory, store, approval_id
        self._recovery, self._clock = recovery, clock
        self._preflighted: tuple[str, str] | None = None

    def preflight(self, scope: ContextualRunScope) -> None:
        failed = False
        self._preflighted = None
        try:
            with self._factory() as session:
                consent = _active(session, self._store, self._approval, self._clock())
                if (
                    not _scope_matches(consent, scope)
                    or _find(session, f"contextual-claim/{self._approval}", SourceSystem.MANUAL)
                    is not None
                ):
                    raise ValueError("scope unavailable")
            self._recovery.preflight(consent)
            self._preflighted = (content_hash_of(_consent_bytes(consent)), _scope_digest(scope))
        except Exception:  # noqa: BLE001 - no private backend diagnostics
            failed = True
        if failed:
            raise ContextualAuthorizationError("contextual authorization preflight failed")

    def _claim_bytes(
        self,
        consent: ContextualConsent,
        scope: ContextualRunScope,
        request: ContextualRequest,
        digest: str,
    ) -> bytes:
        if (
            not _scope_matches(consent, scope)
            or not _request_matches(consent, request)
            or digest != contextual_request_digest(request)
        ):
            raise ValueError("claim scope mismatch")
        return contextual_claim_bytes(
            consent, self._approval, scope, digest, review_context_digest(request.context)
        )

    def claim(
        self,
        scope: ContextualRunScope,
        request: ContextualRequest,
        request_digest: str,
        now: datetime,
    ) -> None:
        failed = False
        try:
            with self._factory() as check:
                consent = _active(check, self._store, self._approval, now)
                if self._preflighted != (
                    content_hash_of(_consent_bytes(consent)),
                    _scope_digest(scope),
                ):
                    raise ValueError("authority changed")
                raw = self._claim_bytes(consent, scope, request, request_digest)
            self._recovery.preflight(consent)
            with self._factory() as session:
                _lock(session, self._approval)
                current = _active(session, self._store, self._approval, max(now, self._clock()))
                if (
                    _consent_bytes(current) != _consent_bytes(consent)
                    or _find(session, f"contextual-claim/{self._approval}", SourceSystem.MANUAL)
                    is not None
                ):
                    raise ValueError("authority consumed or changed")
                _write(
                    session,
                    self._store,
                    f"contextual-claim/{self._approval}",
                    SourceSystem.MANUAL,
                    raw,
                    now,
                )
                session.commit()
        except Exception:  # noqa: BLE001 - fixed errors raised outside handler
            failed = True
        if failed:
            raise ContextualAuthorizationError("contextual authorization claim failed")

    def recheck(
        self,
        scope: ContextualRunScope,
        request: ContextualRequest,
        request_digest: str,
        now: datetime,
    ) -> None:
        failed = False
        try:
            with self._factory() as session:
                consent = _active(session, self._store, self._approval, now)
                claim = _find(session, f"contextual-claim/{self._approval}", SourceSystem.MANUAL)
                if claim is None or _bytes(session, self._store, claim) != self._claim_bytes(
                    consent, scope, request, request_digest
                ):
                    raise ValueError("claim missing or changed")
                self._recovery.preflight(consent)
                current = _active(session, self._store, self._approval, max(now, self._clock()))
                if _consent_bytes(current) != _consent_bytes(consent):
                    raise ValueError("consent changed during recovery")
        except Exception:  # noqa: BLE001 - no private exception chaining
            failed = True
        if failed:
            raise ContextualAuthorizationError("contextual authorization recheck failed")


class BrainstormContextualRecoveryGate:
    """Reuse the existing read-only checkpoint/key gate, never compact authority.

    The legacy-shaped recovery view is passed only to the verifier. It is never
    recorded as a compact consent, looked up as approval or used for dispatch.
    """

    def __init__(self, gate: BrainstormReviewRecoveryGate) -> None:
        from zacai.review_recovery import BrainstormReviewRecoveryGate

        if not isinstance(gate, BrainstormReviewRecoveryGate):
            raise TypeError("actual Brainstorm recovery gate required")
        self._gate = gate

    def preflight(self, consent: ContextualConsent) -> None:
        from zacai.review_authorization import ReviewConsent

        failed = False
        try:
            consent = ContextualConsent.model_validate(consent)
            self._gate.preflight(
                ReviewConsent(
                    id=consent.id,
                    selection=ReviewSelection(
                        consent.selection.selected,
                        consent.selection.earlier,
                        consent.selection.projects,
                    ),
                    route=consent.route,
                    model_digest=consent.model_digest,
                    prepared_digest=consent.prepared_digest,
                    approved_at=consent.approved_at,
                    expires_at=consent.expires_at,
                    human_reference=consent.human_reference,
                    state_recovery_reference=consent.state_recovery_reference,
                    artifact_recovery_reference=consent.artifact_recovery_reference,
                    credential_recovery_reference=consent.credential_recovery_reference,
                ),
                additional_sources=(
                    {x.source_id: x.content_hash for x in consent.selection.research}
                    if isinstance(consent.selection, ResearchReviewSelection)
                    else None
                ),
            )
        except Exception:  # noqa: BLE001 - original gate diagnostics stay private
            failed = True
        if failed:
            raise ContextualAuthorizationError("contextual recovery prerequisites unavailable")


def _prepared_native_contextual_digest(request: ContextualRequestV2) -> str:
    """Exact retained V2 request, including observation, task and event identities."""
    raw = encode_native_contextual_request(request)
    return content_hash_of(
        canonical_bytes(
            {
                "format": "zac-native-contextual-prepared-v2",
                "exact_retained_request_digest": content_hash_of(raw),
            }
        )
    )


def prepared_native_contextual_digest(request: ContextualRequestV2) -> str:
    """Structural consistency only; exact retained observation needs new approval.

    This digest does not authenticate full-field hashes or a supplied sidecar.
    """
    try:
        return _prepared_native_contextual_digest(request)
    except Exception:  # noqa: BLE001,S110 - fixed public error, no private causes
        pass
    raise ContextualAuthorizationError("native contextual request unavailable or invalid")

# Explicit dormant PERSONAL fragment records; original V1 declarations unchanged.
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contextual_storage import (
    _fragment_profile_lineage,
    _fragment_request_provenance,
    _fragment_rows,
    _fragment_same_transaction,
    _fragment_transaction,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualRequestV1,
    encode_history_fragment_contextual_request,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.private_web import BoundaryScope
from zacai.state_repository import record_source

_FRAGMENT_BOUNDARIES = frozenset({B.PERSONAL})
_FRAGMENT_LABELS = frozenset({C.HIGHLY_RESTRICTED})
_FRAGMENT_OWNER_SCOPE = (BoundaryScope(B.PERSONAL, _FRAGMENT_LABELS),)
_FRAGMENT_AUTH_MAX_BYTES = 64_000


class HistoryFragmentConsentV1(Contract):
    """Recorded human decision metadata, not a dispatch or recovery capability."""
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-personal-history-fragment-consent-v1"] = (
        "zac-personal-history-fragment-consent-v1")
    id: UUID
    builder_id: UUID
    task_id: UUID
    request_digest: Digest
    provenance: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=94, repr=False)
    owner_issuer: str = Field(min_length=1, max_length=255, strict=True, repr=False)
    owner_subject: str = Field(min_length=1, max_length=255, strict=True, repr=False)
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_reference: str = Field(min_length=1, max_length=500, strict=True, repr=False)
    route: ModelRoute
    model_digest: Digest
    tokenizer_digest: Digest
    runtime_digest: Digest
    template_digest: Digest
    renderer_digest: Digest
    body_digest: Digest
    prompt_tokens: int = Field(gt=0, strict=True)
    max_output_tokens: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def closed_fragment_decision(self) -> Self:
        ids = tuple(ref.source_id for ref in self.provenance)
        if (any(v.int == 0 for v in (self.id, self.builder_id, self.task_id, *ids))
            or len(set(ids)) != len(ids)
            or ids != tuple(sorted(ids, key=str))
            or any(r.trust_boundary is not B.PERSONAL
                   or r.effective_classification is not C.HIGHLY_RESTRICTED
                   for r in self.provenance)
            or self.route.destination is not Destination.LOCAL or not self.route.available
            or "contextual_meeting_review" not in self.route.capabilities
            or "compact_meeting_review" in self.route.capabilities
            or not self.original_session_issued_at <= self.approved_at < self.expires_at
            <= self.original_session_expires_at
            or not timedelta(0) < self.expires_at-self.approved_at <= timedelta(minutes=15)
            or not all(v.strip() for v in
                       (self.owner_issuer, self.owner_subject, self.human_reference))):
            raise ValueError("closed original fragment decision required")
        return self


class HistoryFragmentClaimV1(Contract):
    """Exact future consumed ledger bytes; codec/load never issue this claim."""
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-personal-history-fragment-claim-v1"] = (
        "zac-personal-history-fragment-claim-v1")
    consent_reference: EvidenceReference = Field(repr=False)
    consent_digest: Digest
    request_digest: Digest
    attempt_id: UUID
    task_id: UUID
    builder_id: UUID
    original_session_binding: Digest = Field(repr=False)
    body_digest: Digest
    route_digest: Digest
    model_digest: Digest
    tokenizer_digest: Digest
    runtime_digest: Digest
    template_digest: Digest
    renderer_digest: Digest
    prompt_tokens: int = Field(gt=0, strict=True)
    max_output_tokens: int = Field(gt=0, strict=True)
    consumed_at: AwareDatetime

    @model_validator(mode="after")
    def exact_claim_identity(self) -> Self:
        if (any(v.int == 0 for v in (self.attempt_id, self.task_id, self.builder_id,
                                     self.consent_reference.source_id))
            or self.consent_reference.trust_boundary is not B.PERSONAL
            or self.consent_reference.effective_classification is not C.HIGHLY_RESTRICTED
            or self.consent_reference.content_hash != self.consent_digest):
            raise ValueError("exact fragment claim subject required")
        return self


def _fragment_authority_bytes(value: HistoryFragmentConsentV1 | HistoryFragmentClaimV1) -> bytes:
    data = value.model_dump(mode="json")
    if type(value) is HistoryFragmentConsentV1:
        data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    raw = canonical_bytes(data)
    if not 0 < len(raw) <= _FRAGMENT_AUTH_MAX_BYTES:
        raise ValueError("bounded fragment authority metadata required")
    return raw


def encode_history_fragment_consent(value: HistoryFragmentConsentV1) -> bytes:
    if type(value) is not HistoryFragmentConsentV1:
        raise ContextualAuthorizationError("fragment consent unavailable")
    return _fragment_authority_bytes(HistoryFragmentConsentV1.model_validate(value))


def decode_history_fragment_consent(raw: bytes) -> HistoryFragmentConsentV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _FRAGMENT_AUTH_MAX_BYTES:
            raise ValueError("bounded consent bytes required")
        value = HistoryFragmentConsentV1.model_validate(json.loads(raw, object_pairs_hook=_unique_pairs))
        if raw != encode_history_fragment_consent(value):
            raise ValueError("canonical consent bytes required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ContextualAuthorizationError("fragment consent unavailable")
    return result


def encode_history_fragment_claim(value: HistoryFragmentClaimV1) -> bytes:
    if type(value) is not HistoryFragmentClaimV1:
        raise ContextualAuthorizationError("fragment claim unavailable")
    return _fragment_authority_bytes(HistoryFragmentClaimV1.model_validate(value))


def decode_history_fragment_claim(raw: bytes) -> HistoryFragmentClaimV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _FRAGMENT_AUTH_MAX_BYTES:
            raise ValueError("bounded claim bytes required")
        value = HistoryFragmentClaimV1.model_validate(json.loads(raw, object_pairs_hook=_unique_pairs))
        if raw != encode_history_fragment_claim(value):
            raise ValueError("canonical claim bytes required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ContextualAuthorizationError("fragment claim unavailable")
    return result


def _fragment_consent_request(consent: HistoryFragmentConsentV1,
                              request: HistoryFragmentContextualRequestV1) -> bytes:
    raw = encode_history_fragment_contextual_request(request)
    if (type(consent) is not HistoryFragmentConsentV1
        or content_hash_of(raw) != consent.request_digest
        or request.task.task_id != consent.task_id or request.route != consent.route
        or request.task.event.trust_boundary is not B.PERSONAL
        or request.task.event.data_classification is not C.HIGHLY_RESTRICTED
        or _fragment_request_provenance(request) != consent.provenance):
        raise ValueError("exact retained fragment request required")
    encode_history_fragment_consent(consent)
    return raw


def _fragment_authority_namespace(consent: HistoryFragmentConsentV1, *, claim: bool) -> str:
    union = content_hash_of(canonical_bytes({"provenance": [r.model_dump(mode="json") for r in consent.provenance]}))
    return (f"personal-history-fragment-{'claim' if claim else 'consent'}/{consent.id}/"
            f"{consent.request_digest}/{union}")


def _fragment_authority_load(session: Session, artifacts: LocalFilesystemArtifactStore,
    own: EvidenceReference, consent: HistoryFragmentConsentV1,
    request: HistoryFragmentContextualRequestV1,
    claim: HistoryFragmentClaimV1 | None = None) -> bytes:
    from sqlalchemy import select
    _fragment_consent_request(consent, request)
    if type(artifacts) is not LocalFilesystemArtifactStore or type(own) is not EvidenceReference:
        raise ValueError("concrete bounded artifact store and Source required")
    entry = _fragment_transaction(session)
    extras = (own,) if claim is None else (claim.consent_reference, own)
    complete = (*consent.provenance, *extras)
    before = _fragment_rows(session, complete, _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS)
    _fragment_profile_lineage(request, before)
    rows = [dict(r) for r in before if dict(r)["id"] == own.source_id]
    system = SourceSystem.USER_INSTRUCTION if claim is None else SourceSystem.MANUAL
    namespace = _fragment_authority_namespace(consent, claim=claim is not None)
    if not rows or len({r["lineage_id"] for r in rows}) != 1:
        raise ValueError("exact unique authority namespace required before body")
    for row in rows:
        captured = row["captured_at"]
        if (type(captured) is not datetime or captured.utcoffset() is None
            or row["system"] is not system or row["external_ref"] != namespace
            or row["supersedes_source_id"] is not None
            or not (consent.approved_at if claim is None else claim.consumed_at)
            <= captured < consent.expires_at):
            raise ValueError("exact authority metadata required before body")
    location = rows[0]["content_location"]
    if type(location) is not str:
        raise ValueError("exact authority location required")
    prefix = f"personal-history-fragment-{'claim' if claim is not None else 'consent'}/{consent.id}/"
    identities = tuple(session.scalars(select(Source.id).where(
        Source.trust_boundary == B.PERSONAL, Source.system == system,
        Source.external_ref.like(prefix + '%')).limit(2)))
    if identities != (own.source_id,):
        raise ValueError("one immutable authority identity required")
    raw = artifacts.get_bounded(B.PERSONAL, location,
                                max_bytes=_FRAGMENT_AUTH_MAX_BYTES)
    _fragment_same_transaction(session, entry)
    expected = (encode_history_fragment_consent(consent) if claim is None
                else encode_history_fragment_claim(claim))
    if content_hash_of(raw) != own.content_hash or raw != expected:
        raise ValueError("exact canonical authority bytes required")
    after = _fragment_rows(session, complete, _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS)
    _fragment_profile_lineage(request, after)
    _fragment_same_transaction(session, entry)
    if after != before:
        raise ValueError("current authority Source union changed")
    return raw


def load_history_fragment_consent(session: Session, *, artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference, expected_consent: HistoryFragmentConsentV1,
    expected_request: HistoryFragmentContextualRequestV1) -> HistoryFragmentConsentV1:
    result = None
    try:
        raw = _fragment_authority_load(session, artifacts, reference, expected_consent, expected_request)
        result = decode_history_fragment_consent(raw)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ContextualAuthorizationError("canonical fragment consent unavailable")
    return result


def load_history_fragment_claim(session: Session, *, artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference, expected_consent: HistoryFragmentConsentV1,
    expected_claim: HistoryFragmentClaimV1,
    expected_request: HistoryFragmentContextualRequestV1) -> HistoryFragmentClaimV1:
    result = None
    try:
        c = expected_claim
        e = expected_consent
        encode_history_fragment_claim(c)
        if (type(c) is not HistoryFragmentClaimV1 or c.consent_digest != content_hash_of(
            encode_history_fragment_consent(e)) or c.request_digest != e.request_digest
            or c.task_id != e.task_id or c.builder_id != e.builder_id
            or c.original_session_binding != e.original_session_binding
            or not e.approved_at <= c.consumed_at < e.expires_at
            or any(getattr(c, n) != getattr(e, n) for n in
                ('body_digest','model_digest','tokenizer_digest','runtime_digest',
                 'template_digest','renderer_digest','prompt_tokens','max_output_tokens'))
            or c.route_digest != content_hash_of(canonical_bytes(
                {**e.route.model_dump(mode="json"), 'capabilities': sorted(e.route.capabilities)}))):
            raise ValueError("original consumed consent identity required")
        load_history_fragment_consent(session, artifacts=artifacts,
            reference=c.consent_reference, expected_consent=e, expected_request=expected_request)
        raw = _fragment_authority_load(session, artifacts, reference, e, expected_request, c)
        result = decode_history_fragment_claim(raw)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ContextualAuthorizationError("canonical fragment claim unavailable")
    return result


def _fragment_decision_owner(operation: NamedSessionOperation, clock: HostObservedClock,
                             consent: HistoryFragmentConsentV1) -> VerifiedNamedSession:
    if type(operation) is not NamedSessionOperation or type(clock) is not HostObservedClock:
        raise ValueError("genuine original owner/session required")
    if operation.host_clock is not clock:
        raise ValueError("same original host clock required")
    owner = operation.recheck(consent.original_session_binding)
    now = clock()
    if (owner.principal.identity.issuer != consent.owner_issuer
        or owner.principal.identity.subject != consent.owner_subject
        or owner.principal.scopes != _FRAGMENT_OWNER_SCOPE
        or owner.issued_at != consent.original_session_issued_at
        or owner.effective_expires_at != consent.original_session_expires_at
        or not consent.approved_at <= now < consent.expires_at):
        raise ValueError("original exact owner decision inactive")
    return owner


def _assert_fragment_generation_unconsumed(session: Session, generation_id: UUID) -> None:
    """Negative shared-parent gate only; absence never proves permission."""
    from sqlalchemy import select

    if tuple(session.scalars(select(Source.id).where(
        Source.trust_boundary == B.PERSONAL, Source.system == SourceSystem.MANUAL,
        Source.external_ref.like(f"personal-history-fragment-claim/{generation_id}/%"),
    ).limit(2))):
        raise ValueError("original fragment generation already consumed")


def _assert_fragment_no_prospective_declaration(session: Session, generation_id: UUID) -> None:
    """Prevent prospective full-purpose declarations entering the legacy arm.

    Caller holds the existing original-parent lock. Absence is not human intent,
    approval or permission, and does not replace complete current checks.
    """
    from sqlalchemy import select

    ids = tuple(session.scalars(select(Source.id).where(
        Source.trust_boundary == B.PERSONAL,
        Source.system == SourceSystem.MANUAL,
        Source.external_ref.like(
            f"personal-history-fragment-declaration-v2/{generation_id}/%"
        ),
    ).limit(1)))
    if ids:
        raise ValueError("prospective fragment declaration requires its publication admission")


def record_history_fragment_consent(*, factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore, consent: HistoryFragmentConsentV1,
    expected_request: HistoryFragmentContextualRequestV1,
    operation: NamedSessionOperation, clock: HostObservedClock) -> EvidenceReference:
    """Trusted attended host records decision only; no claim/processing admission.

    Host must independently authenticate the human decision and actual input
    recovery first. This function verifies the original signed session but cannot
    infer a human decision from a reference string. Own short commit/reopen;
    owner callbacks only outside SQL. Concrete authority recovery remains needed.
    """
    from sqlalchemy import select
    result = None
    try:
        raw = encode_history_fragment_consent(consent)
        _fragment_consent_request(consent, expected_request)
        if type(factory) is not sessionmaker or type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("canonical factory and bounded artifact store required")
        _fragment_decision_owner(operation, clock, consent)
        namespace = _fragment_authority_namespace(consent, claim=False)
        with factory() as session:
            session.begin()
            _lock(session, consent.id)
            entry = _fragment_transaction(session)
            _assert_fragment_no_prospective_declaration(session, consent.id)
            _fragment_same_transaction(session, entry)
            before = _fragment_rows(session, consent.provenance, _FRAGMENT_BOUNDARIES,
                                    _FRAGMENT_LABELS)
            _fragment_profile_lineage(expected_request, before)
            source = session.scalar(select(Source).where(Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.USER_INSTRUCTION,
                Source.external_ref.like(f"personal-history-fragment-consent/{consent.id}/%")))
            newly_recorded = source is None
            if source is None:
                from zacai.backup_artifacts import _assert_personal_custody_append_capacity

                _assert_personal_custody_append_capacity(session, 3)
                location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
                _fragment_same_transaction(session, entry)
                returned = artifacts.get_bounded(B.PERSONAL, location,
                                                 max_bytes=_FRAGMENT_AUTH_MAX_BYTES)
                _fragment_same_transaction(session, entry)
                if returned != raw or _fragment_rows(session, consent.provenance,
                    _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS) != before:
                    raise ValueError("canonical input changed before record")
                recorded = clock()
                _fragment_same_transaction(session, entry)
                if not consent.approved_at <= recorded < consent.expires_at:
                    raise ValueError("decision expired before record")
                _assert_fragment_no_prospective_declaration(session, consent.id)
                _assert_personal_custody_append_capacity(session, 3)
                _fragment_same_transaction(session, entry)
                source, _ = record_source(session, trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED, system=SourceSystem.USER_INSTRUCTION,
                    external_ref=namespace, content_hash=content_hash_of(raw),
                    content_location=location, captured_at=recorded)
            ref = EvidenceReference(source_id=source.id, content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
            load_history_fragment_consent(session, artifacts=artifacts, reference=ref,
                expected_consent=consent, expected_request=expected_request)
            _assert_fragment_no_prospective_declaration(session, consent.id)
            if newly_recorded:
                _assert_personal_custody_append_capacity(session, 2)
            _fragment_same_transaction(session, entry)
            session.commit()
        # Matching committed failures remain recorded, never a renewed decision.
        _fragment_decision_owner(operation, clock, consent)
        with factory() as session:
            session.begin()
            load_history_fragment_consent(session, artifacts=artifacts, reference=ref,
                expected_consent=consent, expected_request=expected_request)
            reopened = _fragment_rows(session, (*consent.provenance, ref),
                                      _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS)
        _fragment_decision_owner(operation, clock, consent)
        with factory() as session:
            session.begin()
            final = _fragment_rows(session, (*consent.provenance, ref),
                                   _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS)
            _fragment_profile_lineage(expected_request, final)
            if final != reopened:
                raise ValueError("final canonical decision rows changed")
        result = ref
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ContextualAuthorizationError("fragment decision record unavailable")
    return result


class CanonicalPersonalFragmentAuthorization:
    """Dormant concrete PRE/RELEASE gate with a durable canonical one-use burn.

    The trusted attended host must separately authenticate the recorded human
    decision, recipient/key custody and exclusive operator window. Construction
    or a None return is not that authority. No host/route is enabled here. The
    purpose-specific per-consent withdrawal writer and authenticated assessment
    and protected output release remain missing activation prerequisites.
    """

    def __init__(self, *, factory: sessionmaker[Session],
                 artifacts: LocalFilesystemArtifactStore,
                 consent_reference: EvidenceReference, consent: HistoryFragmentConsentV1,
                 request: HistoryFragmentContextualRequestV1,
                 protector: PersonalHistoryFragmentProtector,
                 operation: NamedSessionOperation, clock: HostObservedClock) -> None:
        from threading import RLock

        from zacai.contextual_protection import PersonalHistoryFragmentProtector

        failed = False
        try:
            raw = _fragment_consent_request(consent, request)
            if (type(factory) is not sessionmaker
                or type(artifacts) is not LocalFilesystemArtifactStore
                or type(protector) is not PersonalHistoryFragmentProtector
                or type(operation) is not NamedSessionOperation
                or type(clock) is not HostObservedClock or operation.host_clock is not clock
                or protector._factory is not factory or protector._artifacts is not artifacts
                or protector._operation is not operation or protector._clock is not clock
                or factory.kw.get('bind') is not protector._engine
                or factory.kw.get('binds')
                or type(consent_reference) is not EvidenceReference
                or consent_reference.source_id.int == 0
                or consent_reference.trust_boundary is not B.PERSONAL
                or consent_reference.effective_classification is not C.HIGHLY_RESTRICTED
                or consent_reference.content_hash != content_hash_of(encode_history_fragment_consent(consent))
                or consent.body_digest != content_hash_of(request.prompt_body.encode())
                or consent.max_output_tokens != request.task.max_output_tokens):
                raise ValueError('exact original fragment graph required')
            self._factory, self._artifacts = factory, artifacts
            self._consent_reference, self._consent, self._request = consent_reference, consent, request
            self._protector, self._operation, self._clock = protector, operation, clock
            self._raw = raw
            self._consent_raw = encode_history_fragment_consent(consent)
            self._graph = (factory, artifacts, consent_reference, consent, request,
                           protector, operation, clock, protector._engine)
            self._configuration = (consent.model_digest, consent.tokenizer_digest,
                consent.runtime_digest, consent.template_digest, consent.renderer_digest,
                canonical_bytes({**consent.route.model_dump(mode='json'),
                    'capabilities': sorted(consent.route.capabilities)}).decode())
            self._runtime: FragmentLocalContextualRuntime | None = None
            self._claim: HistoryFragmentClaimV1 | None = None
            self._claim_reference: EvidenceReference | None = None
            self._receipt: PersonalFragmentAuthorityReceiptV1 | None = None
            self._phase = 'UNUSED'
            self._released: FragmentContextualDispatchDescriptor | None = None
            self._lock = RLock()
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise ContextualAuthorizationError('invalid PERSONAL fragment authorization graph')

    def bind_runtime(self, runtime: FragmentLocalContextualRuntime) -> None:
        """Bind the actual existing runtime and its bound gate, before preflight.

        No arbitrary protocol or callback returning success can replace this
        concrete graph. This establishes wiring only, not human approval.
        """
        from zacai.intelligence.local_contextual_runtime import FragmentLocalContextualRuntime

        with self._lock:
            failed = False
            try:
                self._graph_check()
                if (self._runtime is not None or self._phase != 'UNUSED'
                    or type(runtime) is not FragmentLocalContextualRuntime
                    or getattr(runtime._recheck, '__self__', None) is not self
                    or getattr(runtime._recheck, '__func__', None) is not type(self).recheck
                    or runtime._configuration != self._configuration
                    or runtime.route != self._consent.route
                    or runtime._attempted or runtime._prepared is not None):
                    raise ValueError('exact unused fragment runtime required')
                self._runtime = runtime
            except Exception:  # noqa: BLE001
                failed = True
            if failed:
                raise ContextualAuthorizationError('PERSONAL fragment runtime binding unavailable')

    def _graph_check(self) -> None:
        current = (self._factory, self._artifacts, self._consent_reference, self._consent,
                   self._request, self._protector, self._operation, self._clock,
                   self._protector._engine)
        if (any(a is not b for a, b in zip(current, self._graph, strict=True))
            or self._protector._factory is not self._factory
            or self._protector._artifacts is not self._artifacts
            or self._protector._operation is not self._operation
            or self._protector._clock is not self._clock
            or self._operation.host_clock is not self._clock
            or self._factory.kw.get('bind') is not self._graph[-1]
            or self._factory.kw.get('binds')
            or _fragment_consent_request(self._consent, self._request) != self._raw
            or encode_history_fragment_consent(self._consent) != self._consent_raw):
            raise ValueError('original fragment authorization graph changed')

    def _descriptor(self, request: HistoryFragmentContextualRequestV1,
                    descriptor: FragmentContextualDispatchDescriptor) -> None:
        from zacai.intelligence.local_contextual_runtime import (
            FragmentContextualDispatchDescriptor,
            FragmentLocalContextualRuntime,
        )
        self._graph_check()
        r = self._runtime
        c = self._consent
        if (request is not self._request or type(descriptor) is not FragmentContextualDispatchDescriptor
            or type(r) is not FragmentLocalContextualRuntime
            or getattr(r._recheck, '__self__', None) is not self
            or getattr(r._recheck, '__func__', None) is not type(self).recheck
            or r._configuration != self._configuration or r.route != c.route
            or type(descriptor.attempt_id) is not UUID or descriptor.attempt_id.int == 0
            or descriptor.phase not in ('PRE_DISPATCH', 'RELEASE')
            or descriptor.retained_request_digest != c.request_digest
            or descriptor.body_digest != c.body_digest
            or type(descriptor.prompt_tokens) is not int or descriptor.prompt_tokens != c.prompt_tokens
            or (descriptor.model_digest, descriptor.tokenizer_digest, descriptor.runtime_digest,
                descriptor.template_digest, descriptor.renderer_digest, descriptor.route_json)
                != self._configuration
            or c.body_digest != content_hash_of(request.prompt_body.encode())
            or c.max_output_tokens != request.task.max_output_tokens):
            raise ValueError('exact original dispatch descriptor required')
        observations = (descriptor.output_digest, descriptor.usage_digest)
        if descriptor.phase == 'PRE_DISPATCH':
            if observations != (None, None):
                raise ValueError('no output before dispatch')
        elif any(type(v) is not str or len(v) != 64
                 or any(ch not in '0123456789abcdef' for ch in v) for v in observations):
            raise ValueError('exact release observations required')
        if descriptor.phase == 'RELEASE' and (
            self._claim is None or self._claim.attempt_id != descriptor.attempt_id):
            raise ValueError('same consumed runtime attempt required')

    def _owner(self) -> None:
        from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
        from zacai.policy import AccessRequest

        self._graph_check()
        owner = _fragment_decision_owner(self._operation, self._clock, self._consent)
        gate = evaluate_gateway(ActionRequest(action_type=ActionType.SUMMARIZE_CONTENT,
            access=AccessRequest(data_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                requestor_boundaries=frozenset(s.boundary for s in owner.principal.scopes),
                destination=Destination.LOCAL), description='bounded approved historical fragment draft'))
        if gate.outcome is not GatewayOutcome.ALLOW:
            raise ValueError('original owner gateway denied')
        self._graph_check()

    def _plan_receipt(self, session: Session, receipt: PersonalFragmentAuthorityReceiptV1,
                      claim: HistoryFragmentClaimV1 | None = None,
                      reference: EvidenceReference | None = None) -> None:
        from zacai.backup_artifacts import prepare_personal_encrypted_custody_backup_plan
        from zacai.contextual_protection import PersonalFragmentAuthorityReceiptV1

        own = self._consent_reference if claim is None else reference
        refs = tuple(sorted((*self._consent.provenance, self._consent_reference,
            *((own,) if claim is not None and own is not None else ())), key=lambda v: str(v.source_id)))
        if (type(receipt) is not PersonalFragmentAuthorityReceiptV1
            or own is None or receipt.kind != ('CONSENT' if claim is None else 'CLAIM')
            or receipt.authority_reference != own
            or receipt.consent_reference != self._consent_reference
            or receipt.request_digest != self._consent.request_digest
            or receipt.consent_digest != self._consent_reference.content_hash
            or receipt.selected_references != refs
            or receipt.task_id != self._consent.task_id or receipt.builder_id != self._consent.builder_id
            or receipt.original_session_binding != self._consent.original_session_binding
            or receipt.approved_at != self._consent.approved_at
            or receipt.expires_at != self._consent.expires_at
            or receipt.original_observed_at != self._request.observed_at
            or receipt.original_session_issued_at != self._consent.original_session_issued_at
            or receipt.original_session_expires_at != self._consent.original_session_expires_at
            or receipt.attempt_id != (None if claim is None else claim.attempt_id)
            or receipt.consumed_at != (None if claim is None else claim.consumed_at)):
            raise ValueError('actual own-subject recovery receipt required')
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        rows = json.loads(plan.rows)
        hashes = tuple(sorted(((UUID(v['id']), v['content_hash']) for v in rows), key=lambda p: str(p[0])))
        fingerprints = tuple(sorted(((UUID(v['id']), content_hash_of(canonical_bytes(v)))
            for v in rows), key=lambda p: str(p[0])))
        if (content_hash_of(plan.rows) != receipt.full_plan_digest
            or hashes != receipt.full_boundary_source_hashes
            or fingerprints != receipt.full_boundary_source_fingerprints):
            raise ValueError('complete current recovery plan changed')

    def _physical_transaction(self, session: Session) -> tuple[
        SessionTransaction, SessionTransaction | None, object, object
    ]:
        """Require the real psycopg transaction holding the existing UUID lock.

        A Session logical transaction and SHOW read committed do not exclude
        DBAPI AUTOCOMMIT. IDLE statements would release an xact advisory lock
        immediately. No legacy helper or other family is widened here.
        """
        from psycopg import Connection as PsycopgConnection
        from psycopg.pq import TransactionStatus

        outer, nested = _fragment_transaction(session)
        connection = session.connection()
        driver = connection.connection.driver_connection
        if (not isinstance(driver, PsycopgConnection)
            or driver.autocommit is not False or driver.closed or driver.broken
            or driver.info.transaction_status is not TransactionStatus.INTRANS
            or not connection.in_transaction()):
            raise ValueError('live physical psycopg transaction required')
        return outer, nested, connection, driver

    def _same_physical_transaction(self, session: Session, entry: tuple[
        SessionTransaction, SessionTransaction | None, object, object
    ]) -> None:
        _fragment_same_transaction(session, (entry[0], entry[1]))
        current = self._physical_transaction(session)
        if any(a is not b for a, b in zip(current, entry, strict=True)):
            raise ValueError('original physical claim transaction changed')

    def _burn(self, descriptor: FragmentContextualDispatchDescriptor,
              receipt: PersonalFragmentAuthorityReceiptV1) -> tuple[HistoryFragmentClaimV1, EvidenceReference]:
        from sqlalchemy import select

        with self._factory() as session:
            session.begin()
            _lock(session, self._consent.id)
            entry = self._physical_transaction(session)
            _assert_fragment_no_prospective_declaration(session, self._consent.id)
            self._same_physical_transaction(session, entry)
            previous = tuple(session.scalars(select(Source.id).where(
                Source.trust_boundary == B.PERSONAL, Source.system == SourceSystem.MANUAL,
                Source.external_ref.like(f'personal-history-fragment-claim/{self._consent.id}/%')).limit(2)))
            if previous:
                raise ValueError('original consent already consumed')
            from zacai.backup_artifacts import _assert_personal_custody_append_capacity

            _assert_personal_custody_append_capacity(session, 2)
            self._plan_receipt(session, receipt)
            load_history_fragment_consent(session, artifacts=self._artifacts,
                reference=self._consent_reference, expected_consent=self._consent,
                expected_request=self._request)
            before = _fragment_rows(session, (*self._consent.provenance, self._consent_reference),
                _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS)
            _fragment_profile_lineage(self._request, before)
            consumed = self._clock()
            self._same_physical_transaction(session, entry)
            if not self._consent.approved_at <= consumed < self._consent.expires_at:
                raise ValueError('original consent expired while waiting for lock')
            c = self._consent
            claim = HistoryFragmentClaimV1(consent_reference=self._consent_reference,
                consent_digest=self._consent_reference.content_hash, request_digest=c.request_digest,
                attempt_id=descriptor.attempt_id, task_id=c.task_id, builder_id=c.builder_id,
                original_session_binding=c.original_session_binding, body_digest=c.body_digest,
                route_digest=content_hash_of(self._configuration[5].encode()),
                model_digest=c.model_digest, tokenizer_digest=c.tokenizer_digest,
                runtime_digest=c.runtime_digest, template_digest=c.template_digest,
                renderer_digest=c.renderer_digest, prompt_tokens=c.prompt_tokens,
                max_output_tokens=c.max_output_tokens, consumed_at=consumed)
            raw = encode_history_fragment_claim(claim)
            location = self._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            self._same_physical_transaction(session, entry)
            returned = self._artifacts.get_bounded(B.PERSONAL, location, max_bytes=_FRAGMENT_AUTH_MAX_BYTES)
            self._same_physical_transaction(session, entry)
            self._graph_check()
            self._descriptor(self._request, descriptor)
            self._plan_receipt(session, receipt)
            if (returned != raw or _fragment_rows(session,
                (*c.provenance, self._consent_reference), _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS) != before
                or not consumed <= self._clock() < c.expires_at):
                raise ValueError('original claim input changed before burn')
            self._same_physical_transaction(session, entry)
            _assert_fragment_no_prospective_declaration(session, c.id)
            _assert_personal_custody_append_capacity(session, 2)
            self._same_physical_transaction(session, entry)
            source, created = record_source(session, trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED, system=SourceSystem.MANUAL,
                external_ref=_fragment_authority_namespace(c, claim=True),
                content_hash=content_hash_of(raw), content_location=location, captured_at=consumed)
            if not created or source.supersedes_source_id is not None:
                raise ValueError('one first canonical claim required')
            reference = EvidenceReference(source_id=source.id, content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
            self._same_physical_transaction(session, entry)
            if not consumed <= self._clock() < c.expires_at:
                raise ValueError('original consent expired before commit')
            self._same_physical_transaction(session, entry)
            _assert_fragment_no_prospective_declaration(session, c.id)
            self._same_physical_transaction(session, entry)
            session.commit()  # Durable burn precedes recovery or the runtime's sole POST.
        return claim, reference

    def _reopen_claim(self) -> None:
        if self._claim is None or self._claim_reference is None:
            raise ValueError('committed original claim required')
        with self._factory() as session:
            session.begin()
            entry = self._physical_transaction(session)
            load_history_fragment_claim(session, artifacts=self._artifacts,
                reference=self._claim_reference, expected_consent=self._consent,
                expected_claim=self._claim, expected_request=self._request)
            self._same_physical_transaction(session, entry)
        self._owner()  # After private loader callbacks, outside canonical leases.

    def _final_claim(self, receipt: PersonalFragmentAuthorityReceiptV1) -> None:
        # The concrete protector has just checked the original owner after its
        # last ciphertext callback. No owner/private-body callback follows it.
        if self._claim is None or self._claim_reference is None:
            raise ValueError('committed original claim required')
        with self._factory() as session:
            session.begin()
            entry = self._physical_transaction(session)
            refs = (*self._consent.provenance, self._consent_reference, self._claim_reference)
            rows = _fragment_rows(session, refs, _FRAGMENT_BOUNDARIES, _FRAGMENT_LABELS)
            _fragment_profile_lineage(self._request, rows)
            self._plan_receipt(session, receipt, self._claim, self._claim_reference)
            self._same_physical_transaction(session, entry)
        # Actual journal remains mutable bookkeeping, never protection authority.
        if content_hash_of(self._protector._run_row(receipt.artifact_backup_run_id)) != receipt.live_journal_digest:
            raise ValueError('original operational recovery journal changed')
        self._graph_check()
        if not self._consent.approved_at <= self._clock() < self._consent.expires_at:
            raise ValueError('original consent expired at terminal boundary')

    def recheck(self, request: HistoryFragmentContextualRequestV1,
                descriptor: FragmentContextualDispatchDescriptor) -> None:
        """Runtime-only PRE burn and read-existing RELEASE, no reusable capability.

        Any matching PRE failure poisons this instance. A committed Source burns
        the consent across instances even when protection/POST never succeeded.
        No receipt remint, original time renewal, cancellation namespace or
        authenticated-review assertion is introduced here.
        """
        from zacai.contextual_protection import PersonalFragmentCleanupUncertain

        with self._lock:
            succeeded = False
            failure: type[RuntimeError] = ContextualAuthorizationError
            try:
                self._descriptor(request, descriptor)
                if descriptor.phase == 'PRE_DISPATCH':
                    if self._phase != 'UNUSED':
                        raise ValueError('one original PRE entry only')
                    self._phase = 'ENTERED'
                    self._owner()
                    prior = self._protector.recheck_consent(reference=self._consent_reference,
                        expected_consent=self._consent, expected_request=self._request)
                    self._owner()
                    self._descriptor(request, descriptor)
                    self._claim, self._claim_reference = self._burn(descriptor, prior)
                    self._owner()
                    self._reopen_claim()
                    self._receipt = self._protector.protect_claim(reference=self._claim_reference,
                        expected_consent=self._consent, expected_claim=self._claim,
                        expected_request=self._request)
                    self._final_claim(self._receipt)
                    self._descriptor(request, descriptor)
                    self._phase = 'DISPATCHED'
                else:
                    if self._phase != 'DISPATCHED' or self._claim is None or self._claim_reference is None:
                        raise ValueError('original consumed PRE required')
                    self._phase = 'RELEASING'
                    self._owner()
                    existing = self._protector.recheck_claim(reference=self._claim_reference,
                        expected_consent=self._consent, expected_claim=self._claim,
                        expected_request=self._request)
                    if existing != self._receipt:
                        raise ValueError('original claim checkpoint changed')
                    self._final_claim(existing)
                    self._descriptor(request, descriptor)
                    self._released = descriptor
                    self._phase = 'RELEASED'
                succeeded = True
            except PersonalFragmentCleanupUncertain:
                failure = PersonalFragmentCleanupUncertain
            except Exception:  # noqa: BLE001,S110 - fixed error outside private exception context
                pass
            finally:
                if not succeeded and self._phase != 'UNUSED':
                    self._phase = 'HELD'
            if not succeeded:
                if failure is PersonalFragmentCleanupUncertain:
                    raise failure('PERSONAL recovery cleanup uncertain; operator review required')
                raise failure('PERSONAL fragment attempt unavailable or consumed')
