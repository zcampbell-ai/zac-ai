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
