"""Dedicated one-shot LOCAL packet-followup authority, outside agents.

New canonical Source prefixes, never meeting consent. Trusted operator alone
records an authenticated human decision. Host snapshot refresh must perform
actual canonical assembly/recovery/current ACL checks; recovery preflight must
verify real current checkpoint/key/credential evidence. No permissive adapter,
route, model invocation, human decision parser or live enrollment is supplied.
Python types are contracts, not a sandbox against hostile in-process code.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, ModelRoute
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.intelligence.text_followup import FOLLOWUP_CAPABILITY
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.text_followup_context import AssembledFollowup
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes, _find, _lock, _write
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class FollowupAuthorizationError(RuntimeError):
    """Fixed diagnostics; host diagnostics must never capture private locals."""


@dataclass(frozen=True)
class FollowupHostSnapshot:
    """Fresh trusted host result, not client-provided authority attestation."""

    assembled: AssembledFollowup = field(repr=False)
    principal: InterfacePrincipal = field(repr=False)
    owner: OwnerGrant = field(repr=False)
    route: ModelRoute
    model_digest: str


def _owner_digest(owner: OwnerGrant) -> str:
    if type(owner) is not OwnerGrant:
        raise ValueError("exact owner required")
    owner = OwnerGrant(owner.identity, owner.scopes)
    return content_hash_of(
        canonical_bytes(
            {
                "issuer": owner.identity.issuer,
                "subject": owner.identity.subject,
                "scopes": sorted(
                    [
                        {
                            "boundary": s.boundary.value,
                            "classifications": sorted(c.value for c in s.classifications),
                        }
                        for s in owner.scopes
                    ],
                    key=lambda s: s["boundary"],
                ),
            }
        )
    )


def followup_content_digest(request: FollowupRequest) -> str:
    """Refresh only observed_at; all identities, source text and budgets remain.

    Full original prepared request.digest is pinned separately in the claim.
    This is not a grant, freshness check or permission to normalize other fields.
    """
    result: str | None = None
    try:
        if type(request) is not FollowupRequest or request != prepare_followup_request(
            request.context
        ):
            raise ValueError("exact prepared request required")
        event = request.context.task.event.model_dump(mode="json")
        del event["observed_at"]
        result = content_hash_of(
            canonical_bytes(
                {
                    "format": "zac-packet-followup-approved-content-v1",
                    "instruction": request.instruction,
                    "evidence": json.loads(request.evidence_json),
                    "schema": json.loads(request.schema_json),
                    "event": event,
                    "max_output_tokens": request.context.task.max_output_tokens,
                    "max_latency_ms": request.context.task.max_latency_ms,
                    "max_estimated_cost_usd": request.context.task.max_estimated_cost_usd,
                }
            )
        )
    except Exception:  # noqa: BLE001,S110 - no private diagnostics
        pass
    if result is None:
        raise FollowupAuthorizationError("follow-up content scope invalid")
    return result


class FollowupRunScope(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    run_id: UUID
    builder_id: UUID
    actor_issuer: Literal["https://accounts.google.com"] = Field(repr=False)
    actor_subject: str = Field(strict=True, min_length=1, max_length=255, repr=False)
    owner_grant_digest: Digest
    conversation_id: UUID
    user_reference: EvidenceReference
    packet_reference: EvidenceReference
    parent_references: tuple[EvidenceReference, ...] = Field(max_length=6)
    context_references: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=40)
    text_receipt_digest: Digest
    packet_receipt_digest: Digest
    content_digest: Digest
    route: ModelRoute
    model_digest: Digest
    max_output_tokens: int = Field(strict=True, ge=1, le=1024)
    max_latency_ms: int = Field(strict=True, ge=1, le=120_000)
    max_estimated_cost_usd: float = Field(strict=True, ge=0, le=1, allow_inf_nan=False)
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL

    @model_validator(mode="after")
    def bounded(self) -> Self:
        refs = (self.packet_reference, *self.context_references)
        if (
            self.route.destination != Destination.LOCAL
            or self.route.capabilities != frozenset({FOLLOWUP_CAPABILITY})
            or not self.route.available
            or self.route.max_output_tokens < self.max_output_tokens
            or self.route.estimated_latency_ms > self.max_latency_ms
            or self.route.estimated_cost_usd > self.max_estimated_cost_usd
            or any(
                r.trust_boundary != B.BRAINSTORM or r.effective_classification != C.CONFIDENTIAL
                for r in refs
            )
            or len({r.source_id for r in refs}) != len(refs)
            or self.user_reference not in self.context_references
            or any(r not in self.context_references for r in self.parent_references)
            or len({r.source_id for r in self.parent_references}) != len(self.parent_references)
        ):
            raise ValueError("invalid bounded follow-up scope")
        return self


def followup_scope_digest(scope: FollowupRunScope) -> str:
    scope = FollowupRunScope.model_validate(scope)
    data = scope.model_dump(mode="json")
    data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    return content_hash_of(canonical_bytes(data))


def scope_from_snapshot(
    snapshot: FollowupHostSnapshot, *, run_id: UUID, builder_id: UUID
) -> FollowupRunScope:
    if (
        type(snapshot) is not FollowupHostSnapshot
        or type(snapshot.assembled) is not AssembledFollowup
        or type(snapshot.principal) is not InterfacePrincipal
        or type(snapshot.owner) is not OwnerGrant
        or type(snapshot.route) is not ModelRoute
        or OwnerGrant(snapshot.principal.identity, snapshot.principal.scopes) != snapshot.owner
    ):
        raise FollowupAuthorizationError("follow-up host identity unavailable")
    if not any(
        s.boundary == B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
        for s in snapshot.owner.scopes
    ):
        raise FollowupAuthorizationError("follow-up host scope unavailable")
    a = snapshot.assembled
    turn = a.saved_turn.turn
    if (
        turn.issuer != snapshot.owner.identity.issuer
        or turn.subject != snapshot.owner.identity.subject
        or a.saved_turn.reference != a.context.user_reference
        or turn.packet_reference != a.context.packet_reference
        or turn.parent_references != a.context.parent_references
    ):
        raise FollowupAuthorizationError("follow-up actor changed")
    request = prepare_followup_request(a.context)
    return FollowupRunScope(
        run_id=run_id,
        builder_id=builder_id,
        actor_issuer=snapshot.owner.identity.issuer,
        actor_subject=snapshot.owner.identity.subject,
        owner_grant_digest=_owner_digest(snapshot.owner),
        conversation_id=turn.conversation_id,
        user_reference=a.context.user_reference,
        packet_reference=a.context.packet_reference,
        parent_references=a.context.parent_references,
        context_references=tuple(item.reference for item in a.context.task.context),
        text_receipt_digest=content_hash_of(
            canonical_bytes(a.saved_turn.recovery_receipt.model_dump(mode="json"))
        ),
        packet_receipt_digest=turn.packet_receipt_digest,
        content_digest=followup_content_digest(request),
        route=snapshot.route,
        model_digest=snapshot.model_digest,
        max_output_tokens=a.context.task.max_output_tokens,
        max_latency_ms=a.context.task.max_latency_ms,
        max_estimated_cost_usd=a.context.task.max_estimated_cost_usd,
    )


class FollowupConsent(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-packet-followup-consent-v1"] = "zac-packet-followup-consent-v1"
    id: UUID
    scope: FollowupRunScope = Field(repr=False)
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_reference: str = Field(strict=True, min_length=1, max_length=500, repr=False)

    @field_validator("approved_at", "expires_at", mode="before")
    @classmethod
    def explicit_time(cls, value: object) -> object:
        if type(value) is not datetime and (type(value) is not str or "T" not in value):
            raise ValueError("explicit aware timestamp required")
        return value

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not self.human_reference.strip() or not timedelta(
            0
        ) < self.expires_at - self.approved_at <= timedelta(minutes=15):
            raise ValueError("invalid follow-up consent")
        return self


class FollowupClaim(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-packet-followup-claim-v1"] = "zac-packet-followup-claim-v1"
    consent_reference: EvidenceReference
    run_scope: FollowupRunScope = Field(repr=False)
    request_digest: Digest
    claimed_at: AwareDatetime

    @field_validator("claimed_at", mode="before")
    @classmethod
    def explicit_time(cls, value: object) -> object:
        if type(value) is not datetime and (type(value) is not str or "T" not in value):
            raise ValueError("explicit aware timestamp required")
        return value


@dataclass(frozen=True)
class ClaimedFollowup:
    claim: FollowupClaim = field(repr=False)
    reference: EvidenceReference

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class FollowupRecoveryGate(Protocol):
    def preflight(self, consent: FollowupConsent) -> object:
        """Actual checkpoint/key/credential recovery; only None acknowledges."""
        ...


def _raw(value: Contract) -> bytes:
    data = value.model_dump(mode="json")
    scope = data.get("scope", data.get("run_scope"))
    if scope is not None:
        scope["route"]["capabilities"] = sorted(scope["route"]["capabilities"])
    raw = canonical_bytes(data)
    if len(raw) > 32_000:
        raise ValueError("authority metadata exceeds bound")
    return raw


def _reference(source: Source) -> EvidenceReference:
    return EvidenceReference(
        source_id=source.id,
        content_hash=source.content_hash,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )


def _source(
    session: Session, store: ArtifactStore, sid: UUID, system: SourceSystem, prefix: str
) -> tuple[Source, bytes]:
    _assert_ledger_isolation(session)
    source = session.get(Source, sid)
    if (
        source is None
        or source.system != system
        or source.trust_boundary != B.BRAINSTORM
        or source.data_classification != C.CONFIDENTIAL
        or not source.external_ref
        or not source.external_ref.startswith(prefix)
    ):
        raise ValueError("authority Source unavailable")
    return source, _bytes(session, store, source)


def _refs(session: Session, scope: FollowupRunScope) -> None:
    _assert_ledger_isolation(session)
    for ref in (scope.packet_reference, *scope.context_references):
        source = session.get(Source, ref.source_id)
        if (
            source is None
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or source.content_hash != ref.content_hash
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("follow-up current Source denied")
        if ref == scope.packet_reference and source.system != SourceSystem.MANUAL:
            raise ValueError("follow-up packet Source kind changed")
        if (
            ref in (scope.user_reference, *scope.parent_references)
            and source.system != SourceSystem.USER_INSTRUCTION
        ):
            raise ValueError("follow-up user Source kind changed")


class CanonicalFollowupAuthorization:
    """Trusted host ledger; snapshot/recovery/owner callbacks are mandatory.

    Snapshot must use canonical assembler.load/protection, never shape-only
    assertions. Long recovery happens outside ledger transactions. Final locked
    checks reread canonical Sources, consent/revocation and current owner.
    No model invocation, live callbacks or enabled issuer are supplied.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        store: ArtifactStore,
        refresh: Callable[[], FollowupHostSnapshot],
        owner: Callable[[], OwnerGrant],
        recovery: FollowupRecoveryGate,
        clock: Callable[[], datetime],
    ) -> None:
        self._factory, self._store = factory, store
        self._refresh, self._owner, self._recovery, self._clock = refresh, owner, recovery, clock

    def _now(self) -> datetime:
        now = self._clock()
        if type(now) is not datetime or now.utcoffset() is None:
            raise ValueError("trusted aware clock required")
        return now

    def _fresh(self, scope: FollowupRunScope) -> None:
        fresh = scope_from_snapshot(
            self._refresh(), run_id=scope.run_id, builder_id=scope.builder_id
        )
        if fresh != scope:
            raise ValueError("follow-up scope changed")

    def _owner_check(self, scope: FollowupRunScope) -> None:
        if _owner_digest(self._owner()) != scope.owner_grant_digest:
            raise ValueError("follow-up owner changed")

    def _load(
        self, session: Session, approval_id: UUID, now: datetime
    ) -> tuple[FollowupConsent, EvidenceReference]:
        source, raw = _source(
            session,
            self._store,
            approval_id,
            SourceSystem.USER_INSTRUCTION,
            "packet-followup-consent/",
        )
        consent = FollowupConsent.model_validate_json(raw)
        if (
            _raw(consent) != raw
            or source.external_ref != f"packet-followup-consent/{consent.id}"
            or source.captured_at != consent.approved_at
            or not consent.approved_at <= now < consent.expires_at
            or _find(
                session, f"packet-followup-revocation/{approval_id}", SourceSystem.USER_INSTRUCTION
            )
            is not None
        ):
            raise ValueError("follow-up authority inactive")
        self._owner_check(consent.scope)
        _refs(session, consent.scope)
        return consent, _reference(source)

    def _recover(self, consent: FollowupConsent) -> None:
        if self._recovery.preflight(consent) is not None:
            raise ValueError("recovery acknowledgement invalid")

    def record(self, consent: FollowupConsent) -> UUID:
        """Only after an authenticated explicit human approval, never input alone."""
        result: UUID | None = None
        try:
            consent = FollowupConsent.model_validate(consent)
            self._fresh(consent.scope)
            self._recover(consent)
            self._fresh(consent.scope)
            with self._factory() as session:
                _lock(session, consent.id)
                now = self._now()
                if not consent.approved_at <= now < consent.expires_at:
                    raise ValueError("consent inactive")
                self._owner_check(consent.scope)
                _refs(session, consent.scope)
                result = _write(
                    session,
                    self._store,
                    f"packet-followup-consent/{consent.id}",
                    SourceSystem.USER_INSTRUCTION,
                    _raw(consent),
                    consent.approved_at,
                )
                if not consent.approved_at <= self._now() < consent.expires_at:
                    raise ValueError("consent expired before commit")
                self._owner_check(consent.scope)
                session.commit()
        except Exception:  # noqa: BLE001 - fixed private-safe diagnostic
            result = None
        if result is None:
            raise FollowupAuthorizationError("follow-up consent unavailable")
        return result

    def claim(
        self, *, approval_id: UUID, scope: FollowupRunScope, request: FollowupRequest
    ) -> ClaimedFollowup:
        """One committed attempt before runtime preflight; failures consume it."""
        result: ClaimedFollowup | None = None
        try:
            scope = FollowupRunScope.model_validate(scope)
            if followup_content_digest(request) != scope.content_digest:
                raise ValueError("request changed")
            event = request.context.task.event
            if not event.occurred_at <= event.observed_at <= self._now():
                raise ValueError("request observation is not yet available")
            self._fresh(scope)
            with self._factory() as session:
                consent, ref = self._load(session, approval_id, self._now())
            if consent.scope != scope:
                raise ValueError("approval scope differs")
            self._recover(consent)
            self._fresh(scope)
            with self._factory() as session:
                _lock(session, approval_id)
                current, current_ref = self._load(session, approval_id, self._now())
                if (
                    current != consent
                    or current_ref != ref
                    or _find(session, f"packet-followup-claim/{approval_id}", SourceSystem.MANUAL)
                    is not None
                ):
                    raise ValueError("authority consumed or changed")
                claim = FollowupClaim(
                    consent_reference=ref,
                    run_scope=scope,
                    request_digest=request.digest,
                    claimed_at=self._now(),
                )
                if (
                    not consent.approved_at <= claim.claimed_at < consent.expires_at
                    or not event.occurred_at <= event.observed_at <= claim.claimed_at
                ):
                    raise ValueError("claim expired or request chronology invalid")
                sid = _write(
                    session,
                    self._store,
                    f"packet-followup-claim/{approval_id}",
                    SourceSystem.MANUAL,
                    _raw(claim),
                    claim.claimed_at,
                )
                if not consent.approved_at <= self._now() < consent.expires_at:
                    raise ValueError("claim expired before commit")
                self._owner_check(scope)
                session.commit()
                result = ClaimedFollowup(
                    claim,
                    EvidenceReference(
                        source_id=sid,
                        content_hash=content_hash_of(_raw(claim)),
                        trust_boundary=B.BRAINSTORM,
                        effective_classification=C.CONFIDENTIAL,
                    ),
                )
        except Exception:  # noqa: BLE001,S110 - no private context or chained diagnostics
            pass
        if result is None:
            raise FollowupAuthorizationError("follow-up claim unavailable")
        return result

    def recheck(self, claimed: ClaimedFollowup, request: FollowupRequest) -> None:
        """Consumed claim remains TTL/revocation/current-owner bound; no dispatch."""
        failed = True
        try:
            if type(claimed) is not ClaimedFollowup:
                raise ValueError("exact claimed attempt required")
            claim = FollowupClaim.model_validate(claimed.claim)
            if (
                claim.request_digest != request.digest
                or followup_content_digest(request) != claim.run_scope.content_digest
            ):
                raise ValueError("request differs from consumed attempt")
            event = request.context.task.event
            if not event.occurred_at <= event.observed_at <= claim.claimed_at:
                raise ValueError("consumed request chronology invalid")
            self._fresh(claim.run_scope)
            with self._factory() as session:
                consent, ref = self._load(session, claim.consent_reference.source_id, self._now())
            if ref != claim.consent_reference or consent.scope != claim.run_scope:
                raise ValueError("consent changed")
            self._recover(consent)
            self._fresh(claim.run_scope)
            with self._factory() as session:
                _lock(session, ref.source_id)
                current, current_ref = self._load(session, ref.source_id, self._now())
                source, raw = _source(
                    session,
                    self._store,
                    claimed.reference.source_id,
                    SourceSystem.MANUAL,
                    "packet-followup-claim/",
                )
                if (
                    current != consent
                    or current_ref != ref
                    or _reference(source) != claimed.reference
                    or source.external_ref != f"packet-followup-claim/{ref.source_id}"
                    or source.captured_at != claim.claimed_at
                    or raw != _raw(claim)
                    or not consent.approved_at <= claim.claimed_at < consent.expires_at
                ):
                    raise ValueError("consumed authority changed")
                if not claim.claimed_at <= self._now() < consent.expires_at:
                    raise ValueError("claim expired before acknowledgement")
                self._owner_check(claim.run_scope)
            failed = False
        except Exception:  # noqa: BLE001,S110 - closed diagnostics
            pass
        if failed:
            raise FollowupAuthorizationError("follow-up authority no longer active")

    def revoke(self, *, approval_id: UUID, human_reference: str) -> UUID:
        """Append explicit human cancellation; never delete or renew authority."""
        result: UUID | None = None
        try:
            if (
                type(human_reference) is not str
                or not human_reference.strip()
                or len(human_reference) > 500
            ):
                raise ValueError("human cancellation reference required")
            with self._factory() as session:
                _lock(session, approval_id)
                source, raw = _source(
                    session,
                    self._store,
                    approval_id,
                    SourceSystem.USER_INSTRUCTION,
                    "packet-followup-consent/",
                )
                consent = FollowupConsent.model_validate_json(raw)
                if (
                    _raw(consent) != raw
                    or source.external_ref != f"packet-followup-consent/{consent.id}"
                ):
                    raise ValueError("consent unavailable")
                self._owner_check(consent.scope)
                now = self._now()
                if now < consent.approved_at:
                    raise ValueError("clock precedes approval")
                result = _write(
                    session,
                    self._store,
                    f"packet-followup-revocation/{approval_id}",
                    SourceSystem.USER_INSTRUCTION,
                    canonical_bytes(
                        {
                            "format": "zac-packet-followup-revocation-v1",
                            "approval_id": str(approval_id),
                            "human_reference": human_reference,
                            "revoked_at": now.isoformat(),
                        }
                    ),
                    now,
                )
                session.commit()
        except Exception:  # noqa: BLE001 - fixed diagnostics
            result = None
        if result is None:
            raise FollowupAuthorizationError("follow-up cancellation unavailable")
        return result
