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
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, ModelRoute
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.intelligence.text_followup import FOLLOWUP_CAPABILITY
from zacai.interfaces.host_clock import HostObservedClock
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


if TYPE_CHECKING:
    from zacai.interfaces.named_decision_inventory import NamedDecisionInventory
    from zacai.interfaces.named_followup_decision import NamedFollowupDecision


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


class FollowupConsentV2(Contract):
    """Declared named-decision linkage, never proof of human admission.

    Trusted canonical binding must verify the actual decision Source, protection,
    original admission/processing window and deterministic consent ID. This type
    does not issue authority, renew expiry or promote historical v1 records.
    """

    model_config = ConfigDict(hide_input_in_errors=True, strict=True)
    format: Literal["zac-packet-followup-consent-v2"] = "zac-packet-followup-consent-v2"
    id: UUID
    scope: FollowupRunScope = Field(repr=False)
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_reference: str = Field(strict=True, min_length=1, max_length=500, repr=False)
    decision_reference: EvidenceReference
    decision_recovery_digest: Digest

    @field_validator("approved_at", "expires_at", mode="before")
    @classmethod
    def explicit_time(cls, value: object) -> object:
        if type(value) is not datetime and (type(value) is not str or "T" not in value):
            raise ValueError("explicit aware timestamp required")
        return value

    @model_validator(mode="after")
    def bounded(self) -> Self:
        reference = self.decision_reference
        if (
            not self.human_reference.strip()
            or not timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=15)
            or reference.trust_boundary != B.BRAINSTORM
            or reference.effective_classification != C.CONFIDENTIAL
            or reference.source_id in {
                self.scope.packet_reference.source_id,
                *(r.source_id for r in self.scope.context_references),
                self.scope.user_reference.source_id,
                *(r.source_id for r in self.scope.parent_references),
            }
        ):
            raise ValueError("invalid named follow-up consent")
        return self


FollowupConsentRecord = FollowupConsent | FollowupConsentV2


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
    @property
    def host_clock(self) -> HostObservedClock:
        """Same process-local watermark as the calling canonical ledger."""
        ...

    @property
    def named_binding(self) -> NamedFollowupConsentBinding | None:
        """Exact original named gate, required for named production composition."""
        ...

    def preflight(self, consent: FollowupConsentRecord) -> object:
        """Current recovered inputs/key before subject commit; None acknowledges."""
        ...

    def protect_consent(self, *, consent: FollowupConsentRecord, reference: EvidenceReference) -> object:
        """Recover committed consent outside SQL; only None acknowledges."""
        ...

    def protect_claim(self, *, claimed: ClaimedFollowup, request: FollowupRequest) -> object:
        """Recover committed consumed attempt; only None acknowledges."""
        ...


class NamedFollowupConsentBinding(Protocol):
    """Trusted actual named-admission/recovery gate; declarations cannot satisfy it.

    Historical integrity is independent of active processing TTL. Fresh checks
    run outside SQL/leases; rows checks must perform canonical read validation
    only. Both acknowledge solely by returning None, never truthy metadata.
    """

    @property
    def host_clock(self) -> HostObservedClock: ...

    def verify_fresh(self, consent: FollowupConsentV2, now: datetime) -> object: ...

    def verify_rows(self, session: Session, consent: FollowupConsentV2, now: datetime) -> object: ...


def load_named_consent_inventory(
    session: Session, *, artifacts: ArtifactStore, consent: FollowupConsentV2,
    as_of: datetime,
) -> NamedDecisionInventory:
    """Actual canonical rows only: no recovery/session/clock callbacks or grant."""
    from zacai.interfaces.named_decision_inventory import load_named_decision_inventory
    from zacai.interfaces.named_followup_decision import named_decision_consent_id

    if type(consent) is not FollowupConsentV2:
        raise ValueError("exact named consent required")
    consent = FollowupConsentV2.model_validate(consent)
    inventory = load_named_decision_inventory(
        session, artifacts=artifacts, reference=consent.decision_reference, as_of=as_of,
    )
    decision = inventory.decision
    if (
        consent.id != named_decision_consent_id(consent.decision_reference.source_id)
        or consent.scope != decision.run_scope
        or consent.approved_at != decision.admitted_at
        or consent.expires_at != decision.processing_expires_at
    ):
        raise ValueError("named consent original binding changed")
    return inventory


class _NamedConsentRows:
    """Explicit adapter from the shared guarded-row protocol to consent checks."""

    def __init__(self, binding: NamedFollowupConsentBinding, consent: FollowupConsentV2) -> None:
        self.binding, self.consent = binding, consent

    def verify_fresh(self, decision: NamedFollowupDecision, now: datetime) -> object:
        raise ValueError("row adapter has no fresh authority")

    def verify_rows(self, session: Session, decision: NamedFollowupDecision, now: datetime) -> object:
        if decision.run_scope != self.consent.scope:
            raise ValueError("named row scope changed")
        return self.binding.verify_rows(session, self.consent, now)


def checked_named_consent_inventory(
    session: Session, *, artifacts: ArtifactStore, consent: FollowupConsentV2,
    binding: NamedFollowupConsentBinding, clock: HostObservedClock, as_of: datetime,
) -> NamedDecisionInventory:
    """Guard the trusted row callback, then reread all actual dependencies."""
    from zacai.interfaces.named_decision_capture import _checked_rows

    # Binding clock identity is validated outside SQL at host construction.
    if type(clock) is not HostObservedClock:
        raise ValueError("named consent shared clock required")
    initial = load_named_consent_inventory(session, artifacts=artifacts, consent=consent, as_of=as_of)
    _checked_rows(session, _NamedConsentRows(binding, consent), initial.decision, as_of)
    session.expire_all()
    return load_named_consent_inventory(session, artifacts=artifacts, consent=consent, as_of=clock())


def _raw(value: Contract) -> bytes:
    data = value.model_dump(mode="json")
    scope = data.get("scope", data.get("run_scope"))
    if scope is not None:
        scope["route"]["capabilities"] = sorted(scope["route"]["capabilities"])
    raw = canonical_bytes(data)
    if len(raw) > 32_000:
        raise ValueError("authority metadata exceeds bound")
    return raw


def validate_followup_consent(value: object) -> FollowupConsentRecord:
    """Revalidate an exact concrete version, including mutated frozen copies."""
    result: FollowupConsentRecord | None = None
    try:
        if type(value) is FollowupConsent:
            result = FollowupConsent.model_validate(value, strict=True)
        elif type(value) is FollowupConsentV2:
            result = FollowupConsentV2.model_validate(value, strict=True)
        if result is not None:
            _raw(result)
    except Exception:  # noqa: BLE001 - fixed diagnostics outside exception context
        result = None
    if result is None:
        raise FollowupAuthorizationError("follow-up consent metadata invalid")
    return result


def encode_followup_consent(value: FollowupConsentRecord) -> bytes:
    """Preserve original canonical v1 bytes; never migrate or infer a version."""
    return _raw(validate_followup_consent(value))


def _consent_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _consent_json_constant(value: str) -> object:
    raise ValueError("nonfinite number")


def _consent_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite number")
    return result


def decode_followup_consent(raw: bytes) -> FollowupConsentRecord:
    """Closed exact-byte historical decoder, not canonical Source validation."""
    result: FollowupConsentRecord | None = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 32_000:
            raise ValueError("bounded bytes required")
        data = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_consent_json_object,
            parse_constant=_consent_json_constant,
            parse_float=_consent_json_float,
        )
        if type(data) is not dict:
            raise ValueError("versioned object required")
        if data.get("format") == "zac-packet-followup-consent-v1":
            result = FollowupConsent.model_validate_json(raw)
        elif data.get("format") == "zac-packet-followup-consent-v2":
            result = FollowupConsentV2.model_validate_json(raw, strict=False)
        else:
            raise ValueError("unsupported consent version")
        # Existing v1 before-validators retain timestamp strings, so strict
        # JSON validation cannot decode even its own bytes. Revalidate the
        # parsed concrete instance strictly, then reject every normalization
        # by exact original-byte comparison; v1 itself remains unchanged.
        result = validate_followup_consent(result)
        if _raw(result) != raw:
            raise ValueError("canonical bytes required")
    except Exception:  # noqa: BLE001 - no private payload diagnostics
        result = None
    if result is None:
        raise FollowupAuthorizationError("follow-up consent metadata invalid")
    return result


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
        clock: HostObservedClock,
        named_binding: NamedFollowupConsentBinding | None = None,
        named_only: bool = False,
    ) -> None:
        valid = False
        try:
            valid = (
                type(clock) is HostObservedClock and recovery.host_clock is clock
                and type(named_only) is bool and (not named_only or named_binding is not None)
                and (named_binding is None or (
                    named_binding.host_clock is clock
                    and recovery.named_binding is named_binding
                    and callable(named_binding.verify_fresh)
                    and callable(named_binding.verify_rows)
                ))
            )
        except Exception:  # noqa: BLE001,S110 - fixed configuration diagnostic
            pass
        if not valid:
            raise FollowupAuthorizationError("shared follow-up host clock required")
        self._factory, self._store = factory, store
        self._refresh, self._owner, self._recovery, self._clock = refresh, owner, recovery, clock
        self._named_binding = named_binding
        self._named_only = named_only

    @property
    def named_binding(self) -> NamedFollowupConsentBinding | None:
        """Exact original host gate; no fallback or inferred authorization."""
        return self._named_binding

    def _named_fresh(self, consent: FollowupConsentRecord) -> None:
        if type(consent) is FollowupConsentV2:
            binding = self._named_binding
            if binding is None or binding.verify_fresh(consent, self._now()) is not None:
                raise ValueError("named consent proof unavailable")

    def _named_rows(self, session: Session, consent: FollowupConsentRecord, now: datetime) -> NamedDecisionInventory | None:
        if type(consent) is not FollowupConsentV2:
            return None
        if self._named_binding is None:
            raise ValueError("named consent binding unavailable")
        return checked_named_consent_inventory(
            session, artifacts=self._store, consent=consent,
            binding=self._named_binding, clock=self._clock, as_of=now,
        )

    def _named_request(self, session: Session, consent: FollowupConsentRecord, request: FollowupRequest) -> None:
        if type(consent) is FollowupConsentV2:
            inventory = load_named_consent_inventory(session, artifacts=self._store, consent=consent, as_of=self._now())
            if (inventory.decision.prepared_request_digest != request.digest
                or inventory.decision.original_observed_at != request.context.task.event.observed_at):
                raise ValueError("named original request changed")

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
    ) -> tuple[FollowupConsentRecord, EvidenceReference]:
        source, raw = _source(
            session,
            self._store,
            approval_id,
            SourceSystem.USER_INSTRUCTION,
            "packet-followup-consent/",
        )
        consent = decode_followup_consent(raw)
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
        if type(consent) is FollowupConsent:
            self._owner_check(consent.scope)
        _refs(session, consent.scope)
        initial_reference = _reference(source)
        self._named_rows(session, consent, now)
        if type(consent) is FollowupConsentV2:
            session.expire_all()
            final_source, final_raw = _source(session, self._store, approval_id,
                SourceSystem.USER_INSTRUCTION, "packet-followup-consent/")
            if (final_raw != raw or _reference(final_source) != initial_reference
                or final_source.external_ref != f"packet-followup-consent/{consent.id}"
                or final_source.captured_at != consent.approved_at):
                raise ValueError("named consent changed during rows validation")
        return consent, _reference(source)

    def _recover(self, consent: FollowupConsentRecord) -> None:
        if self._recovery.preflight(consent) is not None:
            raise ValueError("recovery acknowledgement invalid")

    def record(self, consent: FollowupConsentRecord) -> UUID:
        """Only after an authenticated explicit human approval, never input alone."""
        result: UUID | None = None
        try:
            consent = validate_followup_consent(consent)
            if self._named_only and type(consent) is not FollowupConsentV2:
                raise ValueError("new named consent required")
            self._fresh(consent.scope)
            self._named_fresh(consent)
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
            self._recover(consent)
            self._fresh(consent.scope)
            self._named_fresh(consent)
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
            with self._factory() as session:
                _lock(session, consent.id)
                now = self._now()
                if not consent.approved_at <= now < consent.expires_at:
                    raise ValueError("consent inactive")
                if type(consent) is FollowupConsent:
                    self._owner_check(consent.scope)
                _refs(session, consent.scope)
                self._named_rows(session, consent, now)
                if type(consent) is FollowupConsentV2:
                    from zacai.interfaces.named_decision_capture import _require_request_lock
                    _require_request_lock(session, consent.id)
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
                if type(consent) is FollowupConsent:
                    self._owner_check(consent.scope)
                session.commit()
            reference = EvidenceReference(
                source_id=result,
                content_hash=content_hash_of(_raw(consent)),
                trust_boundary=B.BRAINSTORM,
                effective_classification=C.CONFIDENTIAL,
            )
            if self._recovery.protect_consent(consent=consent, reference=reference) is not None:
                raise ValueError("consent recovery acknowledgement invalid")
            self._fresh(consent.scope)
            self._named_fresh(consent)
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
            with self._factory() as session:
                # After commit, cancellation and claim use the canonical Source
                # ID, not the consent envelope ID used to serialize recording.
                _lock(session, result)
                current, current_reference = self._load(session, result, self._now())
                if current != consent or current_reference != reference:
                    raise ValueError("consent changed after recovery")
            if type(consent) is FollowupConsent:
                self._owner_check(consent.scope)
            if not consent.approved_at <= self._now() < consent.expires_at:
                raise ValueError("consent expired during recovery or final owner check")
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
            if self._named_only and type(consent) is not FollowupConsentV2:
                raise ValueError("named consent required for active processing")
            if consent.scope != scope:
                raise ValueError("approval scope differs")
            self._named_fresh(consent)
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
            self._recover(consent)
            if self._recovery.protect_consent(consent=consent, reference=ref) is not None:
                raise ValueError("consent recovery acknowledgement invalid")
            self._fresh(scope)
            self._named_fresh(consent)
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
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
                self._named_request(session, consent, request)
                if type(consent) is FollowupConsentV2:
                    from zacai.interfaces.named_decision_capture import _require_request_lock
                    _require_request_lock(session, approval_id)
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
                if type(consent) is FollowupConsent:
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
            if self._recovery.protect_claim(claimed=result, request=request) is not None:
                raise ValueError("claim recovery acknowledgement invalid")
            self._fresh(scope)
            self._claimed_check(result, consent)
        except Exception:  # noqa: BLE001 - no private context or chained diagnostics
            result = None
        if result is None:
            raise FollowupAuthorizationError("follow-up claim unavailable")
        return result

    def _claimed_check(self, claimed: ClaimedFollowup, consent: FollowupConsentRecord) -> None:
        """Final locked active-authority check after historical durability recovery."""
        if self._named_only and type(consent) is not FollowupConsentV2:
            raise ValueError("named consent required for active processing")
        claim = claimed.claim
        self._named_fresh(consent)
        if type(consent) is FollowupConsentV2:
            self._owner_check(claim.run_scope)
        with self._factory() as session:
            _lock(session, claim.consent_reference.source_id)
            current, current_ref = self._load(
                session, claim.consent_reference.source_id, self._now()
            )
            source, raw = _source(
                session,
                self._store,
                claimed.reference.source_id,
                SourceSystem.MANUAL,
                "packet-followup-claim/",
            )
            if (
                current != consent
                or current_ref != claim.consent_reference
                or _reference(source) != claimed.reference
                or source.external_ref
                != f"packet-followup-claim/{claim.consent_reference.source_id}"
                or source.captured_at != claim.claimed_at
                or raw != _raw(claim)
                or not consent.approved_at <= claim.claimed_at < consent.expires_at
            ):
                raise ValueError("consumed authority changed")
            if type(consent) is FollowupConsentV2:
                inventory = load_named_consent_inventory(session, artifacts=self._store, consent=consent, as_of=self._now())
                if inventory.decision.prepared_request_digest != claim.request_digest:
                    raise ValueError("named consumed request changed")
        if type(consent) is FollowupConsent:
            self._owner_check(claim.run_scope)
        if not claim.claimed_at <= self._now() < consent.expires_at:
            raise ValueError("claim expired during cleanup or final owner check")

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
            if self._named_only and type(consent) is not FollowupConsentV2:
                raise ValueError("named consent required for active processing")
            if ref != claim.consent_reference or consent.scope != claim.run_scope:
                raise ValueError("consent changed")
            with self._factory() as session:
                self._named_request(session, consent, request)
            self._named_fresh(consent)
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
            self._recover(consent)
            if self._recovery.protect_consent(consent=consent, reference=ref) is not None:
                raise ValueError("consent recovery acknowledgement invalid")
            if self._recovery.protect_claim(claimed=claimed, request=request) is not None:
                raise ValueError("claim recovery acknowledgement invalid")
            self._fresh(claim.run_scope)
            self._claimed_check(claimed, consent)
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
                consent = decode_followup_consent(raw)
                if (
                    _raw(consent) != raw
                    or source.external_ref != f"packet-followup-consent/{consent.id}"
                ):
                    raise ValueError("consent unavailable")
                if type(consent) is FollowupConsent:
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
            if type(consent) is FollowupConsentV2:
                self._owner_check(consent.scope)
                with self._factory() as session:
                    _lock(session, approval_id)
                    current_source, current_raw = _source(session, self._store, approval_id,
                        SourceSystem.USER_INSTRUCTION, "packet-followup-consent/")
                    if current_raw != raw or _reference(current_source) != _reference(source):
                        raise ValueError("named cancellation provenance changed")
                    now = self._now()
                    if now < consent.approved_at:
                        raise ValueError("clock precedes approval")
                    result = _write(session, self._store,
                        f"packet-followup-revocation/{approval_id}", SourceSystem.USER_INSTRUCTION,
                        canonical_bytes({"format": "zac-packet-followup-revocation-v1",
                            "approval_id": str(approval_id), "human_reference": human_reference,
                            "revoked_at": now.isoformat()}), now)
                    session.commit()
        except Exception:  # noqa: BLE001 - fixed diagnostics
            result = None
        if result is None:
            raise FollowupAuthorizationError("follow-up cancellation unavailable")
        return result
