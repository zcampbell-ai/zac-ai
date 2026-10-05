"""One-attempt contextual host composition; no enabled operator or approval issuer.

Explicit trusted adapters own exact one-shot authority, runtime pinning and
recovery. No retries, fallback, discovery or cloud route are enabled. A returned
packet remains a draft needing independent semantic/usefulness evaluation.
Never log exception frame locals or copied source/model inputs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from sqlalchemy.orm import Session, sessionmaker

from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_diagnostics import (
    GenerationFailure,
    ReviewRejection,
    closed_draft_code,
)
from zacai.intelligence.contextual_evaluation import ContextualPacket, encode_contextual_packet
from zacai.intelligence.contextual_generation import (
    ContextualDraft,
    ContextualRequest,
    prepare_contextual_request,
    resolve_contextual_draft,
)
from zacai.intelligence.contextual_storage import capture_contextual_packet, load_contextual_packet
from zacai.intelligence.contracts import IntelligenceTask, ModelRoute
from zacai.intelligence.eligibility import ApprovedRouteRegistry, assess_routes
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.project_review_context import assemble_project_review_context
from zacai.intelligence.research_context import ResearchReviewSelection, append_research_context
from zacai.intelligence.review_audit import (
    ContextualAuditEvent,
    ContextualAuditStage,
    ContextualFailureStep,
    ReviewPreContextAudit,
    append_contextual_audit,
    append_review_pre_context_audit,
)
from zacai.intelligence.review_context import assemble_review_context
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_freshness import review_evidence_digest
from zacai.intelligence.review_host import ReviewSelection, _snapshot
from zacai.intelligence.runtime_diagnostics import (
    PREFLIGHT_CODES,
    RuntimeFailureCode,
    closed_runtime_code,
)
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


def contextual_request_digest(request: ContextualRequest) -> str:
    """Exact model-visible request/context binding, not an authority token."""
    if request != prepare_contextual_request(request.context):
        raise ValueError("contextual request changed")
    raw = json.dumps(
        {
            "context_digest": review_context_digest(request.context),
            "instruction": request.instruction,
            "evidence_json": request.evidence_json,
            "schema_json": request.schema_json,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ContextualRunScope:
    run_id: UUID
    builder_id: UUID
    selection: ReviewSelection | ResearchReviewSelection
    authorized_boundaries: frozenset[TrustBoundary]
    allowed_classifications: frozenset[DataClassification]
    route: ModelRoute
    model_digest: str


class ContextualAuthorization(Protocol):
    def preflight(self, scope: ContextualRunScope) -> None:
        """Authenticate exact read/run scope before artifacts; reject compact consent."""
        ...

    def claim(
        self,
        scope: ContextualRunScope,
        request: ContextualRequest,
        request_digest: str,
        now: datetime,
    ) -> None:
        """Durably consume exact preflight scope/request/route/pin/builder authority.

        Concrete backend authenticates expiry, revocation and replay and binds
        the same exact request digest as the audit. No backend/grant exists here.
        """
        ...

    def recheck(
        self,
        scope: ContextualRunScope,
        request: ContextualRequest,
        request_digest: str,
        now: datetime,
    ) -> None: ...


class ContextualRuntime(Protocol):
    @property
    def route(self) -> ModelRoute: ...
    @property
    def model_digest(self) -> str: ...
    def preflight(self, request: ContextualRequest) -> None:
        """Verify pinned runtime and full input/output capacity without dispatch."""
        ...

    def generate(self, request: ContextualRequest) -> ContextualDraft:
        """One bounded call; parse raw bytes with parse_contextual_draft.

        Adapter owns timeout, bounded transport reads and forbids tools/fallback.
        """
        ...


class ContextualProtection(Protocol):
    def protect(
        self,
        source_id: UUID,
        expected_digest: str,
        audit_source_ids: tuple[UUID, ...],
    ) -> ContextualRecoveryReceipt | None:
        """Verify committed packet, evidence, all audits and snapshot recovery.

        Explicit BrainstormContextualProtector fits this interface. A concrete
        operator must retain/recover receipt metadata before live release.
        None is reserved for explicit synthetic fixtures, never a real trial.
        """
        ...


@dataclass(frozen=True)
class ContextualHostResult:
    run_id: UUID
    packet_source_id: UUID
    packet_digest: str
    packet: ContextualPacket
    audit_source_ids: tuple[UUID, ...]
    recovery_receipt: ContextualRecoveryReceipt | None
    # No semantic PASS, action permission or reusable recovery authority.


@dataclass(frozen=True)
class ContextualHostFailure:
    run_id: UUID
    audit_source_ids: tuple[UUID, ...]
    audit_unavailable: bool


class ContextualHostError(RuntimeError):
    """Fixed errors only; never expose model/storage diagnostics or chains."""


def assemble_contextual_context(
    factory: sessionmaker[Session],
    *,
    artifacts: ArtifactStore,
    selection: ReviewSelection | ResearchReviewSelection,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    now: datetime,
    max_output_tokens: int = 1600,
) -> ReviewContext:
    """Read-only assembly with a host-supplied budget, bound by exact consent.

    The default remains 1600. A larger explicit route budget requires a new
    proposal/consent; no agent decides or expands this allowance.
    """
    if type(max_output_tokens) is not int or max_output_tokens not in {1600, 3200}:
        raise ValueError("unsupported contextual output budget")
    with _snapshot(factory) as session:
        # Keep existing assembly/relationship and canonical Event contracts.
        if selection.projects:
            context = assemble_project_review_context(
                session,
                artifacts=artifacts,
                selected=selection.selected,
                earlier=selection.earlier,
                projects=selection.projects,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                observed_at=now,
            )
        else:
            context = assemble_review_context(
                session,
                artifacts=artifacts,
                selected=selection.selected,
                earlier=selection.earlier,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                observed_at=now,
            )
        data = context.task.model_dump()
        data["max_output_tokens"] = max_output_tokens
        data["required_capabilities"] = (
            context.task.required_capabilities - {"compact_meeting_review"}
        ) | {"contextual_meeting_review"}
        data["instruction"] = (
            "Prepare a source-backed contextual meeting review or material question."
        )
        task = IntelligenceTask.model_validate(data)
        result = ReviewContext(task, context.meeting_source_id, context.related_source_ids)
        if isinstance(selection, ResearchReviewSelection):
            result = append_research_context(
                session,
                artifacts=artifacts,
                context=result,
                research=selection.research,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
            )
        return result


def execute_contextual_shadow(
    factory: sessionmaker[Session],
    *,
    artifacts: ArtifactStore,
    selection: ReviewSelection | ResearchReviewSelection,
    builder_id: UUID,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    registry: ApprovedRouteRegistry,
    runtime: ContextualRuntime,
    authorization: ContextualAuthorization,
    protection: ContextualProtection,
    run_id: UUID | None = None,
    failure_observer: Callable[[ContextualHostFailure], None] | None = None,
    max_release_latency_ms: int = 300_000,
    allow_synthetic_protection: bool = False,
    max_output_tokens: int = 1600,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
) -> ContextualHostResult:
    """Refresh -> claimed authority -> audit -> one call -> capture -> protection.

    Trusted adapter declarations do not prove infrastructure locality. Fresh
    snapshots limit concurrent-change risk; they cannot lock external policy.
    Request age is capped at 120 seconds before dispatch; post-dispatch snapshots
    compare current evidence without renewing authority. Release has its own
    bounded monotonic deadline; every authority recheck still enforces expiry.
    PACKET_CAPTURED with no RUN_FAILED means possibly returned, never proof of
    user delivery: an actual interface must record its own delivery receipt.
    Post-claim failures consume authority. No draft/question returns on any
    failure. Failed-attempt recovery remains an explicit operator responsibility.
    Durable recovery receipts are mandatory by default; only invented fixtures
    may explicitly allow receipt-less protection. No live CLI/service or route
    is enabled; concrete consent storage exists outside this host.
    """
    run_id = run_id if run_id is not None else uuid4()
    request: ContextualRequest | None = None
    route: ModelRoute | None = None
    pin = ""
    packet_id: UUID | None = None
    packet_hash: str | None = None
    audit_ids: list[UUID] = []
    result: ContextualHostResult | None = None
    audit_failed = False
    observer_failed = False
    runtime_failure_code: RuntimeFailureCode | None = None
    draft_failure_code: GenerationFailure | None = None
    draft_rejection: ReviewRejection | None = None
    bound_request_digest: str | None = None
    bound_context_digest: str | None = None
    bound_task_id: UUID | None = None
    bound_boundary: TrustBoundary | None = None
    bound_classification: DataClassification | None = None
    dispatched = False
    failure_step: ContextualFailureStep | None = None
    interruption: str | None = None
    exit_code = 1

    def audit(
        stage: ContextualAuditStage,
        session: Session | None = None,
        capture: tuple[UUID, str] | None = None,
    ) -> UUID:
        if session is None:
            with factory() as owned:
                sid = audit(stage, owned, capture)
                owned.commit()
                audit_ids.append(sid)
            return sid
        captured_id, captured_hash = capture if capture is not None else (packet_id, packet_hash)
        if request is None or route is None or bound_task_id is None:
            sid = append_review_pre_context_audit(
                session,
                artifacts=artifacts,
                event=ReviewPreContextAudit(
                    audit_event_id=uuid4(),
                    run_id=run_id,
                    recorded_at=clock(),
                ),
                authorized_boundaries=authorized_boundaries,
            )
        else:
            diagnostics: dict[str, Any] = {}
            if stage == ContextualAuditStage.RUN_FAILED:
                diagnostics = {"failure_step": failure_step, "dispatch_attempted": dispatched}
                if runtime_failure_code is not None:
                    diagnostics["runtime_failure_code"] = runtime_failure_code
                if draft_failure_code is not None:
                    diagnostics["draft_failure_code"] = draft_failure_code
                if draft_rejection is not None:
                    diagnostics["draft_rejection"] = draft_rejection
            sid = append_contextual_audit(
                session,
                artifacts=artifacts,
                event=ContextualAuditEvent(
                    audit_event_id=uuid4(),
                    run_id=run_id,
                    task_id=bound_task_id,
                    builder_id=builder_id,
                    recorded_at=clock(),
                    trust_boundary=bound_boundary,
                    data_classification=bound_classification,
                    stage=stage,
                    request_digest=bound_request_digest,
                    context_digest=bound_context_digest,
                    route=route.identity,
                    model_digest=pin,
                    packet_source_id=captured_id,
                    packet_digest=captured_hash,
                    **diagnostics,
                ),
                authorized_boundaries=authorized_boundaries,
            )
        return sid

    def assemble(now: datetime) -> ReviewContext:
        return assemble_contextual_context(
            factory,
            artifacts=artifacts,
            selection=selection,
            authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications,
            now=now,
            max_output_tokens=max_output_tokens,
        )

    def refresh() -> None:
        nonlocal failure_step
        failure_step = ContextualFailureStep.FRESHNESS_AGE_CHECK
        assert request is not None
        now = clock()
        age = (now - request.context.task.event.observed_at).total_seconds()
        if age < 0 or (not dispatched and age > 120):
            raise ValueError("request expired or clock regressed")
        failure_step = ContextualFailureStep.REQUEST_INTEGRITY_CHECK
        if contextual_request_digest(request) != bound_request_digest:
            raise ValueError("request binding changed")
        failure_step = ContextualFailureStep.EVIDENCE_REFRESH
        if review_evidence_digest(assemble(now)) != review_evidence_digest(request.context):
            raise ValueError("canonical evidence changed")

    def route_check() -> None:
        nonlocal failure_step
        failure_step = ContextualFailureStep.ROUTE_CHECK
        assert request is not None and route is not None
        if (
            route.destination != Destination.LOCAL
            or not any(item.route == route for item in registry.routes)
            or route.identity
            not in assess_routes(
                request.context.task,
                authorized_boundaries=authorized_boundaries,
                registry=registry,
            ).eligible_routes
            or runtime.route != route
            or runtime.model_digest != pin
        ):
            raise ValueError("route unavailable")
        event = request.context.task.event
        gate = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.SUMMARIZE_CONTENT,
                access=AccessRequest(
                    data_boundary=event.trust_boundary,
                    data_classification=event.data_classification,
                    requestor_boundaries=authorized_boundaries,
                    destination=route.destination,
                ),
                description="prepare bounded contextual review draft",
            )
        )
        if gate.outcome != GatewayOutcome.ALLOW:
            raise ValueError("gateway denied")

    try:
        if type(allow_synthetic_protection) is not bool:
            raise TypeError("explicit synthetic flag required")
        if type(max_release_latency_ms) is not int or not 1 <= max_release_latency_ms <= 600_000:
            raise ValueError("bounded release deadline required")
        if not isinstance(run_id, UUID):
            raise TypeError("host run identity required")
        if not isinstance(builder_id, UUID):
            raise TypeError("host builder identity required")
        route = ModelRoute.model_validate(runtime.route)
        pin = runtime.model_digest
        if type(pin) is not str or not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise ValueError("runtime pin invalid")
        scope = ContextualRunScope(
            run_id,
            builder_id,
            selection,
            authorized_boundaries,
            allowed_classifications,
            route,
            pin,
        )
        authorization.preflight(scope)
        failure_step = ContextualFailureStep.REQUEST_AUDIT
        prepared = prepare_contextual_request(assemble(clock()))
        bound_request_digest = contextual_request_digest(prepared)
        bound_context_digest = review_context_digest(prepared.context)
        bound_task_id = prepared.context.task.task_id
        bound_boundary = prepared.context.task.event.trust_boundary
        bound_classification = prepared.context.task.event.data_classification
        request = prepared
        audit(ContextualAuditStage.REQUEST_PREPARED)
        route_check()
        failure_step = ContextualFailureStep.CLAIM
        authorization.claim(scope, request, bound_request_digest, clock())
        failure_step = ContextualFailureStep.RUNTIME_PREFLIGHT
        runtime.preflight(request)
        refresh()
        failure_step = ContextualFailureStep.DISPATCH_AUDIT
        audit(ContextualAuditStage.DISPATCH_PREPARED)
        refresh()
        route_check()
        failure_step = ContextualFailureStep.AUTHORIZATION_RECHECK
        authorization.recheck(scope, request, bound_request_digest, clock())
        # Recovery rechecks can be slow: refresh again immediately before dispatch.
        refresh()
        route_check()
        failure_step = ContextualFailureStep.DISPATCH_CLOCK_START
        start = monotonic()
        dispatched = True
        failure_step = ContextualFailureStep.GENERATION
        draft = runtime.generate(request)
        failure_step = ContextualFailureStep.GENERATION_LATENCY_CHECK
        release_start = monotonic()
        elapsed = release_start - start
        if not 0 <= elapsed * 1000 <= request.context.task.max_latency_ms:
            raise ValueError("runtime latency exceeded")
        failure_step = ContextualFailureStep.DRAFT_VALIDATION
        review = resolve_contextual_draft(draft, request)
        refresh()
        route_check()
        failure_step = ContextualFailureStep.AUTHORIZATION_RECHECK
        authorization.recheck(scope, request, bound_request_digest, clock())
        failure_step = ContextualFailureStep.PACKET_CAPTURE
        payload = encode_contextual_packet(
            review,
            request.context,
            builder_id=builder_id,
            created_at=clock(),
        )
        with factory() as session:
            captured = capture_contextual_packet(
                session,
                artifacts=artifacts,
                payload=payload,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
            )
            captured_hash = content_hash_of(payload)
            captured_audit = audit(
                ContextualAuditStage.PACKET_CAPTURED,
                session,
                (captured, captured_hash),
            )
            session.commit()
            packet_id, packet_hash = captured, captured_hash
            audit_ids.append(captured_audit)
            failure_step = ContextualFailureStep.CAPTURE_SESSION_CLOSE
        failure_step = ContextualFailureStep.PROTECTION
        receipt = protection.protect(packet_id, packet_hash, tuple(audit_ids))
        failure_step = ContextualFailureStep.RECOVERY_RECEIPT_VALIDATION
        if receipt is None and not allow_synthetic_protection:
            raise ValueError("durable recovery receipt required")
        if receipt is not None:
            receipt = ContextualRecoveryReceipt.model_validate(receipt)
            if (
                receipt.locator.packet_source_id != packet_id
                or receipt.locator.packet_digest != packet_hash
                or receipt.locator.task_id != request.context.task.task_id
                or receipt.locator.builder_id != builder_id
                or receipt.audit_source_ids != tuple(audit_ids)
            ):
                raise ValueError("recovery receipt differs from this run")
        refresh()
        route_check()
        failure_step = ContextualFailureStep.AUTHORIZATION_RECHECK
        authorization.recheck(scope, request, bound_request_digest, clock())
        failure_step = ContextualFailureStep.PACKET_READ
        with _snapshot(factory) as session:
            packet = load_contextual_packet(
                session,
                artifacts=artifacts,
                source_id=packet_id,
                expected_digest=packet_hash,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
            )
        failure_step = ContextualFailureStep.PACKET_VALIDATION
        if packet.context() != request.context or packet.review != review:
            raise ValueError("captured packet differs")
        # Packet read/validation is I/O too: recheck after it before delivery.
        refresh()
        route_check()
        failure_step = ContextualFailureStep.AUTHORIZATION_RECHECK
        authorization.recheck(scope, request, bound_request_digest, clock())
        failure_step = ContextualFailureStep.METADATA_ACCESS_CHECK
        # Returned audit/receipt metadata retains its own current source labels.
        with _snapshot(factory) as session:
            metadata_ids = tuple(audit_ids) + (
                () if receipt is None else (receipt.locator_source_id,)
            )
            for sid in metadata_ids:
                source = session.get(Source, sid)
                if (
                    source is None
                    or source.system != SourceSystem.MANUAL
                    or source.trust_boundary != request.context.task.event.trust_boundary
                    or get_effective_source_classification(session, source_id=sid)
                    not in allowed_classifications
                    or (
                        receipt is not None
                        and sid == receipt.locator_source_id
                        and source.content_hash != receipt.locator_digest
                    )
                ):
                    raise ValueError("returned metadata access changed")
        failure_step = ContextualFailureStep.AUTHORIZATION_RECHECK
        authorization.recheck(scope, request, bound_request_digest, clock())
        failure_step = ContextualFailureStep.RELEASE_LATENCY_CHECK
        release_elapsed = monotonic() - release_start
        if not 0 <= release_elapsed * 1000 <= max_release_latency_ms:
            raise ValueError("release deadline exceeded")
        result = ContextualHostResult(
            run_id, packet_id, packet_hash, packet, tuple(audit_ids), receipt
        )
    except BaseException as error:  # noqa: BLE001 - sanitized cancellation audit
        if failure_step == ContextualFailureStep.DRAFT_VALIDATION:
            draft_failure_code, draft_rejection = closed_draft_code(error)
        if failure_step in {ContextualFailureStep.RUNTIME_PREFLIGHT, ContextualFailureStep.GENERATION}:
            runtime_failure_code = closed_runtime_code(error)
            if runtime_failure_code == RuntimeFailureCode.UNSPECIFIED or (
                failure_step == ContextualFailureStep.RUNTIME_PREFLIGHT and runtime_failure_code not in PREFLIGHT_CODES
            ):
                runtime_failure_code = None
        if isinstance(error, KeyboardInterrupt):
            interruption = "keyboard"
        elif isinstance(error, SystemExit):
            interruption = "exit"
            exit_code = error.code if type(error.code) is int else 1
        elif isinstance(error, asyncio.CancelledError):
            interruption = "cancel"
        try:
            audit(ContextualAuditStage.RUN_FAILED)
        except BaseException as secondary:  # noqa: BLE001 - preserve sanitized cancellation
            audit_failed = True
            if interruption is None:
                if isinstance(secondary, KeyboardInterrupt):
                    interruption = "keyboard"
                elif isinstance(secondary, SystemExit):
                    interruption = "exit"
                    exit_code = secondary.code if type(secondary.code) is int else 1
                elif isinstance(secondary, asyncio.CancelledError):
                    interruption = "cancel"
    if result is None and failure_observer is not None:
        try:
            failure_observer(ContextualHostFailure(run_id, tuple(audit_ids), audit_failed))
        except BaseException as secondary:  # noqa: BLE001 - observer never grants authority
            observer_failed = True
            if interruption is None:
                if isinstance(secondary, KeyboardInterrupt):
                    interruption = "keyboard"
                elif isinstance(secondary, SystemExit):
                    interruption = "exit"
                    exit_code = secondary.code if type(secondary.code) is int else 1
                elif isinstance(secondary, asyncio.CancelledError):
                    interruption = "cancel"
    if interruption == "keyboard":
        raise KeyboardInterrupt
    if interruption == "exit":
        raise SystemExit(exit_code)
    if interruption == "cancel":
        raise asyncio.CancelledError
    if result is None:
        message = (
            "contextual review failed; failure observer unavailable"
            if observer_failed and not audit_failed
            else "contextual review failed; audit unavailable"
            if audit_failed
            else "contextual review failed; no output released"
        )
        raise ContextualHostError(message)
    return result
