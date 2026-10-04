"""D034G one-attempt operator shadow host, no enabled runtime or approval issuer.

Trusted authorization/protection/runtime adapters are mandatory and have no
permissive defaults. Agents/transcripts cannot supply them. No CLI, scheduler,
service activation, private approval backend or model transport is added here.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import ArtifactStore
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.eligibility import ApprovedRouteRegistry, assess_routes
from zacai.intelligence.meeting_review import MeetingReview, ReviewContext
from zacai.intelligence.project_review_context import (
    ReviewedProjectEvidence,
    assemble_project_review_context,
)
from zacai.intelligence.review_audit import (
    ReviewAuditEvent,
    ReviewAuditStage,
    ReviewPreContextAudit,
    append_review_audit,
    append_review_pre_context_audit,
)
from zacai.intelligence.review_context import MeetingEvidence, assemble_review_context
from zacai.intelligence.review_evaluation import review_context_digest, review_evaluation_digests
from zacai.intelligence.review_freshness import check_review_freshness
from zacai.intelligence.review_generation import (
    ReviewDraft,
    ReviewRequest,
    prepare_review_request,
    resolve_review_draft,
)
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary


@dataclass(frozen=True)
class ReviewSelection:
    selected: MeetingEvidence
    earlier: tuple[MeetingEvidence, ...] = ()
    projects: tuple[ReviewedProjectEvidence, ...] = ()


class ReviewAuthorization(Protocol):
    def preflight(self, selection: ReviewSelection, route: ModelRoute, model_digest: str) -> None:
        """Verify actual operator scope/recovery before any selected artifact read."""
        ...

    def claim(
        self,
        run_id: UUID,
        request: ReviewRequest,
        route: ModelRoute,
        model_digest: str,
        now: datetime,
    ) -> None:
        """Durably consume exact one-shot human authority; not a boolean grant.

        Concrete backend must bind selections/evidence, boundary/label, runtime
        and model digest, expiry and replay. Explicit adapters are operator-wired;
        no service or issuer is enabled by this protocol.
        """
        ...

    def recheck(self, run_id: UUID, request: ReviewRequest, now: datetime) -> None:
        """Check current unexpired, unrevoked authority; never renew or retry."""
        ...


class ReviewRuntime(Protocol):
    @property
    def route(self) -> ModelRoute: ...
    @property
    def model_digest(self) -> str: ...
    def preflight(self, request: ReviewRequest) -> None:
        """Verify model pin/locality and full serialized capacity; send no text yet."""
        ...

    def generate(self, request: ReviewRequest) -> ReviewDraft:
        """One bounded call; adapter owns transport deadline and no fallback/tools."""
        ...


class ReviewProtection(Protocol):
    def protect(self, run_id: UUID, audit_source_ids: tuple[UUID, ...]) -> None:
        """Verify committed audit/state/artifact recovery coverage or raise.

        Does not promote/store generated prose or authorize a live invocation.
        """
        ...


@dataclass(frozen=True)
class ShadowReviewResult:
    run_id: UUID
    context: ReviewContext
    review: MeetingReview
    audit_source_ids: tuple[UUID, ...]
    # No approval/semantic PASS field: delivered output still needs evaluation.


class ReviewHostError(RuntimeError):
    """Fixed failure, no private exception/transcript/model text."""


@contextmanager
def _snapshot(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session:
        bind = session.get_bind()
        if not isinstance(bind, Engine) or bind.dialect.name != "postgresql":
            raise ValueError("fresh engine-bound PostgreSQL sessions required")
        if session.in_transaction() or session.identity_map:
            raise ValueError("snapshot session was reused")
        with session.begin():
            # First statement: one fresh consistent snapshot, enforced read-only.
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            yield session


def execute_review_shadow(
    factory: sessionmaker[Session],
    *,
    artifacts: ArtifactStore,
    selection: ReviewSelection,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    registry: ApprovedRouteRegistry,
    runtime: ReviewRuntime,
    authorization: ReviewAuthorization,
    protection: ReviewProtection,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
) -> ShadowReviewResult:
    """Fresh snapshots -> claimed authority -> committed audit -> one draft.

    Registry/adapter declarations are trusted host inputs, not proof of locality
    against hostile infrastructure. A concurrent change after a read remains
    possible; pre/post-generation refresh reduces risk but is not a global lock.
    No default real authorization/runtime/protection backend exists, and no live
    call is authorized by this code. Failure after claim consumes authority; no
    retries. Audit/commit/protection failure never returns a successful draft.
    """
    run_id = uuid4()
    request: ReviewRequest | None = None
    audit_ids: list[UUID] = []
    phase = ReviewAuditStage.RUN_FAILED
    route: ModelRoute
    pin = ""

    def audit(stage: ReviewAuditStage, review_digest: str | None = None) -> None:
        if request is None:
            # This attempt has a real run UUID, but no truthful task/context yet.
            # Persist only owned operator metadata, not denied selection details.
            with factory() as session:
                source_id = append_review_pre_context_audit(
                    session,
                    artifacts=artifacts,
                    event=ReviewPreContextAudit(
                        audit_event_id=uuid4(), run_id=run_id, recorded_at=clock()
                    ),
                    authorized_boundaries=authorized_boundaries,
                )
                session.commit()
            audit_ids.append(source_id)
            return
        event = ReviewAuditEvent(
            audit_event_id=uuid4(),
            run_id=run_id,
            task_id=request.context.task.task_id,
            recorded_at=clock(),
            trust_boundary=request.context.task.event.trust_boundary,
            data_classification=request.context.task.event.data_classification,
            stage=stage,
            context_digest=review_context_digest(request.context),
            route=route.identity,
            review_digest=review_digest,
        )
        with factory() as session:
            source_id = append_review_audit(
                session,
                artifacts=artifacts,
                event=event,
                authorized_boundaries=authorized_boundaries,
            )
            session.commit()  # generation/return must never precede successful commit
        audit_ids.append(source_id)

    def route_check() -> None:
        assert request is not None
        if (
            route.destination != Destination.LOCAL
            or not any(item.route == route for item in registry.routes)
            or route.identity
            not in assess_routes(
                request.context.task,
                authorized_boundaries=authorized_boundaries,
                registry=registry,
            ).eligible_routes
        ):
            raise ValueError("route unavailable or outside approved scope")
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
                description="prepare bounded meeting-review shadow draft",
            )
        )
        if gate.outcome != GatewayOutcome.ALLOW:
            raise ValueError("draft gateway denied")
        if runtime.route != route or runtime.model_digest != pin:
            raise ValueError("runtime registration changed")

    def refresh() -> None:
        assert request is not None
        with _snapshot(factory) as session:
            check_review_freshness(
                session,
                artifacts=artifacts,
                request=request,
                selected=selection.selected,
                earlier=selection.earlier,
                projects=selection.projects,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                checked_at=clock(),
            )

    try:
        route = ModelRoute.model_validate(runtime.route)
        pin = runtime.model_digest
        if not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise ValueError("invalid runtime pin")
        authorization.preflight(selection, route, pin)
        with _snapshot(factory) as session:
            if selection.projects:
                context = assemble_project_review_context(
                    session,
                    artifacts=artifacts,
                    selected=selection.selected,
                    earlier=selection.earlier,
                    projects=selection.projects,
                    authorized_boundaries=authorized_boundaries,
                    allowed_classifications=allowed_classifications,
                    observed_at=clock(),
                )
            else:
                context = assemble_review_context(
                    session,
                    artifacts=artifacts,
                    selected=selection.selected,
                    earlier=selection.earlier,
                    authorized_boundaries=authorized_boundaries,
                    allowed_classifications=allowed_classifications,
                    observed_at=clock(),
                )
            request = prepare_review_request(context)
        audit(ReviewAuditStage.REQUEST_PREPARED)
        phase = ReviewAuditStage.ROUTE_REJECTED
        route_check()
        runtime.preflight(request)
        phase = ReviewAuditStage.AUTHORIZATION_REJECTED
        authorization.claim(run_id, request, route, pin, clock())
        phase = ReviewAuditStage.REFRESH_REJECTED
        refresh()
        audit(ReviewAuditStage.DISPATCH_STARTED)
        # Audit I/O may take time: refresh once more after that committed write.
        refresh()
        route_check()
        phase = ReviewAuditStage.AUTHORIZATION_REJECTED
        authorization.recheck(run_id, request, clock())
        phase = ReviewAuditStage.DISPATCH_FAILED
        started = monotonic()
        draft = runtime.generate(request)
        elapsed = monotonic() - started
        if not 0 <= elapsed * 1000 <= request.context.task.max_latency_ms:
            raise ValueError("late or invalid runtime clock")
        phase = ReviewAuditStage.DRAFT_REJECTED
        review = resolve_review_draft(draft, request)
        phase = ReviewAuditStage.REFRESH_REJECTED
        refresh()
        route_check()
        phase = ReviewAuditStage.AUTHORIZATION_REJECTED
        authorization.recheck(run_id, request, clock())
        phase = ReviewAuditStage.RUN_FAILED
        digest, _ = review_evaluation_digests(review, request.context)
        audit(ReviewAuditStage.DRAFT_VALIDATED, digest)
        protection.protect(run_id, tuple(audit_ids))
        phase = ReviewAuditStage.REFRESH_REJECTED
        refresh()
        route_check()
        phase = ReviewAuditStage.AUTHORIZATION_REJECTED
        authorization.recheck(run_id, request, clock())
        return ShadowReviewResult(run_id, request.context, review, tuple(audit_ids))
    except Exception:  # noqa: BLE001 - never expose private/backend errors
        try:
            audit(phase)
        except Exception:  # noqa: BLE001 - audit failure must also stay fail-closed
            raise ReviewHostError("meeting-review shadow failed; audit unavailable") from None
        raise ReviewHostError("meeting-review shadow failed; no draft released") from None
