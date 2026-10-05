"""D034F closed metadata audit artifacts in canonical Source inventory.

Trusted operator library, no agent endpoint or live invocation. Audit is append-
only by event UUID, not a state machine or permission grant. Caller owns commit;
artifact/DB atomicity and recovery follow the existing D030 orphan-artifact rule.
"""

from __future__ import annotations

from datetime import UTC
from enum import Enum
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, RouteIdentity
from zacai.intelligence.meeting_review import MeetingReview, ReviewContext
from zacai.intelligence.review_evaluation import (
    EvaluationOutcome,
    ReviewEvaluation,
    check_review_evaluation,
)
from zacai.intelligence.runtime_diagnostics import PREFLIGHT_CODES, RuntimeFailureCode
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


class ReviewAuditStage(str, Enum):
    REQUEST_PREPARED = "REQUEST_PREPARED"
    REFRESH_REJECTED = "REFRESH_REJECTED"
    ROUTE_REJECTED = "ROUTE_REJECTED"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    DISPATCH_STARTED = "DISPATCH_STARTED"
    DISPATCH_FAILED = "DISPATCH_FAILED"
    RUN_FAILED = "RUN_FAILED"
    DRAFT_REJECTED = "DRAFT_REJECTED"
    DRAFT_VALIDATED = "DRAFT_VALIDATED"
    EVALUATION_RECORDED = "EVALUATION_RECORDED"


class ContextualAuditStage(str, Enum):
    REQUEST_PREPARED = "REQUEST_PREPARED"
    DISPATCH_PREPARED = "DISPATCH_PREPARED"
    PACKET_CAPTURED = "PACKET_CAPTURED"
    RUN_FAILED = "RUN_FAILED"


class ContextualFailureStep(str, Enum):
    """Closed host operation labels; never exception text or model content."""

    REQUEST_AUDIT = "REQUEST_AUDIT"
    ROUTE_CHECK = "ROUTE_CHECK"
    CLAIM = "CLAIM"
    RUNTIME_PREFLIGHT = "RUNTIME_PREFLIGHT"
    FRESHNESS_AGE_CHECK = "FRESHNESS_AGE_CHECK"
    REQUEST_INTEGRITY_CHECK = "REQUEST_INTEGRITY_CHECK"
    EVIDENCE_REFRESH = "EVIDENCE_REFRESH"
    AUTHORIZATION_RECHECK = "AUTHORIZATION_RECHECK"
    GENERATION_LATENCY_CHECK = "GENERATION_LATENCY_CHECK"
    RECOVERY_RECEIPT_VALIDATION = "RECOVERY_RECEIPT_VALIDATION"
    PACKET_VALIDATION = "PACKET_VALIDATION"
    METADATA_ACCESS_CHECK = "METADATA_ACCESS_CHECK"
    RELEASE_LATENCY_CHECK = "RELEASE_LATENCY_CHECK"
    DISPATCH_AUDIT = "DISPATCH_AUDIT"
    DISPATCH_CLOCK_START = "DISPATCH_CLOCK_START"
    CAPTURE_SESSION_CLOSE = "CAPTURE_SESSION_CLOSE"
    GENERATION = "GENERATION"
    DRAFT_VALIDATION = "DRAFT_VALIDATION"
    PACKET_CAPTURE = "PACKET_CAPTURE"
    PROTECTION = "PROTECTION"
    PACKET_READ = "PACKET_READ"


class ContextualAuditEvent(Contract):
    """Host metadata for the distinct contextual path; never dispatch authority."""

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-contextual-run-audit-v1"] = "zac-contextual-run-audit-v1"
    audit_event_id: UUID
    run_id: UUID
    task_id: UUID
    builder_id: UUID
    recorded_at: AwareDatetime
    trust_boundary: TrustBoundary
    data_classification: DataClassification
    stage: ContextualAuditStage
    request_digest: Digest
    context_digest: Digest
    route: RouteIdentity
    model_digest: Digest
    packet_source_id: UUID | None = None
    packet_digest: Digest | None = None
    failure_step: ContextualFailureStep | None = None
    dispatch_attempted: bool | None = Field(default=None, strict=True)
    runtime_failure_code: RuntimeFailureCode | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if self.failure_step is None:
            data.pop("failure_step", None)
            data.pop("dispatch_attempted", None)
        if self.runtime_failure_code is None:
            data.pop("runtime_failure_code", None)
        return data

    @model_validator(mode="after")
    def consistent_packet(self) -> Self:
        if any(name in self.model_fields_set and getattr(self, name) is None
               for name in ("failure_step", "dispatch_attempted", "runtime_failure_code")):
            raise ValueError("diagnostic fields must be absent rather than null")
        if self.runtime_failure_code == RuntimeFailureCode.UNSPECIFIED:
            raise ValueError("unspecified diagnostic must be absent")
        if self.runtime_failure_code is not None and self.failure_step not in {
            ContextualFailureStep.RUNTIME_PREFLIGHT, ContextualFailureStep.GENERATION
        }:
            raise ValueError("runtime diagnostic requires runtime operation")
        if (self.runtime_failure_code is not None and self.failure_step == ContextualFailureStep.RUNTIME_PREFLIGHT
            and self.runtime_failure_code not in PREFLIGHT_CODES):
            raise ValueError("runtime preflight diagnostic mismatch")
        if (self.failure_step is None) != (self.dispatch_attempted is None):
            raise ValueError("failure operation and dispatch flag must be paired")
        if self.failure_step is not None:
            if self.stage != ContextualAuditStage.RUN_FAILED:
                raise ValueError("failure operation belongs only to failed audit")
            before_dispatch = {ContextualFailureStep.REQUEST_AUDIT, ContextualFailureStep.CLAIM,
                               ContextualFailureStep.RUNTIME_PREFLIGHT, ContextualFailureStep.DISPATCH_AUDIT,
                               ContextualFailureStep.DISPATCH_CLOCK_START}
            before_capture = before_dispatch | {ContextualFailureStep.GENERATION,
                ContextualFailureStep.GENERATION_LATENCY_CHECK, ContextualFailureStep.DRAFT_VALIDATION,
                ContextualFailureStep.PACKET_CAPTURE}
            after_capture = {ContextualFailureStep.CAPTURE_SESSION_CLOSE, ContextualFailureStep.PROTECTION, ContextualFailureStep.RECOVERY_RECEIPT_VALIDATION,
                ContextualFailureStep.PACKET_READ, ContextualFailureStep.PACKET_VALIDATION,
                ContextualFailureStep.METADATA_ACCESS_CHECK, ContextualFailureStep.RELEASE_LATENCY_CHECK}
            if self.failure_step in before_dispatch and self.dispatch_attempted is not False:
                raise ValueError("operation precedes dispatch")
            if self.failure_step in (before_capture - before_dispatch) | after_capture and self.dispatch_attempted is not True:
                raise ValueError("operation follows dispatch attempt")
            if self.failure_step in before_capture and self.packet_digest is not None:
                raise ValueError("operation precedes capture")
            if self.failure_step in after_capture and self.packet_digest is None:
                raise ValueError("operation requires captured packet")
            if self.packet_digest is not None and self.dispatch_attempted is not True:
                raise ValueError("packet requires dispatch attempt")
        if (self.packet_source_id is None) != (self.packet_digest is None):
            raise ValueError("packet metadata must be paired")
        if self.stage == ContextualAuditStage.PACKET_CAPTURED and self.packet_digest is None:
            raise ValueError("captured stage requires packet binding")
        if (
            self.stage
            not in {ContextualAuditStage.PACKET_CAPTURED, ContextualAuditStage.RUN_FAILED}
            and self.packet_digest is not None
        ):
            raise ValueError("packet metadata precedes capture")
        return self


def append_contextual_audit(
    session: Session,
    *,
    artifacts: ArtifactStore,
    event: ContextualAuditEvent,
    authorized_boundaries: frozenset[TrustBoundary],
) -> UUID:
    """Append closed host metadata; caller commits and verifies recovery."""
    failed = False
    result: UUID | None = None
    try:
        event = ContextualAuditEvent.model_validate(event)
        result = _persist_review_audit(
            session,
            artifacts=artifacts,
            event=event,
            authorized_boundaries=authorized_boundaries,
        )
    except Exception:  # noqa: BLE001 - no backend or validation diagnostics
        failed = True
    if failed or result is None:
        raise ValueError("contextual audit unavailable or mismatched")
    return result


class ReviewPreContextAudit(Contract):
    """A real failed host attempt, before any task/evidence packet exists.

    BRAINSTORM operator metadata only. No selected Source IDs, exception text,
    task/context/draft or authority assertion. This record never grants access.
    """

    format: Literal["zac-review-pre-context-audit-v1"] = "zac-review-pre-context-audit-v1"
    audit_event_id: UUID
    run_id: UUID
    recorded_at: AwareDatetime
    trust_boundary: Literal[TrustBoundary.BRAINSTORM] = TrustBoundary.BRAINSTORM
    data_classification: Literal[DataClassification.CONFIDENTIAL] = DataClassification.CONFIDENTIAL
    stage: Literal["PRE_CONTEXT_REJECTED"] = "PRE_CONTEXT_REJECTED"


def append_review_pre_context_audit(
    session: Session,
    *,
    artifacts: ArtifactStore,
    event: ReviewPreContextAudit,
    authorized_boundaries: frozenset[TrustBoundary],
) -> UUID:
    """Commit through the host's own transaction; no denied artifact is read.

    The fixed journal boundary still requires BRAINSTORM access. Failure to write
    or commit it stops the attempt with audit-unavailable, never an invented proof.
    """
    try:
        event = ReviewPreContextAudit.model_validate(event)
        return _persist_review_audit(
            session,
            artifacts=artifacts,
            event=event,
            authorized_boundaries=authorized_boundaries,
        )
    except Exception:  # noqa: BLE001 - private storage diagnostics
        raise ValueError("pre-context review audit unavailable") from None


class ReviewAuditEvent(Contract):
    format: Literal["zac-meeting-review-audit-v1"] = "zac-meeting-review-audit-v1"
    audit_event_id: UUID
    run_id: UUID
    task_id: UUID
    recorded_at: AwareDatetime
    trust_boundary: TrustBoundary
    data_classification: DataClassification
    stage: ReviewAuditStage
    context_digest: Digest
    route: RouteIdentity | None = None
    review_digest: Digest | None = None
    evaluation: ReviewEvaluation | None = None
    evaluation_outcome: EvaluationOutcome | None = None

    @model_validator(mode="after")
    def consistent_payload(self) -> Self:
        is_evaluation = self.stage == ReviewAuditStage.EVALUATION_RECORDED
        if is_evaluation:
            if self.evaluation is None or self.evaluation_outcome is None:
                raise ValueError("evaluation stage requires bound judgments and outcome")
            if (
                self.evaluation.task_id != self.task_id
                or self.evaluation.review_digest != self.review_digest
                or self.evaluation.context_digest != self.context_digest
                or self.evaluation.evaluated_at > self.recorded_at
            ):
                raise ValueError("evaluation audit does not match its metadata")
            judgments = {a.judgment.value for a in self.evaluation.assessments}
            expected = (
                EvaluationOutcome.NEEDS_REVISION
                if "FAIL" in judgments
                else EvaluationOutcome.NEEDS_REVIEW
                if "UNREVIEWED" in judgments
                else EvaluationOutcome.REVIEWED_PASS
            )
            if self.evaluation_outcome != expected:
                raise ValueError("evaluation outcome contradicts judgments")
        elif self.evaluation is not None or self.evaluation_outcome is not None:
            raise ValueError("evaluation metadata only belongs to evaluation stage")
        has_draft = self.stage in {
            ReviewAuditStage.DRAFT_VALIDATED,
            ReviewAuditStage.EVALUATION_RECORDED,
        }
        if has_draft != (self.review_digest is not None):
            raise ValueError("review digest requires validated draft stage")
        if (
            self.stage
            in {
                ReviewAuditStage.DISPATCH_STARTED,
                ReviewAuditStage.DISPATCH_FAILED,
                ReviewAuditStage.DRAFT_REJECTED,
                ReviewAuditStage.DRAFT_VALIDATED,
            }
            and self.route is None
        ):
            raise ValueError("runtime stage requires host route identity")
        return self


def append_review_audit(
    session: Session,
    *,
    artifacts: ArtifactStore,
    event: ReviewAuditEvent,
    authorized_boundaries: frozenset[TrustBoundary],
) -> UUID:
    """Persist exact closed metadata under a canonical MANUAL Source.

    Host must construct truthful events and authenticate permissions separately.
    This does not infer a successful workflow from a stage declaration. No raw
    quotes, generated prose, emails, errors or arbitrary notes are accepted.
    Digests/UUIDs are still private metadata; retain the exact boundary/label.
    Audit Sources join existing artifact backup inventory, but no live backup
    is invoked or verified here. Commit and recovery remain operator duties.
    """
    try:
        event = ReviewAuditEvent.model_validate(event)
        if event.stage == ReviewAuditStage.EVALUATION_RECORDED:
            raise ValueError("evaluation requires exact draft/context verification")
        return _persist_review_audit(
            session,
            artifacts=artifacts,
            event=event,
            authorized_boundaries=authorized_boundaries,
        )
    except Exception:  # noqa: BLE001 - backend errors can contain private metadata
        raise ValueError("meeting review audit unavailable or mismatched") from None


def _persist_review_audit(
    session: Session,
    *,
    artifacts: ArtifactStore,
    event: ReviewAuditEvent | ReviewPreContextAudit | ContextualAuditEvent,
    authorized_boundaries: frozenset[TrustBoundary],
) -> UUID:
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("audit session contains unrelated pending writes")
        if not evaluate_access(
            AccessRequest(
                data_boundary=event.trust_boundary,
                data_classification=event.data_classification,
                requestor_boundaries=authorized_boundaries,
                destination=Destination.LOCAL,
            )
        ).allowed:
            raise ValueError("audit boundary denied")
        raw = canonical_bytes(event.model_dump(mode="json"))
        digest = content_hash_of(raw)
        # Serialize first insertion and retries for this exact audit UUID.
        session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": event.audit_event_id.int % (2**63)}
        )
        prefix = (
            "contextual-run-audit"
            if isinstance(event, ContextualAuditEvent)
            else "meeting-review-pre-context-audit"
            if isinstance(event, ReviewPreContextAudit)
            else "meeting-review-audit"
        )
        external_ref = f"{prefix}/{event.audit_event_id}"
        prior = session.scalar(
            select(Source).where(
                Source.system == SourceSystem.MANUAL,
                Source.trust_boundary == event.trust_boundary,
                Source.external_ref == external_ref,
            )
        )
        if prior is not None and (
            prior.content_hash != digest or prior.data_classification != event.data_classification
        ):
            raise ValueError("audit event UUID cannot be revised")
        location = artifacts.put(event.trust_boundary, digest, raw)
        if content_hash_of(artifacts.get(event.trust_boundary, location)) != digest:
            raise ValueError("audit artifact integrity failed")
        if prior is not None:
            if prior.content_location != location:
                raise ValueError("audit artifact location changed")
            return prior.id
        source, _ = record_source(
            session,
            trust_boundary=event.trust_boundary,
            data_classification=event.data_classification,
            system=SourceSystem.MANUAL,
            external_ref=external_ref,
            content_hash=digest,
            content_location=location,
            captured_at=event.recorded_at.astimezone(UTC),
        )
        return source.id
    except Exception:  # noqa: BLE001 - backend errors can contain private metadata
        raise ValueError("meeting review audit unavailable or mismatched") from None


def append_review_evaluation(
    session: Session,
    *,
    artifacts: ArtifactStore,
    event: ReviewAuditEvent,
    review: MeetingReview,
    context: ReviewContext,
    authorized_boundaries: frozenset[TrustBoundary],
) -> UUID:
    """Verify exact evidence/output binding before appending evaluation metadata."""
    try:
        event = ReviewAuditEvent.model_validate(event)
        if event.stage != ReviewAuditStage.EVALUATION_RECORDED or event.evaluation is None:
            raise ValueError("not an evaluation event")
        outcome = check_review_evaluation(event.evaluation, review, context)
        if (
            event.trust_boundary != context.task.event.trust_boundary
            or event.data_classification != review.data_classification
            or event.evaluation_outcome != outcome
        ):
            raise ValueError("evaluation audit boundary/classification/outcome mismatch")
        return _persist_review_audit(
            session,
            artifacts=artifacts,
            event=event,
            authorized_boundaries=authorized_boundaries,
        )
    except Exception:  # noqa: BLE001 - backend errors can contain private metadata
        raise ValueError("meeting review audit unavailable or mismatched") from None
