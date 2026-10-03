"""D034F exact-draft evaluation bindings, not semantic inference or approval.

Trusted reviewers supply judgments. A PASS record does not prove their identity,
entailment or usefulness and never authorizes actions or fact promotion.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.intelligence.contracts import Contract, Digest
from zacai.intelligence.meeting_review import MeetingReview, ReviewContext, validate_review


class ReviewCriterion(str, Enum):
    FACTUAL_SUPPORT = "FACTUAL_SUPPORT"
    TEMPORAL_CONTEXT = "TEMPORAL_CONTEXT"
    AGREEMENTS_AND_PROMISES = "AGREEMENTS_AND_PROMISES"
    OWNERS_AND_DATES = "OWNERS_AND_DATES"
    UNCERTAINTY = "UNCERTAINTY"
    COMPLETENESS = "COMPLETENESS"
    CONCISION = "CONCISION"
    USEFULNESS = "USEFULNESS"


class ReviewJudgment(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNREVIEWED = "UNREVIEWED"


class CriterionAssessment(Contract):
    criterion: ReviewCriterion
    judgment: ReviewJudgment


class ReviewEvaluation(Contract):
    evaluation_id: UUID
    task_id: UUID
    reviewer_id: UUID
    builder_id: UUID
    evaluated_at: AwareDatetime
    review_digest: Digest
    context_digest: Digest
    assessments: tuple[CriterionAssessment, ...] = Field(min_length=8, max_length=8)

    @model_validator(mode="after")
    def complete_independent_inventory(self) -> Self:
        criteria = [a.criterion for a in self.assessments]
        if len(set(criteria)) != len(criteria) or set(criteria) != set(ReviewCriterion):
            raise ValueError("evaluation requires each criterion exactly once")
        if self.reviewer_id == self.builder_id:
            raise ValueError("reviewer and builder must be independently assigned")
        return self


class EvaluationOutcome(str, Enum):
    REVIEWED_PASS = "REVIEWED_PASS"
    NEEDS_REVISION = "NEEDS_REVISION"
    NEEDS_REVIEW = "NEEDS_REVIEW"


def review_evaluation_digests(review: MeetingReview, context: ReviewContext) -> tuple[str, str]:
    """Bind exact validated output and full evidence/roles, including task IDs.

    Digests stay local metadata; hashing is not anonymization. The host must
    validate reviewer identity separately and refresh before using old evidence.
    """
    context = ReviewContext(context.task, context.meeting_source_id, context.related_source_ids)
    review = validate_review(review, context)
    task_data = context.task.model_dump(mode="json")
    task_data["required_capabilities"] = sorted(context.task.required_capabilities)
    context_data = {
        "task": task_data,
        "meeting_source_id": str(context.meeting_source_id),
        "related_source_ids": sorted(str(sid) for sid in context.related_source_ids),
    }

    def digest(data: object) -> str:
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return hashlib.sha256(raw).hexdigest()

    return digest(review.model_dump(mode="json")), digest(context_data)


def check_review_evaluation(
    evaluation: ReviewEvaluation, review: MeetingReview, context: ReviewContext
) -> EvaluationOutcome:
    """Check binding/inventory and report judgments, without granting authority.

    FAIL takes precedence over UNREVIEWED. Missing, edited or stale draft/context
    bindings reject; actual semantic grading remains an independent reviewer job.
    No owner/date keyword heuristics or automatic approval thresholds are used.
    """
    try:
        evaluation = ReviewEvaluation.model_validate(evaluation)
        output_digest, context_digest = review_evaluation_digests(review, context)
        if (
            evaluation.task_id != context.task.task_id
            or evaluation.review_digest != output_digest
            or evaluation.context_digest != context_digest
            or evaluation.evaluated_at < context.task.event.observed_at
        ):
            raise ValueError("evaluation binding or observation invalid")
        judgments = {a.judgment for a in evaluation.assessments}
        if ReviewJudgment.FAIL in judgments:
            return EvaluationOutcome.NEEDS_REVISION
        if ReviewJudgment.UNREVIEWED in judgments:
            return EvaluationOutcome.NEEDS_REVIEW
        return EvaluationOutcome.REVIEWED_PASS
    except Exception:  # noqa: BLE001 - validation errors may echo private output
        raise ValueError("meeting review evaluation unavailable or mismatched") from None
