"""Exact contextual packets and independently supplied evaluation judgments.

No model calls, persistence, fact promotion or authority. Full evidence is private;
callers must protect storage, recheck source access/freshness and authenticate
reviewers. Digests prove consistency only. Never capture exception frame locals.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from zacai.intelligence.contextual_review import (
    ContextualReview,
    render_contextual_preview,
    validate_contextual_review,
)
from zacai.intelligence.contracts import Contract, Digest, IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.review_evaluation import (
    ReviewJudgment,
    review_context_digest,
)


class ContextualCriterion(str, Enum):
    FACTUAL_SUPPORT = "FACTUAL_SUPPORT"
    TEMPORAL_CONTEXT = "TEMPORAL_CONTEXT"
    AGREEMENTS_AND_PROMISES = "AGREEMENTS_AND_PROMISES"
    OWNERS_AND_DATES = "OWNERS_AND_DATES"
    UNCERTAINTY = "UNCERTAINTY"
    COMPLETENESS = "COMPLETENESS"
    CONCISION = "CONCISION"
    USEFULNESS = "USEFULNESS"
    SCOPE_AND_CONTINUITY = "SCOPE_AND_CONTINUITY"
    CONFLICTS_AND_CLARIFICATIONS = "CONFLICTS_AND_CLARIFICATIONS"


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _review_digest(review: ContextualReview) -> str:
    return hashlib.sha256(_canonical(review.model_dump(mode="json"))).hexdigest()


class ContextualPacket(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    contract_version: Literal[1] = 1
    format: Literal["zac-contextual-packet-v1"]
    renderer_version: Literal[1] = 1
    builder_id: UUID
    created_at: AwareDatetime
    task: IntelligenceTask
    meeting_source_id: UUID
    related_source_ids: frozenset[UUID]
    review: ContextualReview
    review_digest: Digest
    context_digest: Digest
    rendered_preview: str

    def context(self) -> ReviewContext:
        return ReviewContext(self.task, self.meeting_source_id, self.related_source_ids)

    @field_validator("renderer_version", mode="before")
    @classmethod
    def exact_renderer_version(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("invalid renderer version")
        return value

    @model_validator(mode="after")
    def exact_components(self) -> Self:
        if self.created_at < self.task.event.observed_at:
            raise ValueError("capture precedes observed evidence")
        context = self.context()
        review = validate_contextual_review(self.review, context)
        if (
            self.review_digest != _review_digest(review)
            or self.context_digest != review_context_digest(context)
            or self.rendered_preview != render_contextual_preview(review, context)
        ):
            raise ValueError("contextual packet component mismatch")
        return self


def encode_contextual_packet(
    review: ContextualReview, context: ReviewContext, *, builder_id: UUID, created_at: datetime
) -> bytes:
    """Keep exact output, roles, full evidence and versioned visible presentation."""
    try:
        review = validate_contextual_review(review, context)
        packet = ContextualPacket(
            format="zac-contextual-packet-v1",
            builder_id=builder_id,
            created_at=created_at,
            task=context.task,
            meeting_source_id=context.meeting_source_id,
            related_source_ids=context.related_source_ids,
            review=review,
            review_digest=_review_digest(review),
            context_digest=review_context_digest(context),
            rendered_preview=render_contextual_preview(review, context),
        )
        data = packet.model_dump(mode="json")
        data["related_source_ids"] = sorted(data["related_source_ids"])
        data["task"]["required_capabilities"] = sorted(data["task"]["required_capabilities"])
        return _canonical(data)
    except Exception:  # noqa: BLE001, S110 - no private diagnostics in logs or chains
        pass
    raise ValueError("contextual packet unavailable or invalid")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate packet key")
        result[key] = value
    return result


def decode_contextual_packet(payload: bytes) -> ContextualPacket:
    """Accept only exact canonical bytes; defaulting/coercion cannot alter input."""
    try:
        if type(payload) is not bytes or len(payload) > 8 * 1024 * 1024:
            raise ValueError("immutable bounded payload required")
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
        packet = ContextualPacket.model_validate(data)
        if (
            encode_contextual_packet(
                packet.review,
                packet.context(),
                builder_id=packet.builder_id,
                created_at=packet.created_at,
            )
            != payload
        ):
            raise ValueError("noncanonical contextual packet")
        return packet
    except Exception:  # noqa: BLE001, S110 - no private diagnostics in logs or chains
        pass
    raise ValueError("contextual packet unavailable or invalid")


class ContextualAssessment(Contract):
    criterion: ContextualCriterion
    judgment: ReviewJudgment


class ContextualEvaluation(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    contract_version: Literal[1] = 1
    format: Literal["zac-contextual-evaluation-v1"]
    evaluation_id: UUID
    task_id: UUID
    reviewer_id: UUID
    builder_id: UUID
    evaluated_at: AwareDatetime
    packet_digest: Digest
    assessments: tuple[ContextualAssessment, ...] = Field(min_length=10, max_length=10)

    @model_validator(mode="after")
    def complete_independent_inventory(self) -> Self:
        criteria = [item.criterion for item in self.assessments]
        if len(set(criteria)) != len(criteria) or set(criteria) != set(ContextualCriterion):
            raise ValueError("each contextual criterion required exactly once")
        if self.reviewer_id == self.builder_id:
            raise ValueError("independently assigned reviewer required")
        return self


class ContextualOutcome(str, Enum):
    REVIEWED_PASS = "REVIEWED_PASS"
    NEEDS_REVISION = "NEEDS_REVISION"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NEEDS_CLARIFICATION = "NEEDS_CLARIFICATION"


def check_contextual_evaluation(
    evaluation: ContextualEvaluation, payload: bytes
) -> ContextualOutcome:
    """Report supplied judgments for these bytes; never authorize or infer PASS."""
    try:
        if type(payload) is not bytes:
            raise ValueError("immutable payload required")
        evaluation = ContextualEvaluation.model_validate(evaluation)
        packet = decode_contextual_packet(payload)
        if (
            evaluation.task_id != packet.task.task_id
            or evaluation.builder_id != packet.builder_id
            or evaluation.packet_digest != hashlib.sha256(payload).hexdigest()
            or evaluation.evaluated_at < packet.created_at
        ):
            raise ValueError("evaluation binding mismatch")
        judgments = {item.judgment for item in evaluation.assessments}
        if ReviewJudgment.FAIL in judgments:
            return ContextualOutcome.NEEDS_REVISION
        if packet.review.conflicts or packet.review.clarifications:
            return ContextualOutcome.NEEDS_CLARIFICATION
        if ReviewJudgment.UNREVIEWED in judgments:
            return ContextualOutcome.NEEDS_REVIEW
        return ContextualOutcome.REVIEWED_PASS
    except Exception:  # noqa: BLE001, S110 - no private diagnostics in logs or chains
        pass
    raise ValueError("contextual evaluation unavailable or mismatched")
