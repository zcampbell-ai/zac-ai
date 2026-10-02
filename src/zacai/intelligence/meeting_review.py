"""D034 offline meeting-review proposals; no inference, retrieval or state writes.

The trusted host must resolve authorized canonical evidence and supply context.
Exact quotes prove textual presence, not semantic entailment, identity or chronology.
Review output remains a draft; this module cannot promote facts or execute actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from zacai.intelligence.contracts import Contract, IntelligenceTask, classification_covers
from zacai.policy import DataClassification

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=600)]


class Quote(Contract):
    source_id: UUID
    start: Annotated[int, Field(ge=0, strict=True)]
    end: Annotated[int, Field(gt=0, strict=True)]
    text: Annotated[str, StringConstraints(min_length=1, max_length=1500)]

    @model_validator(mode="after")
    def valid_span(self) -> Self:
        if self.end <= self.start or not self.text.strip():
            raise ValueError("quote requires a nonblank forward span")
        return self


class Claim(Contract):
    text: ShortText
    quotes: tuple[Quote, ...] = Field(min_length=1, max_length=4)
    inferred: bool = Field(default=False, strict=True)


class ItemKind(str, Enum):
    DECISION = "DECISION"
    COMMITMENT = "COMMITMENT"
    RISK = "RISK"
    FOLLOW_UP = "FOLLOW_UP"


class ReviewItem(Claim):
    kind: ItemKind
    # Unresolved display labels, never canonical Person IDs or verified dates.
    owner: ShortText | None = None
    due_date: date | None = None


class MeetingReview(Contract):
    contract_version: Literal[1] = 1
    task_id: UUID
    data_classification: DataClassification
    summary: tuple[Claim, ...] = Field(min_length=1, max_length=3)
    # A claimed connection must cite both this meeting and related context.
    continuity: tuple[Claim, ...] = Field(max_length=2, default=())
    items: tuple[ReviewItem, ...] = Field(max_length=12, default=())


@dataclass(frozen=True)
class ReviewContext:
    """Host-selected evidence roles, outside model JSON and the Zac Event contract.

    This is a trusted Python seam, not proof against a malicious host. Related
    sources are candidates for a connection, not confirmed matches. The host must
    independently verify canonical hashes, current labels, policy and relevance.
    """

    task: IntelligenceTask
    meeting_source_id: UUID
    related_source_ids: frozenset[UUID] = frozenset()

    def __post_init__(self) -> None:
        task = IntelligenceTask.model_validate(self.task)
        object.__setattr__(self, "task", task)
        if (
            not isinstance(self.meeting_source_id, UUID)
            or not isinstance(self.related_source_ids, frozenset)
            or any(not isinstance(value, UUID) for value in self.related_source_ids)
        ):
            raise ValueError("host context roles require UUIDs and a frozenset")
        sources = {item.reference.source_id for item in task.context}
        if (
            self.meeting_source_id not in sources
            or self.meeting_source_id in self.related_source_ids
            or not self.related_source_ids <= sources
        ):
            raise ValueError("context roles must name distinct supplied evidence")


def validate_review(review: MeetingReview, context: ReviewContext) -> MeetingReview:
    """Check task linkage, privacy, quote spans, contextual support and brevity.

    Does not verify that a paraphrase follows from a quote, that a person agreed,
    or that one source precedes another. Those require evaluator/human review.
    No truncation: oversized output fails instead of silently hiding risks.
    """
    review = MeetingReview.model_validate(review)
    # Reconstruct even frozen objects: declarations must not skip validation.
    context = ReviewContext(context.task, context.meeting_source_id, context.related_source_ids)
    if review.task_id != context.task.task_id or not classification_covers(
        review.data_classification, context.task.event.data_classification
    ):
        raise ValueError("review task or classification does not match")
    texts = {item.reference.source_id: item.untrusted_text for item in context.task.context}
    for claim in (*review.summary, *review.continuity, *review.items):
        ids = set()
        for quote in claim.quotes:
            text = texts.get(quote.source_id)
            if text is None or quote.end > len(text) or text[quote.start : quote.end] != quote.text:
                raise ValueError("quote does not match supplied evidence")
            ids.add(quote.source_id)
        if context.meeting_source_id not in ids:
            raise ValueError("every review claim must cite the selected meeting")
        if len(claim.text.split()) > 35:
            raise ValueError("review claim exceeds compact display limit")
    for claim in review.continuity:
        if not {quote.source_id for quote in claim.quotes} & context.related_source_ids:
            raise ValueError("continuity requires related-context evidence")
    if sum(len(claim.text.split()) for claim in (*review.summary, *review.continuity)) > 60:
        raise ValueError("summary and contextual connection exceed 60 words")
    preview = _preview(review)
    if len(preview.split()) > 180:
        raise ValueError("review preview exceeds 180 words; revise without silent omission")
    if len(preview) > 1400:
        raise ValueError("review preview exceeds 1400 characters; revise without silent omission")
    return review


def _claim_text(claim: Claim) -> str:
    prefix = "Possible: " if claim.inferred else ""
    return prefix + claim.text


def _preview(review: MeetingReview) -> str:
    lines = ["Draft review", *(_claim_text(claim) for claim in (*review.continuity, *review.summary))]
    if not review.continuity:
        lines.append("Earlier context isn't established from the supplied sources.")
    groups = (
        ("Decisions and commitments", {ItemKind.DECISION, ItemKind.COMMITMENT}),
        ("Risks and follow-ups", {ItemKind.RISK, ItemKind.FOLLOW_UP}),
    )
    for heading, kinds in groups:
        items = [item for item in review.items if item.kind in kinds]
        if items:
            lines.extend(("", heading))
        for item in items:
            details = []
            if item.owner:
                details.append(f"proposed owner: {item.owner}")
            elif item.kind in {ItemKind.COMMITMENT, ItemKind.FOLLOW_UP}:
                details.append("owner unconfirmed")
            if item.due_date:
                details.append(f"proposed date: {item.due_date.isoformat()}")
            suffix = f" ({'; '.join(details)})" if details else ""
            lines.append(f"- {_claim_text(item)}{suffix}")
    return "\n".join(lines)


def render_preview(review: MeetingReview, context: ReviewContext) -> str:
    """Compact draft display; exact evidence stays separately in the review object.

    Plain text, not safe HTML or executable Markdown. A future UI must escape
    untrusted content and expose supporting quotes on demand.
    """
    return _preview(validate_review(review, context))
