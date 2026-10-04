"""Offline contextual review proposals; no retrieval, inference or authority.

Separate from compact MeetingReview and its live operator. Quote presence proves
neither entailment nor project identity. Full evidence and role selection remain
host-owned; unknown context is not evidence of absence. Plain-text previews need
UI escaping. Limits are defensive ceilings, not brevity targets.
Hosts must not capture exception frame locals containing private inputs.
"""

from __future__ import annotations

import unicodedata
from itertools import combinations
from typing import Literal
from uuid import UUID

from pydantic import Field

from zacai.intelligence.contracts import Contract, classification_covers
from zacai.intelligence.meeting_review import (
    Claim,
    ItemKind,
    ReviewContext,
    ReviewItem,
    ShortText,
)
from zacai.policy import DataClassification


class ProvisionalConnection(Claim):
    inferred: Literal[True] = True


class Clarification(Claim):
    """A material gap that changes the answer; optional questions stay outside."""

    question: ShortText
    reason: ShortText


class EvidenceConflict(Clarification):
    """Claim quotes preserve both sides; host/human determines actual conflict."""


class ContextualReview(Contract):
    contract_version: Literal[1] = 1
    format: Literal["zac-contextual-review-v1"]
    task_id: UUID
    data_classification: DataClassification
    overview: tuple[Claim, ...] = Field(default=(), max_length=4)
    background: tuple[Claim, ...] = Field(default=(), max_length=4)
    continuity: tuple[ProvisionalConnection, ...] = Field(default=(), max_length=3)
    items: tuple[ReviewItem, ...] = Field(default=(), max_length=16)
    conflicts: tuple[EvidenceConflict, ...] = Field(default=(), max_length=3)
    clarifications: tuple[Clarification, ...] = Field(default=(), max_length=3)


def validate_contextual_review(
    review: ContextualReview, context: ReviewContext
) -> ContextualReview:
    """Check exact evidence/roles; no semantic grade, approval or source refresh."""
    try:
        review = ContextualReview.model_validate(review)
        context = ReviewContext(context.task, context.meeting_source_id, context.related_source_ids)
        if review.task_id != context.task.task_id or not classification_covers(
            review.data_classification, context.task.event.data_classification
        ):
            raise ValueError("task or label mismatch")
        if not review.overview and not (review.conflicts or review.clarifications):
            raise ValueError("overview required for a full draft")
        texts = {item.reference.source_id: item.untrusted_text for item in context.task.context}
        allowed = context.related_source_ids | {context.meeting_source_id}
        for claim, background in (
            *((c, True) for c in review.background),
            *(
                (c, False)
                for c in (
                    *review.overview,
                    *review.continuity,
                    *review.items,
                    *review.conflicts,
                    *review.clarifications,
                )
            ),
        ):
            display_fields = [claim.text]
            if isinstance(claim, ReviewItem) and claim.owner:
                display_fields.append(claim.owner)
            if isinstance(claim, Clarification):
                display_fields.extend((claim.question, claim.reason))
            if any(
                unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"}
                for value in display_fields
                for c in value
            ):
                raise ValueError("display controls rejected")
            ids = {quote.source_id for quote in claim.quotes}
            if not ids <= allowed:
                raise ValueError("unassigned evidence role")
            for quote in claim.quotes:
                text = texts.get(quote.source_id)
                if (
                    text is None
                    or quote.end > len(text)
                    or text[quote.start : quote.end] != quote.text
                ):
                    raise ValueError("quote mismatch")
                if len(quote.text.strip()) < 8 or sum(c.isalnum() for c in quote.text) < 3:
                    raise ValueError("quote too small")

                def word(c: str) -> bool:
                    return c.isalnum() or c in "_’'"

                if (
                    quote.start > 0 and word(text[quote.start - 1]) and word(text[quote.start])
                ) or (
                    quote.end < len(text) and word(text[quote.end - 1]) and word(text[quote.end])
                ):
                    raise ValueError("quote splits a word")
            if len(claim.text.split()) > 80:
                raise ValueError("claim too large")
            if background:
                if not ids <= context.related_source_ids:
                    raise ValueError("background requires only related evidence")
            elif (claim in review.overview or isinstance(claim, ReviewItem)) and ids != {
                context.meeting_source_id
            }:
                raise ValueError("current overview/items require meeting-only evidence")
            elif context.meeting_source_id not in ids:
                raise ValueError("current claims require selected meeting")
        for connection in review.continuity:
            if not {q.source_id for q in connection.quotes} & context.related_source_ids:
                raise ValueError("connection requires related evidence")
        for item in review.items:
            if item.inferred and item.kind in (ItemKind.DECISION, ItemKind.COMMITMENT):
                raise ValueError("inference cannot establish agreement")
            if item.kind == ItemKind.FOLLOW_UP and not item.inferred:
                raise ValueError("suggested follow-up must be provisional")
        for conflict in review.conflicts:
            if not any(
                a.source_id != b.source_id or a.end <= b.start or b.end <= a.start
                for a, b in combinations(conflict.quotes, 2)
            ):
                raise ValueError("conflict requires distinct supporting passages")
        preview = _full_preview(review)
        if len(preview.split()) > 650 or len(preview) > 6000:
            raise ValueError("review exceeds defensive display ceiling")
        return review
    except Exception:  # noqa: BLE001, S110 - private validation must not be logged
        pass
    raise ValueError("contextual review unavailable or invalid")


def _text(claim: Claim) -> str:
    return ("Possible: " if claim.inferred else "") + claim.text


def _full_preview(review: ContextualReview) -> str:
    lines = ["Contextual overview", *(_text(c) for c in review.overview)]
    lines.extend("Candidate context: " + _text(c) for c in review.background)
    lines.extend(_text(c) for c in review.continuity)
    if not review.continuity:
        lines.append("Project continuity is not established by this draft.")
    for heading, kinds in (
        ("Decisions and commitments", (ItemKind.DECISION, ItemKind.COMMITMENT)),
        ("Risks and follow-ups", (ItemKind.RISK, ItemKind.FOLLOW_UP)),
    ):
        lines.extend(("", heading))
        selected = [item for item in review.items if item.kind in kinds]
        if not selected:
            lines.append("None recorded in this draft; completeness still needs review.")
        for item in selected:
            details = []
            if item.owner:
                details.append("proposed owner: " + item.owner)
            elif item.kind in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP):
                details.append("owner unconfirmed")
            if item.due_date:
                details.append("proposed date: " + item.due_date.isoformat())
            lines.append(
                "- "
                + item.kind.value.title().replace("_", " ")
                + ": "
                + _text(item)
                + (" (" + "; ".join(details) + ")" if details else "")
            )
    # Count retained material gaps in the defensive ceiling, though full prose is held.
    for gap in (*review.conflicts, *review.clarifications):
        lines.append("Needs confirmation: " + gap.text + " " + gap.question + " " + gap.reason)
    return "\n".join(lines)


def render_contextual_preview(review: ContextualReview, context: ReviewContext) -> str:
    """Material questions/conflicts hold the full draft; do not silently resolve."""
    review = validate_contextual_review(review, context)
    gaps = (*review.conflicts, *review.clarifications)
    if gaps:
        gap = gaps[0]
        label = "Conflicting accounts" if isinstance(gap, EvidenceConflict) else "Missing context"
        lines = [
            "Context clarification needed",
            label + ": " + _text(gap),
            gap.question,
            "Why it matters: " + gap.reason,
        ]
        if len(gaps) > 1:
            lines.append(f"{len(gaps) - 1} additional questions retained for follow-up.")
        return "\n".join(lines)
    return _full_preview(review)
