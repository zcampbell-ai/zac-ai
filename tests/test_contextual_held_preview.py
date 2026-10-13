"""Synthetic offline tests for the held summary preview helper only."""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_contextual_review import fixture
from zacai.intelligence.contextual_evaluation import encode_contextual_packet
from zacai.intelligence.contextual_review import (
    Clarification,
    EvidenceConflict,
    render_contextual_held_summary_preview,
    validate_contextual_review,
)
from zacai.intelligence.meeting_review import ItemKind, ReviewItem


def test_supported_overview_and_first_question_both_visible():
    context, review, current, _ = fixture()
    gap = Clarification(
        text="Project attribution is uncertain.",
        quotes=(current,),
        question="Which project does this discussion belong to?",
        reason="The project choice changes the prior context used.",
    )
    review = review.model_copy(update={"clarifications": (gap,)})
    preview = render_contextual_held_summary_preview(review, context)
    assert preview.startswith("Contextual draft summary preview")
    assert "Label: held for review (draft)" in preview
    assert "Draft overview:" in preview
    assert review.overview[0].text in preview
    assert review.items[0].text in preview
    assert "proposed owner: Alex" in preview
    caveat = "Draft items may change once the material gap is resolved."
    assert caveat in preview
    assert preview.index(caveat) < preview.index("Draft items:")
    assert preview.index(caveat) < preview.index("First material gap: missing context, unresolved.")
    assert "First material gap: missing context, unresolved." in preview
    assert "Which project does this discussion belong to?" in preview
    assert "Why it matters: The project choice changes the prior context used." in preview
    assert "\u2014" not in preview


def test_draft_overview_and_items_headings_are_neutral():
    context, review, current, _ = fixture()
    gap = Clarification(
        text="Project attribution is uncertain.",
        quotes=(current,),
        question="Which project does this discussion belong to?",
        reason="The project choice changes the prior context used.",
    )
    review = review.model_copy(update={"clarifications": (gap,)})
    preview = render_contextual_held_summary_preview(review, context)
    assert "Draft overview:" in preview
    assert "Draft items:" in preview
    assert "Supported overview:" not in preview
    assert "Grounded items:" not in preview


def test_held_display_preserves_complete_canonical_packet_bytes_and_digest():
    from hashlib import sha256

    context, review, current, _ = fixture()
    gap = Clarification(
        text="Project attribution is uncertain.", quotes=(current,),
        question="Which project does this discussion belong to?",
        reason="The project choice changes the prior context used.",
    )
    review = review.model_copy(update={"clarifications": (gap,)})
    builder = uuid4()
    created = context.task.event.observed_at + timedelta(seconds=1)
    before = encode_contextual_packet(review, context, builder_id=builder, created_at=created)
    visible = render_contextual_held_summary_preview(review, context)
    after = encode_contextual_packet(review, context, builder_id=builder, created_at=created)
    assert "held for review" in visible and gap.question in visible
    assert before == after and sha256(before).digest() == sha256(after).digest()


def test_two_gaps_show_only_first_question_and_retained_count():
    context, review, current, prior = fixture()
    conflict = EvidenceConflict(
        text="The current and prior accounts differ.",
        quotes=(current, prior),
        question="Did the earlier decision change?",
        reason="The answer changes which commitment is current.",
    )
    clarification = Clarification(
        text="Ownership is unrecorded.",
        quotes=(current,),
        question="Who owns the reporting fix?",
        reason="Ownership affects the next step only.",
    )
    review = review.model_copy(
        update={"conflicts": (conflict,), "clarifications": (clarification,)}
    )
    preview = render_contextual_held_summary_preview(review, context)
    assert "First material gap: conflicting accounts, unresolved." in preview
    assert "Did the earlier decision change?" in preview
    assert "Who owns the reporting fix?" not in preview
    assert "1 additional material gap(s) retained for follow-up." in preview


def test_empty_overview_with_gap_is_valid_and_not_released():
    context, review, current, _ = fixture()
    gap = Clarification(
        text="Project attribution is uncertain.",
        quotes=(current,),
        question="Which project does this discussion belong to?",
        reason="The project choice changes the prior context used.",
    )
    review = review.model_copy(update={"overview": (), "clarifications": (gap,)})
    validated = validate_contextual_review(review, context)
    assert validated.overview == ()
    preview = render_contextual_held_summary_preview(review, context)
    assert "Draft overview: none recorded in this draft." in preview
    assert "Which project does this discussion belong to?" in preview
    assert "released" not in preview.casefold() or "not released" in preview.casefold()


def test_no_gaps_still_draft_and_never_released():
    context, review, _, _ = fixture()
    preview = render_contextual_held_summary_preview(review, context)
    assert "Label: held for review (draft)" in preview
    assert "No material gap is recorded, but this remains a draft held for review." in preview
    assert "It is not released or confirmed by this preview." in preview
    assert "First material gap" not in preview
    assert "Draft items may change once the material gap is resolved." not in preview


def test_invalid_quote_rejected_by_existing_validator_before_rendering():
    context, review, current, _ = fixture()
    bad = current.model_copy(update={"text": "zzzzzzzz"})
    review = review.model_copy(
        update={
            "overview": (
                review.overview[0].model_copy(update={"quotes": (bad,)}),
            )
        }
    )
    with pytest.raises(ValueError):
        render_contextual_held_summary_preview(review, context)


def test_conflicts_remain_unresolved_and_labels_preserved():
    context, review, current, prior = fixture()
    # The held helper displays draft items, not background or continuity.
    inferred_item = ReviewItem(
        kind=ItemKind.FOLLOW_UP,
        text="Check the reporting validation outcome.",
        quotes=(current,),
        inferred=True,
    )
    review = review.model_copy(update={"items": (*review.items, inferred_item)})
    conflict = EvidenceConflict(
        text="The current and prior accounts differ.",
        quotes=(current, prior),
        question="Did the earlier decision change?",
        reason="The answer changes which commitment is current.",
    )
    review = review.model_copy(update={"conflicts": (conflict,)})
    preview = render_contextual_held_summary_preview(review, context)
    assert "unresolved" in preview
    assert "Possible: Check the reporting validation outcome." in preview
    assert "owner unconfirmed" in preview
    assert "proposed owner: Alex" in preview
    assert "confirmed" not in preview.replace("unconfirmed", "").replace("not released or confirmed", "")


def test_material_gap_caveat_appears_before_items_on_conflict_path():
    context, review, current, prior = fixture()
    conflict = EvidenceConflict(
        text="The current and prior accounts differ.",
        quotes=(current, prior),
        question="Did the earlier decision change?",
        reason="The answer changes which commitment is current.",
    )
    review = review.model_copy(update={"conflicts": (conflict,)})
    preview = render_contextual_held_summary_preview(review, context)
    caveat = "Draft items may change once the material gap is resolved."
    assert caveat in preview
    assert preview.count(caveat) == 1
    assert preview.index(caveat) < preview.index("Draft items:")
    assert preview.index(caveat) < preview.index("First material gap")


def test_material_gap_caveat_appears_before_items_on_clarification_path():
    context, review, current, _ = fixture()
    gap = Clarification(
        text="Project attribution is uncertain.",
        quotes=(current,),
        question="Which project does this discussion belong to?",
        reason="The project choice changes the prior context used.",
    )
    review = review.model_copy(update={"clarifications": (gap,)})
    preview = render_contextual_held_summary_preview(review, context)
    caveat = "Draft items may change once the material gap is resolved."
    assert caveat in preview
    assert preview.count(caveat) == 1
    assert preview.index(caveat) < preview.index("Draft items:")
    assert preview.index(caveat) < preview.index("First material gap: missing context, unresolved.")


def test_material_gap_caveat_absent_with_no_gap():
    context, review, _, _ = fixture()
    preview = render_contextual_held_summary_preview(review, context)
    assert "Draft items may change once the material gap is resolved." not in preview
    assert "First material gap" not in preview