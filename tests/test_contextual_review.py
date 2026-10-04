"""Synthetic context only; no provider, private sources or live writes."""

from uuid import uuid4

import pytest

from tests.test_review_evaluation import packet
from zacai.intelligence.contextual_review import (
    Clarification,
    ContextualReview,
    EvidenceConflict,
    ProvisionalConnection,
    render_contextual_preview,
    validate_contextual_review,
)
from zacai.intelligence.meeting_review import Claim, ItemKind, ReviewItem


def fixture():
    context, compact, _ = packet()
    current = compact.summary[0].quotes[0]
    prior = compact.continuity[0].quotes[-1]
    review = ContextualReview(
        format="zac-contextual-review-v1",
        task_id=context.task.task_id,
        data_classification=compact.data_classification,
        overview=(Claim(text="Reporting validation remains underway.", quotes=(current,)),),
        background=(Claim(text="Earlier work reproduced the failure.", quotes=(prior,)),),
        continuity=(
            ProvisionalConnection(
                text="This may continue the reporting investigation.", quotes=(current, prior)
            ),
        ),
        items=(
            ReviewItem(
                text="Alex will test the reporting fix.",
                quotes=(current,),
                kind=ItemKind.COMMITMENT,
                owner="Alex",
            ),
        ),
    )
    return context, review, current, prior


def test_three_sections_and_provisional_link_preserve_context():
    context, review, _, _ = fixture()
    preview = render_contextual_preview(review, context)
    assert preview.startswith("Contextual overview")
    assert "Candidate context:" in preview
    assert "Possible: This may continue" in preview
    assert "Decisions and commitments" in preview
    assert "Risks and follow-ups" in preview
    assert "proposed owner: Alex" in preview
    assert not hasattr(review, "approved")


@pytest.mark.parametrize(
    "change", ["task", "label", "overview", "background", "continuity", "quote"]
)
def test_wrong_roles_task_labels_or_quotes_fail_with_safe_errors(change):
    context, review, current, prior = fixture()
    if change == "task":
        review = review.model_copy(update={"task_id": uuid4()})
    elif change == "label":
        context = type(context)(
            context.task.model_copy(
                update={
                    "event": context.task.event.model_copy(
                        update={"data_classification": "HIGHLY_RESTRICTED"}
                    )
                }
            ),
            context.meeting_source_id,
            context.related_source_ids,
        )
    elif change == "overview":
        review = review.model_copy(
            update={"overview": (Claim(text="Private sentinel", quotes=(prior,)),)}
        )
    elif change == "background":
        review = review.model_copy(
            update={"background": (Claim(text="Bad role", quotes=(current,)),)}
        )
    elif change == "continuity":
        review = review.model_copy(
            update={
                "continuity": (ProvisionalConnection(text="Bad connection", quotes=(current,)),)
            }
        )
    else:
        review = review.model_copy(
            update={
                "overview": (
                    Claim(
                        text="Private sentinel",
                        quotes=(current.model_copy(update={"text": "Private sentinel"}),),
                    ),
                )
            }
        )
    with pytest.raises(ValueError, match="^contextual review unavailable or invalid$") as error:
        validate_contextual_review(review, context)
    assert error.value.__context__ is None


def test_material_question_holds_full_draft():
    context, review, current, _ = fixture()
    review = review.model_copy(
        update={
            "clarifications": (
                Clarification(
                    text="Project attribution is uncertain.",
                    quotes=(current,),
                    question="Which project does this discussion belong to?",
                    reason="The project choice changes the prior context used.",
                ),
            )
        }
    )
    preview = render_contextual_preview(review, context)
    assert preview.startswith("Context clarification needed")
    assert "Which project" in preview
    assert "Decisions and commitments" not in preview


def test_conflict_requires_two_distinct_passages_and_asks_before_draft():
    context, review, current, prior = fixture()
    gap = EvidenceConflict(
        text="The current and prior accounts differ.",
        quotes=(current, prior),
        question="Did the earlier decision change?",
        reason="The answer changes which commitment is current.",
    )
    revised = review.model_copy(update={"conflicts": (gap,)})
    assert "Did the earlier decision change?" in render_contextual_preview(revised, context)
    bad = gap.model_copy(update={"quotes": (current, current)})
    with pytest.raises(ValueError):
        validate_contextual_review(review.model_copy(update={"conflicts": (bad,)}), context)


@pytest.mark.parametrize(
    "kind,inferred",
    [(ItemKind.DECISION, True), (ItemKind.COMMITMENT, True), (ItemKind.FOLLOW_UP, False)],
)
def test_inferences_cannot_be_presented_as_agreements(kind, inferred):
    context, review, current, _ = fixture()
    item = ReviewItem(text="Possible next action.", quotes=(current,), kind=kind, inferred=inferred)
    with pytest.raises(ValueError):
        validate_contextual_review(review.model_copy(update={"items": (item,)}), context)


def test_oversized_claim_rejects_without_truncation():
    context, review, current, _ = fixture()
    claim = Claim(text=" ".join(["word"] * 81), quotes=(current,))
    with pytest.raises(ValueError):
        render_contextual_preview(review.model_copy(update={"overview": (claim,)}), context)


def test_provisional_connection_cannot_be_declared_confirmed():
    _, _, current, prior = fixture()
    with pytest.raises(ValueError):
        ProvisionalConnection(text="Confirmed connection", quotes=(current, prior), inferred=False)


@pytest.mark.parametrize("control", ["\n", "\r", "\u2028", "\u2029", "\u202e", "\u200b"])
@pytest.mark.parametrize("field", ["text", "owner", "question", "reason"])
def test_display_control_injection_is_rejected(control, field):
    context, review, current, _ = fixture()
    forged = "First" + control + "Decisions and commitments"
    if field == "text":
        review = review.model_copy(update={"overview": (Claim(text=forged, quotes=(current,)),)})
    elif field == "owner":
        review = review.model_copy(
            update={"items": (review.items[0].model_copy(update={"owner": forged}),)}
        )
    else:
        gap = Clarification(
            text="Uncertain project.",
            quotes=(current,),
            question="Which project?",
            reason="Attribution changes the answer.",
        )
        review = review.model_copy(
            update={"clarifications": (gap.model_copy(update={field: forged}),)}
        )
    with pytest.raises(ValueError):
        render_contextual_preview(review, context)


def test_empty_overview_allowed_only_for_material_question():
    context, review, current, _ = fixture()
    with pytest.raises(ValueError):
        validate_contextual_review(review.model_copy(update={"overview": ()}), context)
    gap = Clarification(
        text="Unknown project.",
        quotes=(current,),
        question="Which project?",
        reason="The answer determines relevant history.",
    )
    held = review.model_copy(update={"overview": (), "clarifications": (gap,)})
    assert "Which project?" in render_contextual_preview(held, context)


def test_mixed_evidence_cannot_promote_prior_commitment_to_current():
    context, review, current, prior = fixture()
    item = review.items[0].model_copy(update={"quotes": (current, prior)})
    with pytest.raises(ValueError):
        validate_contextual_review(review.model_copy(update={"items": (item,)}), context)


def test_question_context_and_queue_preserved_without_showing_full_draft():
    context, review, current, prior = fixture()
    gap = EvidenceConflict(
        text="Old says test first; new suggests a release.",
        quotes=(current, prior),
        question="Did the release decision change?",
        reason="The accounts imply different release authority.",
    )
    revised = review.model_copy(update={"conflicts": (gap, gap)})
    preview = render_contextual_preview(revised, context)
    assert "Conflicting accounts: Old says test first" in preview
    assert "1 additional questions retained" in preview
    assert review.overview[0].text not in preview
    assert review.items[0].text not in preview


def test_missing_or_wrong_format_and_versions_reject():
    _, review, _, _ = fixture()
    for changes in ({"format": "wrong"}, {"contract_version": True}, {"contract_version": 2}):
        with pytest.raises(ValueError):
            ContextualReview.model_validate({**review.model_dump(), **changes})
    data = review.model_dump()
    del data["format"]
    with pytest.raises(ValueError):
        ContextualReview.model_validate(data)


@pytest.mark.parametrize("size,count", [(70, 16), (500, 16)])
def test_total_word_and_character_ceilings_reject(size, count):
    context, review, current, _ = fixture()
    text = " ".join(["word"] * size) if size == 70 else "x" * size
    items = tuple(
        ReviewItem(text=text, quotes=(current,), kind=ItemKind.RISK) for _ in range(count)
    )
    with pytest.raises(ValueError):
        render_contextual_preview(review.model_copy(update={"items": items}), context)


def test_useful_longer_draft_is_not_forced_to_compact_limit():
    context, review, current, _ = fixture()
    items = tuple(
        ReviewItem(text=" ".join(["detail"] * 65), quotes=(current,), kind=ItemKind.RISK)
        for _ in range(7)
    )
    preview = render_contextual_preview(review.model_copy(update={"items": items}), context)
    assert len(preview.split()) > 400


def test_quote_cannot_use_punctuation_only_or_split_a_word():
    context, review, current, _ = fixture()
    text = context.task.context[0].untrusted_text
    for start, end in ((text.index("."), text.index(".") + 1), (1, current.end)):
        quote = current.model_copy(update={"start": start, "end": end, "text": text[start:end]})
        bad = review.model_copy(
            update={"overview": (Claim(text="Partial evidence.", quotes=(quote,)),)}
        )
        with pytest.raises(ValueError):
            validate_contextual_review(bad, context)


def test_roleless_source_cannot_be_used_even_with_meeting_citation():
    context, review, current, prior = fixture()
    extra = context.task.context[-1].model_copy(
        update={
            "reference": context.task.context[-1].reference.model_copy(
                update={"source_id": uuid4()}
            )
        }
    )
    task = context.task.model_copy(
        update={
            "context": (*context.task.context, extra),
            "event": context.task.event.model_copy(
                update={"provenance": (*context.task.event.provenance, extra.reference)}
            ),
        }
    )
    context = type(context)(task, context.meeting_source_id, context.related_source_ids)
    unassigned = prior.model_copy(update={"source_id": extra.reference.source_id})
    review = review.model_copy(
        update={
            "continuity": (
                ProvisionalConnection(
                    text="Unassigned contextual connection.", quotes=(current, prior, unassigned)
                ),
            )
        }
    )
    with pytest.raises(ValueError):
        validate_contextual_review(review, context)


def test_conflict_distinct_adjacent_passages_and_single_span():
    context, review, current, _ = fixture()
    text = context.task.context[0].untrusted_text
    split = text.index("\n") + 1
    a = current.model_copy(update={"start": 0, "end": split, "text": text[:split]})
    b = current.model_copy(update={"start": split, "end": len(text), "text": text[split:]})
    gap = EvidenceConflict(
        text="Two accounts require checking.",
        quotes=(a, b),
        question="Did the decision change?",
        reason="This affects the next action.",
    )
    assert "Did the decision" in render_contextual_preview(
        review.model_copy(update={"conflicts": (gap,)}), context
    )
    with pytest.raises(ValueError):
        validate_contextual_review(
            review.model_copy(update={"conflicts": (gap.model_copy(update={"quotes": (a,)}),)}),
            context,
        )
