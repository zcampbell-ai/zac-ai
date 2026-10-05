"""Invented packet display only; no live sources/models/delivery."""

from datetime import timedelta
from html import escape
from uuid import uuid4

import pytest

from tests.test_contextual_review import fixture
from zacai.intelligence.contextual_evaluation import (
    decode_contextual_packet,
    encode_contextual_packet,
)
from zacai.intelligence.contextual_review import Clarification
from zacai.intelligence.meeting_review import ItemKind, ReviewItem
from zacai.intelligence.selected_briefing import render_selected_briefing


def selected(review=None):
    context, baseline, current, prior = fixture()
    if review is not None:
        baseline = review(baseline, current, prior)
    created = context.task.event.observed_at + timedelta(seconds=1)
    return decode_contextual_packet(
        encode_contextual_packet(baseline, context, builder_id=uuid4(), created_at=created)
    )


def test_selected_briefing_preserves_all_items_with_context_and_evidence():
    def items(review, current, prior):
        return review.model_copy(
            update={
                "items": tuple(
                    ReviewItem(
                        text=f"Alex will check sample {i}.",
                        quotes=(current,),
                        kind=ItemKind.COMMITMENT,
                        owner="Alex",
                        due_date=current_date,
                    )
                    for i in range(16)
                )
            }
        )

    from datetime import date

    current_date = date(2020, 1, 1)
    packet = selected(items)
    raw = encode_contextual_packet(
        packet.review, packet.context(), builder_id=packet.builder_id, created_at=packet.created_at
    )
    html = render_selected_briefing(packet, as_of=packet.created_at + timedelta(days=10))
    assert html.count('<span class="tag">Commitment:</span>') == 16
    assert "Date from review: 2020-01-01" in html
    assert "current completion or overdue status has not been verified" in html
    assert "Other meetings, messages and calendar activity have not been checked" in html
    for claim in (
        *packet.review.overview,
        *packet.review.background,
        *packet.review.continuity,
        *packet.review.items,
    ):
        assert escape(claim.text) in html
        for quote in claim.quotes:
            assert escape(quote.text) in html
    assert '<meta name="viewport"' in html and "<details><summary>Supporting evidence" in html
    assert raw == encode_contextual_packet(
        packet.review, packet.context(), builder_id=packet.builder_id, created_at=packet.created_at
    )
    assert 'href="http' not in html and "<script" not in html


def test_unowned_suggestion_stays_provisional_and_unassigned():
    def items(review, current, prior):
        return review.model_copy(
            update={
                "items": (
                    ReviewItem(
                        text="Ask for a broader sample.",
                        quotes=(current,),
                        kind=ItemKind.FOLLOW_UP,
                        inferred=True,
                    ),
                )
            }
        )

    packet = selected(items)
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "Suggested follow-up:" in html and "Owner unconfirmed" in html
    assert (
        "Date from review:" not in html
        and "Suggested date:" not in html
        and "Follow-up: Possible:" not in html
    )


def test_material_question_holds_other_claims_and_their_evidence():
    def gaps(review, current, prior):
        return review.model_copy(
            update={
                "clarifications": (
                    Clarification(
                        text="The scope is uncertain.",
                        quotes=(current,),
                        question="Which project does this belong to?",
                        reason="This determines which earlier work to use.",
                    ),
                )
            }
        )

    packet = selected(gaps)
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "One question first" in html
    assert "Which project does this belong to?" in html
    assert packet.review.items[0].text not in html
    assert packet.review.background[0].text not in html
    assert escape(packet.review.background[0].quotes[0].text) not in html
    assert "<h2>Decisions and commitments</h2>" not in html


def test_markup_in_model_claims_is_inert_text():
    def markup(review, current, prior):
        return review.model_copy(
            update={
                "overview": (
                    review.overview[0].model_copy(
                        update={
                            "text": '<img src="https://example.invalid/private" onerror="alert(1)">'
                        }
                    ),
                )
            }
        )

    packet = selected(markup)
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "<img" not in html and "&lt;img" in html
    assert "Content-Security-Policy" in html


@pytest.mark.parametrize("kind", ["naive", "before", "tampered"])
def test_invalid_times_or_packets_reject_without_private_diagnostics(kind):
    packet = selected()
    now = packet.created_at
    if kind == "naive":
        now = now.replace(tzinfo=None)
    elif kind == "before":
        now -= timedelta(seconds=1)
    else:
        packet = packet.model_copy(update={"rendered_preview": "PRIVATE sentinel"})
    with pytest.raises(ValueError, match="^selected briefing unavailable or invalid$") as error:
        render_selected_briefing(packet, as_of=now)
    assert error.value.__context__ is None


@pytest.mark.parametrize("section", ["overview", "background", "clarifications"])
def test_inferences_remain_visible_in_each_display_role(section):
    def inference(review, current, prior):
        if section == "clarifications":
            return review.model_copy(
                update={
                    section: (
                        Clarification(
                            text="The scope may have changed.",
                            quotes=(current,),
                            inferred=True,
                            question="Did the scope change?",
                            reason="This determines the context.",
                        ),
                    )
                }
            )
        values = getattr(review, section)
        return review.model_copy(
            update={section: (values[0].model_copy(update={"inferred": True}),)}
        )

    packet = selected(inference)
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "Possible: " + escape(getattr(packet.review, section)[0].text) in html


def test_conflict_is_labelled_and_rest_of_briefing_explicitly_held():
    from zacai.intelligence.contextual_review import EvidenceConflict

    def conflict(review, current, prior):
        gap = EvidenceConflict(
            text="The accounts may conflict.",
            quotes=(current, prior),
            question="Did the decision change?",
            reason="This changes the next action.",
        )
        return review.model_copy(
            update={
                "conflicts": (gap,),
                "clarifications": (
                    Clarification(
                        text="The scope is uncertain.",
                        quotes=(current,),
                        question="Which scope applies?",
                        reason="This determines the scope.",
                    ),
                ),
            }
        )

    packet = selected(conflict)
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "Conflicting accounts:" in html
    assert "The rest of this briefing is held until this is answered." in html
    assert "1 more question retained." in html
    assert packet.review.items[0].text not in html


def test_suggested_owner_and_date_do_not_become_assignments():
    from datetime import date

    def suggestions(review, current, prior):
        return review.model_copy(
            update={
                "items": (
                    ReviewItem(
                        text="Consider another sample check.",
                        quotes=(current,),
                        kind=ItemKind.FOLLOW_UP,
                        inferred=True,
                        owner="Alex",
                        due_date=date(2030, 2, 15),
                    ),
                )
            }
        )

    packet = selected(suggestions)
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "Suggested owner: Alex" in html and "Suggested date: 2030-02-15" in html
    assert "Date from review:" not in html and "(reported)" not in html
    assert "Suggested follow-up:</span> Possible:" not in html


def test_nested_tampered_quote_is_revalidated_before_display():
    packet = selected()
    claim = packet.review.overview[0]
    quote = claim.quotes[0].model_copy(update={"text": "PRIVATE forged quote"})
    claim = claim.model_copy(update={"quotes": (quote,)})
    packet = packet.model_copy(
        update={"review": packet.review.model_copy(update={"overview": (claim,)})}
    )
    with pytest.raises(ValueError, match="^selected briefing unavailable or invalid$") as error:
        render_selected_briefing(packet, as_of=packet.created_at)
    assert error.value.__context__ is None and "PRIVATE" not in str(error.value)


def test_continuity_label_does_not_stack_provisional_markers():
    packet = selected()
    html = render_selected_briefing(packet, as_of=packet.created_at)
    assert "Possible connection:</span> Possible:" not in html
    assert "Possible connection:</span> " + escape(packet.review.continuity[0].text) in html
