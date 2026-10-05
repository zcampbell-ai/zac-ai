"""Invented work plans only; no sources, credentials, dispatch or state writes."""

from html import escape

import pytest

from tests.test_selected_briefing import selected
from zacai.gateway import ActionType
from zacai.intelligence.contextual_review import Clarification
from zacai.intelligence.selected_briefing import render_selected_briefing
from zacai.intelligence.work_proposals import (
    ProposedStep,
    WorkChoice,
    WorkPreference,
    WorkProposal,
    packet_fingerprint,
    proposal_fingerprint,
    render_work_proposals,
)


def plan(packet):
    return WorkProposal(
        packet_digest=packet_fingerprint(packet),
        item_index=0,
        outcome="Give Alex a reproducible validation checklist.",
        steps=(
            ProposedStep(
                instruction="Draft a checklist using the selected reporting evidence.",
                action_type=ActionType.DRAFT_CONTENT,
                destination="Private local draft",
                method="Eligible local model, subject to host routing",
            ),
            ProposedStep(
                instruction="Ask you to review before sending the checklist to Alex.",
                action_type=ActionType.SEND_EMAIL,
                destination="Alex; address must be confirmed",
                method="Approved mail adapter, when connected",
            ),
        ),
        completion_check="Verify the approved checklist was delivered and retain its receipt.",
    )


def test_work_view_leads_with_plan_preserves_packet_and_all_review_evidence():
    packet = selected()
    proposal = plan(packet)
    before = packet_fingerprint(packet)
    html = render_selected_briefing(
        packet, as_of=packet.created_at, work_view=True, work_proposals=(proposal,)
    )
    assert html.index("How Zac proposes") < html.index("Selected review and context")
    for choice in WorkChoice:
        assert escape(choice.value) in html
    assert proposal.outcome in html and proposal.completion_check in html
    for step in proposal.steps:
        assert step.instruction in html and step.destination in html and step.method in html
    for quote in packet.review.items[0].quotes:
        assert escape(quote.text) in html
    assert "Did everything get done?</strong> Not verified" in html
    assert "completion unverified" in html and "Existing owners remain unchanged" in html
    assert "<button" not in html and "<form" not in html and "<script" not in html
    assert packet_fingerprint(packet) == before


@pytest.mark.parametrize("choice", list(WorkChoice))
def test_choices_remain_preferences_never_execution_or_completion(choice):
    packet = selected()
    proposal = plan(packet)
    preference = WorkPreference(
        proposal_digest=proposal_fingerprint(proposal),
        choice=choice,
        changes="Keep the draft shorter." if choice == WorkChoice.WITH_CHANGES else None,
    )
    html = render_work_proposals(packet, (proposal,), (preference,))
    assert "Your preference:" in html and escape(choice.value) in html
    assert "execution is not connected yet" in html and "Not verified" in html
    if choice == WorkChoice.WITH_CHANGES:
        assert "revised plan and fresh preference needed" in html
    elif choice == WorkChoice.REVIEW_FIRST:
        assert "shipping remains unapproved" in html
    elif choice == WorkChoice.MYSELF:
        assert "You plan to handle this; completion remains unverified" in html
        assert "Owner from review: Alex" in html
    else:
        assert "no execution authorized" in html


@pytest.mark.parametrize(
    "change",
    [
        "packet",
        "plan",
        "duplicate",
        "index",
        "change_missing",
        "extra_change",
        "unknown",
        "duplicate_preference",
    ],
)
def test_stale_wrong_or_ambiguous_bindings_fail_closed(change):
    packet = selected()
    proposal = plan(packet)
    pref = WorkPreference(
        proposal_digest=proposal_fingerprint(proposal), choice=WorkChoice.REVIEW_FIRST
    )
    proposals = (proposal,)
    preferences = (pref,)
    if change == "packet":
        packet = selected()
    elif change == "plan":
        proposals = (proposal.model_copy(update={"outcome": "PRIVATE changed plan"}),)
    elif change == "duplicate":
        proposals = (proposal, proposal)
    elif change == "index":
        proposals = (proposal.model_copy(update={"item_index": True}),)
    elif change == "change_missing":
        preferences = (pref.model_copy(update={"choice": WorkChoice.WITH_CHANGES}),)
    elif change == "extra_change":
        preferences = (pref.model_copy(update={"changes": "PRIVATE change"}),)
    elif change == "unknown":
        preferences = (pref.model_copy(update={"proposal_digest": "0" * 64}),)
    else:
        preferences = (pref, pref)
    with pytest.raises(ValueError, match="^work proposals unavailable or invalid$") as exc:
        render_work_proposals(packet, proposals, preferences)
    assert exc.value.__context__ is None and "PRIVATE" not in str(exc.value)


def test_missing_plan_is_visible_without_fabricated_approach_or_approval():
    packet = selected()
    html = render_work_proposals(packet, ())
    assert packet.review.items[0].text in html and "Approach not prepared" in html
    assert "Your choices:" not in html


def test_material_question_holds_work_and_its_text():
    def gaps(review, current, prior):
        return review.model_copy(
            update={
                "clarifications": (
                    Clarification(
                        text="Scope is uncertain.",
                        quotes=(current,),
                        question="Which project?",
                        reason="The scope changes this work.",
                    ),
                )
            }
        )

    packet = selected(gaps)
    proposal = plan(packet)
    html = render_selected_briefing(
        packet, as_of=packet.created_at, work_view=True, work_proposals=(proposal,)
    )
    assert "Which project?" in html and proposal.outcome not in html
    assert "Did everything get done?" not in html


def test_work_text_markup_is_inert_and_hidden_inputs_rejected():
    packet = selected()
    proposal = plan(packet).model_copy(update={"outcome": '<img src="https://example.invalid">'})
    html = render_work_proposals(packet, (proposal,))
    assert "<img" not in html and "&lt;img" in html
    with pytest.raises(ValueError, match="^selected briefing unavailable or invalid$"):
        render_selected_briefing(packet, as_of=packet.created_at, work_proposals=(proposal,))


def test_large_work_list_stays_expandable_without_losing_items_or_plans():
    from zacai.intelligence.meeting_review import ItemKind, ReviewItem

    def more(review, current, prior):
        return review.model_copy(
            update={
                "items": tuple(
                    ReviewItem(
                        text=f"Alex will check example {i}.",
                        quotes=(current,),
                        kind=ItemKind.COMMITMENT,
                        owner="Alex",
                    )
                    for i in range(16)
                )
            }
        )

    packet = selected(more)
    baseline = plan(packet)
    proposals = tuple(
        baseline.model_copy(
            update={"item_index": i, "outcome": f"Prepare validation checklist {i}."}
        )
        for i in range(16)
    )
    html = render_work_proposals(packet, proposals)
    assert "14 more selected work items (review order, not ranked)" in html
    assert html.count("<article>") == 16
    for i in range(16):
        assert f"Prepare validation checklist {i}." in html
        assert f"Alex will check example {i}." in html


@pytest.mark.parametrize("prepared", [False, True])
def test_inferred_work_keeps_its_headline_marker_with_or_without_plan(prepared):
    def suggestion(review, current, prior):
        return review.model_copy(
            update={
                "items": (
                    review.items[0].model_copy(
                        update={"inferred": True, "kind": "FOLLOW_UP", "owner": None}
                    ),
                )
            }
        )

    packet = selected(suggestion)
    proposal = plan(packet)
    html = render_work_proposals(packet, (proposal,) if prepared else ())
    assert (
        "<strong>Possible: " + escape(proposal.outcome if prepared else packet.review.items[0].text)
        in html
    )
    if not prepared:
        assert "Your choices:" not in html
    else:
        assert "Owner unconfirmed" in html
