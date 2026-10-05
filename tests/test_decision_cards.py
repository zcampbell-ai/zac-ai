"""Invented offline card deck; DOM shape is not physical mobile verification."""

import re
from html import escape
from html.parser import HTMLParser

import pytest

from tests.test_selected_briefing import selected
from tests.test_work_proposals import plan
from zacai.intelligence.contextual_review import Clarification
from zacai.intelligence.decision_cards import DecisionCardRenderMode, render_decision_cards
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.work_proposals import (
    WorkChoice,
    WorkPreference,
    packet_fingerprint,
    proposal_fingerprint,
)


class Shape(HTMLParser):
    def __init__(self):
        super().__init__()
        self.radios = []
        self.buttons = []
        self.articles = 0
        self.forms = 0
        self.scripts = 0
        self.previous_tag = None
        self.radio_card_pairs = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "radio":
            self.radios.append(values)
        if tag == "button":
            self.buttons.append(values)
        if tag == "article":
            self.articles += 1
            self.radio_card_pairs += self.previous_tag == "input"
        self.forms += tag == "form"
        self.scripts += tag == "script"
        self.previous_tag = tag


def deck():
    def items(review, current, prior):
        kinds = (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP, ItemKind.DECISION, ItemKind.RISK)
        return review.model_copy(
            update={
                "items": tuple(
                    review.items[0].model_copy(
                        update={
                            "text": f"Invented retained selected item {index}",
                            "kind": kinds[index % 4],
                            "inferred": index % 4 == 1,
                        }
                    )
                    for index in range(16)
                )
            }
        )

    return selected(items)


def test_one_selected_radio_card_full_retention_keyboard_navigation_and_expand():
    packet = deck()
    proposal = plan(packet)
    before = packet_fingerprint(packet)
    html = render_decision_cards(packet, (proposal,), selected_item=7)
    shape = Shape()
    shape.feed(html)
    assert len(shape.radios) == shape.articles == shape.radio_card_pairs == 16
    assert [r["id"] for r in shape.radios if "checked" in r] == ["card-7"]
    assert len({r["name"] for r in shape.radios}) == 1
    checked = re.search(r"\.card-radio:checked\s*\+\s*\.decision-card\s*\{([^}]*)\}", html)
    hidden = re.search(r"\.card-radio\s*\+\s*\.decision-card\s*\{([^}]*)\}", html)
    assert checked and re.search(r"\bdisplay\s*:\s*block\s*;", checked[1])
    assert hidden and re.search(r"\bdisplay\s*:\s*none\s*;", hidden[1])
    assert "arrow keys change the displayed item" in html
    assert "Previous item" in html and "Next item" in html
    assert "Proposed approach and completion check" in html
    assert "Original item and source evidence" in html
    assert "Selected review order, not a priority ranking" in html
    for item in packet.review.items:
        assert escape(item.text) in html
        for quote in item.quotes:
            assert escape(quote.text) in html and str(quote.source_id) in html
    for claim in (*packet.review.overview, *packet.review.background, *packet.review.continuity):
        assert escape(claim.text) in html
    for step in proposal.steps:
        assert escape(step.instruction) in html and escape(step.destination) in html
    assert escape(proposal.completion_check) in html
    assert packet_fingerprint(packet) == before
    assert shape.forms == shape.scripts == 0
    assert len(shape.buttons) == 4 and all("disabled" in b for b in shape.buttons)


@pytest.mark.parametrize("choice", list(WorkChoice))
def test_four_existing_choices_remain_preferences_not_authorization(choice):
    packet = selected()
    proposal = plan(packet)
    preference = WorkPreference(
        proposal_digest=proposal_fingerprint(proposal),
        choice=choice,
        changes="Use a shorter draft." if choice == WorkChoice.WITH_CHANGES else None,
    )
    html = render_decision_cards(packet, (proposal,), (preference,))
    assert escape(choice.value) in html
    assert "no execution authorized" in html
    assert "shipping leaves shipping unapproved" in html
    assert "Handling it yourself does not mean done" in html
    assert "Decline/defer are navigation or recommendation preferences" in html
    assert "not a gateway denial or permission" in html
    assert "Completion remains unverified" in html
    if preference.changes:
        assert (
            escape(preference.changes) in html
            and "revised plan and fresh preference needed" in html
        )


@pytest.mark.parametrize(
    "change",
    [
        "wrong_packet",
        "changed_plan",
        "duplicate_plan",
        "duplicate_preference",
        "missing_changes",
        "unknown_preference",
        "informational_plan",
        "negative_cursor",
        "past_end_cursor",
        "bool_cursor",
    ],
)
def test_stale_ambiguous_or_invalid_bindings_fail_closed(change):
    packet = deck()
    proposal = plan(packet)
    preference = WorkPreference(
        proposal_digest=proposal_fingerprint(proposal), choice=WorkChoice.AS_PROPOSED
    )
    proposals, preferences, index = (proposal,), (preference,), 0
    if change == "wrong_packet":
        packet = deck()
    elif change == "changed_plan":
        proposals = (proposal.model_copy(update={"outcome": "PRIVATE changed outcome"}),)
    elif change == "duplicate_plan":
        proposals = (proposal, proposal)
    elif change == "duplicate_preference":
        preferences = (preference, preference)
    elif change == "missing_changes":
        preferences = (preference.model_copy(update={"choice": WorkChoice.WITH_CHANGES}),)
    elif change == "unknown_preference":
        preferences = (preference.model_copy(update={"proposal_digest": "0" * 64}),)
    elif change == "informational_plan":
        proposals, preferences = (proposal.model_copy(update={"item_index": 2}),), ()
    elif change == "negative_cursor":
        index = -1
    elif change == "past_end_cursor":
        index = 16
    else:
        index = True
    with pytest.raises(ValueError, match="^decision cards unavailable or invalid$") as exc:
        render_decision_cards(packet, proposals, preferences, selected_item=index)
    assert exc.value.__context__ is None and "PRIVATE" not in str(exc.value)


def test_material_questions_hold_all_work_context_and_controls():
    packet = selected(
        lambda review, current, prior: review.model_copy(
            update={
                "clarifications": (
                    Clarification(
                        text="Client remains uncertain.",
                        question="Which client?",
                        reason="Changes destination",
                        quotes=(current,),
                    ),
                ),
            }
        )
    )
    proposal = plan(packet).model_copy(update={"outcome": "PRIVATE held plan"})
    html = render_decision_cards(packet, (proposal,))
    assert "Which client?" in html and "All work cards and their evidence are held" in html
    assert "PRIVATE held plan" not in html
    assert packet.review.background[0].text not in html
    assert "<article" not in html and "<button" not in html and 'type="radio"' not in html


def test_inferred_owners_are_not_promoted_and_all_controlled_text_is_escaped():
    packet = selected(
        lambda review, current, prior: review.model_copy(
            update={
                "items": (
                    review.items[0].model_copy(
                        update={
                            "kind": ItemKind.FOLLOW_UP,
                            "inferred": True,
                            "text": "<script>PRIVATE original</script>",
                            "owner": "<script>Alex</script>",
                        }
                    ),
                )
            }
        )
    )
    proposal = plan(packet).model_copy(
        update={
            "outcome": "<img src=x onerror=run()>",
            "completion_check": "<script>PRIVATE check</script>",
        }
    )
    html = render_decision_cards(packet, (proposal,))
    assert "Possible: " in html and "Suggested owner: &lt;script&gt;Alex&lt;/script&gt;" in html
    assert "Owner from review:" not in html
    assert "<script>" not in html and "<img " not in html
    assert "&lt;script&gt;" in html and "&lt;img " in html


def test_no_plan_or_informational_item_has_no_approval_controls():
    html = render_decision_cards(deck())
    assert "<button" not in html
    assert "Approach not prepared; no approval choice yet" in html
    assert "Informational review item; no work approval control" in html


def test_empty_review_is_not_claim_that_all_work_is_done():
    packet = selected(lambda review, current, prior: review.model_copy(update={"items": ()}))
    html = render_decision_cards(packet)
    assert "No selected items. Other work has not been checked" in html
    assert "<article" not in html and "Completion remains unverified" in html


def test_source_headline_is_not_replaced_by_proposed_outcome():
    packet = selected()
    proposal = plan(packet).model_copy(
        update={"outcome": "Draft hoped-for result, not source fact"}
    )
    html = render_decision_cards(packet, (proposal,))
    assert "<h2>" + escape(packet.review.items[0].text) + "</h2>" in html
    assert "<h2>Draft hoped-for result" not in html
    assert "<strong>Proposed outcome:</strong> Draft hoped-for result, not source fact" in html


@pytest.mark.parametrize(
    "mode,action",
    [
        (DecisionCardRenderMode.OFFLINE, "none"),
        (DecisionCardRenderMode.HOST_LOGOUT, "self"),
    ],
)
def test_explicit_csp_composition_mode_without_forms_or_active_work_actions(mode, action):
    packet = selected()
    proposal = plan(packet)
    html = render_decision_cards(packet, (proposal,), render_mode=mode)
    assert "form-action &#39;" + action + "&#39;" in html
    assert "default-src &#39;none&#39;" in html
    assert "base-uri &#39;none&#39;" in html
    shape = Shape()
    shape.feed(html)
    assert shape.forms == shape.scripts == 0
    assert all("disabled" in button for button in shape.buttons)
    assert "Presentation only; no approval is recorded" in html


def test_default_offline_csp_cannot_submit_host_logout():
    html = render_decision_cards(selected())
    assert "form-action &#39;none&#39;" in html
    assert "form-action &#39;self&#39;" not in html


@pytest.mark.parametrize("mode", ["host_logout", True, "self", "https://attacker.invalid", None])
def test_render_mode_cannot_be_free_string_or_preference(mode):
    with pytest.raises(ValueError, match="^decision cards unavailable or invalid$") as error:
        render_decision_cards(selected(), render_mode=mode)
    assert error.value.__context__ is None


def test_host_mode_still_escapes_hostile_outcome_and_original_text():
    packet = selected(
        lambda review, current, prior: review.model_copy(
            update={
                "items": (
                    review.items[0].model_copy(
                        update={"text": '<form action="https://attacker.invalid">source</form>'}
                    ),
                )
            }
        )
    )
    proposal = plan(packet).model_copy(
        update={"outcome": '<form action="/execute">draft</form><script>run()</script>'}
    )
    html = render_decision_cards(
        packet, (proposal,), render_mode=DecisionCardRenderMode.HOST_LOGOUT
    )
    assert "<h2>" + escape(packet.review.items[0].text) + "</h2>" in html
    assert "<strong>Proposed outcome:</strong> " + escape(proposal.outcome) in html
    shape = Shape()
    shape.feed(html)
    assert shape.forms == shape.scripts == 0


def test_print_policy_covers_closed_evidence_details_outside_cards():
    # Static policy regression, not proof of physical browser/print behavior.
    class Details(HTMLParser):
        def __init__(self):
            super().__init__()
            self.article = 0
            self.outside_closed = 0

        def handle_starttag(self, tag, attrs):
            if tag == "article":
                self.article += 1
            if tag == "details" and not self.article and "open" not in dict(attrs):
                self.outside_closed += 1

        def handle_endtag(self, tag):
            if tag == "article":
                self.article -= 1

    html = render_decision_cards(deck())
    details = Details()
    details.feed(html)
    assert details.outside_closed >= 1  # Selected context contains retained source evidence.
    print_css = html.split("@media print", 1)[1].split("</style>", 1)[0]
    reveal = re.search(r"(?:^|[{}])\s*main\s+details::details-content\s*\{([^}]*)\}", print_css)
    fallback = re.search(
        r"(?:^|[{}])\s*main\s+details\s*>\s*:not\(summary\)\s*\{([^}]*)\}", print_css
    )
    assert reveal and re.search(r"content-visibility\s*:\s*visible\s*;", reveal[1])
    assert fallback and re.search(r"display\s*:\s*block\s*!important\s*;", fallback[1])
