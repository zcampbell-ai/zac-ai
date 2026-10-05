"""Invented offline histories only; no retrieval, authorization or live release."""

from datetime import timedelta
from html import escape

import pytest

from tests.test_selected_briefing import selected
from tests.test_work_proposals import plan
from tests.test_work_tracking import append, journal_for
from zacai.intelligence.contextual_evaluation import (
    decode_contextual_packet,
    encode_contextual_packet,
)
from zacai.intelligence.contextual_review import Clarification
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.selected_briefing import render_selected_briefing
from zacai.intelligence.work_briefing import render_work_proposals
from zacai.intelligence.work_proposals import WorkChoice, WorkPreference, proposal_fingerprint
from zacai.intelligence.work_tracking import WorkJournal, WorkStatus


def display(packet, journal, **changes):
    args = {
        "as_of": journal.created_at + timedelta(minutes=10),
        "work_view": True,
        "work_proposals": (journal.proposal,),
        "work_journals": (journal,),
    }
    args.update(changes)
    return render_selected_briefing(packet, **args)


@pytest.mark.parametrize(
    "status", [s for s in WorkStatus if s not in (WorkStatus.PROPOSED, WorkStatus.REOPENED)]
)
def test_all_reported_states_visible_without_preference_derived_status(status):
    packet = selected()
    journal = append(journal_for(packet), status)
    html = display(packet, journal)
    assert "Work status:" in html
    assert "Reported" in html and "completion unverified" in html
    assert escape(journal.observations[-1].reason) in html
    assert "Awaiting your preference" not in html
    assert "No preference recorded; this does not override" in html
    assert "Did everything get done?</strong> Not verified" in html
    for ref in journal.observations[-1].evidence:
        assert str(ref.source_id) in html and ref.content_hash in html
    assert "not authenticated approvals or independently verified outcomes" in html
    assert "Latest report:" in html
    assert "this report does not establish current status" in html


def test_full_history_preserved_with_reported_completion_then_reopen():
    packet = selected()
    journal = journal_for(packet)
    for status in (
        WorkStatus.IN_PROGRESS_REPORTED,
        WorkStatus.BLOCKED_REPORTED,
        WorkStatus.COMPLETION_REPORTED,
        WorkStatus.REOPENED,
    ):
        journal = append(journal, status)
    html = display(packet, journal)
    assert "Work status:</strong> Reported reopened" in html
    assert "Reported complete — outcome still unverified" in html
    assert "Previous reports remain historical" in html
    for observation in journal.observations:
        assert observation.observed_at.isoformat() in html
        assert observation.recorded_at.isoformat() in html
        assert escape(observation.reason) in html
    for step in journal.proposal.steps:
        assert escape(step.instruction) in html
    assert escape(packet.review.items[0].text) in html


@pytest.mark.parametrize("choice", list(WorkChoice))
def test_preferences_remain_separate_from_reported_state_and_completion(choice):
    packet = selected()
    journal = append(journal_for(packet), WorkStatus.BLOCKED_REPORTED)
    preference = WorkPreference(
        proposal_digest=proposal_fingerprint(journal.proposal),
        choice=choice,
        changes="Keep it shorter." if choice == WorkChoice.WITH_CHANGES else None,
    )
    html = display(packet, journal, work_preferences=(preference,))
    assert "Work status:</strong> Reported blocked" in html
    assert escape(choice.value) in html
    assert "completion unverified" in html and "execution is not connected yet" in html
    assert "Owner from review: Alex" in html


@pytest.mark.parametrize(
    "change",
    [
        "duplicate",
        "changed_plan",
        "future_journal",
        "future_observation",
        "no_work_view",
        "missing_host_time",
    ],
)
def test_invalid_or_ambiguous_history_binding_fails_closed(change):
    packet = selected()
    journal = append(journal_for(packet), WorkStatus.IN_PROGRESS_REPORTED)
    changes = {}
    if change == "duplicate":
        changes["work_journals"] = (journal, journal)
    elif change == "changed_plan":
        changes["work_proposals"] = (
            journal.proposal.model_copy(update={"outcome": "PRIVATE changed outcome"}),
        )
    elif change == "future_journal":
        changes["as_of"] = journal.created_at - timedelta(seconds=1)
    elif change == "future_observation":
        changes["as_of"] = journal.created_at
    elif change == "no_work_view":
        changes["work_view"] = False
    else:
        with pytest.raises(ValueError, match="work proposals unavailable or invalid") as exc:
            render_work_proposals(packet, (journal.proposal,), journals=(journal,))
        assert exc.value.__context__ is None
        return
    with pytest.raises(ValueError, match="selected briefing unavailable or invalid") as exc:
        display(packet, journal, **changes)
    assert exc.value.__context__ is None and "PRIVATE" not in str(exc.value)


def test_material_question_holds_all_journal_reason_and_evidence():
    packet = selected()
    review = packet.review.model_copy(
        update={
            "clarifications": (
                Clarification(
                    text="Client remains uncertain.",
                    question="Which client?",
                    reason="Changes destination",
                    quotes=packet.review.items[0].quotes,
                ),
            )
        }
    )
    held = decode_contextual_packet(
        encode_contextual_packet(
            review, packet.context(), builder_id=packet.builder_id, created_at=packet.created_at
        )
    )
    journal = append(
        journal_for(held), WorkStatus.BLOCKED_REPORTED, reason="PRIVATE held journal reason"
    )
    html = display(held, journal)
    assert "Which client?" in html and "One question first" in html
    assert "PRIVATE held journal reason" not in html
    assert str(journal.packet_reference.source_id) not in html
    assert "Work status:" not in html


def test_inferred_owner_and_escaped_observation_text_remain_provisional():
    packet = selected(
        lambda review, current, prior: review.model_copy(
            update={
                "items": (
                    review.items[0].model_copy(
                        update={"inferred": True, "kind": ItemKind.FOLLOW_UP}
                    ),
                )
            }
        )
    )
    journal = append(
        journal_for(packet),
        WorkStatus.REVIEW_READY_REPORTED,
        reason="<script>PRIVATE unsafe markup</script>",
    )
    html = display(packet, journal)
    assert "Possible: " in html and "Suggested owner: Alex" in html
    assert "Owner from review: Alex" not in html
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_duplicate_work_identity_across_different_items_rejected():
    packet = selected(
        lambda review, current, prior: review.model_copy(
            update={
                "items": (review.items[0], review.items[0]),
            }
        )
    )
    first = journal_for(packet)
    second = WorkJournal.model_validate(
        first.model_copy(update={"proposal": first.proposal.model_copy(update={"item_index": 1})})
    )
    with pytest.raises(ValueError, match="work proposals unavailable or invalid"):
        render_work_proposals(
            packet,
            (first.proposal, second.proposal),
            journals=(first, second),
            as_of=packet.created_at,
        )


def test_proposal_only_output_compatibility_wrapper_is_exact():
    from zacai.intelligence.work_proposals import render_work_proposals as compatibility_render

    packet = selected()
    proposal = plan(packet)
    assert render_work_proposals(packet, (proposal,)) == compatibility_render(packet, (proposal,))


@pytest.mark.parametrize("label_case", ["stronger_journal", "mismatched_packet_reference"])
def test_page_rejects_stronger_journal_labels_and_mismatched_packet_labels(label_case):
    from zacai.policy import DataClassification as C

    packet = selected()
    if label_case == "mismatched_packet_reference":
        context = packet.context()
        items = tuple(
            item.model_copy(
                update={
                    "reference": item.reference.model_copy(
                        update={
                            "effective_classification": C.CONFIDENTIAL,
                        }
                    )
                }
            )
            for item in packet.task.context
        )
        event = packet.task.event.model_copy(
            update={
                "data_classification": C.CONFIDENTIAL,
                "provenance": tuple(item.reference for item in items),
            }
        )
        task = packet.task.model_copy(update={"context": items, "event": event})
        context = type(context)(task, context.meeting_source_id, context.related_source_ids)
        review = packet.review.model_copy(update={"data_classification": C.CONFIDENTIAL})
        packet = decode_contextual_packet(
            encode_contextual_packet(
                review, context, builder_id=packet.builder_id, created_at=packet.created_at
            )
        )
    journal = journal_for(packet)
    if label_case == "stronger_journal":
        journal = WorkJournal.model_validate(
            journal.model_copy(update={"data_classification": C.HIGHLY_RESTRICTED})
        )
    else:
        journal = WorkJournal.model_validate(
            journal.model_copy(
                update={
                    "packet_reference": journal.packet_reference.model_copy(
                        update={"effective_classification": C.PUBLIC}
                    )
                }
            )
        )
    with pytest.raises(ValueError, match="selected briefing unavailable or invalid"):
        display(packet, journal)
