"""Invented comparison-only answers; no authenticated answer or processing grant."""

from uuid import UUID

import pytest

from tests.test_claude_task_selection import MID, OTHER, choose, prepared, route, sibling
from zacai.intelligence import claude_task_selection as selector


@pytest.fixture(autouse=True)
def same_original_task(monkeypatch):
    from tests import test_claude_task_selection as support

    context = support.base()
    monkeypatch.setattr(support, "base", lambda: context)


def answer(first, selected, excluded):
    return selector.ClaudeTaskResolution(first.selection_binding_digest, selected, excluded)


def test_chosen_unlinked_context_reentry_has_concrete_answer():
    read = prepared(
        text="Sales Audit originally proposed 30 hours.",
        siblings=(sibling(text="Actually use 45 hours instead."),),
        selected_ids=(MID, OTHER),
    )
    first = choose(read, ids=(MID, OTHER))
    assert first.outcome == "CLARIFICATION" and first.request is None
    assert MID in {c.message_id for c in first.candidates}
    if hasattr(selector, "ClaudeTaskResolution"):
        result = choose(read, ids=(MID, OTHER), resolution=answer(first, (MID,), (OTHER,)))
    else:
        # Original supported re-entry actually repeats the question, not just
        # absent API. Same source/task/custody, owner chooses an offered MID.
        result = choose(read, ids=(MID,))
    assert result.outcome == "PROPOSED" and result.request is not None
    assert tuple(e.message_id for e in result.request.sidecar.entries) == (MID,)
    assert result.instruction == first.instruction
    assert not result.processing_authorized and not result.relevance_verified


def test_branch_choice_preserves_ancestor_and_discloses_sibling():
    third = UUID(int=444)
    row = sibling(parent=MID, text="Use 50 hours instead")
    row["uuid"] = str(third)
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(parent=MID, text="Use 45 hours instead"), row),
        selected_ids=(MID, OTHER, third),
    )
    params = {
        "ids": (MID, OTHER, third),
        "route": route().model_copy(update={"max_input_characters": 64000}),
    }
    first = choose(read, **params)
    assert first.outcome == "CLARIFICATION" and first.question.count("?") == 1
    result = choose(read, **params, resolution=answer(first, (MID, OTHER), (third,)))
    assert result.outcome == "PROPOSED" and result.request is not None
    assert tuple(e.message_id for e in result.request.sidecar.entries) == (MID, OTHER)
    assert "Use 45 hours instead" in result.preview.context.task.context[-1].untrusted_text
    assert not result.current_facts_verified


def test_linked_correction_cannot_be_removed_by_comparison():
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(parent=MID, text="Actually use 45 hours instead"),),
        selected_ids=(MID, OTHER),
    )
    params = {
        "ids": (MID, OTHER),
        "route": route().model_copy(update={"max_input_characters": 64000}),
    }
    first = choose(read, **params)
    assert first.outcome == "PROPOSED"
    result = choose(read, **params, resolution=answer(first, (MID,), (OTHER,)))
    assert (
        result.outcome == "MISSING_CONTEXT" and result.request is None and result.question is None
    )
    assert "Required linked" in result.non_choice_reason


def test_unavailable_ancestor_is_non_choice_hold():
    ancestor = sibling(text="Sales Audit " + "x" * 2000)
    ancestor["created_at"] = ancestor["updated_at"] = "2026-10-06T11:30:00Z"
    read = prepared(
        text="Sales Audit 45 hours", parent=OTHER, prefixes=(ancestor,), selected_ids=(MID, OTHER)
    )
    first = choose(read, ids=(MID, OTHER))
    assert first.outcome == "MISSING_CONTEXT" and first.question is None and first.request is None
    assert "unavailable" in first.non_choice_reason
    with pytest.raises(selector.ClaudeTaskSelectionError):
        choose(read, ids=(MID, OTHER), resolution=answer(first, (OTHER,), (MID,)))


def test_capacity_hold_cannot_become_a_pick():
    read = prepared(text="Sales Audit 30 hours")
    small = route().model_copy(update={"max_input_characters": 100})
    first = choose(read, route=small)
    assert first.outcome == "MISSING_CONTEXT" and first.question is None
    again = choose(read, route=small, resolution=answer(first, (MID,), ()))
    assert again.outcome == "MISSING_CONTEXT" and again.request is None and again.question is None
    assert "preview" in again.non_choice_reason


@pytest.mark.parametrize(
    "fault", ["task", "words", "route", "cohort", "digest", "exclusions", "foreign", "pair"]
)
def test_stale_or_wrong_comparison_holds(fault, monkeypatch):
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(text="Use 45 hours instead"),),
        selected_ids=(MID, OTHER),
    )
    first = choose(read, ids=(MID, OTHER))
    resolution = answer(first, (MID,), (OTHER,))
    changes = {"ids": (MID, OTHER), "resolution": resolution}
    if fault == "task":
        from dataclasses import replace

        from tests import test_claude_task_selection as support

        context = support.base()
        changed = replace(context, task=context.task.model_copy(update={"task_id": UUID(int=888)}))
        monkeypatch.setattr(support, "base", lambda: changed)
    elif fault == "words":
        changes["instruction"] = "Summarize Sales Audit differently"
    elif fault == "route":
        changes["route"] = route().model_copy(update={"max_input_characters": 64000})
    elif fault == "cohort":
        changes["ids"] = (MID,)
    elif fault == "digest":
        changes["resolution"] = selector.ClaudeTaskResolution("f" * 64, (MID,), (OTHER,))
    elif fault == "exclusions":
        changes["resolution"] = answer(first, (MID,), ())
    elif fault == "foreign":
        changes["resolution"] = answer(first, (UUID(int=777),), (MID, OTHER))
    else:
        changes["expected_companion"] = read.companion_reference.model_copy(
            update={"content_hash": "f" * 64}
        )
    with pytest.raises(selector.ClaudeTaskSelectionError):
        choose(read, **changes)


def test_unretained_cohort_hold_before_per_message_projection(monkeypatch):
    text = "UNRETAINED_LITERAL Sales Audit 45 hours"
    read = prepared(
        text="Sales Audit 30 hours", siblings=(sibling(parent=MID, text=text),), selected_ids=(MID,)
    )
    original = selector.json.loads
    seen = []

    def observe(value, *args, **kwargs):
        if isinstance(value, bytes) and value == ('"' + text + '"').encode():
            seen.append(value)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(selector.json, "loads", observe)
    result = choose(read, ids=(MID, OTHER))
    assert result.outcome == "MISSING_CONTEXT" and result.request is None
    assert result.question is None and result.options == ()
    assert "retained custody" in result.non_choice_reason
    assert all(
        c.profile_hash is c.full_text_hash is None and c.quote_preview == ""
        for c in result.candidates
    )
    assert seen == []


def test_partial_literal_choice_reentry_and_display_only_normalization():
    read = prepared(text='Icon Park Sales discussion?\n"Dated report"')
    first = choose(read)
    assert first.outcome == "CLARIFICATION" and first.question.count("?") == 1
    assert "\\n" not in first.question and "\\u003f" not in first.question
    assert first.candidates[0].quote_preview == 'Icon Park Sales discussion?\n"Dated report"'
    result = choose(read, resolution=answer(first, (MID,), ()))
    assert result.outcome == "PROPOSED" and result.request is not None
    assert not result.processing_authorized


def test_aggregate_capacity_cannot_be_resolved_by_omitting_a_required_turn():
    first_text = "Sales Audit " + ("a" * 1000 + "\n") * 4 + "a" * 100
    next_text = "Correction " + ("b" * 1000 + "\n") * 4 + "b" * 100
    read = prepared(
        text=first_text, siblings=(sibling(parent=MID, text=next_text),), selected_ids=(MID, OTHER)
    )
    params = {
        "ids": (MID, OTHER),
        "route": route().model_copy(update={"max_input_characters": 64000}),
    }
    first = choose(read, **params)
    assert first.outcome == "MISSING_CONTEXT" and first.question is None
    again = choose(read, **params, resolution=answer(first, (MID,), (OTHER,)))
    assert again.outcome == "MISSING_CONTEXT" and again.question is None and again.request is None
    assert "bounds" in again.non_choice_reason or "capacity" in again.non_choice_reason
