"""Root causal display controls, invented canonical shapes only."""

import copy
import re

from tests import test_selector_branch_closure as branches
from tests.test_claude_task_selection import choose, route
from tests.test_selector_resolution import same_original_task  # noqa: F401
from zacai.intelligence import claude_task_selection as selector


def test_source_numbering_cannot_forge_top_level_choice_markers():
    read, approved = branches.branch_read("edit", prefix="Plan: 1. keep scope; 2. ")
    first = choose(
        read, ids=approved, route=route().model_copy(update={"max_input_characters": 64000})
    )
    assert first.outcome == "CLARIFICATION"
    lines = re.findall(r"(?m)^([1-9][0-9]*)\. (.*)$", first.question)
    assert [int(n) for n, _ in lines] == list(range(1, len(first.options) + 1))
    assert [label for _, label in lines] == [o.display_label for o in first.options]


def test_manual_resolution_cannot_use_a_never_presented_ambiguous_choice(monkeypatch):
    original = branches.canonical_bytes

    def equal_edits(value):
        if (
            isinstance(value, list)
            and value
            and isinstance(value[0], dict)
            and "chat_messages" in value[0]
        ):
            value = copy.deepcopy(value)
            messages = value[0]["chat_messages"]
            messages[-1]["text"] = messages[-2]["text"]
        return original(value)

    monkeypatch.setattr(branches, "canonical_bytes", equal_edits)
    read, approved = branches.branch_read("edit")
    params = {"ids": approved, "route": route().model_copy(update={"max_input_characters": 64000})}
    first = choose(read, **params)
    assert first.outcome == "MISSING_CONTEXT" and first.question is None
    assert len(first.options) == 2
    option = first.options[0]
    manual = selector.ClaudeTaskResolution(
        first.selection_binding_digest,
        option.selected_message_ids,
        option.disclosed_excluded_message_ids,
    )
    try:
        result = choose(read, **params, resolution=manual)
    except selector.ClaudeTaskSelectionError:
        return
    assert result.outcome != "PROPOSED" and result.request is None


def test_presentable_question_has_one_question_and_exact_single_line_labels():
    read, approved = branches.branch_read(
        "edit", prefix="Which item?\n1. invented marker; 2. nested marker. "
    )
    params = {"ids": approved, "route": route().model_copy(update={"max_input_characters": 64000})}
    first = choose(read, **params)
    assert first.outcome == "CLARIFICATION"
    assert first.question.splitlines()[0] == "Which history should I use for this task?"
    assert first.question.count("?") == 1
    assert len(first.question.splitlines()) == 1 + len(first.options)
    for number, option in enumerate(first.options, 1):
        assert "\n" not in option.display_label and "\r" not in option.display_label
        assert first.question.splitlines()[number] == f"{number}. {option.display_label}"
        resolution = selector.prepare_claude_task_resolution(first, option_number=number)
        selected = choose(read, **params, resolution=resolution)
        assert selected.outcome == "PROPOSED" and selected.question is None
        assert (
            tuple(e.message_id for e in selected.request.sidecar.entries)
            == option.selected_message_ids
        )
        assert not selected.processing_authorized and not resolution.owner_answer_authenticated


def test_manual_resolution_cannot_supply_a_choice_for_already_proposed_context():
    from tests.test_claude_task_selection import MID, prepared

    read = prepared(text="Sales Audit proposed30hours")
    first = choose(read)
    assert first.outcome == "PROPOSED" and first.question is None
    manual = selector.ClaudeTaskResolution(first.selection_binding_digest, (MID,), ())
    result = choose(read, resolution=manual)
    assert result.outcome == "MISSING_CONTEXT" and result.request is None
    assert "No presentable original comparison choice" in result.non_choice_reason
