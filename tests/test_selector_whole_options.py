"""Owner-facing numbered whole comparison choices, no authenticated action."""

import pytest

from tests.test_claude_task_selection import choose, route
from tests.test_selector_branch_closure import branch_read
from tests.test_selector_resolution import answer, same_original_task  # noqa: F401
from zacai.intelligence import claude_task_selection as selector


@pytest.mark.parametrize("shape", ["two", "edit"])
def test_one_displayed_number_resolves_without_fixture_lineage_knowledge(shape):
    read, approved = branch_read(shape)
    params = {"ids": approved, "route": route().model_copy(update={"max_input_characters": 64000})}
    first = choose(read, **params)
    assert first.outcome == "CLARIFICATION" and first.request is None
    if hasattr(selector, "prepare_claude_task_resolution"):
        resolution = selector.prepare_claude_task_resolution(first, option_number=1)
    else:
        # Exact old displayed first numbered item is one message, not a branch.
        # Exercising that actual advertised answer demonstrates the old dead end.
        chosen = first.candidates[0].message_id
        resolution = answer(first, (chosen,), tuple(v for v in approved if v != chosen))
    result = choose(read, **params, resolution=resolution)
    assert result.outcome == "PROPOSED" and result.request is not None
    assert tuple(e.message_id for e in result.request.sidecar.entries) == resolution.selected_message_ids
    assert not result.processing_authorized and not resolution.owner_answer_authenticated
    assert len(first.options) == 2
    assert "1. " + first.options[0].display_label in first.question
    for number, option in enumerate(first.options, 1):
        real_answer = selector.prepare_claude_task_resolution(first, option_number=number)
        assert real_answer.selected_message_ids == option.selected_message_ids
        assert set(real_answer.selected_message_ids) | set(real_answer.disclosed_excluded_message_ids) == set(approved)
        value = choose(read, **params, resolution=real_answer)
        assert value.outcome == "PROPOSED"
        assert tuple(e.message_id for e in value.request.sidecar.entries) == option.selected_message_ids


def test_identical_quote_prefix_edit_options_have_differing_literal_labels():
    prefix = "Same opening requirements. " * 12
    read, approved = branch_read("edit", prefix=prefix)
    params = {"ids": approved, "route": route().model_copy(update={"max_input_characters": 64000})}
    first = choose(read, **params)
    assert first.outcome == "CLARIFICATION"
    hits = [v for v in first.candidates if "Same opening" in v.quote_preview]
    assert len(hits) == 2 and hits[0].quote_preview == hits[1].quote_preview
    assert "45hours" in first.question and "50hours" in first.question
    assert len(first.options) == 2 and first.options[0].display_label != first.options[1].display_label
    for number in (1, 2):
        resolution = selector.prepare_claude_task_resolution(first, option_number=number)
        value = choose(read, **params, resolution=resolution)
        assert value.outcome == "PROPOSED" and value.request is not None
        # Display focusing never clips the complete selected original fields.
        assert prefix in value.preview.context.task.context[-1].untrusted_text
        assert all(e.omitted_prefix_characters == e.omitted_suffix_characters == 0 for e in value.request.sidecar.entries)


@pytest.mark.parametrize("number", [0, 3, True, "1"])
def test_invalid_displayed_option_number_cannot_construct_answer(number):
    read, approved = branch_read("edit")
    first = choose(read, ids=approved, route=route().model_copy(update={"max_input_characters": 64000}))
    with pytest.raises(selector.ClaudeTaskSelectionError):
        selector.prepare_claude_task_resolution(first, option_number=number)
