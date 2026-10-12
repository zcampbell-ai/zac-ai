"""Real invented pair; unretained metadata holds without body projection."""

import pytest

from tests.test_claude_task_selection import MID, OTHER, choose, prepared, sibling
from tests.test_selector_resolution import same_original_task  # noqa: F401
from zacai.intelligence import claude_task_selection as selector


@pytest.mark.parametrize("role,parent", [("assistant", MID), ("human", MID)])
def test_valid_indexed_unretained_cohort_is_non_choice_metadata(role, parent, monkeypatch):
    read = prepared(
        text="Sales Audit original words",
        siblings=(sibling(role, parent, "INVENTED UNRETAINED TEXT"),),
        selected_ids=(MID,),
    )
    calls = []

    def no_projection(*args, **kwargs):
        calls.append(True)
        raise AssertionError("no unretained body projection")

    monkeypatch.setattr(selector, "prepare_claude_large_original_message", no_projection)
    monkeypatch.setattr(selector, "prepare_claude_history_context_preview", no_projection)
    first = choose(read, ids=(MID, OTHER))
    assert (
        first.outcome == "MISSING_CONTEXT"
        and first.question is first.request is first.preview is None
    )
    assert first.options == () and calls == []
    assert "retained custody" in first.non_choice_reason
    assert all(
        c.profile_hash is c.full_text_hash is None and c.quote_preview == ""
        for c in first.candidates
    )
    assert not first.processing_authorized and not first.current_facts_verified
    assert {c.message_id for c in first.candidates} == ({MID, OTHER} if role == "human" else {MID})
    manual = selector.ClaudeTaskResolution(first.selection_binding_digest, (MID,), (OTHER,))
    again = choose(read, ids=(MID, OTHER), resolution=manual)
    assert again.outcome == "MISSING_CONTEXT" and again.request is None and calls == []
