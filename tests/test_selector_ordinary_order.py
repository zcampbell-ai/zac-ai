"""Invented ordinary export text; real complete preparation contract unchanged."""
import pytest

from tests.test_claude_task_selection import MID, OTHER, choose, prepared, sibling
from zacai.claude_large_original_message import (
    ClaudeLargeOriginalMessageError,
    prepare_claude_large_original_message,
)


@pytest.mark.parametrize("ordinary", ["", "   ", "weather ", "x" * 1600])
def test_earlier_unlinked_unrelated_ordinary_record_does_not_block(ordinary):
    row = sibling(text=ordinary)
    row["created_at"] = row["updated_at"] = "2026-10-06T11:30:00Z"
    read = prepared(text="Sales Audit proposed 45 hours", prefixes=(row,), selected_ids=(MID, OTHER))
    # Producer still refuses the full unrelated record under existing exact-text
    # constraints. Selection must not trim or clip it to make it eligible.
    with pytest.raises(ClaudeLargeOriginalMessageError):
        prepare_claude_large_original_message(read, message_id=OTHER, character_start=0, character_end=len(ordinary))
    value = choose(read, ids=(MID, OTHER))
    assert value.outcome == "PROPOSED" and value.request is not None
    assert tuple(e.message_id for e in value.request.sidecar.entries) == (MID,)
    assert value.request.sidecar.entries[0].omitted_suffix_characters == 0
    assert not value.processing_authorized and not value.relevance_verified


@pytest.mark.parametrize("ordinary", ["Sales Audit weather ", "Sales Audit " + "x" * 1600])
def test_relevant_unavailable_match_stays_non_choice_without_trim(ordinary):
    row = sibling(text=ordinary)
    row["created_at"] = row["updated_at"] = "2026-10-06T11:30:00Z"
    read = prepared(text="Sales Audit proposed 45 hours", prefixes=(row,), selected_ids=(MID, OTHER))
    value = choose(read, ids=(MID, OTHER))
    assert value.outcome == "MISSING_CONTEXT" and value.request is None and value.question is None
    item = next(v for v in value.candidates if v.message_id == OTHER)
    assert item.unavailable_reason is not None and item.quote_preview == ordinary[:140]
    assert "unavailable" in value.non_choice_reason
