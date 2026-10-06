"""Invented missing-history cases; unknown parents are never inferred roots."""

import json
from uuid import UUID

import pytest

from tests.test_claude_history_index import MID, SECOND, encoded, fixture, inspect
from zacai import claude_history_index as m

MISSING = "44444444-4444-4444-8444-444444444444"
THIRD = "66666666-6666-4666-8666-666666666666"


def test_globally_absent_parent_preserved_as_gap_and_descendants_unavailable():
    value = fixture()
    first, second = value[0]["chat_messages"]
    first["parent_message_uuid"] = MISSING
    value[0]["chat_messages"].append({**second, "uuid": THIRD, "parent_message_uuid": SECOND})
    raw = encoded(value)
    result = inspect(raw)
    conv = result.conversations[0]
    a, b, c = conv.messages
    assert a.parent_id == UUID(MISSING)
    assert a.parent_status == "UNRESOLVED_MISSING"
    assert b.parent_id == UUID(MID) and c.parent_id == UUID(SECOND)
    assert b.parent_status == c.parent_status == "RESOLVED_EARLIER"
    assert result.lineage_complete is conv.lineage_complete is False
    for message in conv.messages:
        assert message.lineage_complete is False
        assert message.held_by_byte_or_lineage_gate is True
        assert message.record_within_existing_byte_limit is True
        original = raw[message.record.start : message.record.end]
        assert json.loads(original)["uuid"] == str(message.original_id)
        assert json.loads(original)["parent_message_uuid"] == str(message.parent_id)
    assert result.completeness_verified is result.capture_authorized is False


def test_explicit_zero_root_and_resolved_children_remain_structurally_complete():
    result = inspect(encoded())
    conv = result.conversations[0]
    a, b = conv.messages
    assert a.parent_id is None and a.parent_status == "EXPLICIT_ZERO_ROOT"
    assert b.parent_status == "RESOLVED_EARLIER"
    assert (
        a.lineage_complete
        and b.lineage_complete
        and conv.lineage_complete
        and result.lineage_complete
    )
    assert not a.held_by_byte_or_lineage_gate and not b.held_by_byte_or_lineage_gate
    assert result.completeness_verified is False


def test_independent_explicit_root_does_not_inherit_unrelated_missing_branch():
    value = fixture()
    value[0]["chat_messages"][0]["parent_message_uuid"] = MISSING
    value[0]["chat_messages"][1]["parent_message_uuid"] = str(m.ZERO_ID)
    result = inspect(encoded(value))
    a, b = result.conversations[0].messages
    assert not a.lineage_complete and a.held_by_byte_or_lineage_gate
    assert b.lineage_complete and b.held_by_byte_or_lineage_gate
    assert result.conversations[0].held_by_byte_or_lineage_gate


@pytest.mark.parametrize("case", ["self", "forward", "cycle", "cross_before", "cross_after"])
def test_present_parent_cannot_be_reclassified_as_missing(case):
    value = fixture()
    first, second = value[0]["chat_messages"]
    if case == "self":
        first["parent_message_uuid"] = MID
    elif case == "forward":
        first["parent_message_uuid"] = SECOND
        second["parent_message_uuid"] = str(m.ZERO_ID)
    elif case == "cycle":
        first["parent_message_uuid"] = SECOND
    else:
        first["parent_message_uuid"] = MISSING
        other = {
            **value[0],
            "uuid": "55555555-5555-4555-8555-555555555555",
            "chat_messages": [{**second, "uuid": MISSING, "parent_message_uuid": str(m.ZERO_ID)}],
        }
        value.insert(0 if case == "cross_before" else len(value), other)
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded(value))
