"""Invented positive multi-conversation coverage, no account/export claims."""

import json
from uuid import UUID

import pytest

from tests.test_claude_history_index import CID, MID, SECOND, encoded, fixture, inspect
from zacai import claude_history_index as m

OTHER_CID = "55555555-5555-4555-8555-555555555555"
OTHER_ROOT = "66666666-6666-4666-8666-666666666666"
OTHER_CHILD = "77777777-7777-4777-8777-777777777777"
MISSING = "88888888-8888-4888-8888-888888888888"


def two_conversations():
    first = fixture()[0]
    other = fixture()[0]
    other["uuid"] = OTHER_CID
    root, child = other["chat_messages"]
    root["uuid"] = OTHER_ROOT
    child["uuid"] = OTHER_CHILD
    child["parent_message_uuid"] = OTHER_ROOT
    return [first, other]


def test_two_conversations_valid_root_child_keep_per_record_cid_and_lineage():
    raw = encoded(two_conversations())
    result = inspect(raw)
    assert result.message_count == 4 and result.lineage_complete
    assert [c.original_id for c in result.conversations] == [UUID(CID), UUID(OTHER_CID)]
    for conv in result.conversations:
        assert conv.lineage_complete and conv.record_within_existing_byte_limit
        assert not conv.held_by_byte_or_lineage_gate
        root, child = conv.messages
        assert root.parent_status == "EXPLICIT_ZERO_ROOT" and root.parent_id is None
        assert child.parent_status == "RESOLVED_EARLIER" and child.parent_id == root.original_id
        for msg in conv.messages:
            assert msg.conversation_id == conv.original_id
            assert msg.lineage_complete and not msg.held_by_byte_or_lineage_gate
            assert msg.record_within_existing_byte_limit
            assert conv.record.start <= msg.record.start < msg.record.end <= conv.record.end
            assert json.loads(raw[msg.record.start : msg.record.end])["uuid"] == str(
                msg.original_id
            )
    assert result.capture_authorized is False


def test_two_conversations_absent_parent_is_gap_in_both_not_a_guessed_root():
    value = two_conversations()
    for conv in value:
        conv["chat_messages"][0]["parent_message_uuid"] = MISSING
    raw = encoded(value)
    result = inspect(raw)
    assert not result.lineage_complete and result.message_count == 4
    for conv in result.conversations:
        root, child = conv.messages
        assert root.parent_id == UUID(MISSING) and root.parent_status == "UNRESOLVED_MISSING"
        assert child.parent_status == "RESOLVED_EARLIER" and child.parent_id == root.original_id
        assert not conv.lineage_complete and conv.held_by_byte_or_lineage_gate
        for msg in conv.messages:
            assert msg.conversation_id == conv.original_id
            assert not msg.lineage_complete and msg.held_by_byte_or_lineage_gate
            assert json.loads(raw[msg.record.start : msg.record.end])["uuid"] == str(
                msg.original_id
            )


@pytest.mark.parametrize("case", ["parent_same", "message_same", "parent_later", "message_later"])
def test_namespace_denial_has_minimally_repaired_positive(case):
    value = fixture()
    root, child = value[0]["chat_messages"]
    target = OTHER_CID if case.endswith("later") else CID
    if case.startswith("parent"):
        root["parent_message_uuid"] = target
    else:
        root["uuid"] = target
        child["parent_message_uuid"] = target
    if case.endswith("later"):
        value.append({**value[0], "uuid": OTHER_CID, "chat_messages": []})
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded(value))
    # Repair only the colliding identity / its dependent parent reference.
    if case.startswith("parent"):
        root["parent_message_uuid"] = str(m.ZERO_ID)
    else:
        root["uuid"] = MID
        child["parent_message_uuid"] = MID
    result = inspect(encoded(value))
    assert result.lineage_complete and result.message_count == 2
    assert result.conversations[0].messages[1].original_id == UUID(SECOND)
    assert all(not conv.held_by_byte_or_lineage_gate for conv in result.conversations)
