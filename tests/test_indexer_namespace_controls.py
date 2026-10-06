"""Invented cross-kind namespace ambiguity; no vendor-wide UUID claims."""

import pytest

from tests.test_claude_history_index import CID, encoded, fixture, inspect
from zacai import claude_history_index as m

OTHER_CONVERSATION = "55555555-5555-4555-8555-555555555555"


@pytest.mark.parametrize("case", ["parent_is_conversation", "message_reuses_conversation"])
def test_present_conversation_id_is_not_a_missing_parent(case):
    value = fixture()
    first, second = value[0]["chat_messages"]
    if case == "parent_is_conversation":
        first["parent_message_uuid"] = CID
    else:
        first["uuid"] = CID
        second["parent_message_uuid"] = CID
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded(value))


@pytest.mark.parametrize(
    "case", ["parent_is_later_conversation", "message_reuses_later_conversation"]
)
def test_later_conversation_ids_are_inventoried_before_any_message_classification(case):
    value = fixture()
    first, second = value[0]["chat_messages"]
    if case == "parent_is_later_conversation":
        first["parent_message_uuid"] = OTHER_CONVERSATION
    else:
        first["uuid"] = OTHER_CONVERSATION
        second["parent_message_uuid"] = OTHER_CONVERSATION
    value.append({**value[0], "uuid": OTHER_CONVERSATION, "chat_messages": []})
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded(value))
