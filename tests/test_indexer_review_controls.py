"""Invented bytes; reviewed gaps, not actual export compatibility acceptance."""

from dataclasses import fields

import pytest

from tests.test_claude_history_index import NOW, encoded, fixture, inspect
from zacai import claude_history_index as m


def test_small_conversation_in_over_limit_file_is_unavailable():
    value = fixture()
    pad = {
        **value[0],
        "uuid": "55555555-5555-4555-8555-555555555555",
        "chat_messages": [],
        "padding": "x" * m.MAX_EXPORT_BYTES,
    }
    result = inspect(encoded(value + [pad]))
    conv = result.conversations[0]
    assert conv.record_within_existing_byte_limit is True
    assert conv.held_by_byte_or_lineage_gate is True


def test_conversation_record_limit_conservatively_blocks_small_messages():
    value = fixture()
    value[0]["padding"] = "x" * (m.MAX_RECORD_BYTES + 1)
    result = inspect(encoded(value))
    assert result.whole_file_within_existing_byte_limit
    assert result.conversations[0].held_by_byte_or_lineage_gate
    assert result.conversations[0].messages[0].held_by_byte_or_lineage_gate


def test_short_text_and_content_ranges_expose_offsets_but_no_guessable_hash():
    value = fixture()
    value[0]["chat_messages"][0]["text"] = "yes"
    first = inspect(encoded(value)).conversations[0].messages[0]
    for span in (first.text_json_value, first.structured_content):
        assert {f.name for f in fields(span)} == {"start", "end"}
        assert not hasattr(span, "content_hash")
    assert not hasattr(first.record, "content_hash")


def test_parent_exists_but_its_reported_time_is_after_child():
    value = fixture()
    value[0]["created_at"] = "2026-10-05T00:00:00Z"
    first, child = value[0]["chat_messages"]
    first["created_at"] = NOW
    child["created_at"] = "2026-10-06T11:00:00Z"
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded(value))


def test_error_traceback_does_not_retain_decoded_builder_locals():
    raw = b'[{"private":"invented-decoded-body"}]'
    with pytest.raises(m.ClaudeHistoryIndexError) as held:
        inspect(raw)
    frame = held.value.__traceback__
    while frame:
        if frame.tb_frame.f_code.co_name == "index_claude_member_history":
            assert not {"walker", "root", "records", "conv", "obj"} & frame.tb_frame.f_locals.keys()
        assert frame.tb_frame.f_code.co_name != "_build"
        frame = frame.tb_next


def test_structural_ceiling_may_hold_below_message_ceiling(monkeypatch):
    # Conjunctive bounds: no promise that MAX_MESSAGES fits MAX_NODES.
    monkeypatch.setattr(m, "MAX_NODES", 10)
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded())
    assert len(fixture()[0]["chat_messages"]) < m.MAX_MESSAGES


def test_non_ascii_date_digits_hold():
    value = fixture()
    value[0]["created_at"] = "２０２６-10-06T12:00:00Z"
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(encoded(value))
