"""Invented complete originals; exact quote identity, not source authority."""

from copy import deepcopy
from uuid import uuid4

import pytest

from tests.test_claude_message_projection import extract, inputs, wire
from zacai import claude_message_projection as m
from zacai.history_manifest import MAX_EXPORT_BYTES, MAX_RECORD_BYTES
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import ContextItem


@pytest.mark.parametrize("text", [" padded", "padded ", "\npadded", "padded\t"])
def test_edge_whitespace_refused_instead_of_contextitem_silent_trim(text):
    values = inputs(wire(text))
    # The downstream legacy contract really strips edges; no offset rewriting here.
    assert ContextItem(reference=values[2], untrusted_text=text).untrusted_text != text
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(values)
    result = extract(inputs(wire("exact quote")))
    assert (
        ContextItem(reference=result.reference, untrusted_text=result.selected_text).untrusted_text
        == result.selected_text
    )
    assert result.selected_text_hash == content_hash_of(result.selected_text.encode())


@pytest.mark.parametrize("ascii", [False, True])
def test_select_after_emoji_escape_prefix_has_absolute_decoded_utf8_offsets(ascii):
    text = '😀 "é"\\next'
    result = extract(inputs(wire(text), ascii=ascii), 6, 10)
    assert result.selected_text == "next"
    assert result.selected_character_start == 6
    assert result.selected_decoded_utf8_start == len(text[:6].encode()) == 10
    assert result.selected_decoded_utf8_end == len(text[:10].encode()) == 14


def test_actual_indexed_metadata_passes_through_exactly():
    values = inputs(index=1)
    result = extract(values)
    row = values[3]
    assert result.message_id == row.original_id
    assert result.conversation_id == row.conversation_id
    assert result.record_bytes == row.record
    assert result.record_hash == content_hash_of(values[1][row.record.start : row.record.end])
    assert result.text_json_bytes == row.text_json_value
    assert result.reported_created_at == row.reported_created_at
    assert result.reported_updated_at == row.reported_updated_at
    assert result.historical_role == row.historical_role == "ASSISTANT"
    assert result.parent_id == row.parent_id
    assert result.parent_status == row.parent_status == "RESOLVED_EARLIER"
    assert result.sender_authenticated is False


def test_oversize_conversation_holds_small_selected_message_with_positive_sibling():
    value = wire("small selected quote")
    assert extract(inputs(value)).selected_text == "small selected quote"
    value[0]["account"]["padding"] = "x" * MAX_RECORD_BYTES
    values = inputs(value)
    assert len(values[1]) < MAX_EXPORT_BYTES
    assert values[3].record.end - values[3].record.start < MAX_RECORD_BYTES
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(values)


def test_large_whole_original_holds_small_individually_bounded_conversations():
    value = []
    for _ in range(70):
        conv = deepcopy(wire("small selected quote")[0])
        conv["uuid"] = str(uuid4())
        first, second = str(uuid4()), str(uuid4())
        conv["chat_messages"][0]["uuid"] = first
        conv["chat_messages"][1]["uuid"] = second
        conv["chat_messages"][1]["parent_message_uuid"] = first
        conv["account"]["padding"] = "x" * 120_000
        value.append(conv)
    assert extract(inputs(value[:1])).selected_text == "small selected quote"
    values = inputs(value)
    assert len(values[1]) > MAX_EXPORT_BYTES
    assert values[3].record.end - values[3].record.start < MAX_RECORD_BYTES
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(values)
