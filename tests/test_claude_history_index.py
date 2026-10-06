"""Invented export bytes only; no actual archive, capture, model or authority."""

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from zacai import claude_history_index as m
from zacai.ingestion.artifact_store import content_hash_of

CID = "11111111-1111-4111-8111-111111111111"
MID = "22222222-2222-4222-8222-222222222222"
SECOND = "33333333-3333-4333-8333-333333333333"
NOW = "2026-10-06T12:00:00Z"


def fixture():
    first = {
        "uuid": MID,
        "sender": "human",
        "text": 'Invented 😀 escaped "quote"\nline',
        "content": [{"type": "text", "text": "Invented different structured text"}],
        "created_at": NOW,
        "updated_at": NOW,
        "parent_message_uuid": str(m.ZERO_ID),
    }
    second = {
        **first,
        "uuid": SECOND,
        "sender": "assistant",
        "parent_message_uuid": MID,
        "text": "Invented generated claim",
        "content": [{"type": "tool_result", "content": [{"unknown": "unassessed"}]}],
    }
    return [
        {
            "uuid": CID,
            "created_at": NOW,
            "updated_at": NOW,
            "account": {"uuid": "private-declared-only"},
            "name": "Invented sensitive title",
            "chat_messages": [first, second],
        }
    ]


def encoded(value=None, *, ascii=False):
    return json.dumps(fixture() if value is None else value, ensure_ascii=ascii, indent=2).encode()


def inspect(raw):
    return m.index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))


@pytest.mark.parametrize("ascii", [False, True])
def test_original_utf8_and_surrogate_pair_byte_spans(ascii):
    raw = encoded(ascii=ascii)
    result = inspect(raw)
    conv = result.conversations[0]
    first, second = conv.messages
    assert result.original_file_hash == content_hash_of(raw)
    assert result.original_file_bytes == len(raw) and result.message_count == 2
    assert first.original_id == UUID(MID) and first.parent_id is None
    assert first.historical_role == "USER" and second.historical_role == "ASSISTANT"
    assert second.parent_id == first.original_id
    assert first.reported_created_at == datetime(2026, 10, 6, 12, tzinfo=UTC)
    assert (
        conv.record.start
        <= first.record.start
        < first.record.end
        <= second.record.start
        < second.record.end
        <= conv.record.end
    )
    for message in conv.messages:
        assert json.loads(raw[message.record.start : message.record.end])["uuid"] == str(
            message.original_id
        )
        for span in (message.record, message.text_json_value, message.structured_content):
            assert message.record.start <= span.start < span.end <= message.record.end
    assert (
        json.loads(raw[first.text_json_value.start : first.text_json_value.end])
        == fixture()[0]["chat_messages"][0]["text"]
    )
    assert b"Invented" not in repr(result).encode()
    assert "sensitive" not in repr(conv) and "generated" not in repr(second)
    assert (
        result.structured_content_assessed
        is result.capture_authorized
        is result.recovery_verified
        is False
    )


def test_whitespace_token_boundaries_and_adjacent_records():
    raw = (
        b"\r\n\t"
        + json.dumps(fixture(), separators=(",", ":"), ensure_ascii=False).encode()
        + b"\t\n"
    )
    result = inspect(raw)
    conv = result.conversations[0]
    assert conv.record.start == 4 and raw[conv.record.start : conv.record.end].startswith(b"{")
    assert raw[conv.messages[0].record.end : conv.messages[1].record.start] == b","


@pytest.mark.parametrize(
    "change",
    [
        "role",
        "naive",
        "date_order",
        "duplicate_message",
        "duplicate_conversation",
        "foreign_parent",
        "later_parent",
        "self_parent",
        "zero_message",
        "uppercase_id",
        "missing_content",
    ],
)
def test_closed_role_date_id_and_parent_lineage(change):
    value = fixture()
    c = value[0]
    first, second = c["chat_messages"]
    if change == "role":
        first["sender"] = "system"
    elif change == "naive":
        first["created_at"] = "2026-10-06T12:00:00"
    elif change == "date_order":
        first["updated_at"] = "2026-10-05T12:00:00Z"
    elif change == "duplicate_message":
        second["uuid"] = MID
    elif change == "duplicate_conversation":
        value.append(c)
    elif change == "foreign_parent":
        second["parent_message_uuid"] = "44444444-4444-4444-8444-444444444444"
        value.append(
            {
                **value[0],
                "uuid": "55555555-5555-4555-8555-555555555555",
                "chat_messages": [{**first, "uuid": second["parent_message_uuid"]}],
            }
        )
    elif change == "later_parent":
        first["parent_message_uuid"] = SECOND
    elif change == "self_parent":
        first["parent_message_uuid"] = MID
    elif change == "zero_message":
        first["uuid"] = str(m.ZERO_ID)
    elif change == "uppercase_id":
        first["uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".upper()
    else:
        del first["content"]
    with pytest.raises(m.ClaudeHistoryIndexError) as held:
        inspect(encoded(value))
    assert str(held.value) == "Claude history metadata unavailable"
    assert held.value.__cause__ is held.value.__context__ is None


@pytest.mark.parametrize(
    "raw",
    [
        b'[{"uuid":1,"uuid":2}]',
        b'[{"uuid":1,"\\u0075uid":2}]',
        b"[1,]",
        b"[] garbage",
        b"\xef\xbb\xbf[]",
        b'[{"x":NaN}]',
        b'[{"x":1e999}]',
        b'[{"x":"\\ud800"}]',
        b'[{"x":"\xff"}]',
    ],
)
def test_json_utf8_duplicate_escape_and_nonfinite_reject(raw):
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(raw)


def test_unknown_structured_fields_preserved_as_exact_unassessed_span():
    value = fixture()
    value[0]["chat_messages"][0]["content"] = [
        {"future_type": {"untrusted": ["do not execute", 7]}}
    ]
    raw = encoded(value)
    result = inspect(raw)
    span = result.conversations[0].messages[0].structured_content
    assert json.loads(raw[span.start : span.end]) == value[0]["chat_messages"][0]["content"]
    assert result.structured_content_assessed is False


def test_oversized_full_record_small_text_has_explicit_gap():
    value = fixture()
    value[0]["chat_messages"][0]["content"] = [{"large": "x" * (m.MAX_RECORD_BYTES + 1)}]
    result = inspect(encoded(value))
    first = result.conversations[0].messages[0]
    assert first.record.end - first.record.start > m.MAX_RECORD_BYTES
    assert (
        first.record_within_existing_byte_limit is False
        and first.held_by_byte_or_lineage_gate is True
    )
    assert result.conversations[0].messages[1].record_within_existing_byte_limit is True


def test_file_over_existing_8mb_does_not_silently_enable_small_record():
    value = fixture()
    value[0]["unassessed_padding"] = "x" * m.MAX_EXPORT_BYTES
    raw = encoded(value)
    assert len(raw) < m.MAX_INPUT_BYTES
    result = inspect(raw)
    assert result.whole_file_within_existing_byte_limit is False
    assert result.conversations[0].messages[0].record_within_existing_byte_limit is True
    assert all(x.held_by_byte_or_lineage_gate for x in result.conversations[0].messages)


@pytest.mark.parametrize(
    "bound",
    [
        "MAX_INPUT_BYTES",
        "MAX_DEPTH",
        "MAX_NODES",
        "MAX_CONVERSATIONS",
        "MAX_MESSAGES",
        "MAX_CONTENT_COMPONENTS",
    ],
)
def test_actual_structural_count_bounds_hold_without_truncation(bound, monkeypatch):
    raw = encoded()
    monkeypatch.setattr(m, bound, 1)
    if bound == "MAX_CONVERSATIONS":
        v = fixture()
        v.append({**v[0], "uuid": "55555555-5555-4555-8555-555555555555", "chat_messages": []})
        raw = encoded(v)
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(raw)


def test_original_hash_mutation_and_exact_type_hold():
    raw = encoded()
    good = inspect(raw)
    assert good.message_count == 2
    with pytest.raises(m.ClaudeHistoryIndexError):
        m.index_claude_member_history(raw + b" ", expected_file_hash=content_hash_of(raw))
    with pytest.raises(m.ClaudeHistoryIndexError):
        m.index_claude_member_history(bytearray(raw), expected_file_hash=content_hash_of(raw))


def test_72_conversations_are_inventory_not_64_record_selection():
    from zacai.history_manifest import MAX_RECORDS

    value = []
    for i in range(72):
        record = fixture()[0]
        record["uuid"] = str(UUID(int=i + 1))
        record["chat_messages"] = []
        value.append(record)
    result = inspect(encoded(value))
    assert len(result.conversations) == 72 > MAX_RECORDS == 64
    assert all(not conv.held_by_byte_or_lineage_gate for conv in result.conversations)
    assert result.source_specific_selection_implemented is False
    assert result.capture_authorized is False and result.completeness_verified is False


def test_whole_bytes_api_documents_reassembled_utf8_chunks_not_streaming():
    # Public API is whole bytes, not an incremental streaming/import API.
    raw = encoded()
    split = raw.index("😀".encode()) + 2
    pieces = (raw[:split], raw[split : split + 1], raw[split + 1 :])
    assert b"".join(pieces) == raw
    assert inspect(b"".join(pieces)) == inspect(raw)


def test_private_malformed_string_diagnostic_is_fixed_and_cause_free():
    raw = b'[{"invented_private_key":"SECRET_FIXTURE_PAYLOAD\\ud800"}]'
    with pytest.raises(m.ClaudeHistoryIndexError) as held:
        inspect(raw)
    assert "SECRET" not in str(held.value) and "private_key" not in str(held.value)
    assert held.value.__context__ is held.value.__cause__ is None


def test_cancellation_is_not_swallowed_as_ordinary_hold(monkeypatch):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(m._Walker, "node", interrupted)
    with pytest.raises(KeyboardInterrupt):
        inspect(encoded())
