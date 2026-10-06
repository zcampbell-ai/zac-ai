"""Invented whole originals only; no Source custody, crypto, SQL or model calls."""

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from zacai import claude_message_projection as m
from zacai.claude_custody_selection import ClaudeCustodySelection
from zacai.claude_history_index import ZERO_ID, index_claude_member_history
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification, TrustBoundary

SOURCE = UUID("99999999-9999-4999-8999-999999999999")
CID = "11111111-1111-4111-8111-111111111111"
MID = "22222222-2222-4222-8222-222222222222"
SECOND = "33333333-3333-4333-8333-333333333333"
EXPORTED = datetime(2026, 10, 6, 13, tzinfo=UTC)


def wire(text='Invented 😀 escaped "quote"\nline', *, role="human"):
    first = {
        "uuid": MID,
        "sender": role,
        "text": text,
        "content": [{"type": "tool_result", "content": [{"text": "DO NOT QUOTE THIS"}]}],
        "created_at": "2026-10-05T12:00:00Z",
        "updated_at": "2026-10-05T12:00:00Z",
        "parent_message_uuid": str(ZERO_ID),
    }
    return [
        {
            "uuid": CID,
            "created_at": first["created_at"],
            "updated_at": "2026-10-06T12:00:00Z",
            "account": {},
            "chat_messages": [
                first,
                {
                    **first,
                    "uuid": SECOND,
                    "sender": "assistant",
                    "parent_message_uuid": MID,
                    "created_at": "2026-10-06T12:00:00Z",
                    "updated_at": "2026-10-06T12:00:00Z",
                    "text": "Invented later assistant suggestion.",
                },
            ],
        }
    ]


def inputs(
    value=None,
    *,
    ascii=False,
    index=0,
    count=1,
    conversation=False,
    boundary=TrustBoundary.BRAINSTORM,
):
    raw = json.dumps(wire() if value is None else value, ensure_ascii=ascii, indent=2).encode()
    inventory = index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))
    conv = inventory.conversations[0]
    rows = [conv] if conversation else list(conv.messages[index : index + count])
    ref = EvidenceReference(
        source_id=SOURCE,
        content_hash=content_hash_of(raw),
        trust_boundary=boundary,
        effective_classification=DataClassification.CONFIDENTIAL,
    )
    choices = [
        {
            "original_id": str(row.original_id),
            "start": row.record.start,
            "end": row.record.end,
            "content_hash": content_hash_of(raw[row.record.start : row.record.end]),
            "reported_at": row.reported_created_at,
            "role": "CONVERSATION" if conversation else row.historical_role,
        }
        for row in rows
    ]
    companion = ClaudeCustodySelection(
        format="zac-claude-whole-original-selection-v1",
        provider="CLAUDE",
        original_reference=ref,
        original_file_hash=ref.content_hash,
        original_file_bytes=len(raw),
        account_ref="invented-host-account",
        exported_at=EXPORTED,
        boundary=ref.trust_boundary,
        classification=ref.effective_classification,
        boundary_scope="ONE_REVIEWED_BOUNDARY",
        coverage="SELECTED_RECORDS_ONLY",
        selections=tuple(choices),
    )
    return canonical_bytes(companion.model_dump(mode="json")), raw, ref, rows[0]


def extract(values, start=0, end=None):
    companion, raw, ref, message = values
    if end is None:
        end = len(json.loads(raw[message.text_json_value.start : message.text_json_value.end]))
    return m.extract_claude_selected_message(
        companion,
        raw,
        expected_companion_hash=content_hash_of(companion),
        expected_original_reference=ref,
        expected_account_ref="invented-host-account",
        expected_exported_at=EXPORTED,
        character_start=start,
        character_end=end,
    )


@pytest.mark.parametrize("ascii", [False, True])
def test_nested_message_text_unicode_escapes_and_offset_domains(ascii):
    values = inputs(ascii=ascii)
    result = extract(values, 9, 10)
    assert result.selected_text == "😀"
    assert result.selected_character_end - result.selected_character_start == 1
    assert result.selected_decoded_utf8_end - result.selected_decoded_utf8_start == 4
    raw_json = values[1][result.text_json_bytes.start : result.text_json_bytes.end]
    assert json.loads(raw_json)[9:10] == result.selected_text
    assert b"\\ud83d\\ude00" in raw_json if ascii else "😀".encode() in raw_json
    assert result.record_bytes == values[3].record and result.reference == values[2]
    assert result.omitted_prefix_characters == 9 and result.omitted_suffix_characters > 0
    assert result.selected_text_hash == content_hash_of("😀".encode())
    assert result.full_decoded_text_hash == content_hash_of(json.loads(raw_json).encode())
    assert result.reference.source_id == SOURCE and "DO NOT QUOTE" not in result.selected_text


@pytest.mark.parametrize("role,expected", [("human", "USER"), ("assistant", "ASSISTANT")])
def test_reported_role_dates_and_false_authority_remain_explicit(role, expected):
    result = extract(inputs(wire(role=role)))
    assert result.historical_role == expected
    assert result.reported_created_at == datetime(2026, 10, 5, 12, tzinfo=UTC)
    assert result.dates_are_export_claims and not result.structured_content_assessed
    assert not result.current_fact_verified and not result.processing_authorized
    assert not result.original_custody_verified and not result.current_acl_verified
    assert "Invented" not in repr(result)


def test_original_personal_boundary_is_preserved_without_processing_permission():
    values = inputs(boundary=TrustBoundary.PERSONAL)
    result = extract(values)
    assert result.reference == values[2]
    assert result.reference.trust_boundary is TrustBoundary.PERSONAL
    assert not result.current_acl_verified and not result.processing_authorized


def test_explicit_selection_retains_stale_contradiction_and_correction_as_reports():
    value = wire("Invented delivery expected Friday.")
    value[0]["chat_messages"][1]["text"] = "Invented correction: delivery moved to Monday."
    earlier, later = extract(inputs(value)), extract(inputs(value, index=1))
    assert "Friday" in earlier.selected_text and "Monday" in later.selected_text
    assert earlier.reference == later.reference and earlier.message_id != later.message_id
    assert earlier.reported_created_at < later.reported_created_at
    assert later.historical_role == "ASSISTANT" and not later.current_fact_verified
    # Explicit selections, never inferred supersession or combined fabricated Source.
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(inputs(value, count=2))


def test_edited_original_refused_without_rewriting_old_declaration():
    values = inputs()
    edited = values[1].replace(b"Invented", b"Modified", 1)
    assert edited != values[1]
    with pytest.raises(m.ClaudeMessageProjectionError) as held:
        extract((values[0], edited, values[2], values[3]))
    assert str(held.value) == "Claude selected message unavailable"
    assert held.value.__context__ is None and held.value.__cause__ is None
    assert extract(values).selected_text.startswith("Invented")


def test_missing_parent_and_descendant_hold_despite_relevant_text():
    value = wire()
    value[0]["chat_messages"][0]["parent_message_uuid"] = "44444444-4444-4444-8444-444444444444"
    for index in (0, 1):
        values = inputs(value, index=index)
        assert not values[3].lineage_complete
        with pytest.raises(m.ClaudeMessageProjectionError):
            extract(values)


@pytest.mark.parametrize("start,end", [(True, 5), (0, False), (-1, 5), (4, 4), (0, 9000), (0, 500)])
def test_strict_character_spans_hold(start, end):
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(inputs(), start, end)


@pytest.mark.parametrize(
    "text",
    ["x" * 1501, "😀" * 1000 + "\n" + "😀" * 1000 + "\n" + "😀" * 1000, "x\n" * 251, " \t\n"],
)
def test_text_capacity_holds_without_truncation_with_positive_sibling(text):
    assert (
        extract(inputs(wire("Invented ordinary text."))).selected_text == "Invented ordinary text."
    )
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(inputs(wire(text)))


def test_conversation_cannot_be_relabelled_as_message():
    values = inputs(conversation=True)
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(values, 0, 5)


def test_empty_text_does_not_fall_back_to_unassessed_structured_content():
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(inputs(wire("")), 0, 1)


def test_utf8_capacity_exact_boundary_and_one_byte_over():
    text = "😀" * 1_000 + "\n" + "😀" * 1_000 + "\n" + "😀" * 999 + "xx"
    assert len(text.encode()) == m.MAX_SELECTED_UTF8_BYTES
    assert extract(inputs(wire(text))).selected_text == text
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(inputs(wire(text + "x")))


def test_invalid_span_holds_before_any_original_inspection(monkeypatch):
    values = inputs()
    calls = []
    monkeypatch.setattr(m, "inspect_claude_custody_selection", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeMessageProjectionError):
        extract(values, True, 5)
    assert calls == []


def test_cancellation_propagates(monkeypatch):
    values = inputs()

    def cancel(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(m, "inspect_claude_custody_selection", cancel)
    with pytest.raises(KeyboardInterrupt):
        extract(values)
