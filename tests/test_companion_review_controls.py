"""Invented review discriminants; no actual archive or authority."""

from dataclasses import fields, replace
from datetime import timedelta

import pytest

from tests.test_claude_custody_selection import EXPORTED, inspect, prepared
from tests.test_claude_history_index import fixture
from zacai import claude_custody_selection as m
from zacai.claude_history_index import index_claude_member_history
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import TrustBoundary as B


def assert_canonical(data):
    assert canonical_bytes(
        m.ClaudeCustodySelection.model_validate(data).model_dump(mode="json")
    ) == canonical_bytes(data)


@pytest.mark.parametrize("field", ["created_at", "updated_at"])
def test_reported_selected_record_date_cannot_follow_known_export(field):
    value = fixture()
    if field == "created_at":
        raw, ref, data = prepared(value)
        earlier = EXPORTED - timedelta(hours=2)
    else:
        value[0]["chat_messages"][0]["updated_at"] = "2026-10-06T12:30:00Z"
        raw, ref, data = prepared(value)
        earlier = EXPORTED - timedelta(minutes=45)
    assert inspect(raw, ref, data).records
    data["exported_at"] = earlier.isoformat().replace("+00:00", "Z")
    assert_canonical(data)
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data, date=earlier)


def test_shared_whole_original_not_one_reviewed_private_boundary():
    raw, ref, data = prepared()
    assert inspect(raw, ref, data).records
    shared = EvidenceReference(
        source_id=ref.source_id,
        content_hash=ref.content_hash,
        trust_boundary=B.SHARED,
        effective_classification=ref.effective_classification,
    )
    data["boundary"] = "SHARED"
    data["original_reference"] = shared.model_dump(mode="json")
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, shared, data)


@pytest.mark.parametrize(
    "flag",
    [
        f.name
        for f in fields(m.ClaudeCustodyInspection)
        if f.name.endswith(("_verified", "_authorized"))
    ],
)
def test_false_flags_cannot_be_constructor_or_replace_overrides(flag):
    raw, ref, data = prepared()
    result = inspect(raw, ref, data)
    assert getattr(result, flag) is False
    with pytest.raises(TypeError):
        m.ClaudeCustodyInspection(
            result.companion,
            result.companion_hash,
            result.records,
            result.original_within_legacy_byte_limit,
            **{flag: True},
        )
    with pytest.raises(ValueError):
        replace(result, **{flag: True})


def test_correct_full_span_wrong_record_hash_is_discriminating():
    raw, ref, data = prepared()
    assert inspect(raw, ref, data).records
    data["selections"][0]["content_hash"] = "0" * 64
    assert_canonical(data)
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data)


def test_two_conversations_message_and_conversation_exact_positive():
    value = fixture()
    second = dict(value[0], uuid="44444444-4444-4444-8444-444444444444", chat_messages=[])
    value.append(second)
    raw, ref, data = prepared(value)
    index = index_claude_member_history(raw, expected_file_hash=ref.content_hash)
    conv = index.conversations[1]
    data["selections"].append(
        {
            "original_id": str(conv.original_id),
            "start": conv.record.start,
            "end": conv.record.end,
            "content_hash": content_hash_of(raw[conv.record.start : conv.record.end]),
            "reported_at": "2026-10-06T12:00:00Z",
            "role": "CONVERSATION",
        }
    )
    assert_canonical(data)
    result = inspect(raw, ref, data)
    assert [r.record_kind for r in result.records] == ["MESSAGE", "CONVERSATION"]
    assert result.records[1].selection.original_id == str(conv.original_id)


def test_null_export_date_positive_and_expected_side_mismatch():
    raw, ref, data = prepared()
    data["exported_at"] = None
    assert_canonical(data)
    assert inspect(raw, ref, data, date=None).records
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data, date=EXPORTED)
    raw, ref, data = prepared()
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data, date=None)


@pytest.mark.parametrize("kind", ["conversation_wrong_role", "message_conversation_role", "nested"])
def test_selection_role_and_nested_original_record_hold(kind):
    raw, ref, data = prepared(conversation=kind == "conversation_wrong_role")
    assert inspect(raw, ref, data).records
    if kind == "conversation_wrong_role":
        data["selections"][0]["role"] = "USER"
    elif kind == "message_conversation_role":
        data["selections"][0]["role"] = "CONVERSATION"
    else:
        index = index_claude_member_history(raw, expected_file_hash=ref.content_hash)
        conv = index.conversations[0]
        data["selections"].append(
            {
                "original_id": str(conv.original_id),
                "start": conv.record.start,
                "end": conv.record.end,
                "content_hash": content_hash_of(raw[conv.record.start : conv.record.end]),
                "reported_at": "2026-10-06T12:00:00Z",
                "role": "CONVERSATION",
            }
        )
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data)


def test_metadata_numeric_token_bound_is_checked_before_integer_conversion():
    assert m._integer("9" * 20) == int("9" * 20)
    with pytest.raises(ValueError, match="bounded metadata integer required"):
        m._integer("9" * 21)


def test_all_inspection_flags_are_fixed_false_metadata():
    flags = [
        f
        for f in fields(m.ClaudeCustodyInspection)
        if f.name.endswith(("_verified", "_authorized"))
    ]
    assert len(flags) == 9
    assert all(f.default is False and not f.init for f in flags)
