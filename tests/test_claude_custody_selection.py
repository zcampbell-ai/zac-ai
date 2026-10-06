"""Invented structural companion only; no Source, human grant or custody proof."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from tests.test_claude_history_index import encoded, fixture
from zacai import claude_custody_selection as m
from zacai.claude_history_index import index_claude_member_history
from zacai.history_manifest import MAX_EXPORT_BYTES
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

EXPORTED = datetime(2026, 10, 6, 13, tzinfo=UTC)
ACCOUNT = "invented-host-account-claim"


def prepared(value=None, *, conversation=False):
    raw = encoded(fixture() if value is None else value)
    index = index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))
    record = index.conversations[0] if conversation else index.conversations[0].messages[0]
    ref = EvidenceReference(
        source_id=UUID("99999999-9999-4999-8999-999999999999"),
        content_hash=content_hash_of(raw),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    choice = {
        "original_id": str(record.original_id),
        "start": record.record.start,
        "end": record.record.end,
        "content_hash": content_hash_of(raw[record.record.start : record.record.end]),
        "reported_at": record.reported_created_at,
        "role": "CONVERSATION" if conversation else record.historical_role,
    }
    proposal = m.ClaudeCustodySelection(
        format="zac-claude-whole-original-selection-v1",
        provider="CLAUDE",
        original_reference=ref,
        original_file_hash=ref.content_hash,
        original_file_bytes=len(raw),
        account_ref=ACCOUNT,
        exported_at=EXPORTED,
        boundary=B.BRAINSTORM,
        classification=C.CONFIDENTIAL,
        boundary_scope="ONE_REVIEWED_BOUNDARY",
        coverage="SELECTED_RECORDS_ONLY",
        selections=(choice,),
    )
    return raw, ref, proposal.model_dump(mode="json")


def inspect(raw, ref, data, **expected):
    companion_raw = canonical_bytes(data)
    return m.inspect_claude_custody_selection(
        companion_raw,
        raw,
        expected_companion_hash=content_hash_of(companion_raw),
        expected_original_reference=ref,
        expected_account_ref=expected.get("account", ACCOUNT),
        expected_exported_at=expected.get("date", EXPORTED),
    )


def test_actual_indexer_record_and_reference_join_preserves_utf8_exact_bytes():
    raw, ref, data = prepared()
    result = inspect(raw, ref, data)
    selected = result.records[0]
    assert result.companion.original_reference == ref
    assert result.companion.original_file_hash == content_hash_of(raw)
    assert result.companion.original_file_bytes == len(raw)
    span = selected.selection
    assert content_hash_of(raw[span.start : span.end]) == span.content_hash
    assert "😀" in raw[span.start : span.end].decode("utf-8")
    assert selected.record_kind == "MESSAGE" and selected.lineage_complete
    assert selected.parent_status == "EXPLICIT_ZERO_ROOT"
    assert not selected.held_by_byte_or_lineage_gate
    assert (
        result.original_source_verified
        is result.original_custody_verified
        is result.capture_authorized
        is False
    )
    assert (
        result.processing_authorized
        is result.recovery_verified
        is result.fact_promotion_authorized
        is False
    )
    assert "invented" not in repr(result) and "invented" not in repr(result.companion)


def test_full_overlegacy_original_is_bound_not_relabelled_as_chunk_or_authority():
    value = fixture()
    value[0]["unassessed_padding"] = "x" * MAX_EXPORT_BYTES
    raw, ref, data = prepared(value)
    assert len(raw) > MAX_EXPORT_BYTES
    result = inspect(raw, ref, data)
    assert result.companion.original_file_hash == content_hash_of(raw)
    assert result.companion.original_file_bytes == len(raw)
    assert result.original_within_legacy_byte_limit is False
    assert result.records[0].held_by_byte_or_lineage_gate is True
    assert result.capture_authorized is result.recovery_verified is False


def test_conversation_span_uses_actual_original_record_not_message_projection():
    raw, ref, data = prepared(conversation=True)
    result = inspect(raw, ref, data)
    assert result.records[0].record_kind == "CONVERSATION"
    assert result.records[0].selection.role == "CONVERSATION"


@pytest.mark.parametrize(
    "change",
    [
        "account",
        "exported_at",
        "role",
        "record_date",
        "start",
        "end",
        "identity",
        "original_bytes",
        "provider",
        "boundary",
        "classification",
        "source_id",
    ],
)
def test_integrity_and_claimed_metadata_mismatch_hold(change):
    raw, ref, data = prepared()
    choice = data["selections"][0]
    if change == "account":
        data["account_ref"] = "other-host-claim"
    elif change == "exported_at":
        data["exported_at"] = (EXPORTED + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    elif change == "role":
        choice["role"] = "ASSISTANT"
    elif change == "record_date":
        choice["reported_at"] = (
            (EXPORTED - timedelta(minutes=59)).isoformat().replace("+00:00", "Z")
        )
    elif change == "start":
        choice["start"] += 1
        choice["content_hash"] = content_hash_of(raw[choice["start"] : choice["end"]])
    elif change == "end":
        choice["end"] -= 1
        choice["content_hash"] = content_hash_of(raw[choice["start"] : choice["end"]])
    elif change == "identity":
        choice["original_id"] = "33333333-3333-4333-8333-333333333333"
    elif change == "original_bytes":
        data["original_file_bytes"] -= 1
    elif change == "provider":
        data["provider"] = "CHATGPT"
    elif change == "boundary":
        data["boundary"] = "PERSONAL"
    elif change == "classification":
        data["classification"] = "INTERNAL"
    elif change == "source_id":
        data["original_reference"]["source_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    if change in ("exported_at", "record_date"):
        assert canonical_bytes(
            m.ClaudeCustodySelection.model_validate(data).model_dump(mode="json")
        ) == canonical_bytes(data)
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data)


def test_original_mutation_cannot_be_accepted_with_previous_companion():
    raw, ref, data = prepared()
    mutated = raw.replace(b"Invented", b"Altered!", 1)
    assert len(mutated) == len(raw)
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(mutated, ref, data)


def test_unresolved_original_parent_stays_gap_and_hold_not_guessed_root():
    value = fixture()
    value[0]["chat_messages"][0]["parent_message_uuid"] = "44444444-4444-4444-8444-444444444444"
    raw, ref, data = prepared(value)
    result = inspect(raw, ref, data)
    record = result.records[0]
    assert record.parent_id == UUID("44444444-4444-4444-8444-444444444444")
    assert record.parent_status == "UNRESOLVED_MISSING" and not record.lineage_complete
    assert record.held_by_byte_or_lineage_gate is True
    assert result.capture_authorized is result.completeness_verified is False


@pytest.mark.parametrize(
    "change", ["too_many", "oversized_record", "outside", "overlap", "overoriginal"]
)
def test_structural_caps_hold_before_indexer_parse(change, monkeypatch):
    raw, ref, data = prepared()
    choice = data["selections"][0]
    if change == "too_many":
        data["selections"] *= 65
    elif change == "oversized_record":
        data["original_file_bytes"] = 200_000
        choice["start"], choice["end"] = 1, 128_002
    elif change == "outside":
        choice["end"] = len(raw) + 1
    elif change == "overlap":
        data["selections"] += [{**choice, "original_id": "33333333-3333-4333-8333-333333333333"}]
    elif change == "overoriginal":
        data["original_file_bytes"] = m.MAX_INPUT_BYTES + 1
    calls = []
    monkeypatch.setattr(
        m, "index_claude_member_history", lambda *args, **kwargs: calls.append(True)
    )
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data)
    assert calls == []


def test_safe_fixed_public_error_and_cancellation(monkeypatch):
    raw, ref, data = prepared()
    with pytest.raises(m.ClaudeCustodySelectionError) as held:
        inspect(raw, ref, data, account="private-invented-account")
    assert "private" not in str(held.value)
    assert held.value.__cause__ is held.value.__context__ is None

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(m, "index_claude_member_history", interrupted)
    with pytest.raises(KeyboardInterrupt):
        inspect(raw, ref, data)


def test_descendant_of_missing_parent_preserves_actual_incomplete_lineage():
    value = fixture()
    value[0]["chat_messages"][0]["parent_message_uuid"] = "44444444-4444-4444-8444-444444444444"
    raw, ref, data = prepared(value)
    index = index_claude_member_history(raw, expected_file_hash=ref.content_hash)
    child = index.conversations[0].messages[1]
    data["selections"] = [
        {
            "original_id": str(child.original_id),
            "start": child.record.start,
            "end": child.record.end,
            "content_hash": content_hash_of(raw[child.record.start : child.record.end]),
            "reported_at": child.reported_created_at.isoformat().replace("+00:00", "Z"),
            "role": "ASSISTANT",
        }
    ]
    result = inspect(raw, ref, data)
    checked = result.records[0]
    assert checked.parent_status == "RESOLVED_EARLIER"
    assert checked.lineage_complete is False and checked.held_by_byte_or_lineage_gate


def test_recomputed_partial_multibyte_range_cannot_replace_full_original_record():
    raw, ref, data = prepared()
    chosen = data["selections"][0]
    chosen["start"] = raw.index("😀".encode()) + 1
    chosen["end"] = chosen["start"] + 2
    chosen["content_hash"] = content_hash_of(raw[chosen["start"] : chosen["end"]])
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(raw, ref, data)


def test_byte_capacity_guard_precedes_any_hash_or_parse(monkeypatch):
    raw, ref, data = prepared()
    companion_raw = canonical_bytes(data)
    expected_hash = content_hash_of(companion_raw)
    calls = []
    monkeypatch.setattr(m, "MAX_INPUT_BYTES", len(raw) - 1)
    monkeypatch.setattr(m, "content_hash_of", lambda value: calls.append("hash"))
    monkeypatch.setattr(
        m, "index_claude_member_history", lambda *args, **kwargs: calls.append("index")
    )
    with pytest.raises(m.ClaudeCustodySelectionError):
        m.inspect_claude_custody_selection(
            companion_raw,
            raw,
            expected_companion_hash=expected_hash,
            expected_original_reference=ref,
            expected_account_ref=ACCOUNT,
            expected_exported_at=EXPORTED,
        )
    assert calls == []


def test_invalid_original_utf8_cannot_be_promoted_by_self_consistent_reference():
    raw, ref, data = prepared()
    damaged = raw.replace("😀".encode(), b"\xff\xff\xff\xff", 1)
    declared = ref.model_copy(update={"content_hash": content_hash_of(damaged)})
    data["original_file_hash"] = declared.content_hash
    data["original_reference"] = declared.model_dump(mode="json")
    with pytest.raises(m.ClaudeCustodySelectionError):
        inspect(damaged, declared, data)


def test_numeric_metadata_token_ceiling_and_noncanonical_codec_hold_before_indexer(monkeypatch):
    raw, ref, data = prepared()
    canonical = canonical_bytes(data)
    huge = canonical.replace(str(len(raw)).encode(), b"9" * 21, 1)
    calls = []
    monkeypatch.setattr(
        m, "index_claude_member_history", lambda *args, **kwargs: calls.append(True)
    )
    for companion_raw in (huge, b" " + canonical):
        with pytest.raises(m.ClaudeCustodySelectionError):
            m.inspect_claude_custody_selection(
                companion_raw,
                raw,
                expected_companion_hash=content_hash_of(companion_raw),
                expected_original_reference=ref,
                expected_account_ref=ACCOUNT,
                expected_exported_at=EXPORTED,
            )
    assert calls == []


@pytest.mark.parametrize("fault", ["duplicate", "unknown"])
def test_closed_metadata_fault_holds_before_original_indexing(monkeypatch, fault):
    raw, ref, data = prepared()
    canonical = canonical_bytes(data)
    if fault == "duplicate":
        bad = canonical[:-1] + b',"provider":"CLAUDE"}'
    else:
        data["capture_authorized"] = True
        bad = canonical_bytes(data)
    calls = []
    monkeypatch.setattr(m, "index_claude_member_history", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeCustodySelectionError) as caught:
        m.inspect_claude_custody_selection(
            bad,
            raw,
            expected_companion_hash=content_hash_of(bad),
            expected_original_reference=ref,
            expected_account_ref=ACCOUNT,
            expected_exported_at=EXPORTED,
        )
    assert calls == []
    assert caught.value.__cause__ is caught.value.__context__ is None
