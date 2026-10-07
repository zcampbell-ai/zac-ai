"""Actual parser/quote catalog/renderer, invented canonical rows; no model/SQL."""

import json
from dataclasses import replace
from datetime import timedelta, timezone
from uuid import UUID

import pytest

from tests.test_claude_original_capture import AT
from tests.test_claude_original_read import host as host  # noqa: PLC0414 - pytest fixture export
from tests.test_claude_original_read import load
from tests.test_claude_original_read import saved as saved  # noqa: PLC0414 - pytest fixture export
from tests.test_claude_reader_current_labels import confidential, current_ref
from tests.test_local_contextual_runtime import route
from tests.test_native_evidence_context import (
    fixture as fixture,  # noqa: PLC0414 - pytest fixture export
)
from tests.test_review_generation import synthetic_context
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import history_context_metadata as m
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog
from zacai.intelligence.contracts import IntelligenceTask, ProcessingStatus
from zacai.intelligence.local_contextual_runtime import LocalContextualRuntimeError, prepare_payload
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def base():
    context = synthetic_context(boundary=B.PERSONAL, classification=C.CONFIDENTIAL)
    task = IntelligenceTask.model_validate(
        {
            **context.task.model_dump(),
            "required_capabilities": frozenset({"contextual_meeting_review"}),
        }
    )
    return ReviewContext(task, context.meeting_source_id, context.related_source_ids)


def prepare(context, read, **changes):
    values = {"character_start": 0, "character_end": 1, "observed_at": AT, "route": route()}
    values.update(changes)
    values["selections"] = (
        m.HistoryMessageSpan(
            message_id=UUID(read.proposal.selections[0].original_id),
            character_start=values.pop("character_start"),
            character_end=values.pop("character_end"),
        ),
    )
    return m.prepare_claude_history_context_preview(context, read, **values)


def test_actual_history_context_prompt_quotes_and_metadata_are_separate(saved):
    saved = confidential(saved)
    saved[0].rows[1]["effective"] = C.HIGHLY_RESTRICTED
    read = load(
        saved,
        companion_reference=current_ref(saved[0].rows[1]),
        allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
    )
    original = base()
    snapshot = original.task.model_dump_json()
    preview = prepare(original, read)
    metadata = preview.sidecar.entries[0]
    assert type(metadata) is m.ClaudeMessageMetadata
    assert metadata.original_binding_reference == read.original_binding_reference
    assert metadata.current_original_reference == read.original_reference
    assert metadata.current_companion_reference == read.companion_reference
    assert metadata.envelope_hash == read.companion_reference.content_hash
    assert metadata.joint_output_classification == C.HIGHLY_RESTRICTED
    assert preview.context.task.event.data_classification == C.HIGHLY_RESTRICTED
    assert preview.original_task.model_dump_json() == snapshot == original.task.model_dump_json()
    assert preview.context.task.task_id != original.task.task_id
    assert preview.context.task.event.event_id != original.task.event.event_id
    assert preview.context.task.event.causation_id == original.task.event.event_id
    assert preview.context.task.event.correlation_id == original.task.event.correlation_id
    assert preview.context.task.required_capabilities == original.task.required_capabilities
    assert preview.context.task.instruction == original.task.instruction
    assert preview.context.task.max_output_tokens == original.task.max_output_tokens
    assert preview.context.task.event.processing_status is ProcessingStatus.NEW
    catalog = _prepare_contextual_catalog(preview.context)
    item = preview.context.task.context[-1]
    assert item.reference.source_id == read.original_reference.source_id  # no invented source
    assert item.reference.content_hash == content_hash_of(read.original_raw)
    assert len(item.untrusted_text) == 1
    assert content_hash_of(item.untrusted_text.encode()) == metadata.selected_text_hash
    body = json.loads(preview.prompt_body)
    data = json.loads(body["messages"][1]["content"])
    assert data["provider_passages"] == json.loads(catalog.evidence_json)
    model_meta = data["history_metadata"][0]
    assert model_meta["historical_role"] == "USER"
    assert (
        model_meta["reported_created_at"] == metadata.model_dump(mode="json")["reported_created_at"]
    )
    assert model_meta["current_fact"] is False and model_meta["citable"] is False
    assert all(
        not key.endswith("hash") and "reference" not in key and "classification" not in key
        for key in model_meta
    )
    assert str(read.original_reference.source_id) not in json.dumps(model_meta)
    assert "historical_role" not in catalog.evidence_json
    assert all(
        q.text == item.untrusted_text[q.start : q.end]
        for _, q in catalog.quotes
        if q.source_id == item.reference.source_id
    )
    # One-character text is correctly noncitable; metadata cannot manufacture a catalog ID.
    assert model_meta["passage_ids"] == []
    assert (
        preview.processing_authorized
        is preview.recovery_verified
        is preview.current_facts_verified
        is False
    )
    with pytest.raises(LocalContextualRuntimeError):
        prepare_payload(preview, route(), "0" * 64)


def test_identity_replay_and_observation_change_preserve_original(saved):
    original, read = base(), load(saved)
    a = prepare(original, read)
    assert prepare(original, read).prompt_body == a.prompt_body
    b = prepare(original, read, observed_at=AT + timedelta(seconds=1))
    assert a.context.task.task_id != b.context.task.task_id
    assert a.context.task.event.event_id != b.context.task.event.event_id
    assert a.original_task == b.original_task == original.task
    assert a.context.task.context == b.context.task.context


def test_whole_payload_capacity_hold_without_truncation(saved):
    original, read = base(), load(saved)
    prepared = prepare(original, read)
    exact = len(prepared.prompt_body.decode())
    assert prepare(
        original, read, route=route().model_copy(update={"max_input_characters": exact})
    ).prompt_body
    with pytest.raises(m.HistoryContextError):
        prepare(
            original, read, route=route().model_copy(update={"max_input_characters": exact - 1})
        )


@pytest.mark.parametrize("fault", ["envelope", "current", "joint", "junk"])
def test_tampered_or_junk_input_holds_cause_free(saved, fault):
    read = load(saved)
    valid_selections = (
        m.HistoryMessageSpan(
            message_id=UUID(read.proposal.selections[0].original_id),
            character_start=0,
            character_end=1,
        ),
    )
    if fault == "envelope":
        read = replace(read, envelope_raw=read.envelope_raw + b" ")
    elif fault == "current":
        read = replace(
            read,
            original_reference=read.original_reference.model_copy(
                update={"content_hash": "0" * 64}
            ),
        )
    elif fault == "joint":
        read = replace(read, joint_output_classification=C.PUBLIC)
    else:
        read = object()
    with pytest.raises(m.HistoryContextError) as error:
        if fault == "junk":
            m.prepare_claude_history_context_preview(
                base(), read, selections=valid_selections, observed_at=AT, route=route()
            )
        else:
            prepare(base(), read)
    assert error.value.__context__ is None


def test_metadata_false_flags_are_exact_and_not_authority(saved):
    preview = prepare(base(), load(saved))
    metadata = preview.sidecar.entries[0].model_dump()
    for key in ("current_fact", "sender_authenticated", "citable"):
        with pytest.raises(ValueError):
            m.ClaudeMessageMetadata.model_validate({**metadata, key: True})
        with pytest.raises(ValueError):
            m.ClaudeMessageMetadata.model_validate({**metadata, key: 0})


@pytest.mark.parametrize("sender, expected_role", [("human", "USER"), ("assistant", "ASSISTANT")])
def test_citable_unicode_selection_maps_claimed_role_dates_only_to_actual_passages(
    host, monkeypatch, sender, expected_role
):
    from tests import test_claude_original_read as reader_test
    from tests.test_claude_history_index import fixture
    from tests.test_claude_original_capture import inputs

    value = fixture()
    value[0]["chat_messages"][0]["sender"] = sender
    text = value[0]["chat_messages"][0]["text"]
    monkeypatch.setattr(reader_test, "inputs", lambda: inputs(value))
    saved = reader_test.saved.__wrapped__(host, monkeypatch)
    read = load(saved)
    start = len("Invented 😀 ")
    preview = prepare(base(), read, character_start=start, character_end=len(text))
    entry = preview.sidecar.entries[0]
    data = json.loads(json.loads(preview.prompt_body)["messages"][1]["content"])
    meta = data["history_metadata"][0]
    catalog = _prepare_contextual_catalog(preview.context)
    actual_quotes = [
        (pid, q) for pid, q in catalog.quotes if q.source_id == read.original_reference.source_id
    ]
    assert actual_quotes and meta["passage_ids"] == [pid for pid, _ in actual_quotes]
    assert meta["historical_role"] == expected_role
    assert entry.character_start == start and entry.decoded_utf8_start == len(text[:start].encode())
    assert entry.decoded_utf8_end == len(text.encode())
    assert entry.omitted_prefix_characters == start and entry.omitted_suffix_characters == 0
    actual_item = preview.context.task.context[-1]
    assert actual_item.untrusted_text == text[start:]
    assert entry.selected_text_hash == content_hash_of(actual_item.untrusted_text.encode())
    assert all(q.text == actual_item.untrusted_text[q.start : q.end] for _, q in actual_quotes)
    assert expected_role not in catalog.evidence_json
    assert meta["reported_created_at"] not in catalog.evidence_json
    assert data["provider_passages"] == json.loads(catalog.evidence_json)
    assert meta["current_fact"] is False and meta["sender_authenticated"] is False
    assert (
        "Assistant suggestions are not user preferences"
        in json.loads(preview.prompt_body)["messages"][0]["content"]
    )


def multi_read(host, monkeypatch, texts):
    """Actual canonical capture/read/parser mechanics, invented scalar persistence."""
    from tests import test_claude_original_read as reader_test
    from tests.test_claude_history_index import encoded, fixture
    from tests.test_claude_original_capture import CID
    from zacai.claude_history_index import index_claude_member_history
    from zacai.claude_original_capture import prepare_claude_custody_proposal
    from zacai.history_manifest import HistorySelection

    value = fixture()
    example = value[0]["chat_messages"][0]
    messages = []
    for i, (sender, text) in enumerate(texts):
        mid = UUID(int=100 + i)
        parent = UUID(int=0 if i == 0 else 99 + i)
        messages.append(
            {
                **example,
                "uuid": str(mid),
                "sender": sender,
                "text": text,
                "parent_message_uuid": str(parent),
                "created_at": f"2026-10-0{i + 1}T12:00:00Z",
                "updated_at": f"2026-10-0{i + 1}T12:00:00Z",
            }
        )
    value[0]["chat_messages"] = messages
    value[0]["created_at"] = messages[0]["created_at"]
    value[0]["updated_at"] = messages[-1]["updated_at"]
    raw = encoded(value)
    index = index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))
    choices = tuple(
        HistorySelection(
            original_id=str(message.original_id),
            start=message.record.start,
            end=message.record.end,
            content_hash=content_hash_of(raw[message.record.start : message.record.end]),
            reported_at=message.reported_created_at,
            role=message.historical_role,
        )
        for message in index.conversations[0].messages
    )
    proposal = prepare_claude_custody_proposal(
        custody_id=CID,
        original_raw=raw,
        account_ref="invented-reported-account",
        exported_at=AT,
        acquired_at=AT,
        captured_at=AT,
        boundary=B.PERSONAL,
        classification=C.HIGHLY_RESTRICTED,
        selections=choices,
    )
    monkeypatch.setattr(reader_test, "inputs", lambda: (raw, proposal))
    saved = reader_test.saved.__wrapped__(host, monkeypatch)
    return load(saved), tuple(
        m.HistoryMessageSpan(
            message_id=UUID(message["uuid"]), character_start=0, character_end=len(message["text"])
        )
        for message in messages
    )


def test_five_messages_one_original_source_actual_prompt_roles_dates_correction_and_conflict(
    host, monkeypatch
):
    values = [
        ("human", "My studio is named Oak."),
        ("assistant", "You could rename the studio Pine."),
        ("human", "Correction: the studio name is Cedar."),
        ("human", "The Aurora contract uses Cedar."),
        ("human", "The Aurora contract uses Birch."),
    ]
    read, selections = multi_read(host, monkeypatch, values)
    original = base()
    preview = m.prepare_claude_history_context_preview(
        original,
        read,
        selections=selections,
        observed_at=AT,
        route=route().model_copy(update={"max_input_characters": 32000}),
    )
    catalog = _prepare_contextual_catalog(preview.context)
    quotes = [
        (pid, q) for pid, q in catalog.quotes if q.source_id == read.original_reference.source_id
    ]
    assert len(quotes) == 5
    assert (
        sum(
            item.reference.source_id == read.original_reference.source_id
            for item in preview.context.task.context
        )
        == 1
    )
    assert len({item.reference.source_id for item in preview.context.task.context}) == len(
        preview.context.task.context
    )
    body = json.loads(preview.prompt_body)
    data = json.loads(body["messages"][1]["content"])
    assert [entry["historical_role"] for entry in data["history_metadata"]] == [
        "USER",
        "ASSISTANT",
        "USER",
        "USER",
        "USER",
    ]
    assert len({entry["reported_created_at"] for entry in data["history_metadata"]}) == 5
    assert (
        preview.original_task == original.task
        and preview.context.task.task_id != original.task.task_id
    )
    assert len(preview.projection_profiles) == 5
    for i, (metadata, (pid, q), raw_profile) in enumerate(
        zip(preview.sidecar.entries, quotes, preview.projection_profiles, strict=True)
    ):
        assert metadata.message_id == selections[i].message_id
        assert metadata.current_original_reference == read.original_reference
        assert metadata.current_companion_reference == read.companion_reference
        assert metadata.original_binding_reference == read.original_binding_reference
        assert metadata.profile_hash == content_hash_of(raw_profile)
        assert data["history_metadata"][i]["passage_ids"] == [pid]
        assert q.text == values[i][1]
        assert (
            q.start == metadata.context_character_start and q.end == metadata.context_character_end
        )
        original_record = json.loads(
            read.original_raw[metadata.record_byte_start : metadata.record_byte_end]
        )
        assert UUID(original_record["uuid"]) == metadata.message_id
        assert metadata.record_hash == content_hash_of(
            read.original_raw[metadata.record_byte_start : metadata.record_byte_end]
        )
        assert metadata.selected_text_hash == content_hash_of(values[i][1].encode())
        assert metadata.current_fact is metadata.sender_authenticated is metadata.citable is False
        assert data["history_metadata"][i]["reported_created_at"] not in q.text
    assert data["provider_passages"] == json.loads(catalog.evidence_json)
    assert "historical_role" not in catalog.evidence_json
    assert preview.context.task.context[-1].reference.content_hash == content_hash_of(
        read.original_raw
    )
    # No semantic quality or owner confirmation follows from exact spans.
    assert (
        preview.current_facts_verified
        is preview.processing_authorized
        is preview.recovery_verified
        is False
    )


def test_duplicate_message_selection_holds_without_inventing_duplicate_sources(saved):
    read = load(saved)
    selection = m.HistoryMessageSpan(
        message_id=UUID(read.proposal.selections[0].original_id), character_start=0, character_end=1
    )
    with pytest.raises(m.HistoryContextError):
        m.prepare_claude_history_context_preview(
            base(), read, selections=(selection, selection), observed_at=AT, route=route()
        )


def test_catalog_pack_cross_message_boundary_holds_instead_of_mixed_role_metadata(
    host, monkeypatch
):
    text = "\n".join("Invented evidence line" for _ in range(126))
    read, selections = multi_read(host, monkeypatch, [("human", text), ("assistant", text)])
    assert all(selection.character_end <= 8000 for selection in selections)
    actual_catalog = m._prepare_contextual_catalog
    crossing = []

    def observed_catalog(context):
        request = actual_catalog(context)
        crossing.extend(
            q
            for _, q in request.quotes
            if q.source_id == read.original_reference.source_id and q.start < len(text) < q.end
        )
        return request

    monkeypatch.setattr(m, "_prepare_contextual_catalog", observed_catalog)
    outcome = None
    try:
        m.prepare_claude_history_context_preview(
            base(),
            read,
            selections=selections,
            observed_at=AT,
            route=route().model_copy(update={"max_input_characters": 64000}),
        )
    except m.HistoryContextError as error:
        outcome = error
    assert crossing  # actual packed catalog crosses original message boundary
    assert outcome is not None


def test_permitted_five_message_preview_preserves_declared_smaller_route_hold(host, monkeypatch):
    read, selections = multi_read(host, monkeypatch, [("human", "Dated reported claim.")] * 5)
    with pytest.raises(m.HistoryContextError):
        m.prepare_claude_history_context_preview(
            base(), read, selections=selections, observed_at=AT, route=route()
        )
    good = m.prepare_claude_history_context_preview(
        base(),
        read,
        selections=selections,
        observed_at=AT,
        route=route().model_copy(update={"max_input_characters": 32000}),
    )
    assert 20000 < len(good.prompt_body.decode()) < 32000
    assert good.context.task.max_output_tokens == good.original_task.max_output_tokens
    assert good.context.task.max_latency_ms == good.original_task.max_latency_ms
    assert good.context.task.max_estimated_cost_usd == good.original_task.max_estimated_cost_usd


def test_same_instant_preview_observation_has_identical_bytes_and_identity(saved):
    original, read = base(), load(saved)
    normal = prepare(original, read)
    offset = prepare(original, read, observed_at=AT.astimezone(timezone(timedelta(hours=3))))
    assert normal == offset


def test_group_current_observations_cannot_diverge_and_capacity_is_not_truncated(saved):
    entry = prepare(base(), load(saved)).sidecar.entries[0]
    sibling = entry.model_copy(update={"message_id": UUID(int=123)})
    good = m.HistoryContextSidecar(
        format="zac-history-context-sidecar-v2", entries=(entry, sibling)
    )
    assert len(good.entries) == 2
    changed = sibling.model_copy(update={"original_tip_id": UUID(int=999)})
    with pytest.raises(ValueError):
        m.HistoryContextSidecar(format=good.format, entries=(entry, changed))
    too_many_bytes = tuple(
        entry.model_copy(update={"message_id": UUID(int=i + 1)}) for i in range(20)
    )
    assert len(m.canonical_bytes([e.model_dump(mode="json") for e in too_many_bytes])) > 16000
    with pytest.raises(ValueError):
        m.HistoryContextSidecar(format=good.format, entries=too_many_bytes)


def test_native_metadata_union_preserves_exact_legacy_sidecar_bytes(fixture):
    from tests.test_native_context_sidecar import request
    from zacai.intelligence.native_context_metadata import (
        decode_native_sidecar,
        encode_native_sidecar,
    )

    native = request(fixture).sidecar
    before = encode_native_sidecar(native)
    union = m.HistoryContextSidecar(format="zac-history-context-sidecar-v2", entries=native.entries)
    assert union.entries == native.entries
    assert decode_native_sidecar(before) == native
    assert encode_native_sidecar(native) == before
