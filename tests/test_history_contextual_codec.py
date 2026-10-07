"""Actual invented parser/profile/context/catalog, no SQL/model/authority."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414 - pytest fixture export
from tests.test_history_context_metadata import base, multi_read
from tests.test_local_contextual_runtime import route
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_contextual_codec as c
from zacai.intelligence.contextual_evaluation import decode_contextual_packet_any
from zacai.intelligence.contextual_generation import (
    _prepare_contextual_catalog,
    prepare_contextual_request,
)
from zacai.intelligence.contextual_review import ContextualReview
from zacai.intelligence.history_context_metadata import prepare_claude_history_context_preview
from zacai.intelligence.meeting_review import Claim


@pytest.fixture
def prepared(host, monkeypatch):
    read, selections = multi_read(
        host,
        monkeypatch,
        [
            ("human", "Use short source-backed paragraphs."),
            ("assistant", "Consider a long generic essay."),
            ("human", "Correction: use three short paragraphs."),
        ],
    )
    original = base()
    selected_route = route().model_copy(update={"max_input_characters": 32000})
    preview = prepare_claude_history_context_preview(
        original, read, selections=selections, observed_at=read.captured_at, route=selected_route
    )
    request = c.prepare_history_contextual_request(
        preview, original_context=original, route=selected_route
    )
    return original, read, preview, request


def test_request_roundtrip_exact_prompt_all_profiles_and_complete_provenance(prepared):
    original, read, preview, request = prepared
    raw = c.encode_history_contextual_request(request)
    restored = c.decode_history_contextual_request(raw)
    assert restored == request and c.encode_history_contextual_request(restored) == raw
    assert restored.context() == preview.context
    assert restored.original_context() == original
    assert tuple(p.encode() for p in restored.projection_profiles) == preview.projection_profiles
    assert restored.task.event.provenance == (
        *original.task.event.provenance,
        read.original_reference,
        read.companion_reference,
    )
    assert restored.prompt_body.encode() == preview.prompt_body
    catalog = _prepare_contextual_catalog(restored.context())
    user = json.loads(json.loads(restored.prompt_body)["messages"][1]["content"])
    assert user["provider_passages"] == json.loads(catalog.evidence_json)
    assert [e["historical_role"] for e in user["history_metadata"]] == ["USER", "ASSISTANT", "USER"]
    assert "historical_role" not in catalog.evidence_json
    assert (
        restored.processing_authorized
        is restored.recovery_verified
        is restored.current_facts_verified
        is False
    )


@pytest.mark.parametrize(
    "fault",
    ["role", "date", "span", "ref", "hash", "profile", "body", "union", "task", "route", "flag"],
)
def test_mutated_request_holds_after_actual_fault_milestone(prepared, fault):
    request = prepared[-1]
    data = json.loads(c.encode_history_contextual_request(request))
    e = data["sidecar"]["entries"][0]
    if fault == "role":
        e["historical_role"] = "ASSISTANT"
    elif fault == "date":
        e["reported_updated_at"] = "2020-01-01T00:00:00Z"
    elif fault == "span":
        e["text_json_byte_start"] += 1
    elif fault == "ref":
        e["current_companion_reference"]["content_hash"] = "1" * 64
    elif fault == "hash":
        e["profile_hash"] = "1" * 64
    elif fault == "profile":
        data["projection_profiles"][0] += " "
    elif fault == "body":
        data["prompt_body"] += " "
        data["prompt_digest"] = content_hash_of(data["prompt_body"].encode())
    elif fault == "union":
        data["task"]["event"]["provenance"].pop()
    elif fault == "task":
        data["task"]["instruction"] += " altered"
    elif fault == "route":
        data["route"]["identity"]["model_id"] += " altered"
    else:
        data["processing_authorized"] = True
    altered = canonical_bytes(data)
    assert altered != c.encode_history_contextual_request(request)
    with pytest.raises(c.HistoryContextualCodecError) as caught:
        c.decode_history_contextual_request(altered)
    assert caught.value.__cause__ is caught.value.__context__ is None


def review_for(request):
    context = request.context()
    q = next(
        q
        for _, q in _prepare_contextual_catalog(context).quotes
        if q.source_id == context.meeting_source_id
    )
    return ContextualReview(
        format="zac-contextual-review-v1",
        task_id=context.task.task_id,
        data_classification=context.task.event.data_classification,
        overview=(Claim(text="The selected meeting reports this dated work.", quotes=(q,)),),
    )


def test_packet_roundtrip_digests_review_and_no_legacy_acceptance(prepared):
    request = prepared[-1]
    raw = c.encode_history_contextual_packet(
        review_for(request),
        request,
        builder_id=uuid4(),
        created_at=request.task.event.observed_at + timedelta(seconds=1),
    )
    p = c.decode_history_contextual_packet(raw)
    assert p.request() == request
    assert p.request_digest == content_hash_of(c.encode_history_contextual_request(request))
    assert p.rendered_preview.startswith("Contextual overview")
    assert p.processing_authorized is p.recovery_verified is p.current_facts_verified is False
    with pytest.raises(ValueError):
        decode_contextual_packet_any(raw)
    with pytest.raises(ValueError):
        prepare_contextual_request(request.context())


@pytest.mark.parametrize(
    "fault", ["request", "request_digest", "review", "context", "render", "created", "flag"]
)
def test_packet_mutations_hold(prepared, fault):
    request = prepared[-1]
    raw = c.encode_history_contextual_packet(
        review_for(request),
        request,
        builder_id=uuid4(),
        created_at=request.task.event.observed_at + timedelta(seconds=1),
    )
    data = json.loads(raw)
    if fault == "request":
        data["request_json"] += " "
    elif fault == "request_digest":
        data["request_digest"] = "1" * 64
    elif fault == "review":
        data["review"]["overview"][0]["text"] += " altered"
    elif fault == "context":
        data["context_digest"] = "1" * 64
    elif fault == "render":
        data["rendered_preview"] += " altered"
    elif fault == "created":
        data["created_at"] = (request.task.event.observed_at - timedelta(seconds=1)).isoformat()
    else:
        data["recovery_verified"] = True
    assert canonical_bytes(data) != raw
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_packet(canonical_bytes(data))


def test_duplicate_keys_noncanonical_and_byte_caps_hold(prepared):
    raw = c.encode_history_contextual_request(prepared[-1])
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(raw + b" ")
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(b'{"format":"x","format":"y"}')
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(b"x" * (c.MAX_REQUEST_BYTES + 1))


def test_preview_extraction_preserves_frozen_body_uuid_and_profile_bytes(host, monkeypatch):
    import importlib.util
    import sys
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "goldens/history-context-before-extraction.py"
    name = "frozen_history_metadata_before_extraction"
    spec = importlib.util.spec_from_file_location(name, path)
    before = importlib.util.module_from_spec(spec)
    sys.modules[name] = before
    spec.loader.exec_module(before)
    read, selections = multi_read(
        host,
        monkeypatch,
        [
            ("human", "A dated preference before correction."),
            ("assistant", "An assistant suggestion is not approval."),
            ("human", "Correction: keep the updated preference provisional."),
        ],
    )
    original = base()
    selected_route = route().model_copy(update={"max_input_characters": 32000})
    values = {
        "selections": tuple(
            before.HistoryMessageSpan.model_validate(s.model_dump()) for s in selections
        ),
        "observed_at": read.captured_at,
        "route": selected_route,
    }
    old = before.prepare_claude_history_context_preview(original, read, **values)
    new = prepare_claude_history_context_preview(
        original, read, selections=selections, observed_at=read.captured_at, route=selected_route
    )
    assert old.prompt_body == new.prompt_body
    assert old.context == new.context
    assert old.sidecar.model_dump_json() == new.sidecar.model_dump_json()
    assert old.projection_profiles == new.projection_profiles
    assert old.original_task == new.original_task == original.task


@pytest.mark.parametrize("fault", ["gap", "overlap", "separator"])
def test_exact_text_join_shape_is_checked_before_identity(prepared, monkeypatch, fault):
    request = prepared[-1]
    data = json.loads(c.encode_history_contextual_request(request))
    e = data["sidecar"]["entries"][1]
    if fault in {"gap", "overlap"}:
        delta = 1 if fault == "gap" else -1
        e["context_character_start"] += delta
        e["context_character_end"] += delta
    else:
        item = data["task"]["context"][-1]
        position = data["sidecar"]["entries"][0]["context_character_end"]
        item["untrusted_text"] = (
            item["untrusted_text"][:position] + " " + item["untrusted_text"][position + 1 :]
        )
    calls = []
    monkeypatch.setattr(c, "derive_history_context", lambda *args: calls.append(True))
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(canonical_bytes(data))
    assert calls == []


def test_actual_combined_utf8_capacity_holds_before_profile_validation(prepared, monkeypatch):
    request = prepared[-1]
    data = json.loads(c.encode_history_contextual_request(request))
    data["task"]["context"][-1]["untrusted_text"] = "🧠" * 3001
    calls = []
    monkeypatch.setattr(c, "_profile", lambda *args: calls.append(True))
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(canonical_bytes(data))
    assert len(data["task"]["context"][-1]["untrusted_text"].encode()) == 12004
    assert calls == []


def test_request_digest_is_exact_and_decode_cannot_reuse_a_packet_family(prepared):
    request = prepared[-1]
    raw = c.encode_history_contextual_request(request)
    assert c.history_contextual_request_digest(request) == content_hash_of(raw)
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_packet(raw)
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_packet(b"x" * (c.MAX_PACKET_BYTES + 1))


def test_second_coherent_foreign_pair_holds_before_any_identity_or_body(prepared, monkeypatch):
    request = prepared[-1]
    data = json.loads(c.encode_history_contextual_request(request))
    entry = data["sidecar"]["entries"][1]
    profile = json.loads(data["projection_profiles"][1])
    # Consistent declared second pair/profile hashes, not a malformed ref.
    for current, binding in [
        ("current_original_reference", "original_binding_reference"),
        ("current_companion_reference", "companion_binding_reference"),
    ]:
        identity = str(uuid4())
        for value in (entry, profile):
            value[current]["source_id"] = identity
            value[binding]["source_id"] = identity
    for value in (entry, profile):
        value["original_tip_id"] = value["original_binding_reference"]["source_id"]
    profile["custody_id"] = str(uuid4())
    raw_profile = canonical_bytes(profile)
    data["projection_profiles"][1] = raw_profile.decode()
    entry["profile_hash"] = content_hash_of(raw_profile)
    from zacai.claude_large_original_message import ClaudeLargeOriginalMessageProfile
    from zacai.intelligence.history_context_metadata import ClaudeMessageMetadata

    assert ClaudeMessageMetadata.model_validate(entry)
    assert ClaudeLargeOriginalMessageProfile.model_validate(profile)
    calls = []
    monkeypatch.setattr(c, "derive_history_context", lambda *args: calls.append("identity"))
    monkeypatch.setattr(c, "render_history_context_body", lambda *args: calls.append("body"))
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(canonical_bytes(data))
    assert calls == []


def test_same_pair_but_divergent_declared_custody_uuid_holds(prepared, monkeypatch):
    data = json.loads(c.encode_history_contextual_request(prepared[-1]))
    profile = json.loads(data["projection_profiles"][1])
    profile["custody_id"] = str(uuid4())
    raw = canonical_bytes(profile)
    data["projection_profiles"][1] = raw.decode()
    data["sidecar"]["entries"][1]["profile_hash"] = content_hash_of(raw)
    calls = []
    monkeypatch.setattr(c, "derive_history_context", lambda *args: calls.append(True))
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(canonical_bytes(data))
    assert calls == []
