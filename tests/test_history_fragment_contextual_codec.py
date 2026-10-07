"""Invented actual parser/profile/catalog. No SQL, recovery, owner or model proof."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import AT, prepared
from tests.test_history_context_metadata import base
from tests.test_history_contextual_codec import review_for
from tests.test_local_contextual_runtime import route
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_fragment_contextual_codec as c
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.history_contextual_codec import decode_history_contextual_request


def request(inherited=False):
    missing, parent = uuid4(), uuid4()
    prefixes = (
        (
            {
                "uuid": str(parent),
                "sender": "assistant",
                "text": "Earlier suggestion",
                "content": [],
                "created_at": "2026-10-06T11:00:00Z",
                "updated_at": "2026-10-06T11:00:00Z",
                "parent_message_uuid": str(missing),
            },
        )
        if inherited
        else ()
    )
    read = prepared(parent=parent if inherited else missing, prefixes=prefixes)
    f = prepare(read)
    return c.prepare_history_fragment_contextual_request(
        base(),
        f,
        observed_at=AT,
        route=route()
        .model_copy(update={"max_input_characters": 32000})
        .model_copy(update={"max_input_characters": 32000}),
    )


@pytest.mark.parametrize("inherited", [False, True])
def test_actual_incomplete_profile_roundtrip_and_packet(inherited):
    value = request(inherited)
    raw = c.encode_history_fragment_contextual_request(value)
    assert c.decode_history_fragment_contextual_request(raw) == value
    p = json.loads(value.profile_json)
    assert p["lineage_gap"] == (
        "INHERITED_MISSING_ANCESTOR" if inherited else "DIRECT_MISSING_PARENT"
    )
    assert p["lineage_complete"] is p["thread_context_complete"] is False
    wire = json.loads(value.prompt_body)
    metadata = json.loads(wire["messages"][1]["content"])["history_fragment_metadata"]
    assert metadata["citable"] is metadata["current_fact"] is False
    assert (
        value.processing_authorized
        is value.recovery_verified
        is value.current_facts_verified
        is False
    )
    packet = c.encode_history_fragment_contextual_packet(
        review_for(value), value, builder_id=uuid4(), created_at=AT + timedelta(seconds=1)
    )
    saved = c.decode_history_fragment_contextual_packet(packet)
    assert saved.request() == value
    assert "Current facts and owner preferences unconfirmed" in saved.rendered_preview
    assert (
        saved.processing_authorized
        is saved.recovery_verified
        is saved.current_facts_verified
        is False
    )
    with pytest.raises(ValueError):
        prepare_contextual_request(value.context())
    with pytest.raises(ValueError):
        decode_history_contextual_request(raw)


@pytest.mark.parametrize(
    "fault",
    ["originaltask", "task", "profile", "text", "ref", "date", "gap", "omission", "flag", "body"],
)
def test_exact_component_tamper_holds(fault):
    data = json.loads(c.encode_history_fragment_contextual_request(request()))
    if fault in {"originaltask", "task"}:
        data["original_task" if fault == "originaltask" else "task"]["instruction"] += " changed"
    elif fault == "profile":
        data["profile_json"] += " "
    elif fault == "text":
        data["observation"]["selected_text"] = "Changed!"
    elif fault == "ref":
        data["task"]["event"]["provenance"][-1]["content_hash"] = "1" * 64
    elif fault in {"date", "gap"}:
        p = json.loads(data["profile_json"])
        p["reported_updated_at" if fault == "date" else "lineage_gap"] = (
            "2026-10-06T12:01:00Z" if fault == "date" else "INHERITED_MISSING_ANCESTOR"
        )
        data["profile_json"] = canonical_bytes(p).decode()
        data["profile_digest"] = content_hash_of(data["profile_json"].encode())
    elif fault == "omission":
        data["observation"]["omitted_suffix_characters"] += 1
    elif fault == "flag":
        data["processing_authorized"] = True
    elif fault == "body":
        data["prompt_body"] += " "
        data["prompt_digest"] = content_hash_of(data["prompt_body"].encode())
    mutated = canonical_bytes(data)
    with pytest.raises(c.HistoryContextualCodecError) as error:
        c.decode_history_fragment_contextual_request(mutated)
    assert error.value.__context__ is None


def test_packet_injected_attribution_and_permission_hold():
    value = request()
    raw = c.encode_history_fragment_contextual_packet(
        review_for(value), value, builder_id=uuid4(), created_at=AT + timedelta(seconds=1)
    )
    for key, replacement in [
        ("rendered_preview", "Confirmed current owner preference"),
        ("processing_authorized", True),
        ("recovery_verified", True),
    ]:
        data = json.loads(raw)
        data[key] = replacement
        with pytest.raises(c.HistoryContextualCodecError):
            c.decode_history_fragment_contextual_packet(canonical_bytes(data))


def test_foreign_fragment_and_nested_history_hold():
    from dataclasses import replace

    f = prepare(prepared(parent=uuid4()))
    altered = replace(f, fragment=replace(f.fragment, parent_id=uuid4()))
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            base(),
            altered,
            observed_at=AT,
            route=route().model_copy(update={"max_input_characters": 32000}),
        )
    value = request()
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            value.context(),
            f,
            observed_at=AT,
            route=route().model_copy(update={"max_input_characters": 32000}),
        )
