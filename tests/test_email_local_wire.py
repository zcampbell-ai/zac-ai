"""Wholly invented passive email wire/tokenizer/response checks; no dispatch."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_email_generation import output
from tests.test_email_generation import req as source_email_req
from tests.test_ollama_token_counter import installed as source_installed
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import email_local_wire as wire
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    OllamaQwenContextualTokenCounter,
    OllamaQwenEmailTokenCounter,
    OllamaQwenReviewTokenCounter,
    render_contextual_prompt,
    render_email_prompt,
    render_review_prompt,
)


@pytest.fixture(name="email_req")
def email_fixture():
    return source_email_req.__wrapped__()


@pytest.fixture(name="installed")
def manifest_fixture(tmp_path):
    return source_installed.__wrapped__(tmp_path)


@pytest.fixture
def case(email_req, installed, monkeypatch):
    monkeypatch.setattr(local, "_http", lambda *a: pytest.fail("passive email wire made HTTP call"))
    route = ModelRoute(
        identity={"provider_id": "ollama", "model_id": wire.MODEL, "runtime_id": wire.RUNTIME},
        destination="LOCAL",
        capabilities=frozenset({"email_draft"}),
        max_input_characters=64000,
        max_output_tokens=2048,
        estimated_latency_ms=0.0,
        estimated_cost_usd=0.0,
        available=True,
    )
    counter = OllamaQwenEmailTokenCounter(models_root=installed[0], model_digest=installed[2])
    count = wire.count_email_local_prompt(email_req, route, installed[2], counter)
    return email_req, route, installed[2], counter, count


def reply(case, **changes):
    req, _, _, _, count = case
    value = {
        "model": wire.MODEL,
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": canonical_bytes(output(req)).decode()},
        "prompt_eval_count": count,
        "eval_count": 75,
    }
    return value | changes


def parse(case, raw, **changes):
    req, route, digest, _, count = case
    return wire.parse_email_local_response(
        raw,
        req,
        route,
        digest,
        **({"expected_prompt_tokens": count, "elapsed_ms": 100.0} | changes),
    )


def assert_response_rejects(case, value, **changes):
    with pytest.raises(
        wire.EmailLocalWireError, match="^email local response unavailable or invalid$"
    ) as error:
        parse(case, canonical_bytes(value), **changes)
    assert error.value.__context__ is None


def test_complete_exact_email_wire_and_actual_offline_count(case, installed):
    req, route, digest, counter, count = case
    body = wire.prepare_email_local_payload(req, route, digest)
    data = json.loads(body)
    assert (
        data["messages"][0]["content"]
        == req.instruction + "\nOutput JSON schema: " + req.schema_json
    )
    assert data["messages"][1]["content"] == req.input_json
    assert (
        json.loads(data["messages"][1]["content"])["current_task_instruction"]
        == req.specification.task().instruction
    )
    assert data["format"] == json.loads(req.schema_json)
    assert data["options"] == {"temperature": 0, "num_predict": 1000, "num_ctx": 8192}
    assert all(data[k] is False for k in ("stream", "think", "truncate", "shift"))
    tok = installed[3]
    tok.no_truncation()
    tok.no_padding()
    assert count == len(tok.encode(render_email_prompt(body), add_special_tokens=False).ids)
    assert counter.model_digest == digest
    assert render_email_prompt(body) == (
        "<|im_start|>system\n" + data["messages"][0]["content"] + "<|im_end|>\n"
        "<|im_start|>user\n" + req.input_json + "<|im_end|>\n"
        "<|im_start|>assistant\n<think>\n\n</think>\n\n"
    )


@pytest.mark.parametrize("field", ["instruction", "input_json", "schema_json", "quotes"])
def test_modified_request_cannot_form_wire(case, field):
    req, route, digest, _, _ = case
    values = {
        "instruction": "INVENTED_PRIVATE_MARKER",
        "input_json": "{}",
        "schema_json": "{}",
        "quotes": (),
    }
    with pytest.raises(
        wire.EmailLocalWireError, match="^email local payload unavailable or invalid$"
    ) as error:
        wire.prepare_email_local_payload(replace(req, **{field: values[field]}), route, digest)
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    "mutation",
    [
        "destination",
        "model",
        "runtime",
        "provider",
        "capability",
        "unavailable",
        "output_cap",
        "input_cap",
        "latency",
        "cost",
        "pin",
        "context_output",
    ],
)
def test_route_and_declared_budget_guards(case, mutation):
    req, route, digest, _, _ = case
    value = route.model_dump(mode="python")
    if mutation in {"model", "runtime", "provider"}:
        key = {"model": "model_id", "runtime": "runtime_id", "provider": "provider_id"}[mutation]
        value["identity"] = route.identity.model_copy(update={key: "invented:other"})
    elif mutation == "destination":
        value["destination"] = "CLOUD"
    elif mutation == "capability":
        value["capabilities"] = frozenset({"contextual_meeting_review"})
    elif mutation == "unavailable":
        value["available"] = False
    elif mutation == "output_cap":
        value["max_output_tokens"] = 999
    elif mutation == "context_output":
        value["max_output_tokens"] = 8192
    elif mutation == "input_cap":
        value["max_input_characters"] = 1
    elif mutation == "latency":
        value["estimated_latency_ms"] = 1001.0
    elif mutation == "cost":
        value["estimated_cost_usd"] = 1.0
    else:
        digest = "wrong pin"
    with pytest.raises(
        wire.EmailLocalWireError, match="^email local payload unavailable or invalid$"
    ) as error:
        wire.prepare_email_local_payload(req, route.model_copy(update=value), digest)
    assert error.value.__context__ is None


@pytest.mark.parametrize("cached", [None, 0, 1, "full"])
def test_full_total_usage_parity_optional_cached_subset_and_existing_candidate_resolution(
    case, cached
):
    req, route, digest, _, count = case
    value = reply(case)
    if cached is not None:
        value["prompt_eval_cached_count"] = count if cached == "full" else cached
    raw = canonical_bytes(value)
    parsed = parse(case, raw)
    assert parsed.usage.input_tokens == count
    assert parsed.reported_prompt_eval_cached_count == value.get("prompt_eval_cached_count")
    packet, resolved = wire.resolve_email_local_response(
        raw,
        req,
        route,
        digest,
        expected_prompt_tokens=count,
        elapsed_ms=100.0,
        builder_id=uuid4(),
        created_at=req.specification.task().event.observed_at,
    )
    assert resolved == parsed
    assert packet.candidate.subject == "Revised estimate"
    assert packet.candidate.paragraphs[0].text == "Could you send the revised estimate?"
    assert all(
        getattr(packet, k) is False
        for k in (
            "processing_authorized",
            "generation_authenticated",
            "reviewer_authenticated",
            "recovery_verified",
            "ready_to_deliver",
            "current_facts_verified",
            "sending_authorized",
        )
    )


@pytest.mark.parametrize(
    "fault",
    [
        "model",
        "role",
        "tools",
        "thinking",
        "empty_tools",
        "done",
        "length",
        "unknown",
        "input_subset",
        "input_extra",
        "input_bool",
        "output_zero",
        "output_extra",
        "cache_extra",
        "cache_negative",
        "cache_bool",
        "cache_null",
        "cache_float",
        "duration",
        "date",
        "content",
        "model_schema",
    ],
)
def test_closed_response_and_exact_total_count_with_cached_subset_guards(case, fault):
    value = reply(case)
    count = case[4]
    if fault == "model":
        value["model"] = "wrong:local"
    elif fault == "role":
        value["message"]["role"] = "user"
    elif fault in {"tools", "thinking", "empty_tools"}:
        value["message"]["tool_calls" if fault != "thinking" else "thinking"] = (
            [] if fault == "empty_tools" else "forbidden"
        )
    elif fault == "done":
        value["done"] = 1
    elif fault == "length":
        value["done_reason"] = "length"
    elif fault == "unknown":
        value["sending_authorized"] = True
    elif fault == "input_subset":
        value["prompt_eval_count"] = count - 1
        value["prompt_eval_cached_count"] = 1
    elif fault == "input_extra":
        value["prompt_eval_count"] = count + 1
    elif fault == "input_bool":
        value["prompt_eval_count"] = True
    elif fault == "output_zero":
        value["eval_count"] = 0
    elif fault == "output_extra":
        value["eval_count"] = 1001
    elif fault.startswith("cache_"):
        value["prompt_eval_cached_count"] = {
            "cache_extra": count + 1,
            "cache_negative": -1,
            "cache_bool": True,
            "cache_null": None,
            "cache_float": 1.0,
        }[fault]
    elif fault == "duration":
        value["eval_duration"] = True
    elif fault == "date":
        value["created_at"] = 123
    elif fault == "content":
        value["message"]["content"] = []
    else:
        value["message"]["content"] = '{"format": "foreign-output"}'
    assert_response_rejects(case, value)


@pytest.mark.parametrize("elapsed", [True, -1.0, 1001.0, float("nan"), float("inf")])
def test_elapsed_bound_no_provider_time_claim(case, elapsed):
    assert_response_rejects(case, reply(case), elapsed_ms=elapsed)


@pytest.mark.parametrize("count", [True, 0, 8192])
def test_full_measured_count_and_output_reservation_rejects(case, count):
    assert_response_rejects(case, reply(case), expected_prompt_tokens=count)


def test_duplicate_key_in_otherwise_valid_response_rejected(case):
    valid = canonical_bytes(reply(case))
    assert parse(case, valid).usage.input_tokens == case[4]
    # Equal duplicate values would survive a last-wins JSON decoder unchanged.
    duplicate = b'{"model":' + canonical_bytes(wire.MODEL) + b',' + valid[1:]
    with pytest.raises(
        wire.EmailLocalWireError, match="^email local response unavailable or invalid$"
    ) as error:
        parse(case, duplicate)
    assert error.value.__context__ is None


def test_duplicate_malformed_and_oversize_response(case):
    raws = [b'{"model":"x","model":"y"}', b"NaN", b"\xff", b"{}", b"x" * 128001]
    for raw in raws:
        with pytest.raises(
            wire.EmailLocalWireError, match="^email local response unavailable or invalid$"
        ) as error:
            parse(case, raw)
        assert error.value.__context__ is None


def test_optional_known_reported_metadata_and_invalid_candidate_fixed_error(case):
    value = reply(
        case,
        created_at="2026-10-01T00:00:00Z",
        total_duration=0,
        load_duration=0,
        prompt_eval_duration=10,
        eval_duration=20,
    )
    assert parse(case, canonical_bytes(value)).usage.input_tokens == case[4]
    req, route, digest, _, count = case
    draft = output(req)
    draft["subject_support"]["evidence_ids"] = ["f" * 32 + ":e999"]
    value["message"]["content"] = canonical_bytes(draft).decode()
    with pytest.raises(
        wire.EmailLocalWireError, match="^email local candidate unavailable or invalid$"
    ) as error:
        wire.resolve_email_local_response(
            canonical_bytes(value),
            req,
            route,
            digest,
            expected_prompt_tokens=count,
            elapsed_ms=100.0,
            builder_id=uuid4(),
            created_at=req.specification.task().event.observed_at,
        )
    assert error.value.__context__ is None


def test_counter_profile_pin_manifest_and_reservation_fail_closed(case, installed, monkeypatch):
    req, route, digest, counter, _ = case
    bad_counters = [
        OllamaQwenReviewTokenCounter(models_root=installed[0], model_digest=digest),
        OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=digest),
    ]
    for bad in bad_counters:
        with pytest.raises(
            wire.EmailLocalWireError, match="^email local count unavailable or invalid$"
        ) as error:
            wire.count_email_local_prompt(req, route, digest, bad)
        assert error.value.__context__ is None
    with pytest.raises(wire.EmailLocalWireError):
        wire.count_email_local_prompt(req, route, "f" * 64, counter)
    monkeypatch.setattr(counter, "count_prompt_tokens", lambda body: 8192)
    with pytest.raises(wire.EmailLocalWireError):
        wire.count_email_local_prompt(req, route, digest, counter)
    monkeypatch.undo()
    installed[1].write_bytes(b"corrupt synthetic manifest")
    with pytest.raises(wire.EmailLocalWireError):
        wire.count_email_local_prompt(req, route, digest, counter)


def test_legacy_renderers_remain_exact_and_email_schema_is_separate(case):
    from tests.test_contextual_generation import request
    from tests.test_ollama_token_counter import payload
    from tests.test_review_generation import route, synthetic_context
    from zacai.intelligence.local_contextual_runtime import prepare_payload

    compact = payload()
    r = route().model_copy(
        update={
            "identity": route().identity.model_copy(update={"model_id": wire.MODEL}),
            "capabilities": frozenset({"contextual_meeting_review"}),
        }
    )
    contextual = prepare_payload(request(synthetic_context()), r, case[2])
    for body, render in ((compact, render_review_prompt), (contextual, render_contextual_prompt)):
        data = json.loads(body)
        expected = (
            "<|im_start|>system\n"
            + data["messages"][0]["content"]
            + "<|im_end|>\n"
            + "<|im_start|>user\n"
            + data["messages"][1]["content"]
            + "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
        )
        assert render(body) == expected
        with pytest.raises(LocalTokenCounterError):
            render_email_prompt(body)
    email = wire.prepare_email_local_payload(case[0], case[1], case[2])
    for render in (render_review_prompt, render_contextual_prompt):
        with pytest.raises(LocalTokenCounterError):
            render(email)
