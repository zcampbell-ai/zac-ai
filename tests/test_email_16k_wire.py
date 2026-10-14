"""Invented passive route-capacity checks; no credentials, tokenizer files or dispatch."""
import json

import pytest

from tests.test_email_generation import output
from tests.test_email_generation import req as invented_request
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import email_local_wire as wire
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    OllamaQwenEmailTokenCounter,
    render_email_prompt,
)

DIGEST = "a" * 64


@pytest.fixture
def request_value():
    return invented_request.__wrapped__()


def route(runtime=wire.RUNTIME):
    return ModelRoute(
        identity={"provider_id": "ollama", "model_id": wire.MODEL, "runtime_id": runtime},
        destination="LOCAL", capabilities=frozenset({"email_draft"}),
        max_input_characters=64000, max_output_tokens=2048,
        estimated_latency_ms=0.0, estimated_cost_usd=0.0, available=True,
    )


def counter(monkeypatch, value):
    result = object.__new__(OllamaQwenEmailTokenCounter)
    result._digest = DIGEST
    def count(self, body):
        assert self is result
        assert render_email_prompt(body)
        return value
    monkeypatch.setattr(OllamaQwenEmailTokenCounter, "count_prompt_tokens", count)
    monkeypatch.setattr(OllamaQwenEmailTokenCounter, "verify_runtime", lambda self: pytest.fail("network/runtime verification forbidden"))
    return result


def response(request_value, incoming=9776, outgoing=75, **extra):
    return canonical_bytes({
        "model": wire.MODEL, "done": True, "done_reason": "stop",
        "message": {"role": "assistant", "content": canonical_bytes(output(request_value)).decode()},
        "prompt_eval_count": incoming, "eval_count": outgoing, **extra,
    })


def test_old_bytes_and_explicit_new_route_preserve_complete_evidence(request_value):
    assert wire.RUNTIME == "mac-loopback-email-8k" and wire.CONTEXT_TOKENS == 8192
    old = wire.prepare_email_local_payload(request_value, route(), DIGEST)
    expected = json.dumps({
        "model": wire.MODEL, "stream": False, "think": False, "truncate": False,
        "shift": False, "keep_alive": 0, "format": json.loads(request_value.schema_json),
        "messages": [
            {"role": "system", "content": request_value.instruction + "\nOutput JSON schema: " + request_value.schema_json},
            {"role": "user", "content": request_value.input_json.replace("<", "\\u003c")},
        ],
        "options": {"temperature": 0, "num_predict": 1000, "num_ctx": 8192},
    }, ensure_ascii=False).encode("utf-8")
    assert old == expected
    large = wire.prepare_email_local_payload(request_value, route(wire.LARGE_RUNTIME), DIGEST)
    expected_large = json.loads(old)
    expected_large["options"]["num_ctx"] = 16384
    assert large == json.dumps(expected_large, ensure_ascii=False).encode("utf-8")
    assert render_email_prompt(old) == render_email_prompt(large)


def test_full_9776_plus_1000_requires_explicit_large_route(request_value, monkeypatch):
    sentinel = counter(monkeypatch, 9776)
    with pytest.raises(wire.EmailLocalWireError):
        wire.count_email_local_prompt(request_value, route(), DIGEST, sentinel)
    assert wire.count_email_local_prompt(request_value, route(wire.LARGE_RUNTIME), DIGEST, sentinel) == 9776


@pytest.mark.parametrize("value", [True, False, 0, -1, 9776.0, 16385, 15385])
def test_large_count_rejects_invalid_or_reserved_output_overflow(request_value, monkeypatch, value):
    with pytest.raises(wire.EmailLocalWireError):
        wire.count_email_local_prompt(request_value, route(wire.LARGE_RUNTIME), DIGEST, counter(monkeypatch, value))


def test_large_exact_reservation_boundary(request_value, monkeypatch):
    assert wire.count_email_local_prompt(request_value, route(wire.LARGE_RUNTIME), DIGEST, counter(monkeypatch, 15384)) == 15384


@pytest.mark.parametrize("runtime", ["default", "mac-loopback-email-16k ", "MAC-LOOPBACK-EMAIL-16K", "mac-loopback-email-32k", "mac-loopback-contextual-16k"])
def test_unknown_and_lookalike_routes_denied(request_value, runtime):
    with pytest.raises(wire.EmailLocalWireError):
        wire.prepare_email_local_payload(request_value, route().model_copy(update={"identity": route().identity.model_copy(update={"runtime_id": runtime})}), DIGEST)


def test_large_response_keeps_full_count_parity_and_cached_subset(request_value):
    parsed = wire.parse_email_local_response(
        response(request_value, prompt_eval_cached_count=9000), request_value,
        route(wire.LARGE_RUNTIME), DIGEST, expected_prompt_tokens=9776, elapsed_ms=1,
    )
    assert parsed.usage.input_tokens == 9776 and parsed.reported_prompt_eval_cached_count == 9000
    with pytest.raises(wire.EmailLocalWireError):
        wire.parse_email_local_response(response(request_value), request_value, route(), DIGEST, expected_prompt_tokens=9776, elapsed_ms=1)


@pytest.mark.parametrize("incoming,outgoing,expected", [(776,75,9776), (9777,75,9776), (True,75,9776), (9776,True,9776), (9776,1001,9776), (15385,1,15385), (1,1,True)])
def test_large_response_rejects_parity_types_output_and_reservation(request_value, incoming, outgoing, expected):
    with pytest.raises(wire.EmailLocalWireError):
        wire.parse_email_local_response(response(request_value,incoming,outgoing), request_value, route(wire.LARGE_RUNTIME), DIGEST, expected_prompt_tokens=expected, elapsed_ms=1)


@pytest.mark.parametrize("capacity", [True, 4096, 32768, "16384"])
def test_email_renderer_still_closed_to_two_exact_capacities(request_value, capacity):
    body = json.loads(wire.prepare_email_local_payload(request_value, route(), DIGEST))
    body["options"]["num_ctx"] = capacity
    with pytest.raises(LocalTokenCounterError):
        render_email_prompt(json.dumps(body).encode())
