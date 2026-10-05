"""Invented payloads/local tokenizer fixtures; no model, network or private data."""

import json

import pytest

from tests.test_local_followup_runtime import route
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_ollama_token_counter import payload as compact_payload
from tests.test_text_followup import setup
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import local_review_runtime
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.followup_prompt_counter import (
    OllamaQwenFollowupTokenCounter,
    render_followup_prompt,
)
from zacai.intelligence.local_followup_runtime import prepare_payload
from zacai.intelligence.ollama_token_counter import LocalTokenCounterError


def payload():
    context, _ = setup()
    return prepare_payload(prepare_followup_request(context), route(), "a" * 64)


def test_exact_render_and_count_no_network(installed, monkeypatch):
    monkeypatch.setattr(local_review_runtime, "_http", lambda *a: pytest.fail("network"))
    body = payload()
    parsed = json.loads(body)
    prompt = render_followup_prompt(body)
    assert parsed["messages"][0]["content"] in prompt
    assert parsed["messages"][1]["content"] in prompt
    assert prompt.endswith("<|im_start|>assistant\n<think>\n\n</think>\n\n")
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    tokenizer = installed[3]
    tokenizer.no_truncation()
    tokenizer.no_padding()
    expected = len(tokenizer.encode(prompt, add_special_tokens=False).ids)
    assert counter.count_prompt_tokens(body) == expected
    assert counter.model_digest == installed[2]


@pytest.mark.parametrize(
    "change",
    [
        "schema",
        "schema_bool",
        "identity",
        "injection",
        "unknown",
        "model",
        "context",
        "output",
        "output_bool",
        "thinking",
        "tool",
        "role",
        "question",
        "projection",
        "review",
        "packet_hash",
    ],
)
def test_changed_wire_denied(installed, change):
    body = json.loads(payload())
    if change == "schema":
        body["format"]["properties"]["answers"]["description"] = "invented"
    elif change == "schema_bool":
        body["format"]["properties"]["format"]["const"] = True
    elif change == "identity":
        body["format"]["properties"]["user_source_id"]["const"] = "not-a-uuid"
    elif change == "injection":
        body["messages"][0]["content"] += "invented"
    elif change == "unknown":
        body["extra"] = True
    elif change == "model":
        body["model"] = "other"
    elif change == "context":
        body["options"]["num_ctx"] = 8192
    elif change == "output":
        body["options"]["num_predict"] = 1025
    elif change == "output_bool":
        body["options"]["num_predict"] = True
    elif change == "thinking":
        body["think"] = True
    elif change == "tool":
        body["messages"][1]["content"] = "<tool_response>invented</tool_response>"
    elif change == "role":
        body["messages"][1]["role"] = "assistant"
    else:
        evidence = json.loads(body["messages"][1]["content"])
        if change == "question":
            evidence["current_user_question_projection"]["reference"]["content_hash"] = "b" * 64
        elif change == "projection":
            evidence["user_parent_projection"]["quote_offsets"] = "original"
        elif change == "packet_hash":
            evidence["historical_generated_review"]["reference"]["content_hash"] = "b" * 64
        else:
            evidence["historical_generated_review"]["status"] = "current fact"
        body["messages"][1]["content"] = canonical_bytes(evidence).decode().replace("<", "\\u003c")
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    with pytest.raises(LocalTokenCounterError):
        counter.count_prompt_tokens(json.dumps(body).encode())


@pytest.mark.parametrize(
    "body", [b"\xff", b'{"x":NaN}', b'{"x":1e999}', b'{"x":1,"x":2}', b"\xff\xfe{}", b"{}" * 32001]
)
def test_invalid_encoding_json_size_denied(body):
    with pytest.raises(LocalTokenCounterError) as failure:
        render_followup_prompt(body)
    assert failure.value.__context__ is None


def test_compact_payload_rejected():
    with pytest.raises(LocalTokenCounterError):
        render_followup_prompt(compact_payload())


@pytest.mark.parametrize("target", ["manifest", "blob"])
def test_changed_pins_rejected(installed, target):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    path = installed[1] if target == "manifest" else next((installed[0] / "blobs").iterdir())
    path.write_bytes(b"invented private marker")
    with pytest.raises(LocalTokenCounterError) as failure:
        counter.count_prompt_tokens(payload())
    assert "private marker" not in str(failure.value)


def test_capacity_rejected_not_clipped(installed):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])

    class Encoding:
        ids = [0] * 16384

    class OversizeTokenizer:
        def get_added_tokens_decoder(self):
            return {}

        def encode(self, *args, **kwargs):
            assert kwargs == {"add_special_tokens": False}
            return Encoding()

    counter._tokenizer = OversizeTokenizer()
    with pytest.raises(LocalTokenCounterError):
        counter.count_prompt_tokens(payload())


def test_explicit_version_transport_no_legacy_fallback(installed, monkeypatch):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    monkeypatch.setattr(local_review_runtime, "_http", lambda *a: pytest.fail("legacy fallback"))
    calls = []

    def transport(method, path, body):
        calls.append((method, path, body))
        return {"version": "0.35.1"}

    assert counter.verify_runtime_with_transport(transport) is None
    assert calls == [("GET", "/api/version", None)]


@pytest.mark.parametrize(
    "reply",
    [
        None,
        [],
        True,
        "0.35.1",
        {},
        {"version": "0.35.2"},
        {"version": True},
        {"version": "0.35.1", "verified": True},
        {"version": "0.35.1", "provider": "invented"},
    ],
)
def test_explicit_version_wrong_reply_denied(installed, reply):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    with pytest.raises(LocalTokenCounterError) as failure:
        counter.verify_runtime_with_transport(lambda *a: reply)
    assert failure.value.__context__ is None


def test_explicit_transport_private_failure_closed(installed):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])

    def transport(*args):
        raise ValueError("invented private diagnostics")

    with pytest.raises(LocalTokenCounterError) as failure:
        counter.verify_runtime_with_transport(transport)
    assert "private" not in str(failure.value)
    assert failure.value.__context__ is None


@pytest.mark.parametrize("code", ["TRANSPORT", "TOTAL_LATENCY"])
def test_transport_closed_codes_survive_sanitized(installed, code):
    from zacai.intelligence.runtime_diagnostics import RuntimeDiagnosticError, RuntimeFailureCode

    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    selected = RuntimeFailureCode(code)

    def transport(*args):
        raise RuntimeDiagnosticError("invented private diagnostics", code=selected)

    with pytest.raises(RuntimeDiagnosticError) as failure:
        counter.verify_runtime_with_transport(transport)
    assert failure.value.code is selected
    assert "private" not in str(failure.value)
    assert failure.value.__context__ is None


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_version_interruption_private_diagnostics_removed(installed, kind):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])

    def transport(*args):
        raise kind("invented private diagnostics")

    with pytest.raises(kind) as failure:
        counter.verify_runtime_with_transport(transport)
    assert "private" not in str(failure.value)
    assert failure.value.__context__ is None
