"""Actual parser/diagnostics with invented responses, no transport authority."""

import pytest

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_local_runtime import posts, setup
from zacai.intelligence import local_contextual_runtime as m
from zacai.intelligence.runtime_diagnostics import PREFLIGHT_CODES
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F


@pytest.mark.parametrize("completion", ["length", "stop"])
@pytest.mark.parametrize("fault,expected", [
    ("tools", F.RESPONSE_AUTHORITY),
    ("missing", F.RESPONSE_SHAPE),
])
def test_message_authority_precedes_completion(fixture, prepared, monkeypatch, completion, fault, expected):
    rt, request, _counter, gate, calls = setup(fixture, prepared, monkeypatch)
    rt.preflight_native(request)
    original = m._http

    def http(method, path, body=None):
        value = original(method, path, body)
        if path == "/api/chat":
            value["done_reason"] = completion
            value["eval_count"] = request.context.task.max_output_tokens
            if fault == "tools":
                value["message"]["tool_calls"] = [{"function": {"name": "invented"}}]
            else:
                del value["message"]
        return value

    monkeypatch.setattr(m, "_http", http)
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:
        rt.generate_native(request)
    assert error.value.code is expected
    assert error.value.code not in PREFLIGHT_CODES
    assert error.value.did_transport_attempt is True
    assert len(posts(calls)) == 1 and gate.calls == 1 and rt.usage is None


def test_post_request_mutation_never_looks_like_preflight(fixture, prepared, monkeypatch):
    rt, request, _counter, gate, calls = setup(fixture, prepared, monkeypatch)
    rt.preflight_native(request)
    original = m._http
    posted = []

    def http(method, path, body=None):
        value = original(method, path, body)
        if path == "/api/chat":
            posted.append(True)
        if path == "/api/show" and posted:
            object.__setattr__(request, "instruction", "invented late mutation")
        return value

    monkeypatch.setattr(m, "_http", http)
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:
        rt.generate_native(request)
    assert error.value.code is F.RESPONSE_AUTHORITY
    assert error.value.code not in PREFLIGHT_CODES
    assert error.value.did_transport_attempt is True
    assert len(posts(calls)) == 1 and gate.calls == 1
