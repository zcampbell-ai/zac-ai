"""Invented exact route and fake responses; no model/authority or database calls."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_local_contextual_runtime import route
from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_local_runtime import posts, setup
from zacai.intelligence import local_contextual_runtime as m
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F


def test_actual_constructor_route_snapshot_stable_across_processes():
    r = route().model_copy(update={"capabilities": frozenset({
        "contextual_meeting_review", "invented_a", "invented_b",
    })})
    data = r.model_dump(mode="json")
    data["capabilities"] = sorted(r.capabilities)
    code = """
import json,sys
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence import local_contextual_runtime as m
calls=[]
m._http=lambda *args: calls.append(args)
r=ModelRoute.model_validate_json(sys.argv[1])
runtime=m.NativeLocalContextualRuntime(route=r,model_digest='a'*64,
 tokenizer_digest='b'*64,runtime_digest=m.native_contextual_runtime_digest(),
 template_digest='c'*64,renderer_digest='d'*64,token_counter=object(),dispatch_gate=object())
assert not calls
print(runtime._route_snapshot)
"""
    src = str(Path(m.__file__).resolve().parents[2])
    snapshots = []
    for seed in range(4):
        result = subprocess.run(
            [sys.executable, "-c", code, json.dumps(data)],
            env={"PYTHONHASHSEED": str(seed), "PYTHONPATH": src},
            capture_output=True, text=True, check=True,
        )
        snapshots.append(result.stdout.strip())
    assert len(set(snapshots)) == 1
    assert json.loads(snapshots[0])["capabilities"] == sorted(r.capabilities)


def test_actual_pre_gate_deadline_has_zero_gate_and_post(fixture, prepared, monkeypatch):
    rt, request, _counter, gate, calls = setup(fixture, prepared, monkeypatch)
    rt.preflight_native(request)
    ticks = iter([0, 1000])
    monkeypatch.setattr(m.time, "perf_counter", lambda: next(ticks))
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:
        rt.generate_native(request)
    assert error.value.code is F.TOTAL_LATENCY
    assert error.value.did_transport_attempt is False
    assert gate.calls == 0 and not posts(calls)


@pytest.mark.parametrize("case,expected", [
    ("output", F.OUTPUT_LIMIT),
    ("context", F.RESPONSE_LENGTH),
    ("early", F.RESPONSE_LENGTH),
    ("invalid", F.RESPONSE_USAGE),
])
def test_length_completion_exact_existing_semantics(fixture, prepared, monkeypatch, case, expected):
    rt, request, _counter, gate, calls = setup(fixture, prepared, monkeypatch)
    rt.preflight_native(request)
    original = m._http

    def http(method, path, body=None):
        value = original(method, path, body)
        if path == "/api/chat":
            value["done_reason"] = "length"
            if case in {"output", "context", "invalid"}:
                value["eval_count"] = request.context.task.max_output_tokens
            if case == "context":
                value["prompt_eval_count"] = 8192 - value["eval_count"]
            if case == "invalid":
                value["eval_count"] += 1
        return value

    monkeypatch.setattr(m, "_http", http)
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:
        rt.generate_native(request)
    assert error.value.code is expected
    assert error.value.did_transport_attempt is True
    assert len(posts(calls)) == 1 and gate.calls == 1 and rt.usage is None
