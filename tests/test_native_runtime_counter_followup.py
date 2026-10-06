"""Invented SQLite evidence, synthetic tokenizer, fake HTTP; no authority claim."""

import json
import threading
from dataclasses import replace

import pytest

from tests.test_local_contextual_runtime import route
from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_derivation_admission import projection
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_local_runtime import Gate, posts, setup
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import local_contextual_runtime as m
from zacai.intelligence import native_prompt_counter as n
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F


def test_reentrant_generate_during_real_preflight_denies_without_deadlock(
    fixture, prepared, monkeypatch,
):
    rt, request, counter, gate, calls = setup(fixture, prepared, monkeypatch)
    observed, completed = [], threading.Event()

    def callback(phase):
        if phase == "count":
            try:
                rt.generate_native(request)
            except m.NativeLocalContextualRuntimeError as error:
                observed.append(error.code)

    counter.callback = callback

    def preflight():
        try:
            rt.preflight_native(request)
        finally:
            completed.set()

    worker = threading.Thread(target=preflight, daemon=True)
    worker.start()
    assert completed.wait(2), "reentrant generate deadlocked real preflight"
    worker.join(1)
    assert not worker.is_alive() and observed
    assert all(code is F.PREFLIGHT_BINDING for code in observed)
    assert not posts(calls) and gate.calls == 0
    counter.callback = None
    rt.generate_native(request)
    assert len(posts(calls)) == 1 and gate.calls == 1


def test_concurrent_generate_denies_while_counter_owns_preflight_lock(
    fixture, prepared, monkeypatch,
):
    rt, request, counter, gate, calls = setup(fixture, prepared, monkeypatch)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    preflight_finished = threading.Event()
    preflight_results, preflight_errors, errors = [], [], []

    def callback(phase):
        if phase == "count":
            entered.set()
            release.wait(3)

    counter.callback = callback
    def preflight():
        try:
            rt.preflight_native(request)
            preflight_results.append(True)
        except BaseException as error:  # noqa: BLE001 - worker failures must fail parent-thread assertions
            preflight_errors.append(type(error))
        finally:
            preflight_finished.set()

    worker = threading.Thread(target=preflight, daemon=True)
    worker.start()
    assert entered.wait(1)

    def generate():
        try:
            rt.generate_native(request)
        except m.NativeLocalContextualRuntimeError as error:
            errors.append(error.code)
        finally:
            finished.set()

    second = threading.Thread(target=generate, daemon=True)
    second.start()
    try:
        assert finished.wait(1), "generate blocked behind real counter callback"
        assert errors == [F.PREFLIGHT_BINDING]
        assert not posts(calls)
    finally:
        release.set()
        worker.join(2)
        second.join(2)
    assert not worker.is_alive() and not second.is_alive()
    assert preflight_finished.is_set() and preflight_results == [True] and not preflight_errors
    counter.callback = None
    rt.generate_native(request)
    assert len(posts(calls)) == 1 and gate.calls == 1


def test_substituted_catalog_schema_holds_serializer_before_gate(
    fixture, prepared, monkeypatch,
):
    rt, request, _counter, gate, calls = setup(fixture, prepared, monkeypatch)
    original = m._prepare_contextual_catalog

    original_schema = json.loads(original(request.context).schema_json)
    with_related = generation.contextual_draft_schema(related_citable=True)
    without_related = generation.contextual_draft_schema(related_citable=False)
    assert original_schema in (with_related, without_related)
    opposite = without_related if original_schema == with_related else with_related
    assert opposite != original_schema
    substitutions = []

    def substituted(context):
        actual = original(context)
        substitutions.append(opposite)
        return replace(actual, schema_json=json.dumps(opposite, sort_keys=True, separators=(",", ":")))

    monkeypatch.setattr(m, "_prepare_contextual_catalog", substituted)
    outcome = None
    try:
        rt.preflight_native(request)
    except m.NativeLocalContextualRuntimeError as error:
        outcome = error.code
    # Reachability is independent of whether the runtime actually holds.
    assert substitutions and all(schema == opposite for schema in substitutions)
    assert outcome is F.REQUEST_PAYLOAD
    assert not posts(calls) and gate.calls == 0
    # The genuine V2 request/schema was not mutated; only the grammar join drifted.
    assert request.schema_json == original(request.context).schema_json


def test_model_metadata_exact_current_allowlist(fixture, prepared, monkeypatch):
    rt, request, _counter, gate, calls = setup(fixture, prepared, monkeypatch)
    rt.preflight_native(request)
    rt.generate_native(request)
    raw = json.loads(json.loads(posts(calls)[0][2])["messages"][1]["content"])
    visible = raw["untrusted_noncitable_metadata"]["entries"][0]
    current = request.sidecar.entries[0].model_dump(mode="json")
    expected = set(current) - {"reference", "external_ref", "field_text_hash"}
    assert set(visible) == expected | {"passage_ids"}
    assert visible["relevance_reason"] == current["relevance_reason"]
    assert all(visible[k] == current[k] for k in expected)
    assert gate.calls == 1


def test_real_synthetic_counter_inside_native_runtime(fixture, prepared, installed, monkeypatch):
    request = generation.prepare_native_contextual_request(projection(fixture, prepared))
    counter = n.OllamaQwenNativeContextualTokenCounter(
        models_root=installed[0], model_digest=installed[2],
    )
    model_route = route().model_copy(update={
        "identity": route().identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"}),
    })
    gate, calls = Gate(), []
    monkeypatch.setattr(type(counter), "verify_runtime", lambda self: None)

    def http(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/tags":
            return {"models": [{"name": model_route.identity.model_id, "digest": installed[2]}]}
        if path == "/api/show":
            return {}
        passage = json.loads(json.loads(body)["messages"][1]["content"])["provider_passages"][0]
        return {"model": model_route.identity.model_id, "done": True, "done_reason": "stop",
                "prompt_eval_count": counter.count_prompt_tokens(body), "eval_count": 100,
                "message": {"role": "assistant", "content": json.dumps({
                    "format": "zac-contextual-draft-v2", "background": [], "continuity": [],
                    "items": [], "conflicts": [], "clarifications": [],
                    "overview": [{"text": "Invented dated evidence.", "evidence_ids": [passage["id"]],
                                  "inferred": False}],
                })}}

    monkeypatch.setattr(m, "_http", http)
    rt = m.NativeLocalContextualRuntime(
        route=model_route, model_digest=counter.model_digest,
        tokenizer_digest=counter.tokenizer_digest, runtime_digest=m.native_contextual_runtime_digest(),
        template_digest=counter.template_digest, renderer_digest=counter.renderer_digest,
        token_counter=counter, dispatch_gate=gate,
    )
    rt.preflight_native(request)
    draft = rt.generate_native(request)
    body = posts(calls)[0][2]
    prompt = n.render_native_prompt(body)
    assert prompt == n.render_contextual_prompt(body)
    messages = json.loads(body)["messages"]
    assert prompt == n._TEMPLATE.format(
        system=messages[0]["content"].strip(n.base._SPACE),
        user=messages[1]["content"].strip(n.base._SPACE),
    )
    assert counter.count_prompt_tokens(body) == gate.descriptor.prompt_tokens == rt.usage.input_tokens
    assert rt.resolve_native(draft, request).task_id == request.context.task.task_id
    assert len(posts(calls)) == 1 and gate.calls == 1


@pytest.mark.parametrize("target", ["tokenizers_version", "renderer_source", "trim_space", "template_text"])
def test_real_counter_prospective_pin_sensitivity(installed, monkeypatch, target):
    counter = n.OllamaQwenNativeContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    before = (counter.tokenizer_digest, counter.renderer_digest, counter.template_digest)
    if target == "tokenizers_version":
        monkeypatch.setattr(n, "version", lambda package: "invented-version")
    elif target == "renderer_source":
        original = n.Path.read_bytes
        filename = n.Path(n.__file__).resolve()
        monkeypatch.setattr(n.Path, "read_bytes", lambda path: original(path) + b"\n" if path.resolve() == filename else original(path))
    elif target == "trim_space":
        monkeypatch.setattr(n.base, "_SPACE", n.base._SPACE + "invented")
    else:
        monkeypatch.setattr(n, "_TEMPLATE", n._TEMPLATE + "invented")
    after = (counter.tokenizer_digest, counter.renderer_digest, counter.template_digest)
    index = {"tokenizers_version": 0, "renderer_source": 1, "trim_space": 2, "template_text": 2}[target]
    assert before[index] != after[index]
    assert all(before[i] == after[i] for i in range(3) if i != index)


def test_future_retained_metadata_field_stays_out_of_model_body(fixture, prepared, monkeypatch):
    _rt, request, _counter, _gate, _calls = setup(fixture, prepared, monkeypatch)
    cls = type(request.sidecar.entries[0])
    original = cls.model_dump

    def future_field(entry, **kwargs):
        return {**original(entry, **kwargs), "future_retained_private": "invented-private-detail"}

    monkeypatch.setattr(cls, "model_dump", future_field)
    visible = m._model_native_metadata(request)["entries"][0]
    assert "future_retained_private" not in visible
    assert visible["relevance_reason"] == request.sidecar.entries[0].relevance_reason
    # Test the serializer's allowlist in isolation; this is not a valid new V2 codec field.
