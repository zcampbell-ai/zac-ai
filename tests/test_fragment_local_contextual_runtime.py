"""Invented canonical fragment + real synthetic tokenizer, mocked model metadata/POST.

No owner, source ACL, recovery, model parity or activation evidence.
"""

import json
from uuid import uuid4

import pytest

from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import AT, prepared
from tests.test_history_context_metadata import base
from tests.test_local_contextual_runtime import route
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence.history_fragment_contextual_codec import (
    prepare_history_fragment_contextual_request,
)
from zacai.intelligence.ollama_token_counter import (
    OllamaQwenContextualTokenCounter,
    render_contextual_prompt,
)


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
    r = route().model_copy(
        update={
            "identity": route().identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"}),
            "max_input_characters": 32000,
        }
    )
    return prepare_history_fragment_contextual_request(
        base(), prepare(read), observed_at=AT, route=r
    )


def setup(installed, monkeypatch, inherited=False):
    value = request(inherited)
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    pins = local.fragment_contextual_counter_pins(counter)
    events = []
    monkeypatch.setattr(counter, "verify_runtime", lambda: events.append("runtime"))
    monkeypatch.setattr(local, "verify_model", lambda *args: events.append("model"))
    runtime = local.FragmentLocalContextualRuntime(
        route=value.route,
        model_digest=installed[2],
        tokenizer_digest=pins[0],
        template_digest=pins[1],
        renderer_digest=pins[2],
        runtime_digest=local.fragment_contextual_runtime_digest(),
        token_counter=counter,
        recheck=lambda request, descriptor: events.append("host"),
    )
    bodies = []

    def post(body, remaining):
        assert 0 < remaining <= value.task.max_latency_ms / 1000
        bodies.append(body)
        catalog = generation._prepare_contextual_catalog(value.context())
        draft = {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "Historical evidence remains uncertain.",
                    "evidence_ids": [catalog.quotes[0][0]],
                    "inferred": False,
                }
            ],
            "background": [],
            "continuity": [],
            "items": [],
            "conflicts": [],
            "clarifications": [],
        }
        return {
            "model": value.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": counter.count_prompt_tokens(body),
            "eval_count": 100,
        }

    monkeypatch.setattr(local, "_fragment_http_post", post)
    return runtime, value, counter, events, bodies


@pytest.mark.parametrize("inherited", [False, True])
def test_actual_fragment_full_body_offline_count_one_mock_post_and_exact_quotes(
    installed, monkeypatch, inherited
):
    r, q, counter, events, bodies = setup(installed, monkeypatch, inherited)
    body = q.prompt_body.encode()
    actual = counter.count_prompt_tokens(body)
    tok = installed[3]
    tok.no_padding()
    tok.no_truncation()
    assert actual == len(tok.encode(render_contextual_prompt(body), add_special_tokens=False).ids)
    payload = json.loads(json.loads(body)["messages"][1]["content"])
    assert payload["history_fragment_metadata"]["citable"] is False
    assert payload["history_fragment_metadata"]["lineage_complete"] is False
    r.preflight_fragment(q)
    assert bodies == [] and events == ["runtime", "model"]
    draft = r.generate_fragment(q)
    review = r.resolve_fragment(draft, q)
    assert review.task_id == q.task.task_id and review.overview[0].quotes
    assert bodies == [body] and r.did_transport_attempt is True
    assert q.processing_authorized is q.recovery_verified is q.current_facts_verified is False
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert len(bodies) == 1


@pytest.mark.parametrize("fault", ["missing", "copy", "body", "profile", "route", "count", "pin"])
def test_changed_binding_holds_without_post_and_burns(installed, monkeypatch, fault):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    if fault != "missing":
        r.preflight_fragment(q)
    if fault == "copy":
        q = q.model_copy()
    elif fault == "body":
        object.__setattr__(q, "prompt_body", q.prompt_body + " ")
    elif fault == "profile":
        object.__setattr__(q, "profile_digest", "f" * 64)
    elif fault == "route":
        r._route = r.route.model_copy(update={"max_input_characters": 31000})
    elif fault == "count":
        monkeypatch.setattr(counter, "count_prompt_tokens", lambda body: 8192)
    elif fault == "pin":
        r._template_digest = "f" * 64
    with pytest.raises(local.FragmentLocalContextualRuntimeError) as e:
        r.generate_fragment(q)
    assert bodies == [] and e.value.did_transport_attempt is False
    assert e.value.__cause__ is e.value.__context__ is None
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)


def test_mutation_during_actual_counter_callback_holds_before_post(installed, monkeypatch):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    count = counter.count_prompt_tokens
    fired = []

    def mutated(body):
        result = count(body)
        fired.append(True)
        object.__setattr__(q, "prompt_digest", "f" * 64)
        return result

    monkeypatch.setattr(counter, "count_prompt_tokens", mutated)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert fired and bodies == []


def test_original_deadline_cannot_be_renewed_by_model_callback(installed, monkeypatch):
    r, q, _, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    clock = [0.0]
    monkeypatch.setattr(local.time, "perf_counter", lambda: clock[0])

    def slow(*args):
        clock[0] = q.task.max_latency_ms / 1000 + 1

    monkeypatch.setattr(local, "verify_model", slow)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert clock[0] > 0 and bodies == []


@pytest.mark.parametrize("fault", ["unknown", "noncitable", "metadata"])
def test_only_eligible_exact_catalog_quotes_resolve(fault):
    q = request()
    if fault == "noncitable":
        from tests.test_history_fragment_family_catalog import make

        _, _, q = make("Invented citable passage\nx")
    quotes = generation._prepare_contextual_catalog(q.context()).quotes
    eid = quotes[0][0] if fault == "metadata" else "invented:unknown"
    if fault == "noncitable":
        payload = json.loads(json.loads(q.prompt_body)["messages"][1]["content"])
        eid = next(row["id"] for row in payload["provider_passages"] if row["text"] == "x")
        assert eid not in dict(quotes)
    draft = generation.ContextualDraft.model_validate(
        {
            "format": "zac-contextual-draft-v2",
            "overview": [{"text": "Historical report.", "evidence_ids": [eid], "inferred": False}],
            "background": [],
            "continuity": [],
            "items": [],
            "conflicts": [],
            "clarifications": [],
        }
    )
    if fault == "metadata":
        object.__setattr__(q, "profile_digest", "f" * 64)
    with pytest.raises(generation.ContextualGenerationError):
        generation.resolve_history_fragment_contextual_draft(draft, q)


def test_bound_post_uses_literal_endpoint_remaining_timeout_and_closes(monkeypatch):
    import http.client

    events = []

    class Response:
        status = 200

        def getheader(self, *args):
            return "identity"

        def read(self, cap):
            events.append(("read", cap))
            return b"{}"

    class Connection:
        def __init__(self, host, port, timeout):
            events.append((host, port, timeout))

        def request(self, method, path, **kwargs):
            events.append((method, path))

        def getresponse(self):
            return Response()

        def close(self):
            events.append("closed")

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    assert local._fragment_http_post(b"{}", 0.125) == {}
    assert events == [
        ("127.0.0.1", 11434, 0.125),
        ("POST", "/api/chat"),
        ("read", 2_000_001),
        "closed",
    ]
    with pytest.raises(ValueError):
        local._fragment_http_post(b"{}", 0)
    assert len(events) == 4


def test_legacy_family_refused_before_counter_or_metadata(installed, monkeypatch):
    from tests.test_contextual_generation import request as legacy
    from tests.test_review_generation import synthetic_context

    r, _, _, events, bodies = setup(installed, monkeypatch)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.preflight_fragment(legacy(synthetic_context()))
    assert events == [] and bodies == []


def test_real_pinned_tokenizer_blob_drift_burns_before_post(installed, monkeypatch):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    path = counter._files[1][0]
    old = path.read_bytes()
    try:
        path.write_bytes(old + b" ")
        with pytest.raises(local.FragmentLocalContextualRuntimeError):
            r.generate_fragment(q)
        assert bodies == []
    finally:
        path.write_bytes(old)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert bodies == []


def test_post_response_callback_drift_holds_without_usage(installed, monkeypatch):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    count = [0]

    def current():
        count[0] += 1
        if count[0] == 2:
            object.__setattr__(q, "profile_digest", "f" * 64)

    monkeypatch.setattr(counter, "verify_runtime", current)
    with pytest.raises(local.FragmentLocalContextualRuntimeError) as e:
        r.generate_fragment(q)
    assert count[0] == 2 and len(bodies) == 1
    assert e.value.did_transport_attempt is True and r.usage is None


def test_counter_interruption_burns_original_attempt(installed, monkeypatch):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    original = counter.count_prompt_tokens

    def interrupt(body):
        raise KeyboardInterrupt

    monkeypatch.setattr(counter, "count_prompt_tokens", interrupt)
    with pytest.raises(KeyboardInterrupt):
        r.generate_fragment(q)
    monkeypatch.setattr(counter, "count_prompt_tokens", original)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert bodies == []


def test_late_mock_transport_response_is_not_released(installed, monkeypatch):
    r, q, _, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    clock = [0.0]
    monkeypatch.setattr(local.time, "perf_counter", lambda: clock[0])
    post = local._fragment_http_post

    def delayed(body, remaining):
        result = post(body, remaining)
        clock[0] = q.task.max_latency_ms / 1000 + 1
        return result

    monkeypatch.setattr(local, "_fragment_http_post", delayed)
    with pytest.raises(local.FragmentLocalContextualRuntimeError) as error:
        r.generate_fragment(q)
    assert len(bodies) == 1 and clock[0] > 0
    assert error.value.did_transport_attempt is True and r.usage is None


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize(
    "fault", ["reject", "body", "pin", "coherent_pins", "clock", "unexpected_return"]
)
def test_actual_host_gate_seam_holds_and_attempt_burns(installed, monkeypatch, phase, fault):
    r, q, _, _events, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    clock = [0.0]
    monkeypatch.setattr(local.time, "perf_counter", lambda: clock[0])
    gates = []

    def recheck(value, descriptor):
        assert value is q
        which = "before" if descriptor.phase == "PRE_DISPATCH" else "after"
        gates.append(which)
        if which != phase:
            return None
        if fault == "reject":
            raise ValueError("INVENTED_PRIVATE_GATE_REASON")
        if fault == "body":
            object.__setattr__(q, "prompt_digest", "f" * 64)
        if fault == "pin":
            r._template_digest = "f" * 64
        if fault == "coherent_pins":
            r._template_digest = "f" * 64
            r._configuration = (*r._configuration[:3], "f" * 64, *r._configuration[4:])
        if fault == "clock":
            clock[0] = q.task.max_latency_ms / 1000 + 1
        if fault == "unexpected_return":
            return True
        return None

    r._recheck = recheck  # Explicit invented trusted-host seam, no actual authority.
    with pytest.raises(local.FragmentLocalContextualRuntimeError) as error:
        r.generate_fragment(q)
    assert gates == (["before"] if phase == "before" else ["before", "after"])
    assert len(bodies) == (0 if phase == "before" else 1)
    assert error.value.did_transport_attempt is (phase == "after")
    assert r.usage is None
    assert "INVENTED_PRIVATE_GATE_REASON" not in str(error.value)
    assert error.value.__cause__ is error.value.__context__ is None
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert len(bodies) == (0 if phase == "before" else 1)


def test_callback_order_surrounds_transport_and_output(installed, monkeypatch):
    r, q, _counter, events, _bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    events.clear()
    post = local._fragment_http_post

    def current(value, descriptor):
        assert value is q
        events.append("before" if descriptor.phase == "PRE_DISPATCH" else "after")

    def transport(body, remaining):
        events.append("post")
        return post(body, remaining)

    r._recheck = current
    monkeypatch.setattr(local, "_fragment_http_post", transport)
    r.generate_fragment(q)
    assert events == ["runtime", "model", "before", "post", "runtime", "model", "after"]


def test_constructor_has_no_default_or_noncallable_host_gate(installed, monkeypatch):
    r, q, counter, events, bodies = setup(installed, monkeypatch)
    fields = {"route": q.route, "model_digest": installed[2], "tokenizer_digest": r._tokenizer_digest,
              "runtime_digest": r._runtime_digest, "template_digest": r._template_digest,
              "renderer_digest": r._renderer_digest, "token_counter": counter}
    with pytest.raises(TypeError):
        local.FragmentLocalContextualRuntime(**fields)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        local.FragmentLocalContextualRuntime(**fields, recheck=None)
    assert events == [] and bodies == []


def test_gate_receives_exact_phase_attempt_body_pins_output_and_usage(installed, monkeypatch):
    from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
    from zacai.intelligence.history_fragment_contextual_codec import (
        encode_history_fragment_contextual_request,
    )

    r, q, counter, _, bodies = setup(installed, monkeypatch)
    seen = []

    def gate(value, descriptor):
        assert value is q
        assert type(descriptor) is local.FragmentContextualDispatchDescriptor
        assert descriptor.body_digest == content_hash_of(q.prompt_body.encode())
        assert descriptor.retained_request_digest == content_hash_of(
            encode_history_fragment_contextual_request(q))
        assert descriptor.prompt_tokens == counter.count_prompt_tokens(q.prompt_body.encode())
        assert (descriptor.model_digest, descriptor.tokenizer_digest, descriptor.runtime_digest,
                descriptor.template_digest, descriptor.renderer_digest, descriptor.route_json) == r._configuration
        assert descriptor.attempt_id.int != 0
        if descriptor.phase == "PRE_DISPATCH":
            assert bodies == [] and descriptor.output_digest is descriptor.usage_digest is None
        else:
            assert descriptor.phase == "RELEASE" and len(bodies) == 1
            assert descriptor.output_digest and descriptor.usage_digest
        seen.append(descriptor)

    r._recheck = gate
    r.preflight_fragment(q)
    draft = r.generate_fragment(q)
    assert [d.phase for d in seen] == ["PRE_DISPATCH", "RELEASE"]
    assert seen[0].attempt_id == seen[1].attempt_id
    assert seen[1].output_digest == content_hash_of(canonical_bytes(draft.model_dump(mode="json")))
    assert seen[1].usage_digest == content_hash_of(canonical_bytes(r.usage.model_dump(mode="json")))
    # A new runtime owns a fresh nonce, not a reusable approval capability.
    other, other_q, _, _, _ = setup(installed, monkeypatch)
    other_seen = []
    other._recheck = lambda value, descriptor: other_seen.append(descriptor)
    other.preflight_fragment(other_q)
    other.generate_fragment(other_q)
    assert other_seen[0].attempt_id != seen[0].attempt_id


@pytest.mark.parametrize("phase", ["PRE_DISPATCH", "RELEASE"])
@pytest.mark.parametrize("field", ["phase", "attempt_id", "body_digest", "prompt_tokens", "output_digest"])
def test_changed_descriptor_holds_and_burns(installed, monkeypatch, phase, field):
    r, q, _, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    fired = []

    def gate(value, descriptor):
        if descriptor.phase == phase:
            fired.append(phase)
            replacement = {"phase": "UNKNOWN", "attempt_id": uuid4(), "body_digest": "f" * 64,
                           "prompt_tokens": -1, "output_digest": "f" * 64}[field]
            object.__setattr__(descriptor, field, replacement)

    r._recheck = gate
    with pytest.raises(local.FragmentLocalContextualRuntimeError) as error:
        r.generate_fragment(q)
    assert fired == [phase]
    assert len(bodies) == (0 if phase == "PRE_DISPATCH" else 1)
    assert error.value.did_transport_attempt == (phase == "RELEASE")
    assert error.value.code == (local.F.PREFLIGHT_BINDING if phase == "PRE_DISPATCH"
                                else local.F.RESPONSE_AUTHORITY)
    assert r.usage is None and error.value.__context__ is None
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert len(bodies) == (0 if phase == "PRE_DISPATCH" else 1)


@pytest.mark.parametrize("fault,code", [
    ("model", "RESPONSE_MODEL"), ("done", "RESPONSE_INCOMPLETE"),
    ("length_limit", "OUTPUT_LIMIT"), ("length_short", "RESPONSE_LENGTH"),
    ("reason", "RESPONSE_STOP_REASON"), ("tools", "RESPONSE_AUTHORITY"),
    ("thinking", "RESPONSE_AUTHORITY"), ("role", "RESPONSE_AUTHORITY"),
    ("bool_input", "RESPONSE_USAGE"), ("negative_input", "RESPONSE_USAGE"),
    ("bool_output", "RESPONSE_USAGE"), ("negative_output", "RESPONSE_USAGE"),
    ("over_output", "RESPONSE_USAGE"), ("over_context", "RESPONSE_USAGE"),
    ("prompt", "PROMPT_COUNT_MISMATCH"), ("duplicate_content", "RESPONSE_SCHEMA"),
    ("schema", "RESPONSE_SCHEMA"), ("duplicate_transport", "TRANSPORT"),
])
def test_actual_fragment_parser_closed_postattempt_failures(installed, monkeypatch, fault, code):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    r.preflight_fragment(q)
    original = local._fragment_http_post
    gates = []
    r._recheck = lambda value, descriptor: gates.append(descriptor.phase)

    def post(body, remaining):
        reply = original(body, remaining)
        if fault == "model":
            reply["model"] = "different"
        elif fault == "done":
            reply["done"] = False
        elif fault.startswith("length"):
            reply["done_reason"] = "length"
            reply["eval_count"] = q.task.max_output_tokens if fault == "length_limit" else 1
        elif fault == "reason":
            reply["done_reason"] = "other"
        elif fault == "tools":
            reply["message"]["tool_calls"] = [{}]
        elif fault == "thinking":
            reply["message"]["thinking"] = "invented"
        elif fault == "role":
            reply["message"]["role"] = "system"
        elif fault == "bool_input":
            reply["prompt_eval_count"] = True
        elif fault == "negative_input":
            reply["prompt_eval_count"] = -1
        elif fault == "bool_output":
            reply["eval_count"] = True
        elif fault == "negative_output":
            reply["eval_count"] = -1
        elif fault == "over_output":
            reply["eval_count"] = q.task.max_output_tokens + 1
        elif fault == "over_context":
            # Same exact input count; exceed the route context using output.
            reply["eval_count"] = local._context_tokens(q.route) + 1
        elif fault == "prompt":
            reply["prompt_eval_count"] = counter.count_prompt_tokens(body) + 1
        elif fault == "duplicate_content":
            reply["message"]["content"] = '{"format":"x","format":"y"}'
        elif fault == "schema":
            reply["message"]["content"] = '{}'
        elif fault == "duplicate_transport":
            # Actual transport JSON primitive, not a permissive json.loads.
            from zacai.intelligence.local_review_runtime import _json
            return _json(b'{"model":"x","model":"y"}')
        return reply

    monkeypatch.setattr(local, "_fragment_http_post", post)
    with pytest.raises(local.FragmentLocalContextualRuntimeError) as error:
        r.generate_fragment(q)
    assert len(bodies) == 1 and gates == ["PRE_DISPATCH"]
    assert error.value.code.value == code
    assert error.value.did_transport_attempt is r.did_transport_attempt is True
    assert r.usage is None
    assert error.value.__cause__ is error.value.__context__ is None
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)
    assert len(bodies) == 1


@pytest.mark.parametrize("phase", ["preflight", "generate", "release"])
def test_non_none_runtime_verification_contract_holds(installed, monkeypatch, phase):
    r, q, counter, _, bodies = setup(installed, monkeypatch)
    if phase != "preflight":
        r.preflight_fragment(q)
    calls = []

    def verify():
        calls.append(True)
        return True if phase != "release" or len(calls) == 2 else None

    monkeypatch.setattr(counter, "verify_runtime", verify)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        (r.preflight_fragment if phase == "preflight" else r.generate_fragment)(q)
    assert len(bodies) == (1 if phase == "release" else 0)
    assert r.usage is None
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        r.generate_fragment(q)


def test_unavailable_route_rejected_before_counter_or_metadata(installed, monkeypatch):
    r, q, counter, events, bodies = setup(installed, monkeypatch)
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        local.FragmentLocalContextualRuntime(
            route=q.route.model_copy(update={"available": False}), model_digest=installed[2],
            tokenizer_digest=r._tokenizer_digest, template_digest=r._template_digest,
            renderer_digest=r._renderer_digest, runtime_digest=r._runtime_digest,
            token_counter=counter, recheck=lambda request, descriptor: None)
    assert events == [] and bodies == []
