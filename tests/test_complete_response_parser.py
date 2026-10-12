"""Invented structural responses; no dispatch, permission or live I/O."""
import json
from pathlib import Path

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_fragment_local_contextual_runtime import request as fragment_request
from tests.test_history_contextual_codec import prepared as prepared  # noqa: PLC0414
from zacai.intelligence import local_contextual_runtime as local


def reply(q):
    content = {"format": "zac-contextual-draft-v2", "overview": [], "background": [],
               "continuity": [], "items": [], "conflicts": [], "clarifications": []}
    return {"model": q.route.identity.model_id, "done": True, "done_reason": "stop",
            "prompt_eval_count": 123, "eval_count": 4,
            "message": {"role": "assistant", "content": json.dumps(content)}}


def changed(q, fault):
    r = reply(q)
    elapsed = 1.0
    if fault == "shape": return [], elapsed
    if fault == "model": r["model"] = "other"
    if fault == "done": r["done"] = False
    if fault == "message": r["message"] = []
    if fault == "role": r["message"]["role"] = "user"
    if fault == "tools": r["message"]["tool_calls"] = [{}]
    if fault == "thinking": r["message"]["thinking"] = "invented"
    if fault == "reason": r["done_reason"] = "other"
    if fault == "length": r["done_reason"] = "length"
    if fault == "limit":
        r["done_reason"] = "length"
        r["eval_count"] = q.task.max_output_tokens
    if fault == "bool": r["eval_count"] = True
    if fault == "negative": r["prompt_eval_count"] = -1
    if fault == "count": r["prompt_eval_count"] = 124
    if fault == "capacity": r["eval_count"] = q.task.max_output_tokens + 1
    if fault == "context": r["prompt_eval_count"] = local._context_tokens(q.route)
    if fault == "latency": elapsed = q.task.max_latency_ms + 1.0
    if fault == "negative_latency": elapsed = -1.0
    if fault == "schema": r["message"]["content"] = '{}'
    if fault == "duplicate": r["message"]["content"] = '{"format":"x","format":"y"}'
    if fault == "content": r["message"]["content"] = None
    return r, elapsed


FAULTS = [("shape", "RESPONSE_SHAPE"), ("model", "RESPONSE_MODEL"),
          ("done", "RESPONSE_INCOMPLETE"), ("message", "RESPONSE_SHAPE"),
          ("role", "RESPONSE_AUTHORITY"), ("tools", "RESPONSE_AUTHORITY"),
          ("thinking", "RESPONSE_AUTHORITY"), ("reason", "RESPONSE_STOP_REASON"),
          ("length", "RESPONSE_LENGTH"), ("limit", "OUTPUT_LIMIT"),
          ("bool", "RESPONSE_USAGE"), ("negative", "RESPONSE_USAGE"),
          ("count", "PROMPT_COUNT_MISMATCH"), ("capacity", "RESPONSE_USAGE"),
          ("context", "PROMPT_COUNT_MISMATCH"), ("latency", "RESPONSE_LATENCY"),
          ("negative_latency", "RESPONSE_LATENCY"), ("schema", "RESPONSE_SCHEMA"),
          ("duplicate", "RESPONSE_SCHEMA"), ("content", "RESPONSE_SCHEMA")]


def outcome(parser, r, q, elapsed):
    try:
        return parser(r, q, q.route, elapsed, 123)
    except local.LocalContextualRuntimeError as e:
        assert e.__cause__ is e.__context__ is None
        return type(e), str(e), e.code


@pytest.mark.parametrize("fault,code", FAULTS)
def test_complete_actual_request_closed_reply_failures(prepared, fault, code):
    q = prepared[3]
    r, elapsed = changed(q, fault)
    with pytest.raises(local.LocalContextualRuntimeError) as e:
        local._parse_history_response(r, q, q.route, elapsed, 123)
    assert e.value.code.value == code
    assert e.value.__cause__ is e.value.__context__ is None


def test_complete_positive_and_exact_budget_boundary(prepared):
    q = prepared[3]
    r = reply(q)
    r["eval_count"] = q.task.max_output_tokens
    draft, usage = local._parse_history_response(r, q, q.route, q.task.max_latency_ms, 123)
    assert draft.format == "zac-contextual-draft-v2"
    assert usage.input_tokens == 123 and usage.output_tokens == q.task.max_output_tokens
    assert usage.latency_ms == q.task.max_latency_ms and usage.cost_usd == 0
    assert q.processing_authorized is False


def test_complete_family_holds_before_foreign_attribute_access(prepared):
    called = []
    class Foreign:
        @property
        def task(self):
            called.append(True)
            raise AssertionError("foreign budget accessed")
    q = prepared[3]
    for invalid in (Foreign(), fragment_request()):
        with pytest.raises(local.LocalContextualRuntimeError) as e:
            local._parse_history_response(reply(q), invalid, q.route, 1, 123)
        assert e.value.code is local.F.REQUEST_PAYLOAD
    assert not called


def test_complete_invalid_canonical_request_and_route_hold(prepared):
    q = prepared[3]
    for invalid, route in ((q.model_copy(update={"prompt_body": q.prompt_body + "x"}), q.route),
                           (q, q.route.model_copy(update={"max_input_characters": 31999}))):
        with pytest.raises(local.LocalContextualRuntimeError) as e:
            local._parse_history_response(reply(q), invalid, route, 1, 123)
        assert e.value.code is local.F.REQUEST_PAYLOAD


@pytest.mark.parametrize("fault", ["positive", *[x[0] for x in FAULTS]])
def test_fragment_matches_original_installed_wrapper(fault):
    q = fragment_request()
    original = Path(__file__).parents[1] / "goldens/original_fragment_response.py"
    namespace = dict(vars(local))
    exec(compile(original.read_bytes(), str(original), "exec"), namespace)  # noqa: S102 - pinned old function
    r, elapsed = (reply(q), 1.0) if fault == "positive" else changed(q, fault)
    assert outcome(namespace["_parse_fragment_response"], r, q, elapsed) == outcome(
        local._parse_fragment_response, r, q, elapsed)


def test_complete_actual_context_capacity_and_zero_usage_compatibility(prepared):
    q = prepared[3]
    r = reply(q)
    r["prompt_eval_count"] = local._context_tokens(q.route)
    with pytest.raises(local.LocalContextualRuntimeError) as e:
        local._parse_history_response(r, q, q.route, 1, r["prompt_eval_count"])
    assert e.value.code is local.F.RESPONSE_USAGE
    r["prompt_eval_count"] = r["eval_count"] = 0
    _, usage = local._parse_history_response(r, q, q.route, 0, 0)
    assert usage.input_tokens == usage.output_tokens == usage.latency_ms == 0
    # Preserves old parser semantics; zero usage is not invocation authentication.
