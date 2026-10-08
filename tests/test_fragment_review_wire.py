"""Invented wire and replies only; no runtime/tokenizer/authority."""

import json
from dataclasses import replace

import pytest

from tests.test_fragment_review_preparation import case as original_case
from tests.test_fragment_review_preparation import prepare
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_review_wire as m
from zacai.intelligence.contextual_evaluation import ContextualCriterion
from zacai.intelligence.ollama_token_counter import LocalTokenCounterError, render_review_prompt


@pytest.fixture
def case():
    return original_case.__wrapped__()


@pytest.fixture
def wire_case(case):
    raw, q, args = case
    route = args["route"].model_copy(
        update={
            "identity": args["route"].identity.model_copy(
                update={"model_id": m.MODEL, "runtime_id": m.RUNTIME}
            ),
            "max_output_tokens": 32000,
        }
    )
    args = args | {"route": route, "max_output_tokens": 128}
    selected = (raw, q, args)
    p = prepare(selected)
    return selected, p


def wire(wire_case):
    (raw, _, args), p = wire_case
    return m.serialize_fragment_review_wire(
        p, packet_raw=raw, rubric_utf8=args["rubric_utf8"], template_utf8=args["template_utf8"]
    )


def reply():
    judgments = {
        "format": "zac-history-fragment-review-judgments-v1",
        "assessments": [{"criterion": c.value, "judgment": "PASS"} for c in ContextualCriterion],
    }
    return {
        "model": m.MODEL,
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": json.dumps(judgments)},
        "prompt_eval_count": 100,
        "eval_count": 12,
    }


def test_exact_full_body_profile_schema_and_requested_not_advertised(wire_case):
    data = json.loads(wire(wire_case))
    p = wire_case[1]
    assert data["messages"][1]["content"].encode() == p.body
    assert data["format"] == m.FragmentReviewJudgments.model_json_schema()
    assert data["options"] == {"temperature": 0, "num_predict": 128, "num_ctx": 16384}
    assert p.route.max_output_tokens == 32000
    assert all(data[k] is False for k in ("stream", "think", "truncate", "shift"))
    assert data["keep_alive"] == 0


def test_existing_real_counter_rejects_new_schema_without_fake_count(wire_case):
    with pytest.raises(LocalTokenCounterError):
        render_review_prompt(wire(wire_case))


def test_transport_overhead_holds_never_truncates(wire_case, monkeypatch):
    raw = wire(wire_case)
    monkeypatch.setattr(m, "MAX_WIRE_BYTES", len(raw) - 1)
    with pytest.raises(m.FragmentReviewWireError):
        wire(wire_case)
    monkeypatch.setattr(m, "MAX_WIRE_BYTES", len(raw))
    assert wire(wire_case) == raw


@pytest.mark.parametrize(
    "field,value", [("body", b"wrong"), ("body_digest", "f" * 64), ("request_digest", "f" * 64)]
)
def test_prepared_mutation_holds(wire_case, field, value):
    selected, p = wire_case
    with pytest.raises(m.FragmentReviewWireError):
        wire((selected, replace(p, **{field: value})))


@pytest.mark.parametrize("field,value", [("model_id", "other"), ("runtime_id", "other")])
def test_wrong_profile_holds(case, field, value):
    raw, q, args = case
    route = args["route"].model_copy(
        update={
            "identity": args["route"].identity.model_copy(
                update={"model_id": m.MODEL, "runtime_id": m.RUNTIME, field: value}
            )
        }
    )
    selected = (raw, q, args | {"route": route})
    with pytest.raises(m.FragmentReviewWireError):
        wire((selected, prepare(selected)))


def test_closed_reported_response_is_not_authenticated():
    result = m.parse_fragment_review_response(canonical_bytes(reply()), requested_output_tokens=128)
    assert len(result.judgments.assessments) == 10
    assert result.reported_input_tokens == 100 and result.reported_output_tokens == 12
    assert "PASS" not in repr(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("model", "other"),
        ("done", False),
        ("done_reason", "length"),
        ("eval_count", 129),
        ("prompt_eval_count", True),
        ("eval_count", -1),
        ("prompt_eval_count", 16384),
        ("error", "private"),
    ],
)
def test_reply_mutations_hold(field, value):
    data = reply() | {field: value}
    with pytest.raises(m.FragmentReviewWireError):
        m.parse_fragment_review_response(canonical_bytes(data), requested_output_tokens=128)


@pytest.mark.parametrize(
    "extra", [{"thinking": "private"}, {"tool_calls": []}, {"reviewer_id": "fake"}]
)
def test_message_extra_holds(extra):
    data = reply()
    data["message"].update(extra)
    with pytest.raises(m.FragmentReviewWireError):
        m.parse_fragment_review_response(canonical_bytes(data), requested_output_tokens=128)


def test_duplicate_nested_and_model_provenance_hold():
    data = reply()
    data["message"]["content"] = (
        '{"format":"zac-history-fragment-review-judgments-v1","assessments":[],"task_id":"fake"}'
    )
    with pytest.raises(m.FragmentReviewWireError):
        m.parse_fragment_review_response(canonical_bytes(data), requested_output_tokens=128)
    raw = canonical_bytes(reply()).replace(
        b'"role":"assistant"', b'"role":"assistant","role":"assistant"'
    )
    with pytest.raises(m.FragmentReviewWireError):
        m.parse_fragment_review_response(raw, requested_output_tokens=128)


@pytest.mark.parametrize("raw,budget", [(b"\xff", 128), (b"x" * 16001, 128), (b"{}", True)])
def test_invalid_bytes_and_budget_hold(raw, budget):
    with pytest.raises(m.FragmentReviewWireError):
        m.parse_fragment_review_response(raw, requested_output_tokens=budget)


def test_nonempty_judgments_reported_zero_output_holds():
    data = reply()
    assert data["message"]["content"]
    data["eval_count"] = 0
    with pytest.raises(m.FragmentReviewWireError):
        m.parse_fragment_review_response(canonical_bytes(data), requested_output_tokens=128)
    data["eval_count"] = 1
    parsed = m.parse_fragment_review_response(canonical_bytes(data), requested_output_tokens=128)
    assert parsed.reported_output_tokens == 1
    assert len(parsed.judgments.assessments) == 10
