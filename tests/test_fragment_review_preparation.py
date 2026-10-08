"""Invented full packet/context, no runtime/authentication/recovery/model calls."""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_history_contextual_codec import review_for
from tests.test_history_fragment_contextual_codec import request
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_review_preparation as m
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_packet,
    encode_history_fragment_contextual_packet,
)
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.policy import Destination


@pytest.fixture
def case():
    q = request(True)
    builder = uuid4()
    raw = encode_history_fragment_contextual_packet(
        review_for(q), q, builder_id=builder, created_at=q.observed_at + timedelta(seconds=1)
    )
    rubric = b"Review every criterion against full dated evidence, not citation presence alone."
    template = b"Independently evaluate this complete answer. Return only the exact ten criterion judgments."
    route = q.route.model_copy(
        update={
            "capabilities": frozenset({m.PURPOSE}),
            "max_input_characters": 64000,
            "max_output_tokens": 2048,
            "estimated_latency_ms": 60000,
        }
    )
    args = {
        "expected_packet_digest": content_hash_of(raw),
        "expected_task_id": q.task.task_id,
        "expected_builder_id": builder,
        "reviewer_id": uuid4(),
        "run_id": uuid4(),
        "route": route,
        "max_output_tokens": 2048,
        "max_latency_ms": 60000,
        "rubric_utf8": rubric,
        "template_utf8": template,
        "expected_rubric_digest": content_hash_of(rubric),
        "expected_template_digest": content_hash_of(template),
        "model_digest": "a" * 64,
        "reviewer_wire_digest": "b" * 64,
    }
    return raw, q, args


def prepare(case, **changes):
    raw, _, args = case
    return m.prepare_fragment_review_request(raw, **(args | changes))


def test_full_canonical_packet_answer_context_role_date_gaps_included(case):
    raw, q, args = case
    p = prepare(case)
    data = json.loads(p.body)
    assert canonical_bytes(data["packet"]) == raw
    packet = decode_history_fragment_contextual_packet(raw)
    assert data["packet"]["rendered_preview"] == packet.rendered_preview
    request_wire = json.loads(data["packet"]["request_json"])
    assert request_wire == json.loads(packet.request_json)
    assert request_wire["task"] == q.task.model_dump(mode="json")
    assert request_wire["profile_json"] == q.profile_json
    assert request_wire["original_task"] == q.original_task.model_dump(mode="json")
    assert "Current facts and owner preferences unconfirmed." in data["packet"]["rendered_preview"]
    assert data["rubric"].encode() == args["rubric_utf8"]
    assert data["review_instruction"].encode() == args["template_utf8"]
    assert p.body_digest == content_hash_of(p.body)
    assert (
        p.processing_authorized
        is p.reviewer_authenticated
        is p.recovery_verified
        is p.current_facts_verified
        is False
    )
    assert repr(p).find("Earlier suggestion") < 0
    m.verify_fragment_review_request(
        p, packet_raw=raw, rubric_utf8=args["rubric_utf8"], template_utf8=args["template_utf8"]
    )


@pytest.mark.parametrize(
    "field",
    [
        "expected_task_id",
        "expected_builder_id",
        "expected_packet_digest",
        "expected_rubric_digest",
        "expected_template_digest",
        "model_digest",
        "reviewer_wire_digest",
    ],
)
def test_exact_host_binding_mutations_hold(case, field):
    bad = (
        uuid4() if field.endswith("_id") else ("0" * 64 if field.startswith("expected_") else "BAD")
    )
    with pytest.raises(m.FragmentReviewPreparationError) as exc:
        prepare(case, **{field: bad})
    assert exc.value.__context__ is exc.value.__cause__ is None


@pytest.mark.parametrize(
    "fault", ["external", "purpose", "unavailable", "output", "latency", "capacity"]
)
def test_route_scope_resource_refusals(case, fault):
    route = case[2]["route"]
    change = {
        "external": {"destination": Destination.EXTERNAL},
        "purpose": {"capabilities": frozenset({"generate"})},
        "unavailable": {"available": False},
        "output": {"max_output_tokens": 1024},
        "latency": {"estimated_latency_ms": 60001},
        "capacity": {"max_input_characters": 1},
    }[fault]
    with pytest.raises(m.FragmentReviewPreparationError):
        prepare(case, route=route.model_copy(update=change))


@pytest.mark.parametrize(
    "field", ["body", "body_digest", "request_digest", "rubric_digest", "template_digest"]
)
def test_prepared_body_and_instruction_drift_refuse_reconstruction(case, field):
    p = prepare(case)
    bad = p.body + b" " if field == "body" else "0" * 64
    with pytest.raises(m.FragmentReviewPreparationError):
        m.verify_fragment_review_request(
            replace(p, **{field: bad}),
            packet_raw=case[0],
            rubric_utf8=case[2]["rubric_utf8"],
            template_utf8=case[2]["template_utf8"],
        )


def test_canonical_changed_full_packet_old_digest_refused(case):
    raw, _, args = case
    p = decode_history_fragment_contextual_packet(raw)
    changed = encode_history_fragment_contextual_packet(
        p.review,
        p.request(),
        builder_id=p.builder_id,
        created_at=p.created_at + timedelta(seconds=1),
    )
    assert decode_history_fragment_contextual_packet(changed)
    with pytest.raises(m.FragmentReviewPreparationError):
        m.prepare_fragment_review_request(changed, **args)


@pytest.mark.parametrize("field", ["reviewer_id", "run_id"])
def test_distinct_host_review_identity_required(case, field):
    _, q, args = case
    with pytest.raises(m.FragmentReviewPreparationError):
        prepare(
            case,
            **{field: args["expected_builder_id"] if field == "reviewer_id" else q.task.task_id},
        )


def judgments(judgment=ReviewJudgment.UNREVIEWED):
    return {
        "format": "zac-history-fragment-review-judgments-v1",
        "assessments": [
            {"criterion": c.value, "judgment": judgment.value} for c in m.ContextualCriterion
        ],
    }


@pytest.mark.parametrize("judgment", list(ReviewJudgment))
def test_only_closed_ten_model_judgments_no_host_headers(case, judgment):
    parsed = m.parse_fragment_review_judgments(canonical_bytes(judgments(judgment)))
    assert len(parsed.assessments) == 10 and {v.judgment for v in parsed.assessments} == {judgment}
    schema = json.loads(prepare(case).body)["judgments_schema"]
    assert (
        set(schema["properties"]) == {"format", "assessments"}
        and schema["additionalProperties"] is False
    )


@pytest.mark.parametrize(
    "field", ["task_id", "builder_id", "reviewer_id", "packet_digest", "evaluated_at", "route"]
)
def test_model_authored_host_fields_refused(field):
    data = judgments()
    data[field] = "invented"
    with pytest.raises(m.FragmentReviewPreparationError):
        m.parse_fragment_review_judgments(canonical_bytes(data))


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "unknown", "extra", "duplicate-key", "utf8", "oversize"]
)
def test_malformed_judgments_hold(fault):
    data = judgments()
    if fault == "missing":
        data["assessments"].pop()
    elif fault == "duplicate":
        data["assessments"][-1] = data["assessments"][0]
    elif fault == "unknown":
        data["assessments"][0]["criterion"] = "MADE_UP"
    elif fault == "extra":
        data["assessments"][0]["judgment"] = "PASS_WITH_AUTHORITY"
    raw = canonical_bytes(data)
    if fault == "duplicate-key":
        raw = b'{"format":"x",' + raw[1:]
    elif fault == "utf8":
        raw = b"\xff"
    elif fault == "oversize":
        raw = b" " * 8001
    with pytest.raises(m.FragmentReviewPreparationError):
        m.parse_fragment_review_judgments(raw)


def test_whole_body_ceiling_holds_without_truncation(case, monkeypatch):
    p = prepare(case)
    assert len(p.body) > 1
    monkeypatch.setattr(m, "MAX_REVIEW_BODY_BYTES", len(p.body) - 1)
    with pytest.raises(m.FragmentReviewPreparationError):
        prepare(case)
    monkeypatch.setattr(m, "MAX_REVIEW_BODY_BYTES", len(p.body))
    assert prepare(case).body == p.body


@pytest.mark.parametrize("field", ["rubric_utf8", "template_utf8"])
def test_changed_exact_instruction_bytes_old_pin_refused(case, field):
    with pytest.raises(m.FragmentReviewPreparationError):
        prepare(case, **{field: case[2][field] + b" changed"})


def test_closed_false_flags_cannot_be_constructor_overrides(case):
    p = prepare(case)
    for key in (
        "processing_authorized",
        "reviewer_authenticated",
        "recovery_verified",
        "current_facts_verified",
    ):
        with pytest.raises(ValueError):
            replace(p, **{key: True})


def test_high_advertised_route_capacity_accepts_bounded_requested_output(case):
    route = case[2]["route"].model_copy(update={"max_output_tokens": 32000})
    p = prepare(case, route=route)
    assert p.route.max_output_tokens == 32000 and p.max_output_tokens == 2048
    assert json.loads(p.body)["review_budgets"] == {
        "max_output_tokens": 2048,
        "max_latency_ms": 60000,
    }


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("max_output_tokens", 2049),
        ("max_output_tokens", True),
        ("max_latency_ms", 60001),
        ("max_latency_ms", 0),
    ],
)
def test_requested_budget_closed_ceiling(case, field, bad):
    with pytest.raises(m.FragmentReviewPreparationError):
        prepare(case, **{field: bad})


def test_declared_cost_retained_without_implied_spend_admission(case):
    p = prepare(case, route=case[2]["route"].model_copy(update={"estimated_cost_usd": 1}))
    assert p.route.estimated_cost_usd == 1 and p.processing_authorized is False
