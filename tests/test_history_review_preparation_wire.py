"""Real invented complete profiles/packet; rows/owner simulated, no operational I/O."""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_history_contextual_codec import host as host  # noqa: PLC0414
from tests.test_history_contextual_codec import (
    prepared as original_prepared,  # noqa: F401 - fixture alias
)
from tests.test_history_contextual_codec import review_for
from tests.test_history_fragment_contextual_codec import request as fragment_request
from tests.test_history_generation_review_declaration import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_review_preparation as p
from zacai.intelligence import history_review_wire as w
from zacai.intelligence.contextual_evaluation import ContextualCriterion
from zacai.intelligence.history_contextual_codec import (
    decode_history_contextual_packet,
    encode_history_contextual_packet,
    encode_history_contextual_request,
)
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_packet,
)
from zacai.intelligence.review_evaluation import ReviewJudgment


@pytest.fixture
def prepared(original_prepared):  # noqa: F811 - pytest fixture alias
    from zacai.intelligence.history_context_metadata import (
        HistoryMessageSpan,
        prepare_claude_history_context_preview,
    )
    from zacai.intelligence.history_contextual_codec import prepare_history_contextual_request

    original, read, _, prior = original_prepared
    entry = prior.sidecar.entries[0]
    preview = prepare_claude_history_context_preview(
        original,
        read,
        selections=tuple(
            HistoryMessageSpan(
                message_id=e.message_id,
                character_start=e.character_start,
                character_end=e.character_end,
            )
            for e in (prior.sidecar.entries[0], prior.sidecar.entries[2])
        ),
        observed_at=entry.projection_observed_at,
        route=prior.route,
    )
    request = prepare_history_contextual_request(
        preview, original_context=original, route=prior.route
    )
    return original, read, preview, request


@pytest.fixture
def case(declaration_case):
    q, g, profile = declaration_case
    rubric = (
        b"Review each of the ten criteria against all original dated context and the full answer."
    )
    template = b"Independently evaluate the full answer; return only exact criterion judgments."
    profile = profile.model_copy(
        update={
            "rubric_digest": content_hash_of(rubric),
            "template_digest": content_hash_of(template),
            "route": profile.route.model_copy(
                update={
                    "max_input_characters": 64000,
                    "identity": profile.route.identity.model_copy(update={"runtime_id": w.RUNTIME}),
                }
            ),
        }
    )
    raw = encode_history_contextual_packet(
        review_for(q), q, builder_id=g.builder_id, created_at=g.approved_at + timedelta(seconds=1)
    )
    args = {
        "expected_packet_digest": content_hash_of(raw),
        "expected_task_id": q.task.task_id,
        "expected_builder_id": g.builder_id,
        "expected_request": q,
        "review": profile,
        "rubric_utf8": rubric,
        "template_utf8": template,
    }
    return raw, q, args


def prepare(case, **changes):
    raw, _, args = case
    return p.prepare_history_review_request(raw, **(args | changes))


def wire(case, value=None):
    raw, q, args = case
    return w.serialize_history_review_wire(
        value or prepare(case),
        packet_raw=raw,
        expected_request=q,
        rubric_utf8=args["rubric_utf8"],
        template_utf8=args["template_utf8"],
    )


def judgments():
    return {
        "format": "zac-history-complete-review-judgments-v1",
        "assessments": [{"criterion": c.value, "judgment": "PASS"} for c in ContextualCriterion],
    }


def test_exact_whole_packet_request_dates_profiles_coverage_and_false_authority(case):
    raw, q, args = case
    value = prepare(case)
    data = json.loads(value.body)
    assert p._review_packet_raw(data["packet"], data["packet_representation"]) == raw
    packet = decode_history_contextual_packet(raw)
    assert packet.request() == q
    assert json.loads(packet.request_json)["sidecar"] == q.sidecar.model_dump(mode="json")
    assert json.loads(packet.request_json)["projection_profiles"] == list(q.projection_profiles)
    assert packet.request_digest == content_hash_of(encode_history_contextual_request(q))
    assert data["review_purpose"]["route"]["max_output_tokens"] == 32000
    assert value.max_output_tokens == args["review"].max_output_tokens
    assert value.reviewer_id != value.builder_id
    assert value.body_digest == content_hash_of(value.body)
    assert (
        value.processing_authorized
        is value.reviewer_authenticated
        is value.recovery_verified
        is value.current_facts_verified
        is False
    )
    p.verify_history_review_request(
        value,
        packet_raw=raw,
        expected_request=q,
        rubric_utf8=args["rubric_utf8"],
        template_utf8=args["template_utf8"],
    )
    body = json.loads(wire(case))
    assert body["messages"][1]["content"].encode() == value.body
    assert body["format"] == p.HistoryReviewJudgments.model_json_schema()
    assert body["options"]["num_predict"] == value.max_output_tokens
    assert all(body[k] is False for k in ("stream", "think", "truncate", "shift"))


@pytest.mark.parametrize(
    "field",
    [
        "expected_packet_digest",
        "expected_task_id",
        "expected_builder_id",
        "expected_request",
        "review",
    ],
)
def test_host_original_binding_required(case, field):
    value = (
        None
        if field in ("expected_request", "review")
        else (uuid4() if field.endswith("_id") else "0" * 64)
    )
    with pytest.raises(p.HistoryReviewPreparationError) as error:
        prepare(case, **{field: value})
    assert error.value.__context__ is error.value.__cause__ is None


@pytest.mark.parametrize(
    "field", ["body", "body_digest", "request_digest", "purpose_digest", "packet_digest"]
)
def test_prepared_tamper_cannot_reach_wire(case, field):
    value = prepare(case)
    bad = b"private tamper" if field == "body" else "0" * 64
    with pytest.raises(w.HistoryReviewWireError) as error:
        wire(case, replace(value, **{field: bad}))
    assert error.value.__context__ is None


def test_wrong_fragment_family_refused_even_matching_hash(case):
    q = fragment_request(True)
    raw = encode_history_fragment_contextual_packet(
        review_for(q),
        q,
        builder_id=case[2]["expected_builder_id"],
        created_at=q.observed_at + timedelta(seconds=1),
    )
    with pytest.raises(p.HistoryReviewPreparationError):
        p.prepare_history_review_request(
            raw, **(case[2] | {"expected_packet_digest": content_hash_of(raw)})
        )


@pytest.mark.parametrize("fault", ["role", "date", "profile", "coverage", "preview", "provenance"])
def test_full_packet_metadata_mutation_is_not_discarded(case, fault):
    data = json.loads(case[0])
    q = json.loads(data["request_json"])
    e = q["sidecar"]["entries"][0]
    if fault == "role":
        e["historical_role"] = "ASSISTANT"
    elif fault == "date":
        e["reported_created_at"] = "2000-01-01T00:00:00Z"
    elif fault == "profile":
        q["projection_profiles"][0] += " "
    elif fault == "coverage":
        e["character_end"] -= 1
    elif fault == "provenance":
        q["task"]["event"]["provenance"] = []
    else:
        data["rendered_preview"] += " omitted coverage"
    if fault != "preview":
        data["request_json"] = canonical_bytes(q).decode()
        data["request_digest"] = content_hash_of(data["request_json"].encode())
    raw = canonical_bytes(data)
    with pytest.raises(p.HistoryReviewPreparationError):
        p.prepare_history_review_request(
            raw, **(case[2] | {"expected_packet_digest": content_hash_of(raw)})
        )


@pytest.mark.parametrize(
    "fault", ["builder", "rubric", "template", "budget", "purpose", "unavailable", "external"]
)
def test_review_assignment_and_original_declared_budget_hold(case, fault):
    profile = case[2]["review"]
    change = {}
    if fault == "builder":
        change = {"reviewer_id": case[2]["expected_builder_id"]}
    elif fault in ("rubric", "template"):
        change = {fault + "_digest": "0" * 64}
    elif fault == "budget":
        change = {"max_output_tokens": 32001}
    else:
        from zacai.policy import Destination

        field, val = {
            "purpose": ("capabilities", frozenset({"generate"})),
            "unavailable": ("available", False),
            "external": ("destination", Destination.EXTERNAL),
        }[fault]
        change = {"route": profile.route.model_copy(update={field: val})}
    with pytest.raises(p.HistoryReviewPreparationError):
        prepare(case, review=profile.model_copy(update=change))


def test_no_truncation_after_transport_overhead(case, monkeypatch):
    raw = wire(case)
    monkeypatch.setattr(w, "MAX_WIRE_BYTES", len(raw) - 1)
    with pytest.raises(w.HistoryReviewWireError):
        wire(case)
    monkeypatch.setattr(w, "MAX_WIRE_BYTES", len(raw))
    assert wire(case) == raw


@pytest.mark.parametrize("fault", ["host", "duplicate", "missing", "fragment", "repeat", "bool"])
def test_judgments_only_no_model_host_authority(fault):
    d = judgments()
    if fault == "host":
        d["reviewer_id"] = str(uuid4())
    elif fault == "missing":
        d["assessments"].pop()
    elif fault == "fragment":
        d["format"] = "zac-history-fragment-review-judgments-v1"
    elif fault == "repeat":
        d["assessments"][-1] = d["assessments"][0]
    elif fault == "bool":
        d["assessments"][0]["judgment"] = True
    raw = canonical_bytes(d)
    if fault == "duplicate":
        raw = raw.replace(b'"format":', b'"format":"bad","format":')
    with pytest.raises(p.HistoryReviewPreparationError) as error:
        p.parse_history_review_judgments(raw)
    assert error.value.__context__ is error.value.__cause__ is None


def test_ten_judgments_remain_unauthenticated():
    value = p.parse_history_review_judgments(canonical_bytes(judgments()))
    assert all(v.judgment is ReviewJudgment.PASS for v in value.assessments)
    assert not hasattr(value, "reviewer_id")


@pytest.mark.parametrize("fault", ["model", "reason", "thinking", "count", "schema"])
def test_closed_response_refusals(fault):
    d = {
        "model": w.MODEL,
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": json.dumps(judgments())},
        "prompt_eval_count": 100,
        "eval_count": 12,
    }
    if fault == "model":
        d["model"] = "other"
    elif fault == "reason":
        d["done_reason"] = "length"
    elif fault == "thinking":
        d["message"]["thinking"] = "private"
    elif fault == "count":
        d["eval_count"] = 513
    else:
        d["message"]["content"] = json.dumps(
            {
                "format": "zac-history-fragment-review-judgments-v1",
                "assessments": judgments()["assessments"],
            }
        )
    with pytest.raises(w.HistoryReviewWireError):
        w.parse_history_review_response(canonical_bytes(d), requested_output_tokens=512)


def test_original_three_message_whole_wire_preserves_correction_without_omission(original_prepared):  # noqa: F811 - pytest fixture alias
    oversized = case.__wrapped__(declaration_case.__wrapped__(original_prepared))
    value = prepare(oversized)
    assert len(value.body) <= p.MAX_REVIEW_BODY_BYTES
    assert len(json.loads(value.body)["packet"]["request"]) > 0
    assert len(oversized[1].sidecar.entries) == 3
    actual = wire(oversized, value)
    assert len(actual) <= w.MAX_WIRE_BYTES
    assert json.loads(actual)["messages"][1]["content"].encode() == value.body
    # Whole packet remains exact. Successful preparation does not promise wire fit.
    assert p._review_packet_raw(json.loads(value.body)["packet"], json.loads(value.body)["packet_representation"]) == oversized[0]


def test_literal_markup_role_date_and_coverage_are_preserved(case):
    raw, q, args = case
    value = prepare(case)
    data = json.loads(value.body)
    assert p._review_packet_raw(data["packet"], data["packet_representation"]) == raw
    sidecar = data["packet"]["request"]["sidecar"]
    assert sidecar == q.sidecar.model_dump(mode="json")
    assert w.serialize_history_review_wire(
        value,
        packet_raw=raw,
        expected_request=q,
        rubric_utf8=args["rubric_utf8"],
        template_utf8=args["template_utf8"],
    ) == wire(case)


def test_closed_response_positive_reports_are_not_authenticated():
    raw = canonical_bytes(
        {
            "model": w.MODEL,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(judgments())},
            "prompt_eval_count": 100,
            "eval_count": 12,
        }
    )
    value = w.parse_history_review_response(raw, requested_output_tokens=512)
    assert value.reported_input_tokens == 100 and value.reported_output_tokens == 12
    assert len(value.judgments.assessments) == 10
    assert not hasattr(value, "reviewer_authenticated")


@pytest.mark.parametrize(
    "field,value",
    [
        ("eval_count", 0),
        ("eval_count", True),
        ("prompt_eval_count", 0),
        ("prompt_eval_count", True),
        ("total_duration", -1),
    ],
)
def test_closed_response_invalid_reported_usage_and_timing(field, value):
    d = {
        "model": w.MODEL,
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": json.dumps(judgments())},
        "prompt_eval_count": 100,
        "eval_count": 12,
    }
    d[field] = value
    with pytest.raises(w.HistoryReviewWireError):
        w.parse_history_review_response(canonical_bytes(d), requested_output_tokens=512)


def test_actual_full_three_message_overcap_holds_without_losing_packet(original_prepared):  # noqa: F811 - fixture alias
    c = case.__wrapped__(declaration_case.__wrapped__(original_prepared))
    template = b"Independent complete review with all original dated evidence. " * 60
    profile = c[2]["review"].model_copy(update={"template_digest": content_hash_of(template)})
    c = (c[0], c[1], c[2] | {"template_utf8": template, "review": profile})
    value = prepare(c, packet_representation=p.LEGACY_PACKET_REPRESENTATION)
    assert p._review_packet_raw(json.loads(value.body)["packet"], json.loads(value.body)["packet_representation"]) == c[0]
    with pytest.raises(w.HistoryReviewWireError):
        wire(c, value)


@pytest.mark.parametrize("fault", ["marker", "raw_field", "missing", "unknown", "request"])
def test_lossless_view_reconstruction_refuses_tamper(case, fault):
    data = json.loads(prepare(case).body)
    if fault == "marker":
        # The renderer reconstructs the exact declared input including its closed marker.
        from zacai.intelligence.history_review_prompt_counter import render_history_review_prompt

        wire_data = json.loads(wire(case))
        data["packet_representation"] = "canonical-packet-original"
        wire_data["messages"][1]["content"] = canonical_bytes(data).decode()
        from zacai.intelligence.ollama_token_counter import LocalTokenCounterError

        with pytest.raises(LocalTokenCounterError):
            render_history_review_prompt(canonical_bytes(wire_data))
        return
    view = data["packet"]
    if fault == "raw_field":
        view["request_json"] = "{}"
    elif fault == "missing":
        view.pop("created_at")
    elif fault == "unknown":
        view["unexpected"] = True
    else:
        view["request"]["sidecar"]["entries"][0]["historical_role"] = "ASSISTANT"
    with pytest.raises(ValueError):
        p._review_packet_raw(view, data["packet_representation"])
