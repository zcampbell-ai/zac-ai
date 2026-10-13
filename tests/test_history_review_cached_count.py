"""Actual wholly invented PUBLIC response, no model calls or authenticated review."""

import json
from pathlib import Path

import pytest

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.history_review_wire import (
    HistoryReviewWireError,
    parse_history_review_response,
)

RAW = Path(__file__).parent / "fixtures/invented-actual-review-reply.json"


def parse(data):
    return parse_history_review_response(canonical_bytes(data), requested_output_tokens=512)


def test_exact_invented_actual_reply_is_parsed_without_repair():
    raw = RAW.read_bytes()
    data = json.loads(raw)
    value = parse_history_review_response(raw, requested_output_tokens=512)
    assert value.reported_input_tokens == data["prompt_eval_count"] == 8976
    assert value.reported_output_tokens == data["eval_count"] == 306
    assert value.judgments.model_dump(mode="json") == json.loads(data["message"]["content"])
    assert RAW.read_bytes() == raw


@pytest.mark.parametrize("cached", [0, 1, 8976])
def test_valid_cache_declaration_does_not_subtract_reported_input(cached):
    data = json.loads(RAW.read_bytes())
    data["prompt_eval_cached_count"] = cached
    value = parse(data)
    assert value.reported_input_tokens == 8976 and value.reported_output_tokens == 306


def test_absent_optional_reply_keeps_original_result():
    data = json.loads(RAW.read_bytes())
    data.pop("prompt_eval_cached_count")
    assert parse(data) == parse_history_review_response(
        RAW.read_bytes(), requested_output_tokens=512
    )


@pytest.mark.parametrize("cached", [True, False, 0.0, -1, 8977, 2**64, "0", None])
def test_invalid_optional_cache_holds_with_fixed_cause_free_error(cached):
    data = json.loads(RAW.read_bytes())
    data["prompt_eval_cached_count"] = cached
    with pytest.raises(HistoryReviewWireError) as caught:
        parse(data)
    assert str(caught.value) == "history review response unavailable or invalid"
    assert caught.value.__context__ is None and caught.value.__cause__ is None


@pytest.mark.parametrize(
    "fault", ["unknown", "duplicate", "cached_does_not_reduce_capacity", "nested_message_field"]
)
def test_unknown_duplicate_and_total_capacity_remain_closed(fault):
    data = json.loads(RAW.read_bytes())
    if fault == "unknown":
        data["unrecognized_cached_tokens"] = 0
    elif fault == "cached_does_not_reduce_capacity":
        data["prompt_eval_count"] = 16384 - data["eval_count"] + 1
        data["prompt_eval_cached_count"] = data["prompt_eval_count"]
    elif fault == "nested_message_field":
        data["message"]["prompt_eval_cached_count"] = 0
    raw = canonical_bytes(data)
    if fault == "duplicate":
        assert raw.count(b'"prompt_eval_cached_count":0') == 1
        raw = raw.replace(
            b'"prompt_eval_cached_count":0',
            b'"prompt_eval_cached_count":0,"prompt_eval_cached_count":0',
        )
    with pytest.raises(HistoryReviewWireError):
        parse_history_review_response(raw, requested_output_tokens=512)
