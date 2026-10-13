"""Pure fresh profile/wire controls; no claim, SQL, model transport or approval."""

import json

import pytest

from tests.test_compact_review_wire import serialize
from tests.test_complete_review_lossless import case as case  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes as cb
from zacai.intelligence import history_review_preparation as p
from zacai.intelligence import history_review_wire as w
from zacai.intelligence.history_generation_review_declaration import (
    HistoryReviewPurposeProfileV1,
)
from zacai.intelligence.history_review_prompt_counter import render_history_review_prompt


def profile(case, runtime, latency, **updates):
    _, kw = case
    data = kw["review"].model_dump(mode="json")
    data["route"]["identity"]["runtime_id"] = runtime
    data["max_latency_ms"] = latency
    data.update(updates)
    return HistoryReviewPurposeProfileV1.model_validate(data)


@pytest.mark.parametrize(
    "runtime", [w.RUNTIME, w.COMPACT_RUNTIME, w.COMPACT_RUNTIME + "-unknown", "unregistered"]
)
@pytest.mark.parametrize("latency", [60001, 120000])
def test_original_and_unknown_runtime_profiles_cannot_enlarge_original_limit(
    case, runtime, latency
):
    with pytest.raises(ValueError):
        profile(case, runtime, latency)


@pytest.mark.parametrize("latency", [1, 60000, 60001, 120000])
def test_explicit_new_runtime_has_closed_prospective_cap(case, latency):
    # A low requested budget requires matching eligible route estimates.
    raw, kw = case
    data = kw["review"].model_dump(mode="json")
    data["route"]["identity"]["runtime_id"] = w.RECOVERY_WINDOW_RUNTIME
    data["route"]["estimated_latency_ms"] = float(min(latency, 90000))
    data["max_latency_ms"] = latency
    selected = HistoryReviewPurposeProfileV1.model_validate(data)
    prepared, serialized = serialize((raw, kw | {"review": selected}))
    restored = w.decode_history_review_wire_body(
        json.loads(json.loads(serialized)["messages"][1]["content"])
    )
    assert cb(restored) == prepared.body
    assert prepared.max_latency_ms == selected.max_latency_ms == latency
    assert prepared.max_output_tokens == kw["review"].max_output_tokens
    assert not prepared.processing_authorized and not prepared.reviewer_authenticated
    assert render_history_review_prompt(serialized)


@pytest.mark.parametrize("latency", [0, -1, 120001, True, False, 120000.0, "120000"])
def test_new_runtime_refuses_outside_limit_and_noninteger_values(case, latency):
    with pytest.raises(ValueError):
        profile(case, w.RECOVERY_WINDOW_RUNTIME, latency)


def test_old_fixed_inputs_keep_serialized_profile_and_original_sixty_seconds(case):
    _, kw = case
    original = kw["review"]
    restored = HistoryReviewPurposeProfileV1.model_validate(original.model_dump(mode="json"))
    assert restored == original and restored.max_latency_ms == 60000
    assert cb(restored.model_dump(mode="json")) == cb(original.model_dump(mode="json"))
    assert set(restored.model_dump()) == set(original.model_dump())
    _, old_wire = serialize(case)
    options = json.loads(old_wire)["options"]
    selected = profile(case, w.RECOVERY_WINDOW_RUNTIME, 120000)
    prepared, new_wire = serialize((case[0], kw | {"review": selected}))
    assert json.loads(new_wire)["options"] == options
    assert json.loads(new_wire)["format"] == json.loads(old_wire)["format"]
    assert prepared.purpose.expiry_rule == original.expiry_rule
    assert selected.route.identity.runtime_id == w.RECOVERY_WINDOW_RUNTIME


@pytest.mark.parametrize(
    "fault", ["external", "unavailable", "paid", "oversized_output", "estimate_over_cap"]
)
def test_new_runtime_is_no_permission_cost_or_capability_override(case, fault):
    _, kw = case
    data = kw["review"].model_dump(mode="json")
    data["route"]["identity"]["runtime_id"] = w.RECOVERY_WINDOW_RUNTIME
    data["max_latency_ms"] = 120000
    if fault == "external":
        data["route"]["destination"] = "EXTERNAL"
    elif fault == "unavailable":
        data["route"]["available"] = False
    elif fault == "paid":
        data["max_estimated_cost_usd"] = 1.0
    elif fault == "oversized_output":
        data["max_output_tokens"] = 2049
    else:
        data["route"]["estimated_latency_ms"] = 120001.0
    with pytest.raises(ValueError):
        HistoryReviewPurposeProfileV1.model_validate(data)


def test_new_budget_cannot_be_added_to_old_prepared_body_or_profile(case):
    raw, kw = case
    old_prepared, _ = serialize(case)
    # model_copy does not establish validation; existing preparation revalidates.
    changed = kw["review"].model_copy(update={"max_latency_ms": 120000})
    with pytest.raises(p.HistoryReviewPreparationError):
        p.prepare_history_review_request(raw, **(kw | {"review": changed}))
    assert old_prepared.max_latency_ms == 60000


@pytest.mark.parametrize(
    "fault",
    [
        "processing_flag",
        "recovery_flag",
        "current_fact_flag",
        "weakened_classification",
        "invalid_classification",
    ],
)
def test_new_runtime_keeps_source_classification_and_authority_flags_closed(case, fault):
    from zacai.intelligence.history_contextual_codec import HistoryContextualRequestV1

    selected = profile(case, w.RECOVERY_WINDOW_RUNTIME, 120000)
    assert selected.max_latency_ms == 120000
    request = case[1]["expected_request"].model_dump(mode="json")
    if fault.endswith("_flag"):
        field = {
            "processing_flag": "processing_authorized",
            "recovery_flag": "recovery_verified",
            "current_fact_flag": "current_facts_verified",
        }[fault]
        request[field] = True
    elif fault == "weakened_classification":
        request["task"]["event"]["data_classification"] = "PUBLIC"
        request["task"]["context"][0]["reference"]["effective_classification"] = "HIGHLY_RESTRICTED"
    else:
        request["task"]["context"][0]["reference"]["effective_classification"] = "INVALID"
    with pytest.raises(ValueError):
        HistoryContextualRequestV1.model_validate(request)
