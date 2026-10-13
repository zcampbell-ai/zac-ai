"""Prompt/wire preservation checks, not semantic model judgments or authority."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from tests.test_complete_review_lossless import case as case  # noqa: PLC0414
from tests.test_review_generation import synthetic_context
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualCriterion
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.history_generation_review_declaration import (
    FACT_AGREEMENT_INSTRUCTION_V3,
    GENERATION_WIRE_V1,
    GENERATION_WIRE_V2,
    GENERATION_WIRE_V3,
    prepare_history_generation_wire,
)
from zacai.intelligence.history_review_preparation import (
    HistoryReviewPreparationError,
    prepare_history_review_request,
)
from zacai.intelligence.history_review_prompt_counter import render_history_review_prompt
from zacai.intelligence.history_review_wire import serialize_history_review_wire

PROSPECTIVE = Path(__file__).parent / "fixtures/prospective_fact_agreement_v3"
CASES = json.loads((PROSPECTIVE / "semantic-trial-cases.json").read_bytes())
RUBRIC = (PROSPECTIVE / "rubric.facts-agreements-v2.txt").read_bytes()
TEMPLATE = (PROSPECTIVE / "template.v1.txt").read_bytes()


@pytest.mark.parametrize("trial", CASES, ids=[c["id"] for c in CASES])
def test_new_prompt_preserves_each_untrusted_source_and_original_task_budget(trial):
    original = synthetic_context(related=False)
    task = original.task.model_copy(
        update={
            "instruction": trial["task"],
            "required_capabilities": frozenset({"contextual_meeting_review"}),
            "context": (
                original.task.context[0].model_copy(update={"untrusted_text": trial["source"]}),
            ),
        }
    )
    context = replace(original, task=task)
    request = prepare_contextual_request(context)
    passages = json.loads(request.evidence_json)
    assert [passage["text"] for passage in passages] == [trial["source"]]
    assert request.context.task.instruction == trial["task"]
    assert (task.max_latency_ms, task.max_output_tokens, task.max_estimated_cost_usd) == (
        original.task.max_latency_ms,
        original.task.max_output_tokens,
        original.task.max_estimated_cost_usd,
    )
    assert trial["source"] not in request.instruction
    # This guards unchanged shared instructions, NOT a model's compliance.
    assert "Decisions require explicit agreement" in request.instruction
    assert FACT_AGREEMENT_INSTRUCTION_V3 not in request.instruction
    assert "COMMITMENT require inferred=false" in request.instruction
    assert "Host evidence roles:" in request.instruction


def test_prospective_rubric_covers_closed_existing_ten_criteria_without_schema_changes():
    definitions = [line.split(":", 1)[0] for line in RUBRIC.decode().splitlines()[1:]]
    assert len(definitions) == len(set(definitions)) == 10
    assert set(definitions) == {criterion.value for criterion in ContextualCriterion}
    assert (
        TEMPLATE
        == (Path(__file__).parent / "fixtures/complete_review_public/template.txt").read_bytes()
    )


def test_new_rubric_cannot_silently_use_old_declared_profile(case):
    raw, args = case
    with pytest.raises(HistoryReviewPreparationError) as error:
        prepare_history_review_request(raw, **(args | {"rubric_utf8": RUBRIC}))
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_fresh_comparison_profile_transmits_exact_rubric_and_keeps_complete_packet_budgets(case):
    raw, args = case
    original_profile = args["review"]
    original_dump = original_profile.model_dump_json()
    # Fresh comparison-only profile, never modification of an admitted declaration.
    prospective = original_profile.model_copy(update={"rubric_digest": content_hash_of(RUBRIC)})
    params = args | {"review": prospective, "rubric_utf8": RUBRIC}
    prepared = prepare_history_review_request(raw, **params)
    wire = serialize_history_review_wire(
        prepared,
        packet_raw=raw,
        expected_request=args["expected_request"],
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    body = json.loads(wire)
    user = json.loads(body["messages"][1]["content"])
    assert user["rubric"] == RUBRIC.decode() and user["rubric_digest"] == content_hash_of(RUBRIC)
    assert user["review_instruction"] == TEMPLATE.decode()
    assert user["packet_digest"] == content_hash_of(raw)
    assert prepared.max_latency_ms == original_profile.max_latency_ms == 60000
    assert prepared.max_output_tokens == original_profile.max_output_tokens == 512
    assert prospective.template_digest == original_profile.template_digest
    assert original_profile.model_dump_json() == original_dump
    assert prepared.processing_authorized is prepared.reviewer_authenticated is False
    assert render_history_review_prompt(wire)


def test_old_packet_and_v1_v2_wire_remain_exact_while_explicit_v3_changes_only_system(case):
    raw, args = case
    request = args["expected_request"]
    v1 = prepare_history_generation_wire(request, generation_wire_format=GENERATION_WIRE_V1)
    v2 = prepare_history_generation_wire(request, generation_wire_format=GENERATION_WIRE_V2)
    v3 = prepare_history_generation_wire(request, generation_wire_format=GENERATION_WIRE_V3)
    old_pins = json.loads((PROSPECTIVE / "old-generation-wire-pins.json").read_bytes())
    assert content_hash_of(v1) == old_pins["v1"]
    assert content_hash_of(v2) == old_pins["v2"]
    first, second, third = map(json.loads, (v1, v2, v3))
    assert second["messages"][1] == third["messages"][1]
    assert (
        third["messages"][0]["content"]
        == second["messages"][0]["content"] + "\n" + FACT_AGREEMENT_INSTRUCTION_V3
    )
    assert (
        PROSPECTIVE / "generation-instructions.v3.txt"
    ).read_text() == FACT_AGREEMENT_INSTRUCTION_V3
    assert first["messages"][1] != third["messages"][1]  # exact V2 task prefix retained
    for name in third.keys() - {"messages"}:
        assert first[name] == second[name] == third[name]
    assert args["review"].max_latency_ms == 60000 and args["review"].max_output_tokens == 512
    assert content_hash_of(raw) == old_pins["packet"]
