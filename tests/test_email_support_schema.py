"""Model-facing finite support schemas and actual parser branch controls."""

import json
from uuid import uuid4

import pytest

from tests.test_email_generation import output, support
from tests.test_email_generation import req as source_request
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.email_generation import (
    EmailModelOutputV1,
    parse_email_model_output,
    resolve_email_model_output,
)
from zacai.intelligence.email_local_wire import MODEL, RUNTIME, prepare_email_local_payload
from zacai.intelligence.ollama_token_counter import render_email_prompt


@pytest.fixture
def req():
    return source_request.__wrapped__()


def test_actual_model_schema_has_closed_discriminated_branch_constraints(req):
    schema = json.loads(req.schema_json)
    # Check the actual model-facing request, not a hand-authored alternative schema.
    assert schema == EmailModelOutputV1.model_json_schema()
    paragraph = schema["$defs"]["EmailOutputParagraphV1"]["properties"]["support"]
    assert paragraph["discriminator"]["propertyName"] == "support_kind"
    assert len(paragraph["oneOf"]) == 3
    kinds = {"SOURCE_QUOTE", "CURRENT_TASK_INTENT", "CONVENTIONAL"}
    assert set(paragraph["discriminator"]["mapping"]) == kinds
    for kind, ref in paragraph["discriminator"]["mapping"].items():
        branch = schema["$defs"][ref.rsplit("/", 1)[-1]]
        props = branch["properties"]
        assert branch["additionalProperties"] is False
        assert set(branch["required"]) == {
            "category",
            "support_kind",
            "explanation",
            "evidence_ids",
            "instruction_text",
            "convention",
        }
        assert props["support_kind"]["const"] == kind
        assert props["evidence_ids"]["type"] == "array"
        if kind == "SOURCE_QUOTE":
            assert set(props["category"]["enum"]) == {"FACT", "PROPOSAL", "OWNER_POSITION"}
            assert props["evidence_ids"]["minItems"] == 1
            assert props["evidence_ids"]["maxItems"] == 4
            assert props["instruction_text"]["type"] == "null"
            assert props["convention"]["type"] == "null"
        else:
            assert props["evidence_ids"]["maxItems"] == 0
            if kind == "CURRENT_TASK_INTENT":
                assert props["category"]["const"] == "PROPOSAL"
                assert props["instruction_text"]["type"] == "string"
                assert props["instruction_text"]["minLength"] == 1
                assert props["convention"]["type"] == "null"
            else:
                assert props["category"]["const"] == "CONVENTIONAL"
                assert props["instruction_text"]["type"] == "null"
                assert set(props["convention"]["enum"]) == {"GREETING", "SIGNOFF"}
        if kind == "SOURCE_QUOTE":
            assert props["evidence_ids"]["items"]["pattern"] == r"^[0-9a-f]{32}:e[1-9][0-9]*$"
    subject = schema["properties"]["subject_support"]["anyOf"]
    assert subject[0]["oneOf"] == paragraph["oneOf"]
    assert subject[0]["discriminator"] == paragraph["discriminator"]
    assert subject[1]["type"] == "null"


@pytest.mark.parametrize(
    "kind,category,convention",
    [
        ("SOURCE_QUOTE", "FACT", None),
        ("SOURCE_QUOTE", "PROPOSAL", None),
        ("SOURCE_QUOTE", "OWNER_POSITION", None),
        ("CURRENT_TASK_INTENT", "PROPOSAL", None),
        ("CONVENTIONAL", "CONVENTIONAL", "GREETING"),
        ("CONVENTIONAL", "CONVENTIONAL", "SIGNOFF"),
    ],
)
def test_each_valid_branch_preserves_encoded_field_shape_and_resolves(
    req, kind, category, convention
):
    raw = output(req)
    selected = support(req, category=category, kind=kind)
    selected["convention"] = convention
    text = "Could you send the revised estimate?"
    if convention == "GREETING":
        text = "Hi Mira,"
    elif convention == "SIGNOFF":
        text = "Thanks,"
    raw["paragraphs"] = [{"text": text, "support": selected}]
    parsed = parse_email_model_output(canonical_bytes(raw))
    assert parsed.model_dump(mode="json") == raw
    packet = resolve_email_model_output(
        parsed, req, builder_id=uuid4(), created_at=req.specification.task().event.observed_at
    )
    assert packet.candidate.evidence_detail[1].support_kind == kind
    assert all(
        getattr(packet, name) is False
        for name in (
            "processing_authorized",
            "generation_authenticated",
            "reviewer_authenticated",
            "recovery_verified",
            "current_facts_verified",
            "ready_to_deliver",
            "sending_authorized",
        )
    )


@pytest.mark.parametrize(
    "kind,changes",
    [
        ("SOURCE_QUOTE", {"instruction_text": "Ask for the revised estimate."}),
        ("SOURCE_QUOTE", {"convention": "GREETING"}),
        ("SOURCE_QUOTE", {"category": "CONVENTIONAL"}),
        ("SOURCE_QUOTE", {"evidence_ids": []}),
        ("SOURCE_QUOTE", {"evidence_ids": ["f" * 32 + ":e1"] * 5}),
        ("CURRENT_TASK_INTENT", {"category": "FACT"}),
        ("CURRENT_TASK_INTENT", {"category": "OWNER_POSITION"}),
        ("CURRENT_TASK_INTENT", {"evidence_ids": ["f" * 32 + ":e1"]}),
        ("CURRENT_TASK_INTENT", {"instruction_text": None}),
        ("CURRENT_TASK_INTENT", {"instruction_text": ""}),
        ("CURRENT_TASK_INTENT", {"convention": "SIGNOFF"}),
        ("CONVENTIONAL", {"category": "PROPOSAL"}),
        ("CONVENTIONAL", {"evidence_ids": ["f" * 32 + ":e1"]}),
        ("CONVENTIONAL", {"instruction_text": "Ask for the revised estimate."}),
        ("CONVENTIONAL", {"convention": None}),
        ("CONVENTIONAL", {"convention": "INVENTED"}),
    ],
)
def test_cross_branch_model_fields_reject_at_actual_parser(req, kind, changes):
    raw = output(req)
    category = "CONVENTIONAL" if kind == "CONVENTIONAL" else "PROPOSAL"
    selected = support(req, category=category, kind=kind)
    selected["convention"] = "GREETING" if kind == "CONVENTIONAL" else None
    raw["paragraphs"][0]["support"] = selected | changes
    with pytest.raises(ValueError, match="^email model output unavailable or invalid$") as error:
        parse_email_model_output(canonical_bytes(raw))
    assert error.value.__context__ is None


def test_current_email_wire_and_renderer_derive_the_exact_branch_schema(req):
    route = ModelRoute(
        identity={"provider_id": "ollama", "model_id": MODEL, "runtime_id": RUNTIME},
        destination="LOCAL",
        capabilities=frozenset({"email_draft"}),
        max_input_characters=64000,
        max_output_tokens=2048,
        estimated_latency_ms=0.0,
        estimated_cost_usd=0.0,
        available=True,
    )
    body = prepare_email_local_payload(req, route, "a" * 64)
    assert json.loads(body)["format"] == json.loads(req.schema_json)
    assert "Output JSON schema: " + req.schema_json in render_email_prompt(body)
