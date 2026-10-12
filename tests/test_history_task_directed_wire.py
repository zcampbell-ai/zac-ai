"""Invented exact canonical wire tests; no runtime admission or model calls."""

import json

import pytest

from tests.test_history_generation_review_declaration import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_history_generation_review_declaration import host as host  # noqa: PLC0414
from tests.test_history_generation_review_declaration import prepared as prepared  # noqa: PLC0414
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import history_generation_review_declaration as m
from zacai.intelligence.history_contextual_codec import encode_history_contextual_request


def v2(q):
    return m.prepare_history_generation_wire(q, generation_wire_format=m.GENERATION_WIRE_V2)


def test_v1_exact_reconstruction_and_default_remain(declaration_case):
    q, g, profile = declaration_case
    before = encode_history_contextual_request(q)
    old = m.prepare_history_generation_wire(
        q, generation_wire_format="zac-history-complete-generation-wire-v1"
    )
    assert old == m.prepare_history_generation_wire(q, generation_wire_format=m.GENERATION_WIRE_V1)
    declaration = m.prepare_history_generation_review_declaration(g, q, review=profile)
    assert declaration.generation_wire_json.encode() == old
    assert (
        m.decode_history_generation_review_declaration(
            m.encode_history_generation_review_declaration(declaration)
        )
        == declaration
    )
    assert encode_history_contextual_request(q) == before
    assert g.generation_wire_format == m.GENERATION_WIRE_V1


def test_exact_instruction_and_unchanged_evidence_visible(declaration_case):
    q, _, _ = declaration_case
    old = json.loads(
        m.prepare_history_generation_wire(
            q, generation_wire_format="zac-history-complete-generation-wire-v1"
        )
    )
    wire = json.loads(v2(q))
    user = wire["messages"][1]["content"]
    prefix = "Current signed task requested outcome (JSON string):\n"
    encoded, evidence = user[len(prefix) :].split("\nUntrusted source context (unchanged):\n", 1)
    assert json.loads(encoded) == q.original_task.instruction == q.task.instruction
    assert evidence == old["messages"][1]["content"]
    assert old["format"] == wire["format"]
    assert old["options"] == wire["options"]
    assert m.TASK_OUTCOME_HIERARCHY in wire["messages"][0]["content"]
    assert "Overview/items cite meeting passages only." in wire["messages"][0]["content"]
    assert "Use no em dash" in wire["messages"][0]["content"]


def test_explicit_v2_consent_declaration_binding(declaration_case):
    q, old, profile = declaration_case
    g = old.model_copy(
        update={
            "generation_wire_format": m.GENERATION_WIRE_V2,
            "generation_wire_digest": content_hash_of(v2(q)),
        }
    )
    d = m.prepare_history_generation_review_declaration(g, q, review=profile)
    assert d.generation_wire_json.encode() == v2(q)
    assert (
        m.decode_history_generation_review_declaration(
            m.encode_history_generation_review_declaration(d)
        )
        == d
    )
    with pytest.raises(m.HistoryDeclarationError):
        m.validate_history_consent_request(
            g.model_copy(update={"generation_wire_format": m.GENERATION_WIRE_V1}), q
        )


@pytest.mark.parametrize("bad", ["unknown", "", None, True])
def test_unknown_wire_format_is_closed(declaration_case, bad):
    with pytest.raises(m.HistoryDeclarationError):
        m.prepare_history_generation_wire(declaration_case[0], generation_wire_format=bad)


def directed_request(prepared, instruction):
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.history_context_metadata import (
        HistoryMessageSpan,
        prepare_claude_history_context_preview,
    )
    from zacai.intelligence.history_contextual_codec import prepare_history_contextual_request
    from zacai.intelligence.meeting_review import ReviewContext

    original, read, _, prior = prepared
    task = IntelligenceTask.model_validate(
        {**original.task.model_dump(), "instruction": instruction}
    )
    context = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    route = prior.route.model_copy(
        update={"identity": prior.route.identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"})}
    )
    preview = prepare_claude_history_context_preview(
        context,
        read,
        selections=tuple(
            HistoryMessageSpan(
                message_id=e.message_id,
                character_start=e.character_start,
                character_end=e.character_end,
            )
            for e in prior.sidecar.entries
        ),
        observed_at=prior.sidecar.entries[0].projection_observed_at,
        route=route,
    )
    return prepare_history_contextual_request(preview, original_context=context, route=route)


def test_unicode_crlf_exact_wording_changes_actual_wire(prepared):
    text = "Summarize café work.\r\nAsk one scope question: who approved?"
    a = directed_request(prepared, text)
    b = directed_request(prepared, "Summarize only the dated acceptance gap.")
    prefix = "Current signed task requested outcome (JSON string):\n"
    user = json.loads(v2(a))["messages"][1]["content"]
    assert json.loads(user[len(prefix) :].split("\nUntrusted source context", 1)[0]) == text
    assert a.task.instruction == a.original_task.instruction == text
    assert v2(a) != v2(b)


def test_oversized_exact_task_holds_before_wire(prepared):
    q = directed_request(prepared, "é" * 1025)
    with pytest.raises(m.HistoryDeclarationError):
        v2(q)
    assert m.prepare_history_generation_wire(
        q, generation_wire_format="zac-history-complete-generation-wire-v1"
    )


def test_actual_d2_encoder_goldens_remain_byte_identical():
    from pathlib import Path

    from zacai.intelligence.history_publication_admission import (
        decode_history_publication_admission,
    )
    from zacai.intelligence.history_publication_generation import _claim_namespace

    root = Path(__file__).parent / "fixtures/history_wire_v1_d2"
    proof = json.loads((root / "proof.json").read_bytes())
    decoded = {}
    for name, decoder, encoder in [
        ("consent", m.decode_history_consent, m.encode_history_consent),
        ("claim", m.decode_history_claim, m.encode_history_claim),
        (
            "declaration",
            m.decode_history_generation_review_declaration,
            m.encode_history_generation_review_declaration,
        ),
    ]:
        raw = (root / (name + ".json")).read_bytes()
        value = decoder(raw)
        decoded[name] = value
        assert encoder(value) == raw
        assert content_hash_of(raw) == proof["hashes"][name + ".json"]
    d = decoded["declaration"]
    assert m.history_generation_review_declaration_digest(d) == proof["domain_digest"]
    a = decode_history_publication_admission((root / "admission.json").read_bytes())
    assert _claim_namespace(d, a, decoded["claim"]) == proof["claim_namespace"]
    from zacai.intelligence.history_contextual_codec import decode_history_contextual_request

    q = decode_history_contextual_request(d.generation_request_json.encode())
    assert (
        m.prepare_history_generation_wire(q, generation_wire_format=m.GENERATION_WIRE_V1)
        == (root / "wire.json").read_bytes()
    )


@pytest.mark.parametrize("text", ["é" * 1024, "Line\n" + "\t" * 500 + "end"])
def test_exact_utf8_boundary_and_escape_expansion(prepared, text):
    q = directed_request(prepared, text)
    assert v2(q)
    assert len(text.encode("utf8")) <= 2048


def test_renderer_requires_explicit_format(declaration_case):
    with pytest.raises(TypeError):
        m.prepare_history_generation_wire(declaration_case[0])
