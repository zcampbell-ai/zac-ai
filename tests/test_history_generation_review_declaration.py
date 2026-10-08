"""Invented complete codecs only; no admission, claims, model or recovery."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_history_contextual_codec import host as host  # noqa: PLC0414
from tests.test_history_contextual_codec import prepared as prepared  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_generation_review_declaration as m
from zacai.intelligence.contextual_storage import _history_request_provenance
from zacai.intelligence.history_contextual_codec import encode_history_contextual_request
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B


@pytest.fixture
def declaration_case(prepared):
    from zacai.intelligence.history_context_metadata import (
        HistoryMessageSpan,
        prepare_claude_history_context_preview,
    )
    from zacai.intelligence.history_contextual_codec import prepare_history_contextual_request

    _original, read, _, prior = prepared
    from tests.test_review_generation import synthetic_context
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.meeting_review import ReviewContext

    context = synthetic_context(boundary=B.PERSONAL, classification=C.HIGHLY_RESTRICTED)
    task = IntelligenceTask.model_validate(
        {
            **context.task.model_dump(),
            "required_capabilities": frozenset({"contextual_meeting_review"}),
        }
    )
    original = ReviewContext(task, context.meeting_source_id, context.related_source_ids)
    actual_route = prior.route.model_copy(
        update={"identity": prior.route.identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"})}
    )
    selections = tuple(
        HistoryMessageSpan(
            message_id=e.message_id,
            character_start=e.character_start,
            character_end=e.character_end,
        )
        for e in prior.sidecar.entries
    )
    preview = prepare_claude_history_context_preview(
        original,
        read,
        selections=selections,
        observed_at=prior.sidecar.entries[0].projection_observed_at,
        route=actual_route,
    )
    q = prepare_history_contextual_request(preview, original_context=original, route=actual_route)
    at = q.sidecar.entries[0].projection_observed_at
    g = m.HistoryConsentV1(
        id=uuid4(),
        builder_id=uuid4(),
        task_id=q.task.task_id,
        request_digest=content_hash_of(encode_history_contextual_request(q)),
        provenance=_history_request_provenance(q),
        owner_issuer="invented-issuer",
        owner_subject="invented-owner",
        original_session_binding="0" * 64,
        original_session_issued_at=at - timedelta(seconds=1),
        original_session_expires_at=at + timedelta(minutes=10),
        approved_at=at,
        expires_at=at + timedelta(minutes=5),
        human_reference="prospective-not-approved",
        route=q.route,
        model_digest="1" * 64,
        tokenizer_digest="2" * 64,
        runtime_digest="3" * 64,
        template_digest="4" * 64,
        renderer_digest="5" * 64,
        body_digest=content_hash_of(q.prompt_body.encode()),
        generation_wire_digest=content_hash_of(m.prepare_history_generation_wire(q)),
        prompt_tokens=500,
        max_output_tokens=q.task.max_output_tokens,
    )
    profile = m.HistoryReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=q.route.model_copy(
            update={
                "capabilities": frozenset({m.PURPOSE}),
                "max_output_tokens": 32000,
                "estimated_latency_ms": 1000,
                "estimated_cost_usd": 0.0,
            }
        ),
        model_digest="1" * 64,
        tokenizer_digest="2" * 64,
        runtime_digest="3" * 64,
        template_digest="4" * 64,
        renderer_digest="5" * 64,
        rubric_digest="6" * 64,
        reviewer_wire_digest="7" * 64,
        body_derivation_digest="8" * 64,
        context_window_tokens=16384,
        max_output_tokens=512,
        max_latency_ms=1000,
        max_estimated_cost_usd=0.0,
    )
    return q, g, profile


def declared(case):
    q, g, p = case
    return m.prepare_history_generation_review_declaration(g, q, review=p)


def test_complete_bytes_roles_dates_words_and_false_flags(declaration_case):
    q, g, p = declaration_case
    d = declared(declaration_case)
    assert m.decode_history_consent(m.encode_history_consent(g)) == g
    assert m.validate_history_consent_request(g, q) == encode_history_contextual_request(q)
    raw = m.encode_history_generation_review_declaration(d)
    restored = m.decode_history_generation_review_declaration(raw)
    assert (
        restored == d
        and restored.generation_request_json.encode() == encode_history_contextual_request(q)
    )
    assert restored.generation_consent_json.encode() == m.encode_history_consent(g)
    assert q.original_task.instruction == q.task.instruction
    assert [e.historical_role for e in q.sidecar.entries] == ["USER", "ASSISTANT", "USER"]
    assert len({e.reported_created_at for e in q.sidecar.entries}) == 3
    assert "Correction: use three short paragraphs." in q.prompt_body
    assert d.review == p and d.review_profile_digest == m.history_review_profile_digest(p)
    assert d.approved_at == g.approved_at and d.expires_at == g.expires_at
    for v in (g, d):
        assert (
            v.processing_authorized
            is v.owner_admitted
            is v.recovery_verified
            is v.reviewer_authenticated
            is v.current_facts_verified
            is False
        )
    assert q.current_facts_verified is False
    assert "invented-owner" not in repr(d)
    assert m.history_generation_review_declaration_digest(d) != content_hash_of(raw)


@pytest.mark.parametrize(
    "field",
    [
        "request_digest",
        "body_digest",
        "task_id",
        "route",
        "provenance",
        "max_output_tokens",
        "generation_wire_digest",
    ],
)
def test_stale_generation_scope_cannot_bind_exact_request(declaration_case, field):
    q, g, p = declaration_case
    changes = {
        "request_digest": "9" * 64,
        "body_digest": "9" * 64,
        "task_id": uuid4(),
        "route": g.route.model_copy(update={"max_output_tokens": g.route.max_output_tokens + 1}),
        "provenance": g.provenance[:-1],
        "max_output_tokens": g.max_output_tokens + 1,
        "generation_wire_digest": "9" * 64,
    }
    altered = g.model_copy(update={field: changes[field]})
    assert altered != g
    with pytest.raises(m.HistoryDeclarationError):
        m.prepare_history_generation_review_declaration(altered, q, review=p)


@pytest.mark.parametrize(
    "field",
    [
        "generation_consent_digest",
        "generation_request_digest",
        "review_profile_digest",
        "approved_at",
        "expires_at",
    ],
)
def test_declaration_hash_or_original_window_change_holds(declaration_case, field):
    d = declared(declaration_case)
    value = "9" * 64 if field.endswith("digest") else getattr(d, field) + timedelta(seconds=1)
    with pytest.raises(m.HistoryDeclarationError) as error:
        m.encode_history_generation_review_declaration(d.model_copy(update={field: value}))
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("field", ["role", "date", "currentfact", "words", "body", "profile"])
def test_real_complete_codec_rejects_changed_request_components(declaration_case, field):
    q, _g, _p = declaration_case
    data = json.loads(encode_history_contextual_request(q))
    if field == "role":
        data["sidecar"]["entries"][0]["historical_role"] = "ASSISTANT"
    elif field == "date":
        data["sidecar"]["entries"][0]["reported_created_at"] = "2020-01-01T00:00:00Z"
    elif field == "currentfact":
        data["current_facts_verified"] = True
    elif field == "words":
        data["task"]["instruction"] += " changed"
    elif field == "body":
        data["prompt_body"] += " "
        data["prompt_digest"] = content_hash_of(data["prompt_body"].encode())
    else:
        data["projection_profiles"][0] += " "
    d = declared(declaration_case)
    changed = canonical_bytes(data)
    assert changed != d.generation_request_json.encode()
    with pytest.raises(m.HistoryDeclarationError):
        m.encode_history_generation_review_declaration(
            d.model_copy(
                update={
                    "generation_request_json": changed.decode(),
                    "generation_request_digest": content_hash_of(changed),
                }
            )
        )


@pytest.mark.parametrize(
    "field",
    [
        "reviewer_id",
        "run_id",
        "purpose",
        "derivation_rule",
        "route",
        "max_output_tokens",
        "max_latency_ms",
    ],
)
def test_wrong_review_family_actor_capacity_or_fixed_combined_deadline(declaration_case, field):
    q, g, p = declaration_case
    changes = {
        "reviewer_id": g.builder_id,
        "run_id": g.task_id,
        "purpose": "history_fragment_independent_review",
        "derivation_rule": "exact_retained_fragment_packet_and_original_request_v1",
        "route": p.route.model_copy(update={"destination": Destination.EXTERNAL}),
        "max_output_tokens": 32001,
        "max_latency_ms": 60001,
    }
    with pytest.raises(m.HistoryDeclarationError):
        m.prepare_history_generation_review_declaration(
            g, q, review=p.model_copy(update={field: changes[field]})
        )
    if field == "max_latency_ms":
        # Both scopes individually valid, but their sum does not fit original time.
        short = g.model_copy(
            update={
                "expires_at": g.approved_at + timedelta(milliseconds=q.task.max_latency_ms + 500)
            }
        )
        m.encode_history_consent(short)
        m._profile_bytes(p)
        with pytest.raises(m.HistoryDeclarationError):
            m.prepare_history_generation_review_declaration(short, q, review=p)


@pytest.mark.parametrize("fault", ["none", "duplicate", "noncanonical", "oversize", "flag"])
def test_closed_canonical_declaration_encoding(declaration_case, fault):
    d = declared(declaration_case)
    raw = m.encode_history_generation_review_declaration(d)
    if fault == "none":
        with pytest.raises(m.HistoryDeclarationError):
            m.prepare_history_generation_review_declaration(
                declaration_case[1], declaration_case[0], review=None
            )
        return
    if fault == "duplicate":
        raw = b'{"format":"ignored",' + raw[1:]
    elif fault == "noncanonical":
        raw = b" " + raw
    elif fault == "oversize":
        raw = b" " * (m.MAX_DECLARATION_BYTES + 1)
    else:
        data = json.loads(raw)
        data["processing_authorized"] = True
        raw = canonical_bytes(data)
    with pytest.raises(m.HistoryDeclarationError):
        m.decode_history_generation_review_declaration(raw)


def test_distinct_complete_consent_claim_codecs_without_minting(declaration_case):
    _q, g, _ = declaration_case
    raw = m.encode_history_consent(g)
    c = m.HistoryClaimV1(
        consent_reference=m.EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(raw),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        ),
        consent_digest=content_hash_of(raw),
        request_digest=g.request_digest,
        attempt_id=uuid4(),
        task_id=g.task_id,
        builder_id=g.builder_id,
        original_session_binding=g.original_session_binding,
        body_digest=g.body_digest,
        generation_wire_digest=g.generation_wire_digest,
        route_digest="6" * 64,
        model_digest=g.model_digest,
        tokenizer_digest=g.tokenizer_digest,
        runtime_digest=g.runtime_digest,
        template_digest=g.template_digest,
        renderer_digest=g.renderer_digest,
        prompt_tokens=g.prompt_tokens,
        max_output_tokens=g.max_output_tokens,
        consumed_at=g.approved_at,
    )
    assert m.decode_history_claim(m.encode_history_claim(c)) == c
    assert (
        c.processing_authorized
        is c.owner_admitted
        is c.recovery_verified
        is c.reviewer_authenticated
        is c.current_facts_verified
        is False
    )
    for decode in (m.decode_history_claim, m.decode_history_consent):
        data = json.loads(raw if decode == m.decode_history_consent else m.encode_history_claim(c))
        data["format"] = data["format"].replace("complete", "fragment")
        with pytest.raises(m.HistoryDeclarationError):
            decode(canonical_bytes(data))


@pytest.mark.parametrize(
    "field",
    [
        "provenance",
        "owner_issuer",
        "original_session_expires_at",
        "expires_at",
        "route",
        "prompt_tokens",
    ],
)
def test_consent_closed_personal_scope_session_and_types(declaration_case, field):
    _, g, _ = declaration_case
    weaker = tuple(
        r.model_copy(update={"effective_classification": C.CONFIDENTIAL}) for r in g.provenance
    )
    values = {
        "provenance": weaker,
        "owner_issuer": " ",
        "original_session_expires_at": g.approved_at,
        "expires_at": g.approved_at + timedelta(minutes=16),
        "route": g.route.model_copy(update={"destination": Destination.EXTERNAL}),
        "prompt_tokens": True,
    }
    with pytest.raises(m.HistoryDeclarationError):
        m.encode_history_consent(g.model_copy(update={field: values[field]}))


def test_complete_only_styled_wire_preserves_every_evidence_and_original_word(declaration_case):
    q, g, _ = declaration_case
    before = encode_history_contextual_request(q)
    original = json.loads(q.prompt_body)
    wire = m.prepare_history_generation_wire(q)
    value = json.loads(wire)
    expected = json.loads(q.prompt_body)
    expected["messages"][0]["content"] += "\n" + m.GENERATION_STYLE_CLAUSE
    assert value == expected
    assert value["messages"][1] == original["messages"][1]
    assert value["format"] == original["format"] if "format" in original else True
    assert encode_history_contextual_request(q) == before
    assert wire != q.prompt_body.encode()
    assert content_hash_of(wire) == g.generation_wire_digest
    d = declared(declaration_case)
    assert d.generation_wire_json.encode() == wire
    altered = value.copy()
    altered["messages"] = [x.copy() for x in value["messages"]]
    altered["messages"][0]["content"] += " unapproved"
    raw = canonical_bytes(altered)
    assert raw != wire
    with pytest.raises(m.HistoryDeclarationError):
        m.encode_history_generation_review_declaration(
            d.model_copy(
                update={
                    "generation_wire_json": raw.decode(),
                    "generation_wire_digest": content_hash_of(raw),
                }
            )
        )


def test_actual_legacy_consent_object_and_bytes_not_accepted(declaration_case):
    from zacai.contextual_authorization import (
        HistoryFragmentConsentV1,
        encode_history_fragment_consent,
    )

    q, g, p = declaration_case
    value = g.model_dump(mode="json")
    value.pop("generation_wire_format")
    value.pop("generation_wire_digest")
    value["format"] = "zac-personal-history-fragment-consent-v1"
    old = HistoryFragmentConsentV1.model_validate(value)
    raw = encode_history_fragment_consent(old)
    assert raw != m.encode_history_consent(g)
    with pytest.raises(m.HistoryDeclarationError):
        m.decode_history_consent(raw)
    with pytest.raises(m.HistoryDeclarationError):
        m.prepare_history_generation_review_declaration(old, q, review=p)
