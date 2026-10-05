"""Invented pure metadata/byte bindings only; no actual authority or recovery.

Existing in-memory fixture builds canonical-looking inputs; neither its mocked
Source objects nor fabricated receipts establish real processing permission.
"""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tests.test_text_reply_capture import fixture as reply_fixture
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.interfaces import named_followup_decision as module
from zacai.interfaces.followup_authorization import followup_content_digest
from zacai.interfaces.text_turn_capture import decode_text_turn, encode_text_turn


@pytest.fixture
def fixture(monkeypatch):
    state = reply_fixture.__wrapped__(monkeypatch)
    scope = state.reply_inputs["claimed"].claim.run_scope
    turn = decode_text_turn(state.raw[scope.user_reference.content_hash])
    manifest = module.NamedFollowupManifest(
        actor_issuer=scope.actor_issuer, actor_subject=scope.actor_subject,
        owner_grant_digest=scope.owner_grant_digest, conversation_id=scope.conversation_id,
        request_id=turn.request_id, run_id=scope.run_id, builder_id=scope.builder_id,
        nonce_digest="9" * 64, issued_at=state.now,
        admission_expires_at=state.now + timedelta(minutes=5), processing_ttl_seconds=300,
        packet_reference=scope.packet_reference, packet_receipt_digest=scope.packet_receipt_digest,
        evidence_references=tuple(item.reference for item in state.reply_inputs["request"].context.packet.task.context),
        parents=tuple(module.ManifestUserParent(reference=ref) for ref in scope.parent_references),
        route=scope.route, model_digest=scope.model_digest, runtime_endpoint="http://127.0.0.1:11434",
        tokenizer_digest="b" * 64, request_template_digest="c" * 64,
        max_output_tokens=scope.max_output_tokens, max_latency_ms=scope.max_latency_ms,
        max_estimated_cost_usd=scope.max_estimated_cost_usd,
    )
    decision = module.NamedFollowupDecision(
        manifest=manifest, manifest_digest=module.named_manifest_digest(manifest),
        admitted_at=state.now, processing_expires_at=state.now + timedelta(minutes=5),
        bound_at=state.now + timedelta(seconds=1),
        original_observed_at=state.reply_inputs["request"].context.task.event.observed_at,
        session_binding_digest="a" * 64,
        question_reference=scope.user_reference,
        original_utf8_digest=content_hash_of(turn.original_text.encode("utf-8")),
        question_receipt_digest=scope.text_receipt_digest,
        prepared_request_digest=state.reply_inputs["request"].digest, run_scope=scope,
    )
    state.manifest, state.decision, state.turn = manifest, decision, turn
    state.bindings = {
        "owner": state.client._owner(), "turn": turn, "turn_source_id": scope.user_reference.source_id,
        "turn_receipt": state.reply_inputs["text_receipt"], "packet_receipt": state.receipt,
        "request": state.reply_inputs["request"], "runtime_endpoint": manifest.runtime_endpoint,
        "tokenizer_digest": manifest.tokenizer_digest, "request_template_digest": manifest.request_template_digest,
    }
    return state


def test_exact_codecs_digests_and_declarations_not_authority(fixture):
    s = fixture
    manifest = module.encode_named_manifest(s.manifest)
    decision = module.encode_named_decision(s.decision)
    assert module.decode_named_manifest(manifest) == s.manifest
    assert module.decode_named_decision(decision) == s.decision
    assert module.named_manifest_digest(s.manifest) != content_hash_of(manifest)
    assert module.named_decision_digest(s.decision) != content_hash_of(decision)
    assert module.named_manifest_digest(s.manifest) != module.named_decision_digest(s.decision)
    assert module.validate_declared_bindings(s.decision, **s.bindings) is None
    for value in (s.manifest, s.decision):
        assert not value.processing_authorized and not value.execution_authorized
        assert not value.capture_verified
    assert s.turn.original_text not in decision.decode()
    assert b'"cookie"' not in decision and b'"csrf"' not in decision and b'"nonce"' not in decision
    assert s.turn.subject not in repr(s.decision) and s.turn.subject not in repr(s.manifest)
    assert len(manifest) <= module.MAX_MANIFEST_BYTES and len(decision) <= module.MAX_DECISION_BYTES


@pytest.mark.parametrize("update", [
    {"processing_expires_at": "tomorrow"}, {"processing_expires_at": None},
    {"manifest_digest": "f" * 64}, {"question_reference": None},
])
def test_tampered_decision_revalidated_on_encode(fixture, update):
    with pytest.raises(module.NamedFollowupDecisionError):
        module.encode_named_decision(fixture.decision.model_copy(update=update))


@pytest.mark.parametrize("field", ["route", "model_digest", "actor_subject", "owner_grant_digest",
                                   "packet_receipt_digest", "max_output_tokens", "parent_references"])
def test_scope_substitution_does_not_match_published_manifest(fixture, field):
    s = fixture
    original = s.decision.run_scope
    if field == "route":
        value = original.route.model_copy(update={"identity": original.route.identity.model_copy(update={"model_id": "other"})})
    elif field == "max_output_tokens":
        value = original.max_output_tokens - 1
    elif field == "parent_references":
        value = (original.user_reference,)
    else:
        value = "different-actor" if field == "actor_subject" else "f" * 64
    with pytest.raises(module.NamedFollowupDecisionError):
        module.encode_named_decision(s.decision.model_copy(update={"run_scope": original.model_copy(update={field: value})}))


@pytest.mark.parametrize("mutation", ["duplicate", "nested_duplicate", "unknown", "whitespace", "coercion", "nonfinite", "overflow", "epoch_time", "generated_parent", "raw_cookie"])
def test_exact_codec_rejects_ambiguous_or_coerced_json(fixture, mutation):
    raw = module.encode_named_decision(fixture.decision)
    if mutation == "duplicate":
        raw = raw[:-1] + b',"action":"ask_caz_locally"}'
    elif mutation == "nested_duplicate":
        raw = raw.replace(b'"nonce_digest":', b'"nonce_digest":"' + b'f' * 64 + b'","nonce_digest":', 1)
    elif mutation == "whitespace":
        raw = b" " + raw
    else:
        data = json.loads(raw)
        if mutation == "unknown":
            data["approved"] = True
        elif mutation == "coercion":
            data["manifest"]["max_output_tokens"] = "512"
        elif mutation in ("nonfinite", "overflow"):
            raw = raw.replace(b'"max_estimated_cost_usd":0.0', b'"max_estimated_cost_usd":' + (b'NaN' if mutation == "nonfinite" else b'1e999'), 1)
        elif mutation == "epoch_time":
            data["admitted_at"] = 1791158400
        elif mutation == "generated_parent":
            data["question_kind"] = "generated_followup_reply"
        else:
            data["raw_cookie"] = "invented-not-a-secret"
        if mutation not in ("nonfinite", "overflow"):
            raw = canonical_bytes(data)
    with pytest.raises(module.NamedFollowupDecisionError) as error:
        module.decode_named_decision(raw)
    assert error.value.__context__ is None and error.value.__cause__ is None


@pytest.mark.parametrize("endpoint", ["https://external.test", "http://localhost:11434", "http://127.0.0.1:11434/path", "http://user:password@127.0.0.1:11434", "http://127.0.0.1"])
def test_declared_endpoint_cannot_introduce_remote_or_credential_url(fixture, endpoint):
    with pytest.raises(module.NamedFollowupDecisionError):
        module.encode_named_manifest(fixture.manifest.model_copy(update={"runtime_endpoint": endpoint}))


def test_separate_admission_and_processing_deadlines_no_silent_renewal(fixture):
    s = fixture
    decision = s.decision
    # Decoding history needs no current clock; it does not renew any deadline.
    assert module.decode_named_decision(module.encode_named_decision(decision)).processing_expires_at == decision.processing_expires_at
    for update in (
        {"admitted_at": s.manifest.admission_expires_at},
        {"processing_expires_at": decision.processing_expires_at + timedelta(seconds=1)},
        {"bound_at": decision.processing_expires_at},
    ):
        with pytest.raises(module.NamedFollowupDecisionError):
            module.encode_named_decision(decision.model_copy(update=update))


def test_consent_namespace_depends_only_on_exact_canonical_decision_source():
    source = uuid4()
    assert module.named_decision_consent_id(source) == module.named_decision_consent_id(source)
    assert module.named_decision_consent_id(source) != module.named_decision_consent_id(uuid4())
    with pytest.raises(module.NamedFollowupDecisionError):
        module.named_decision_consent_id(str(source))


@pytest.mark.parametrize("field", ["runtime_endpoint", "tokenizer_digest", "request_template_digest", "turn_source_id", "turn", "turn_receipt", "owner", "request"])
def test_actual_declared_inputs_must_match_exact_question_owner_receipt_and_pins(fixture, field):
    s = fixture
    inputs = dict(s.bindings)
    if field == "runtime_endpoint":
        inputs[field] = "http://127.0.0.1:11435"
    elif field in ("tokenizer_digest", "request_template_digest"):
        inputs[field] = "f" * 64
    elif field == "turn_source_id":
        inputs[field] = uuid4()
    elif field == "turn":
        inputs[field] = s.turn.model_copy(update={"original_text": s.turn.original_text.strip()})
    elif field == "turn_receipt":
        inputs[field] = inputs[field].model_copy(update={"source_id": uuid4()})
    else:
        inputs[field] = object()
    with pytest.raises(module.NamedFollowupDecisionError):
        module.validate_declared_bindings(s.decision, **inputs)


def test_future_original_observation_held_even_when_digest_and_scope_rebound(fixture):
    s = fixture
    original = s.bindings["request"]
    event = original.context.task.event.model_copy(update={"observed_at": s.decision.bound_at + timedelta(seconds=1)})
    context = replace(original.context, task=original.context.task.model_copy(update={"event": event}))
    request = prepare_followup_request(context)
    assert followup_content_digest(request) == s.decision.run_scope.content_digest
    decision = s.decision.model_copy(update={"prepared_request_digest": request.digest,
                                            "original_observed_at": event.observed_at})
    with pytest.raises(module.NamedFollowupDecisionError):
        module.encode_named_decision(decision)
    with pytest.raises(module.NamedFollowupDecisionError):
        module.validate_declared_bindings(decision, **{**s.bindings, "request": request})


def test_future_packet_proof_held_even_when_all_receipt_digests_rebound(fixture):
    s = fixture
    receipt = s.receipt.model_copy(update={"verified_at": s.manifest.issued_at + timedelta(seconds=1)})
    digest = content_hash_of(encode_recovery_receipt(receipt))
    manifest = s.manifest.model_copy(update={"packet_receipt_digest": digest})
    turn = s.turn.model_copy(update={"packet_receipt_digest": digest})
    new_ref = s.decision.question_reference.model_copy(update={"content_hash": content_hash_of(encode_text_turn(turn))})
    turn_receipt = s.bindings["turn_receipt"].model_copy(update={"turn_digest": new_ref.content_hash})
    turn_receipt_digest = content_hash_of(canonical_bytes(turn_receipt.model_dump(mode="json")))
    original = s.bindings["request"]
    items = tuple(item.model_copy(update={"reference": new_ref}) if item.reference == original.context.user_reference else item
                  for item in original.context.task.context)
    event = original.context.task.event.model_copy(update={"provenance": tuple(new_ref if ref == original.context.user_reference else ref
                                                                             for ref in original.context.task.event.provenance)})
    context = replace(original.context, user_reference=new_ref,
                      task=original.context.task.model_copy(update={"context": items, "event": event}))
    request = prepare_followup_request(context)
    scope = s.decision.run_scope.model_copy(update={
        "packet_receipt_digest": digest, "user_reference": new_ref,
        "context_references": tuple(item.reference for item in items),
        "text_receipt_digest": turn_receipt_digest, "content_digest": followup_content_digest(request),
    })
    decision = s.decision.model_copy(update={
        "manifest": manifest, "manifest_digest": module.named_manifest_digest(manifest), "run_scope": scope,
        "question_reference": new_ref, "question_receipt_digest": turn_receipt_digest,
        "prepared_request_digest": request.digest,
    })
    # All hashes/declared bindings are consistent; ONLY chronology is invalid.
    module.decode_named_decision(module.encode_named_decision(decision))
    with pytest.raises(module.NamedFollowupDecisionError):
        module.validate_declared_bindings(decision, **{**s.bindings, "packet_receipt": receipt, "turn": turn,
                                                       "turn_receipt": turn_receipt, "request": request})


def test_frozen_exact_types_and_no_generated_human_parent(fixture):
    with pytest.raises(ValidationError):
        fixture.manifest.nonce_digest = "f" * 64
    with pytest.raises(ValidationError):
        module.ManifestUserParent(kind="generated_followup_reply", reference=fixture.manifest.evidence_references[0])
    with pytest.raises(module.NamedFollowupDecisionError):
        module.decode_named_decision(b"x" * (module.MAX_DECISION_BYTES + 1))
    with pytest.raises(module.NamedFollowupDecisionError):
        module.decode_named_manifest(b"x" * (module.MAX_MANIFEST_BYTES + 1))



def test_original_observation_exact_roundtrip_and_required_not_inferred(fixture):
    decision = fixture.decision
    raw = module.encode_named_decision(decision)
    decoded = module.decode_named_decision(raw)
    assert decoded.original_observed_at == fixture.bindings["request"].context.task.event.observed_at
    assert decoded.original_observed_at != decoded.bound_at
    assert module.encode_named_decision(decoded) == raw
    data = json.loads(raw)
    del data["original_observed_at"]
    with pytest.raises(module.NamedFollowupDecisionError):
        module.decode_named_decision(canonical_bytes(data))


def test_different_in_bounds_declared_observation_does_not_match_original_request(fixture):
    s = fixture
    decision = s.decision.model_copy(update={"original_observed_at": s.decision.bound_at})
    # Shape/chronology is valid, but the unchanged original prepared request
    # carries a different exact observation. No silent reconstruction is allowed.
    module.decode_named_decision(module.encode_named_decision(decision))
    with pytest.raises(module.NamedFollowupDecisionError):
        module.validate_declared_bindings(decision, **s.bindings)
