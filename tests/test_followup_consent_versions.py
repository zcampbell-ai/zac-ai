"""Invented pure metadata only; no Source, human admission or recovery proof."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference, ModelRoute, RouteIdentity
from zacai.interfaces import followup_authorization as m
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B


@pytest.fixture
def consents():
    def ref(number):
        return EvidenceReference(source_id=UUID(int=number), content_hash=str(number) * 64,
                                 trust_boundary=B.BRAINSTORM, effective_classification=C.CONFIDENTIAL)

    now = datetime(2026, 10, 5, 12, tzinfo=UTC)
    scope = m.FollowupRunScope(
        run_id=UUID(int=10), builder_id=UUID(int=11), actor_issuer="https://accounts.google.com",
        actor_subject="invented-owner", owner_grant_digest="a" * 64, conversation_id=UUID(int=12),
        user_reference=ref(1), packet_reference=ref(2), parent_references=(ref(3),),
        context_references=(ref(1), ref(3)), text_receipt_digest="b" * 64,
        packet_receipt_digest="c" * 64, content_digest="d" * 64,
        route=ModelRoute(identity=RouteIdentity(provider_id="invented", model_id="invented", runtime_id="invented"),
                         destination=Destination.LOCAL, capabilities=frozenset({"packet_followup"}),
                         max_input_characters=64000, max_output_tokens=512,
                         estimated_latency_ms=1000.0, estimated_cost_usd=0.0, available=True),
        model_digest="e" * 64, max_output_tokens=512, max_latency_ms=1000,
        max_estimated_cost_usd=0.0,
    )
    fields = {"id": UUID(int=13), "scope": scope, "approved_at": now,
              "expires_at": now + timedelta(minutes=15), "human_reference": "invented local admission"}
    return (m.FollowupConsent(**fields),
            m.FollowupConsentV2(**fields, decision_reference=ref(4), decision_recovery_digest="f" * 64))


def test_original_v1_golden_and_exact_roundtrip(consents):
    v1, v2 = consents
    raw = m._raw(v1)
    assert content_hash_of(raw) == "ce62ccbf38a192367698436334bb9da5835f0bc1f9b6fbee96d5db7dd46f65d2"
    assert m.encode_followup_consent(v1) == raw
    assert type(m.decode_followup_consent(raw)) is m.FollowupConsent
    assert m.decode_followup_consent(raw) == v1
    assert m.encode_followup_consent(m.decode_followup_consent(raw)) == raw
    assert type(m.decode_followup_consent(m.encode_followup_consent(v2))) is m.FollowupConsentV2
    assert m.decode_followup_consent(m.encode_followup_consent(v2)) == v2
    assert v1.format == "zac-packet-followup-consent-v1"
    assert "decision_reference" not in json.loads(raw)


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("update", [
    {"human_reference": " "}, {"human_reference": True}, {"approved_at": 1000},
    {"expires_at": None}, {"id": "00000000-0000-0000-0000-00000000000d"},
    {"scope": None}, {"format": "zac-packet-followup-consent-v3"},
])
def test_mutated_frozen_instance_revalidation(consents, index, update):
    with pytest.raises(m.FollowupAuthorizationError) as error:
        m.encode_followup_consent(consents[index].model_copy(update=update))
    assert error.value.__context__ is None
    assert str(error.value) == "follow-up consent metadata invalid"


@pytest.mark.parametrize("field", ["decision_reference", "decision_recovery_digest"])
def test_v2_linkage_required_not_optional(consents, field):
    fields = consents[1].model_dump()
    del fields[field]
    with pytest.raises(ValidationError):
        m.FollowupConsentV2(**fields)
    fields[field] = None
    with pytest.raises(ValidationError):
        m.FollowupConsentV2(**fields)


@pytest.mark.parametrize("which", ["packet_reference", "user_reference", "parent_references"])
def test_decision_cannot_reuse_dependency_source(consents, which):
    value = getattr(consents[1].scope, which)
    if isinstance(value, tuple):
        value = value[0]
    with pytest.raises(m.FollowupAuthorizationError):
        m.encode_followup_consent(consents[1].model_copy(update={"decision_reference": value}))


@pytest.mark.parametrize("update", [{"trust_boundary": B.PERSONAL}, {"effective_classification": C.INTERNAL}])
def test_decision_family_closed(consents, update):
    value = consents[1].decision_reference.model_copy(update=update)
    with pytest.raises(m.FollowupAuthorizationError):
        m.encode_followup_consent(consents[1].model_copy(update={"decision_reference": value}))


@pytest.mark.parametrize("minutes", [0, -1, 16])
@pytest.mark.parametrize("index", [0, 1])
def test_explicit_existing_processing_window(consents, index, minutes):
    value = consents[index]
    with pytest.raises(m.FollowupAuthorizationError):
        m.encode_followup_consent(value.model_copy(update={"expires_at": value.approved_at + timedelta(minutes=minutes)}))


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("kind", ["space", "duplicate", "nested_duplicate", "unknown", "unknown_version", "missing_version",
                                   "null_version", "promote", "coerced", "nonfinite", "overflow", "uppercase_uuid"])
def test_closed_json_codec(consents, index, kind):
    raw = m.encode_followup_consent(consents[index])
    data = json.loads(raw)
    if kind == "space":
        raw += b" "
    elif kind == "duplicate":
        raw = raw.replace(b'{', b'{"format":"wrong",', 1)
    elif kind == "nested_duplicate":
        raw = raw.replace(b'"scope":{', b'"scope":{"actor_subject":"wrong",', 1)
    else:
        if kind == "unknown":
            data["approved"] = True
        elif kind == "unknown_version":
            data["format"] = "zac-packet-followup-consent-v3"
        elif kind == "missing_version":
            del data["format"]
        elif kind == "null_version":
            data["format"] = None
        elif kind == "promote":
            data["format"] = "zac-packet-followup-consent-v2" if index == 0 else "zac-packet-followup-consent-v1"
        elif kind == "coerced":
            data["scope"]["max_output_tokens"] = "512"
        elif kind == "uppercase_uuid":
            data["id"] = data["id"].upper()
        raw = canonical_bytes(data)
        if kind in ("nonfinite", "overflow"):
            raw = raw.replace(b'"max_estimated_cost_usd":0.0', b'"max_estimated_cost_usd":' + (b'NaN' if kind == "nonfinite" else b'1e999'))
    with pytest.raises(m.FollowupAuthorizationError) as error:
        m.decode_followup_consent(raw)
    assert error.value.__context__ is None


@pytest.mark.parametrize("raw", [b"", b"{}", b"[]", b"null", b"\xff", b"x" * 32001, "{}", bytearray(b"{}")])
def test_bounded_exact_bytes_only(raw):
    with pytest.raises(m.FollowupAuthorizationError):
        m.decode_followup_consent(raw)


def test_exact_instance_only_and_nested_mutation(consents):
    class Derived(m.FollowupConsent):
        pass

    with pytest.raises(m.FollowupAuthorizationError):
        m.validate_followup_consent(Derived(**consents[0].model_dump()))
    with pytest.raises(m.FollowupAuthorizationError):
        m.validate_followup_consent(consents[0].model_dump())
    scope = consents[1].scope.model_copy(update={"max_output_tokens": True})
    with pytest.raises(m.FollowupAuthorizationError):
        m.encode_followup_consent(consents[1].model_copy(update={"scope": scope}))


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("field,value", [
    ("approved_at", 1791201600), ("approved_at", "2026-10-05"),
    ("approved_at", "2026-10-05T12:00:00"),
    ("approved_at", "2026-10-05T12:00:00+00:00"),
    ("approved_at", "2026-10-05T12:00:00.000000Z"),
    ("human_reference", True),
])
def test_timestamp_syntax_and_strict_field_bytes(consents, index, field, value):
    data = json.loads(m.encode_followup_consent(consents[index]))
    data[field] = value
    with pytest.raises(m.FollowupAuthorizationError):
        m.decode_followup_consent(canonical_bytes(data))


def test_version_two_is_declaration_not_actual_source_or_renewal(consents):
    first = consents[1]
    assert m.validate_followup_consent(first) == first
    assert first.approved_at == consents[0].approved_at
    assert first.expires_at == consents[0].expires_at
    # No source lookup, ID allocation or processing grant is hidden in codec.
    # Actual decision Source-ID relation must be enforced by future host binding.
    assert first.id != first.decision_reference.source_id
    assert not hasattr(first, "processing_authorized")
