"""Pure declarations/codecs only: no session/SQL/age/capture/admission success."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from tests.test_chatgpt_native_view import fixture_body, raw
from tests.test_gmail_app_observation import NOW, prepared
from zacai.chatgpt_native_view import prepare_chatgpt_native_view
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.email_app_input import (
    EmailAppInputError,
    check_email_app_preparations,
    prepare_email_app_input_selection,
)
from zacai.interfaces.email_input import (
    EmailInputSelectionV1,
    EmailNativeSelectionV1,
    EmailOwnerInstructionV1,
    decode_email_owner_instruction,
    encode_email_owner_instruction,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def selection(p):
    return prepare_email_app_input_selection(
        preparations=(p,),
        recipient=None,
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )


def instruction(selected):
    return EmailOwnerInstructionV1(
        format="zac-brainstorm-email-owner-instruction-v1",
        request_id=uuid4(),
        issuer="https://accounts.google.com",
        subject="invented-owner",
        original_session_binding="a" * 64,
        original_session_issued_at=NOW - timedelta(minutes=1),
        original_session_expires_at=NOW + timedelta(hours=1),
        recorded_at=NOW,
        original_text="Ask for an update.\nPreserve exact direction.",
        selection=selected,
    )


def test_exact_app_declaration_deterministic_codec_and_no_authority():
    p = prepared()
    selected = selection(p)
    assert selected == selection(p)
    check_email_app_preparations(selected, (p,), NOW)
    for ref, artifact in zip(selected.references(), p.artifacts, strict=True):
        assert ref.content_hash == content_hash_of(artifact.original_bytes)
    value = instruction(selected)
    encoded = encode_email_owner_instruction(value)
    reopened = decode_email_owner_instruction(encoded)
    assert reopened == value and reopened.original_text.encode() == value.original_text.encode()
    assert reopened.selection.references() == selected.references()
    assert reopened.processing_authorized is False
    assert p.companion.acquisition_account_verified is False


@pytest.mark.parametrize("mutation", ["body", "namespace", "future", "foreign", "duplicate"])
def test_changed_server_bytes_scope_or_selection_holds(mutation):
    p = prepared()
    selected = selection(p)
    preparations = (p,)
    if mutation == "body":
        p = replace(p, literal_text="invented substituted body")
        preparations = (p,)
    elif mutation == "namespace":
        pair = selected.app[0].model_copy(
            update={"raw_namespace": selected.app[0].raw_namespace + "x"}
        )
        selected = selected.model_copy(update={"app": (pair,)})
    elif mutation == "future":
        p = prepared(inspected_at=NOW + timedelta(seconds=1))
        selected, preparations = selection(p), (p,)
    elif mutation == "foreign":
        p = replace(p, artifacts=())
        preparations = (p,)
    else:
        preparations = (p, p)
    with pytest.raises((ValueError, EmailAppInputError)):
        check_email_app_preparations(selected, preparations, NOW)


def test_existing_native_instruction_serialization_bytes_remain_exact():
    original = raw(fixture_body())
    ref = EvidenceReference(
        source_id=UUID(int=1),
        content_hash=content_hash_of(original),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    companion = prepare_chatgpt_native_view(
        original,
        original_reference=ref,
        expected_thread_id="thread-1",
        selected_pointer="/turns/0/items/0/content/0/text",
        start=1,
        end=3,
        observed_at=NOW,
    )
    cref = ref.model_copy(
        update={
            "source_id": UUID(int=2),
            "content_hash": content_hash_of(canonical_bytes(companion.model_dump(mode="json"))),
        }
    )
    native = EmailInputSelectionV1(
        format="zac-brainstorm-email-input-selection-v1",
        native=(
            EmailNativeSelectionV1(
                capture_id=UUID(int=3),
                original_reference=ref,
                companion_reference=cref,
                companion=companion,
            ),
        ),
        recipient=None,
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )
    value = instruction(native)
    # Independent pre-variant wire shape: field serialization/discriminator may
    # not add app keys or rewrite the native selection's bytes.
    expected = value.model_dump(mode="json")
    expected["selection"] = native.model_dump(mode="json")
    encoded = encode_email_owner_instruction(value)
    assert encoded == canonical_bytes(expected)
    assert decode_email_owner_instruction(encoded).selection == native
    assert b'"app"' not in encoded
