"""Wholly invented offline scope/codec controls; no owner/SQL/semantic authority proof."""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_email_generation import output
from tests.test_email_generation import req as source_request
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.email_generation import parse_email_model_output, resolve_email_model_output
from zacai.interfaces.email_owner_review import _can_accept, _scope_bindings
from zacai.interfaces.email_owner_review_contracts import (
    CONFIRMATION,
    EmailOwnerAssessmentV1,
    EmailOwnerReviewManifestV1,
    decode_email_owner_review,
    email_review_digests,
    encode_email_owner_review,
)
from zacai.interfaces.email_processing_contracts import EmailProcessingRecoveryReceiptV1


@pytest.fixture
def case():
    req = source_request.__wrapped__()
    at = req.specification.task().event.observed_at
    packet = resolve_email_model_output(
        parse_email_model_output(canonical_bytes(output(req))),
        req,
        builder_id=uuid4(),
        created_at=at,
    )
    ref = req.specification.task().context[0].reference
    receipt = EmailProcessingRecoveryReceiptV1(
        source_id=ref.source_id,
        record_digest=ref.content_hash,
        captured_at=at,
        verified_at=at,
        artifact_backup_run_id=uuid4(),
        artifact_ciphertext_hash="a" * 64,
        state_ciphertext_hash="a" * 64,
        state_plaintext_hash="a" * 64,
        journal_ciphertext_hash="a" * 64,
        journal_plaintext_hash="a" * 64,
    )
    recipient, text, evidence = email_review_digests(packet)
    manifest = EmailOwnerReviewManifestV1(
        action_id=uuid4(),
        output_reference=ref,
        output_receipt=receipt,
        input_reference=ref,
        specification_digest=packet.specification_digest,
        candidate_digest=packet.candidate_digest,
        recipient_digest=recipient,
        whole_text_digest=text,
        evidence_digest=evidence,
        source_preimages_json="{}",
        prior_assessment_reference=None,
        prior_assessment_rows_json=None,
        read_observed_at=at,
    )
    return packet, manifest, at


@pytest.mark.parametrize("decision", ["ACCEPT", "DECLINE", "DEFER"])
def test_distinct_decisions_preserve_literal_reason_and_never_flip_candidate_flags(case, decision):
    packet, manifest, at = case
    literal = "Owner's exact reason.\nKeep both lines."
    value = EmailOwnerAssessmentV1(
        manifest=manifest,
        decision=decision,
        reason=literal,
        semantic_confirmation=CONFIRMATION if decision == "ACCEPT" else None,
        issuer="invented",
        subject="invented",
        original_session_binding="a" * 64,
        original_session_issued_at=at - timedelta(minutes=1),
        original_session_expires_at=at + timedelta(minutes=30),
        assessed_at=at,
    )
    assert decode_email_owner_review(encode_email_owner_review(value)) == value
    assert value.reason.encode() == literal.encode()
    for flag in (
        "processing_authorized",
        "generation_authenticated",
        "reviewer_authenticated",
        "recovery_verified",
        "ready_to_deliver",
        "current_facts_verified",
        "sending_authorized",
    ):
        assert getattr(packet, flag) is False


@pytest.mark.parametrize(
    "decision,confirmation",
    [("ACCEPT", None), ("ACCEPT", "yes"), ("DECLINE", CONFIRMATION), ("DEFER", CONFIRMATION)],
)
def test_accept_requires_exact_whole_scope_ack_and_decline_defer_are_not_accept(
    case, decision, confirmation
):
    _, manifest, at = case
    with pytest.raises(ValueError):
        EmailOwnerAssessmentV1(
            manifest=manifest,
            decision=decision,
            reason="Invented reason",
            semantic_confirmation=confirmation,
            issuer="invented",
            subject="invented",
            original_session_binding="a" * 64,
            original_session_issued_at=at - timedelta(minutes=1),
            original_session_expires_at=at + timedelta(minutes=30),
            assessed_at=at,
        )


@pytest.mark.parametrize(
    "field",
    [
        "recipient_digest",
        "whole_text_digest",
        "evidence_digest",
        "candidate_digest",
        "specification_digest",
    ],
)
def test_whole_scope_drift_is_not_authenticated_by_other_matching_digests(case, field):
    packet, manifest, _ = case
    original = SimpleNamespace(
        output=SimpleNamespace(packet=packet),
        consent=SimpleNamespace(manifest=SimpleNamespace(input_reference=manifest.input_reference)),
    )
    _scope_bindings(manifest, original)
    changed = manifest.model_copy(update={field: "f" * 64})
    with pytest.raises(
        ValueError, match="^whole candidate/recipient/evidence review scope changed$"
    ):
        _scope_bindings(changed, original)


def test_duplicate_json_and_edits_are_rejected_by_closed_assessment_codec(case):
    _, manifest, at = case
    value = EmailOwnerAssessmentV1(
        manifest=manifest,
        decision="DEFER",
        reason="PRIVATE_MARKER",
        semantic_confirmation=None,
        issuer="invented",
        subject="invented",
        original_session_binding="a" * 64,
        original_session_issued_at=at - timedelta(minutes=1),
        original_session_expires_at=at + timedelta(minutes=30),
        assessed_at=at,
    )
    raw = encode_email_owner_review(value)
    for changed in (
        raw.replace(b'"decision":"DEFER"', b'"decision":"DEFER","decision":"DEFER"'),
        raw[:-1] + b',"edited_body":"PRIVATE_MARKER"}',
    ):
        with pytest.raises(
            ValueError, match="^email owner review record unavailable or invalid$"
        ) as error:
            decode_email_owner_review(changed)
        assert error.value.__context__ is None
        assert "PRIVATE_MARKER" not in str(error.value)


def test_unresolved_recipient_question_has_no_acceptance_bypass(case):
    from zacai.intelligence.email_generation import prepare_email_generation_request

    packet, _, _ = case
    _can_accept(packet)
    specification = packet.specification().model_copy(update={"recipient": None})
    request = prepare_email_generation_request(specification)
    model_output = {
        "format": "zac-email-model-output-v1",
        "subject": None,
        "subject_support": None,
        "paragraphs": [],
        "blocking_question": {
            "question": "Who should receive this email?",
            "reason": "The recipient is missing.",
            "kind": "MISSING_FACT",
            "evidence_ids": [request.quotes[0][0]],
        },
    }
    question_only = resolve_email_model_output(
        parse_email_model_output(canonical_bytes(model_output)),
        request,
        builder_id=uuid4(),
        created_at=specification.task().event.observed_at,
    )
    with pytest.raises(ValueError, match="^dependent or unresolved candidate cannot be accepted$"):
        _can_accept(question_only)
