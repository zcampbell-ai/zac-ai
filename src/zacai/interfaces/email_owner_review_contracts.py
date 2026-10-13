"""Closed human email assessment/release declarations, never sending capabilities."""

from __future__ import annotations

from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Digest, EvidenceReference
from zacai.intelligence.email_draft import EmailContract, EmailDraftPacketV1
from zacai.interfaces.email_processing_contracts import EmailProcessingRecoveryReceiptV1

CONFIRMATION = "I reviewed the complete recipient, subject, body and supporting evidence."


def email_review_digests(packet: EmailDraftPacketV1) -> tuple[str, str, str]:
    spec, candidate = packet.specification(), packet.candidate
    return (
        content_hash_of(
            canonical_bytes(
                {"recipient": spec.recipient.model_dump(mode="json") if spec.recipient else None}
            )
        ),
        content_hash_of(
            canonical_bytes(
                {"subject": candidate.subject, "body": [p.text for p in candidate.paragraphs]}
            )
        ),
        content_hash_of(
            canonical_bytes(
                {
                    "evidence": [e.model_dump(mode="json") for e in candidate.evidence_detail],
                    "blocking_question": candidate.blocking_question.model_dump(mode="json")
                    if candidate.blocking_question
                    else None,
                }
            )
        ),
    )


class EmailOwnerReviewManifestV1(EmailContract):
    format: Literal["zac-brainstorm-email-owner-review-manifest-v1"] = (
        "zac-brainstorm-email-owner-review-manifest-v1"
    )
    action_id: UUID
    output_reference: EvidenceReference
    output_receipt: EmailProcessingRecoveryReceiptV1
    input_reference: EvidenceReference
    specification_digest: Digest
    candidate_digest: Digest
    recipient_digest: Digest
    whole_text_digest: Digest
    evidence_digest: Digest
    source_preimages_json: str = Field(strict=True, max_length=40000, repr=False)
    prior_assessment_reference: EvidenceReference | None
    prior_assessment_rows_json: str | None = Field(strict=True, max_length=24000, repr=False)
    read_observed_at: AwareDatetime

    @model_validator(mode="after")
    def exact(self) -> Self:
        if (
            self.action_id.int == 0
            or self.output_reference.source_id != self.output_receipt.source_id
            or self.output_reference.content_hash != self.output_receipt.record_digest
            or self.output_receipt.verified_at > self.read_observed_at
            or (self.prior_assessment_reference is None)
            != (self.prior_assessment_rows_json is None)
        ):
            raise ValueError("exact protected output review scope required")
        return self

    def digest(self) -> str:
        return content_hash_of(canonical_bytes(self.model_dump(mode="json")))


class EmailOwnerAssessmentV1(EmailContract):
    format: Literal["zac-brainstorm-email-owner-assessment-v1"] = (
        "zac-brainstorm-email-owner-assessment-v1"
    )
    manifest: EmailOwnerReviewManifestV1 = Field(repr=False)
    decision: Literal["ACCEPT", "DECLINE", "DEFER"]
    reason: str = Field(strict=True, min_length=1, max_length=2000, repr=False)
    semantic_confirmation: (
        Literal["I reviewed the complete recipient, subject, body and supporting evidence."] | None
    )
    issuer: str = Field(strict=True, min_length=1, max_length=256, repr=False)
    subject: str = Field(strict=True, min_length=1, max_length=256, repr=False)
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    assessed_at: AwareDatetime

    @model_validator(mode="after")
    def exact_action(self) -> Self:
        if (
            not self.reason.strip()
            or (self.decision == "ACCEPT") != (self.semantic_confirmation == CONFIRMATION)
            or not self.original_session_issued_at
            <= self.manifest.read_observed_at
            <= self.assessed_at
            < self.original_session_expires_at
        ):
            raise ValueError("distinct exact original owner decision required")
        return self


class EmailOwnerReleaseV1(EmailContract):
    format: Literal["zac-brainstorm-email-owner-release-v1"] = (
        "zac-brainstorm-email-owner-release-v1"
    )
    assessment_reference: EvidenceReference
    output_reference: EvidenceReference
    manifest_digest: Digest
    released_at: AwareDatetime
    status: Literal["OWNER_ACCEPTED_FOR_MANUAL_USE"] = "OWNER_ACCEPTED_FOR_MANUAL_USE"


EmailOwnerReviewRecordV1 = EmailOwnerAssessmentV1 | EmailOwnerReleaseV1


def decode_email_owner_review(raw: bytes) -> EmailOwnerReviewRecordV1:
    from zacai.intelligence.email_draft import _load

    try:
        data = _load(raw, 64000)
        classes = {
            c.model_fields["format"].default: c
            for c in (EmailOwnerAssessmentV1, EmailOwnerReleaseV1)
        }
        return classes[data["format"]].model_validate(data)
    except Exception:  # noqa: BLE001,S110
        pass
    raise ValueError("email owner review record unavailable or invalid")


def encode_email_owner_review(value: EmailOwnerReviewRecordV1) -> bytes:
    try:
        if type(value) not in (EmailOwnerAssessmentV1, EmailOwnerReleaseV1):
            raise ValueError("closed review record required")
        raw = canonical_bytes(value.model_dump(mode="json"))
        if decode_email_owner_review(raw) != value:
            raise ValueError("exact canonical owner review required")
        return raw
    except Exception:  # noqa: BLE001,S110
        pass
    raise ValueError("email owner review record unavailable or invalid")


class EmailOwnerReviewRecoveryReceiptV1(EmailContract):
    format: Literal["zac-brainstorm-email-owner-review-recovery-v1"] = (
        "zac-brainstorm-email-owner-review-recovery-v1"
    )
    source_id: UUID
    record_digest: Digest
    captured_at: AwareDatetime
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    artifact_ciphertext_hash: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @property
    def receipt_object(self) -> str:
        return (
            f"BRAINSTORM/state/email-owner-review-{self.source_id}/receipt-{self.record_digest}.age"
        )

    @property
    def state_object(self) -> str:
        return (
            f"BRAINSTORM/state/email-owner-review-{self.source_id}/{self.state_ciphertext_hash}.age"
        )

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/email-owner-review-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"
