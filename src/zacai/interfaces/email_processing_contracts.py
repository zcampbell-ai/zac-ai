"""Closed email-purpose canonical declarations; none is a standalone capability."""

from __future__ import annotations

from datetime import timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Digest, EvidenceReference, ModelRoute, UsageObservation
from zacai.intelligence.email_draft import (
    EmailContract,
    EmailDraftPacketV1,
    EmailDraftSpecificationV1,
)
from zacai.intelligence.email_generation import prepare_email_generation_request
from zacai.intelligence.email_local_wire import prepare_email_local_payload
from zacai.interfaces.email_input import EmailInputRecoveryReceiptV1

ACTION = "Generate this exact email candidate once locally for my review. Do not send it."


def request_digest(specification: EmailDraftSpecificationV1) -> str:
    request = prepare_email_generation_request(specification)
    return content_hash_of(
        canonical_bytes(
            {
                "specification": specification.model_dump(mode="json"),
                "instruction": request.instruction,
                "input_json": request.input_json,
                "schema_json": request.schema_json,
            }
        )
    )


class EmailProcessingManifestV1(EmailContract):
    format: Literal["zac-brainstorm-email-processing-manifest-v1"] = (
        "zac-brainstorm-email-processing-manifest-v1"
    )
    action_id: UUID
    builder_id: UUID
    input_reference: EvidenceReference
    input_receipt: EmailInputRecoveryReceiptV1
    specification: EmailDraftSpecificationV1 = Field(repr=False)
    source_preimages_json: str = Field(repr=False, max_length=24000)
    route: ModelRoute
    model_digest: Digest
    tokenizer_digest: Digest
    implementation_digest: Digest
    request_digest: Digest
    body_digest: Digest
    schema_digest: Digest
    full_prompt_tokens: int = Field(strict=True, ge=1, le=8192)

    @model_validator(mode="after")
    def bindings(self) -> Self:
        request = prepare_email_generation_request(self.specification)
        task = self.specification.task()
        if (
            self.action_id.int == 0
            or self.builder_id.int == 0
            or self.input_reference.source_id != self.input_receipt.source_id
            or self.input_reference.content_hash != self.input_receipt.instruction_digest
            or self.request_digest != request_digest(self.specification)
            or self.schema_digest != content_hash_of(request.schema_json.encode())
            or self.body_digest
            != content_hash_of(prepare_email_local_payload(request, self.route, self.model_digest))
            or self.full_prompt_tokens + task.max_output_tokens > 8192
            or self.route.estimated_cost_usd != 0
        ):
            raise ValueError("exact finite email manifest required")
        return self

    def digest(self) -> str:
        return content_hash_of(canonical_bytes(self.model_dump(mode="json")))


class EmailProcessingConsentV1(EmailContract):
    format: Literal["zac-brainstorm-email-processing-consent-v1"] = (
        "zac-brainstorm-email-processing-consent-v1"
    )
    manifest: EmailProcessingManifestV1 = Field(repr=False)
    action_text: Literal[
        "Generate this exact email candidate once locally for my review. Do not send it."
    ]
    issuer: str = Field(strict=True, min_length=1, max_length=256, repr=False)
    subject: str = Field(strict=True, min_length=1, max_length=256, repr=False)
    session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    approved_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def window(self) -> Self:
        if not (
            self.original_session_issued_at
            <= self.manifest.specification.task().event.observed_at
            <= self.approved_at
            < self.expires_at
            <= self.original_session_expires_at
            and self.expires_at - self.approved_at <= timedelta(minutes=10)
        ):
            raise ValueError("original bounded email consent window required")
        return self


class EmailProcessingClaimV1(EmailContract):
    format: Literal["zac-brainstorm-email-processing-claim-v1"] = (
        "zac-brainstorm-email-processing-claim-v1"
    )
    consent_reference: EvidenceReference
    manifest_digest: Digest
    attempt_id: UUID
    claimed_at: AwareDatetime


class EmailProcessingOutputV1(EmailContract):
    format: Literal["zac-brainstorm-email-processing-output-v1"] = (
        "zac-brainstorm-email-processing-output-v1"
    )
    claim_reference: EvidenceReference
    attempt_id: UUID
    body_digest: Digest
    response_text: str = Field(strict=True, max_length=128000, repr=False)
    packet: EmailDraftPacketV1 = Field(repr=False)
    usage: UsageObservation
    reported_prompt_eval_cached_count: int | None = Field(strict=True, ge=0)
    completed_at: AwareDatetime
    status: Literal["NEEDS_OWNER_SEMANTIC_REVIEW"] = "NEEDS_OWNER_SEMANTIC_REVIEW"


EmailProcessingRecordV1 = (
    EmailProcessingConsentV1 | EmailProcessingClaimV1 | EmailProcessingOutputV1
)


def encode_record(value: EmailProcessingRecordV1) -> bytes:
    try:
        if type(value) not in (
            EmailProcessingConsentV1,
            EmailProcessingClaimV1,
            EmailProcessingOutputV1,
        ):
            raise ValueError("closed record required")
        raw = canonical_bytes(value.model_dump(mode="json"))
        if not 0 < len(raw) <= 256000 or decode_record(raw) != value:
            raise ValueError("canonical bounded record required")
        return raw
    except Exception:  # noqa: BLE001,S110
        pass
    raise ValueError("email processing record unavailable or invalid")


def decode_record(raw: bytes) -> EmailProcessingRecordV1:
    from zacai.intelligence.email_draft import _load

    try:
        data = _load(raw, 256000)
        kinds = {
            k.model_fields["format"].default: k
            for k in (EmailProcessingConsentV1, EmailProcessingClaimV1, EmailProcessingOutputV1)
        }
        return kinds[data["format"]].model_validate(data)
    except Exception:  # noqa: BLE001,S110
        pass
    raise ValueError("email processing record unavailable or invalid")


class EmailProcessingRecoveryReceiptV1(EmailContract):
    format: Literal["zac-brainstorm-email-processing-recovery-v1"] = (
        "zac-brainstorm-email-processing-recovery-v1"
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
            f"BRAINSTORM/state/email-processing-{self.source_id}/receipt-{self.record_digest}.age"
        )

    @property
    def state_object(self) -> str:
        return (
            f"BRAINSTORM/state/email-processing-{self.source_id}/{self.state_ciphertext_hash}.age"
        )

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/email-processing-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"
