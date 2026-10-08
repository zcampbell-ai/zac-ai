"""Dormant complete-history declarations: codecs never approve or mint claims.

Exact original session, request and profile comparisons are metadata only.
Current Source access, signed owner, browser admission, physical transaction,
recovery and observed runtime authority remain separate consumer prerequisites.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import _history_request_provenance
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, ModelRoute
from zacai.intelligence.history_contextual_codec import (
    MAX_PACKET_BYTES,
    MAX_REQUEST_BYTES,
    HistoryContextualRequestV1,
    decode_history_contextual_request,
    encode_history_contextual_request,
)
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B

MAX_AUTHORITY_BYTES = 64000
MAX_DECLARATION_BYTES = MAX_PACKET_BYTES
PURPOSE = "history_complete_independent_review"
GENERATION_STYLE_CLAUSE = (
    "Use concise prose in the owner's voice. Use no em dash in generated prose; "
    "retain exact punctuation in evidence quotes. Do not infer owner authorship "
    "from USER role alone."
)
_PROFILE_DOMAIN = b"zac-history-review-purpose-profile-v1\x00"
_DECLARATION_DOMAIN = b"zac-history-generation-review-declaration-v1\x00"


class HistoryDeclarationError(ValueError):
    """Fixed safe diagnostic, never an approval decision."""


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in values:
        if key in data:
            raise ValueError("duplicate key")
        data[key] = value
    return data


class HistoryConsentV1(Contract):
    """Recorded human decision metadata, not a dispatch or recovery capability."""

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-personal-history-complete-consent-v1"] = (
        "zac-personal-history-complete-consent-v1"
    )
    id: UUID
    builder_id: UUID
    task_id: UUID
    request_digest: Digest
    provenance: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=95, repr=False)
    owner_issuer: str = Field(min_length=1, max_length=255, strict=True, repr=False)
    owner_subject: str = Field(min_length=1, max_length=255, strict=True, repr=False)
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_reference: str = Field(min_length=1, max_length=500, strict=True, repr=False)
    route: ModelRoute
    model_digest: Digest
    tokenizer_digest: Digest
    runtime_digest: Digest
    template_digest: Digest
    renderer_digest: Digest
    body_digest: Digest
    generation_wire_format: Literal["zac-history-complete-generation-wire-v1"] = (
        "zac-history-complete-generation-wire-v1"
    )
    generation_wire_digest: Digest
    prompt_tokens: int = Field(gt=0, strict=True)
    max_output_tokens: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def closed_complete_history_decision(self) -> Self:
        ids = tuple(ref.source_id for ref in self.provenance)
        if (
            any(v.int == 0 for v in (self.id, self.builder_id, self.task_id, *ids))
            or len(set(ids)) != len(ids)
            or ids != tuple(sorted(ids, key=str))
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in self.provenance
            )
            or self.route.destination is not Destination.LOCAL
            or not self.route.available
            or "contextual_meeting_review" not in self.route.capabilities
            or "compact_meeting_review" in self.route.capabilities
            or not self.original_session_issued_at
            <= self.approved_at
            < self.expires_at
            <= self.original_session_expires_at
            or not timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=15)
            or not all(
                v.strip() for v in (self.owner_issuer, self.owner_subject, self.human_reference)
            )
        ):
            raise ValueError("closed original complete history decision required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False

    @property
    def current_facts_verified(self) -> Literal[False]:
        return False


class HistoryClaimV1(Contract):
    """Exact future consumed ledger bytes; codec/load never issue this claim."""

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-personal-history-complete-claim-v1"] = (
        "zac-personal-history-complete-claim-v1"
    )
    consent_reference: EvidenceReference = Field(repr=False)
    consent_digest: Digest
    request_digest: Digest
    attempt_id: UUID
    task_id: UUID
    builder_id: UUID
    original_session_binding: Digest = Field(repr=False)
    body_digest: Digest
    generation_wire_format: Literal["zac-history-complete-generation-wire-v1"] = (
        "zac-history-complete-generation-wire-v1"
    )
    generation_wire_digest: Digest
    route_digest: Digest
    model_digest: Digest
    tokenizer_digest: Digest
    runtime_digest: Digest
    template_digest: Digest
    renderer_digest: Digest
    prompt_tokens: int = Field(gt=0, strict=True)
    max_output_tokens: int = Field(gt=0, strict=True)
    consumed_at: AwareDatetime

    @model_validator(mode="after")
    def exact_claim_identity(self) -> Self:
        if (
            any(
                v.int == 0
                for v in (
                    self.attempt_id,
                    self.task_id,
                    self.builder_id,
                    self.consent_reference.source_id,
                )
            )
            or self.consent_reference.trust_boundary is not B.PERSONAL
            or self.consent_reference.effective_classification is not C.HIGHLY_RESTRICTED
            or self.consent_reference.content_hash != self.consent_digest
        ):
            raise ValueError("exact complete history claim subject required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False

    @property
    def current_facts_verified(self) -> Literal[False]:
        return False


def _authority_bytes(value: HistoryConsentV1 | HistoryClaimV1) -> bytes:
    data = value.model_dump(mode="json")
    if type(value) is HistoryConsentV1:
        data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    raw = canonical_bytes(data)
    if not 0 < len(raw) <= MAX_AUTHORITY_BYTES:
        raise ValueError("bounded complete history authority metadata required")
    return raw


def encode_history_consent(value: HistoryConsentV1) -> bytes:
    result = None
    try:
        if type(value) is not HistoryConsentV1:
            raise TypeError("exact complete history consent required")
        result = _authority_bytes(HistoryConsentV1.model_validate(value))
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history consent unavailable")
    return result


def decode_history_consent(raw: bytes) -> HistoryConsentV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_AUTHORITY_BYTES:
            raise ValueError("bounded consent bytes required")
        value = HistoryConsentV1.model_validate(json.loads(raw, object_pairs_hook=_pairs))
        if raw != encode_history_consent(value):
            raise ValueError("canonical consent bytes required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryDeclarationError("complete history consent unavailable")
    return result


def encode_history_claim(value: HistoryClaimV1) -> bytes:
    result = None
    try:
        if type(value) is not HistoryClaimV1:
            raise TypeError("exact complete history claim required")
        result = _authority_bytes(HistoryClaimV1.model_validate(value))
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history claim unavailable")
    return result


def decode_history_claim(raw: bytes) -> HistoryClaimV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_AUTHORITY_BYTES:
            raise ValueError("bounded claim bytes required")
        value = HistoryClaimV1.model_validate(json.loads(raw, object_pairs_hook=_pairs))
        if raw != encode_history_claim(value):
            raise ValueError("canonical claim bytes required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryDeclarationError("complete history claim unavailable")
    return result


def prepare_history_generation_wire(request: HistoryContextualRequestV1) -> bytes:
    """Exact complete-only prospective wire, not an admission or token count.

    V1 canonical request/packet reconstruction is untouched. Concrete consumers
    must count and send these actual bytes with original task/request binding.
    The fixed instruction cannot prove semantic style or authentic authorship.
    """
    result = None
    try:
        if type(request) is not HistoryContextualRequestV1:
            raise TypeError("exact complete request required")
        encode_history_contextual_request(request)
        value = json.loads(request.prompt_body, object_pairs_hook=_pairs)
        messages = value["messages"]
        if (
            type(messages) is not list
            or len(messages) != 2
            or messages[0]["role"] != "system"
            or type(messages[0]["content"]) is not str
        ):
            raise ValueError("closed contextual wire required")
        messages[0]["content"] += "\n" + GENERATION_STYLE_CLAUSE
        wire = canonical_bytes(value)
        if not 0 < len(wire) <= 64000:
            raise ValueError("bounded complete generation wire required")
        # Existing real generic renderer accepts the unchanged draft schema.
        # This is structural rendering validation, NOT actual tokenizer counting.
        from zacai.intelligence.ollama_token_counter import render_contextual_prompt

        render_contextual_prompt(wire)
        result = wire
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history generation wire unavailable")
    return result


def validate_history_consent_request(
    consent: HistoryConsentV1, request: HistoryContextualRequestV1
) -> bytes:
    """Compare declarations only; no current Source or owner permission is proved."""
    result = None
    try:
        if type(consent) is not HistoryConsentV1 or type(request) is not HistoryContextualRequestV1:
            raise TypeError("exact complete request and consent required")
        encode_history_consent(consent)
        raw = encode_history_contextual_request(request)
        if (
            content_hash_of(raw) != consent.request_digest
            or request.task.task_id != consent.task_id
            or request.route != consent.route
            or request.task.event.trust_boundary is not B.PERSONAL
            or request.task.event.data_classification is not C.HIGHLY_RESTRICTED
            or _history_request_provenance(request) != consent.provenance
            or content_hash_of(request.prompt_body.encode("utf-8")) != consent.body_digest
            or request.task.max_output_tokens != consent.max_output_tokens
            or content_hash_of(prepare_history_generation_wire(request))
            != consent.generation_wire_digest
        ):
            raise ValueError("exact complete history request required")
        result = raw
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history request binding unavailable")
    return result


class HistoryReviewPurposeProfileV1(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-history-review-purpose-profile-v1"] = (
        "zac-history-review-purpose-profile-v1"
    )
    purpose: Literal["history_complete_independent_review"] = "history_complete_independent_review"
    reviewer_id: UUID
    run_id: UUID
    route: ModelRoute = Field(repr=False)
    model_digest: Digest
    tokenizer_digest: Digest
    runtime_digest: Digest
    template_digest: Digest
    renderer_digest: Digest
    rubric_digest: Digest
    reviewer_wire_digest: Digest
    body_derivation_digest: Digest
    derivation_rule: Literal["exact_retained_complete_history_packet_and_original_request_v1"] = (
        "exact_retained_complete_history_packet_and_original_request_v1"
    )
    runtime_endpoint: Literal["http://127.0.0.1:11434"] = "http://127.0.0.1:11434"
    context_window_tokens: Literal[8192, 16384]
    max_input_bytes: Literal[64000] = 64000
    max_output_tokens: int = Field(strict=True, ge=1, le=2048)
    max_latency_ms: int = Field(strict=True, ge=1, le=60000)
    max_estimated_cost_usd: float = Field(strict=True, ge=0, le=0, allow_inf_nan=False)
    expiry_rule: Literal["same_original_processing_expiry"] = "same_original_processing_expiry"

    @model_validator(mode="after")
    def closed_declared_profile(self) -> Self:
        r = self.route
        if (
            self.reviewer_id.int == 0
            or self.run_id.int == 0
            or r.destination is not Destination.LOCAL
            or r.available is not True
            or r.capabilities != frozenset({PURPOSE})
            or self.max_output_tokens > r.max_output_tokens
            or r.estimated_latency_ms > self.max_latency_ms
            or r.estimated_cost_usd > self.max_estimated_cost_usd
        ):
            raise ValueError("closed declared LOCAL review profile required")
        return self


def _profile_bytes(profile: HistoryReviewPurposeProfileV1) -> bytes:
    if type(profile) is not HistoryReviewPurposeProfileV1:
        raise ValueError("exact review profile required")
    value = HistoryReviewPurposeProfileV1.model_validate(
        profile.model_dump(mode="json")
    ).model_dump(mode="json")
    value["route"]["capabilities"] = sorted(value["route"]["capabilities"])
    return canonical_bytes(value)


def history_review_profile_digest(profile: HistoryReviewPurposeProfileV1) -> str:
    return content_hash_of(_PROFILE_DOMAIN + _profile_bytes(profile))


class HistoryGenerationReviewDeclarationV1(Contract):
    """Whole prospective publication metadata, never inherited inner approval."""

    model_config = ConfigDict(hide_input_in_errors=True)

    format: Literal["zac-history-generation-review-declaration-v1"] = (
        "zac-history-generation-review-declaration-v1"
    )
    generation_consent_json: str = Field(strict=True, min_length=1, max_length=64000, repr=False)
    generation_request_json: str = Field(
        strict=True, min_length=1, max_length=MAX_REQUEST_BYTES, repr=False
    )
    generation_wire_json: str = Field(strict=True, min_length=1, max_length=64000, repr=False)
    generation_wire_digest: Digest
    generation_consent_digest: Digest
    generation_request_digest: Digest
    review: HistoryReviewPurposeProfileV1 = Field(repr=False)
    review_profile_digest: Digest
    approved_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_original_declaration(self) -> Self:
        consent_raw = self.generation_consent_json.encode("utf-8")
        request_raw = self.generation_request_json.encode("utf-8")
        g = decode_history_consent(consent_raw)
        q = decode_history_contextual_request(request_raw)
        validate_history_consent_request(g, q)
        profile = self.review
        if (
            self.generation_consent_digest != content_hash_of(consent_raw)
            or self.generation_request_digest != content_hash_of(request_raw)
            or g.body_digest != content_hash_of(q.prompt_body.encode("utf-8"))
            or g.max_output_tokens != q.task.max_output_tokens
            or self.generation_wire_json.encode("utf-8") != prepare_history_generation_wire(q)
            or self.generation_wire_digest != g.generation_wire_digest
            or self.generation_wire_digest
            != content_hash_of(self.generation_wire_json.encode("utf-8"))
            or self.approved_at != g.approved_at
            or self.expires_at != g.expires_at
            or self.review_profile_digest != history_review_profile_digest(profile)
        ):
            raise ValueError("exact original generation bytes/time/scope required")
        if (
            profile.reviewer_id == g.builder_id
            or profile.run_id == g.task_id
            or q.task.max_latency_ms + profile.max_latency_ms
            > (g.expires_at - g.approved_at).total_seconds() * 1000
        ):
            raise ValueError("distinct declared review and fixed combined window required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False

    @property
    def current_facts_verified(self) -> Literal[False]:
        return False


def prepare_history_generation_review_declaration(
    generation: HistoryConsentV1,
    request: HistoryContextualRequestV1,
    *,
    review: HistoryReviewPurposeProfileV1,
) -> HistoryGenerationReviewDeclarationV1:
    """Compare exact canonical declarations; this does not record human admission."""
    result = None
    try:
        generation_raw = encode_history_consent(generation)
        request_raw = encode_history_contextual_request(request)
        result = HistoryGenerationReviewDeclarationV1(
            generation_consent_json=generation_raw.decode("utf-8"),
            generation_request_json=request_raw.decode("utf-8"),
            generation_wire_json=prepare_history_generation_wire(request).decode("utf-8"),
            generation_wire_digest=generation.generation_wire_digest,
            generation_consent_digest=content_hash_of(generation_raw),
            generation_request_digest=content_hash_of(request_raw),
            review=review,
            review_profile_digest=history_review_profile_digest(review),
            approved_at=generation.approved_at,
            expires_at=generation.expires_at,
        )
        encode_history_generation_review_declaration(result)
    except Exception:  # noqa: BLE001 - no input fields in fixed diagnostics
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history declaration unavailable or mismatched")
    return result


def encode_history_generation_review_declaration(
    value: HistoryGenerationReviewDeclarationV1,
) -> bytes:
    result = None
    try:
        if type(value) is not HistoryGenerationReviewDeclarationV1:
            raise TypeError("exact declaration required")
        data = HistoryGenerationReviewDeclarationV1.model_validate(
            value.model_dump(mode="json")
        ).model_dump(mode="json")
        data["review"] = json.loads(_profile_bytes(value.review))
        result = canonical_bytes(data)
        if len(result) > MAX_DECLARATION_BYTES:
            result = None
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history declaration unavailable or mismatched")
    return result


def decode_history_generation_review_declaration(
    raw: bytes,
) -> HistoryGenerationReviewDeclarationV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_DECLARATION_BYTES:
            raise ValueError("bounded exact declaration required")

        result = HistoryGenerationReviewDeclarationV1.model_validate(
            json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
        )
        if encode_history_generation_review_declaration(result) != raw:
            result = None
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationError("complete history declaration unavailable or mismatched")
    return result


def history_generation_review_declaration_digest(
    value: HistoryGenerationReviewDeclarationV1,
) -> str:
    return content_hash_of(
        _DECLARATION_DOMAIN + encode_history_generation_review_declaration(value)
    )
