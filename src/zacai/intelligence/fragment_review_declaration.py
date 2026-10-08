"""Prospective whole generation/review declaration, without owner admission.

Canonical bytes bind declarations, not signatures, grants, current Source rows,
recovery or processing authority. Existing generation-only consent is unchanged.
A future host must admit/protect the FULL publication before generation; wrapping
an already-approved inner consent cannot authorize review retroactively.
"""

from __future__ import annotations

import json
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from zacai.contextual_authorization import (
    HistoryFragmentConsentV1,
    _fragment_consent_request,
    decode_history_fragment_consent,
    encode_history_fragment_consent,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, ModelRoute
from zacai.intelligence.fragment_review_preparation import PURPOSE
from zacai.intelligence.history_contextual_codec import MAX_PACKET_BYTES, MAX_REQUEST_BYTES
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualRequestV1,
    decode_history_fragment_contextual_request,
    encode_history_fragment_contextual_request,
)
from zacai.policy import Destination

MAX_DECLARATION_BYTES = MAX_PACKET_BYTES
_PROFILE_DOMAIN = b"zac-fragment-review-purpose-profile-v1\x00"
_DECLARATION_DOMAIN = b"zac-fragment-generation-review-declaration-v2\x00"


class FragmentReviewDeclarationError(ValueError):
    """Fixed private-safe declaration error, never an approval verdict."""


class FragmentReviewPurposeProfileV1(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-fragment-review-purpose-profile-v1"] = (
        "zac-fragment-review-purpose-profile-v1"
    )
    purpose: Literal["history_fragment_independent_review"] = "history_fragment_independent_review"
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
    derivation_rule: Literal["exact_retained_fragment_packet_and_original_request_v1"] = (
        "exact_retained_fragment_packet_and_original_request_v1"
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


def _profile_bytes(profile: FragmentReviewPurposeProfileV1) -> bytes:
    if type(profile) is not FragmentReviewPurposeProfileV1:
        raise ValueError("exact review profile required")
    value = FragmentReviewPurposeProfileV1.model_validate(profile).model_dump(mode="json")
    value["route"]["capabilities"] = sorted(value["route"]["capabilities"])
    return canonical_bytes(value)


def fragment_review_profile_digest(profile: FragmentReviewPurposeProfileV1) -> str:
    return content_hash_of(_PROFILE_DOMAIN + _profile_bytes(profile))


class FragmentGenerationReviewDeclarationV2(Contract):
    """Whole prospective publication metadata, never inherited inner approval."""

    model_config = ConfigDict(hide_input_in_errors=True)

    format: Literal["zac-fragment-generation-review-declaration-v2"] = (
        "zac-fragment-generation-review-declaration-v2"
    )
    generation_consent_json: str = Field(strict=True, min_length=1, max_length=64000, repr=False)
    generation_request_json: str = Field(
        strict=True, min_length=1, max_length=MAX_REQUEST_BYTES, repr=False
    )
    generation_consent_digest: Digest
    generation_request_digest: Digest
    review: FragmentReviewPurposeProfileV1 | None = Field(repr=False)
    review_profile_digest: Digest | None
    approved_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_original_declaration(self) -> Self:
        consent_raw = self.generation_consent_json.encode("utf-8")
        request_raw = self.generation_request_json.encode("utf-8")
        g = decode_history_fragment_consent(consent_raw)
        q = decode_history_fragment_contextual_request(request_raw)
        _fragment_consent_request(g, q)
        profile = self.review
        if (
            self.generation_consent_digest != content_hash_of(consent_raw)
            or self.generation_request_digest != content_hash_of(request_raw)
            or g.body_digest != content_hash_of(q.prompt_body.encode("utf-8"))
            or g.max_output_tokens != q.task.max_output_tokens
            or self.approved_at != g.approved_at
            or self.expires_at != g.expires_at
            or self.review_profile_digest
            != (None if profile is None else fragment_review_profile_digest(profile))
        ):
            raise ValueError("exact original generation bytes/time/scope required")
        if profile is not None and (
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


def prepare_fragment_generation_review_declaration(
    generation: HistoryFragmentConsentV1,
    request: HistoryFragmentContextualRequestV1,
    *,
    review: FragmentReviewPurposeProfileV1 | None,
) -> FragmentGenerationReviewDeclarationV2:
    """Compare exact canonical declarations; this does not record human admission."""
    result = None
    try:
        generation_raw = encode_history_fragment_consent(generation)
        request_raw = encode_history_fragment_contextual_request(request)
        result = FragmentGenerationReviewDeclarationV2(
            generation_consent_json=generation_raw.decode("utf-8"),
            generation_request_json=request_raw.decode("utf-8"),
            generation_consent_digest=content_hash_of(generation_raw),
            generation_request_digest=content_hash_of(request_raw),
            review=review,
            review_profile_digest=None
            if review is None
            else fragment_review_profile_digest(review),
            approved_at=generation.approved_at,
            expires_at=generation.expires_at,
        )
        encode_fragment_generation_review_declaration(result)
    except Exception:  # noqa: BLE001 - no input fields in fixed diagnostics
        result = None
    if result is None:
        raise FragmentReviewDeclarationError(
            "fragment review declaration unavailable or mismatched"
        )
    return result


def encode_fragment_generation_review_declaration(
    value: FragmentGenerationReviewDeclarationV2,
) -> bytes:
    result = None
    try:
        if type(value) is not FragmentGenerationReviewDeclarationV2:
            raise TypeError("exact declaration required")
        data = FragmentGenerationReviewDeclarationV2.model_validate(value).model_dump(mode="json")
        if value.review is not None:
            data["review"] = json.loads(_profile_bytes(value.review))
        result = canonical_bytes(data)
        if len(result) > MAX_DECLARATION_BYTES:
            result = None
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise FragmentReviewDeclarationError(
            "fragment review declaration unavailable or mismatched"
        )
    return result


def decode_fragment_generation_review_declaration(
    raw: bytes,
) -> FragmentGenerationReviewDeclarationV2:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_DECLARATION_BYTES:
            raise ValueError("bounded exact declaration required")

        def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
            data: dict[str, object] = {}
            for key, value in values:
                if key in data:
                    raise ValueError("duplicate key")
                data[key] = value
            return data

        result = FragmentGenerationReviewDeclarationV2.model_validate(
            json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        )
        if encode_fragment_generation_review_declaration(result) != raw:
            result = None
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise FragmentReviewDeclarationError(
            "fragment review declaration unavailable or mismatched"
        )
    return result


def fragment_generation_review_declaration_digest(
    value: FragmentGenerationReviewDeclarationV2,
) -> str:
    return content_hash_of(
        _DECLARATION_DOMAIN + encode_fragment_generation_review_declaration(value)
    )
