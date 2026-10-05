"""Pure named-action declarations; no issuer, Source writer or permission.

The trusted authenticated host must prove the named owner action, consumed nonce
and session/CSRF checks. Canonical adapters must independently resolve every
Source kind/byte hash/effective ACL, owner, lineage and retained recovery receipt,
including the generated packet and original evidence. A declared USER_INSTRUCTION
parent is not proof of its actual Source kind; generated replies must never be
relabelled human input. Route/model/tokenizer/template/locality declarations must
be checked against actual trusted runtime state before any processing.

These contracts preserve v1 authority/history bytes untouched. A future explicit
v2 consent must reference the protected named-decision Source and its recovery;
neither these types nor digests/IDs can create that Source or extend permission.
Source content_hash remains SHA256(encoded bytes); domain-separated correlation
digests below deliberately differ from the physical Source hash. No raw nonce,
cookie, CSRF, question text or credential is persisted by these envelopes.
"""

from __future__ import annotations

import json
import math
import re
from datetime import timedelta
from typing import Literal, Self
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from zacai.contextual_recovery_record import ContextualRecoveryReceipt, encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, ModelRoute
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.interfaces.followup_authorization import (
    FollowupRunScope,
    _owner_digest,
    followup_content_digest,
)
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.text_turn_capture import (
    TextTurn,
    TextTurnRecoveryReceipt,
    encode_text_turn,
)
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B

MAX_MANIFEST_BYTES = 16_000
MAX_DECISION_BYTES = 32_000
MAX_QUESTION_BYTES = 8_000
_CONSENT_NAMESPACE = UUID("f1643669-2448-50e0-a13f-55a18d02510d")
_MANIFEST_DOMAIN = b"zac-named-followup-manifest-digest-v1\x00"
_DECISION_DOMAIN = b"zac-named-followup-decision-digest-v1\x00"


class NamedFollowupDecisionError(ValueError):
    """Fixed diagnostics without private values or exception chains."""


class _Declaration(Contract):
    model_config = ConfigDict(strict=True, hide_input_in_errors=True)

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False

    @property
    def capture_verified(self) -> Literal[False]:
        return False


def _private_reference(ref: EvidenceReference) -> None:
    if (
        type(ref) is not EvidenceReference
        or type(ref.source_id) is not UUID
        or type(ref.content_hash) is not str
        or re.fullmatch(r"[0-9a-f]{64}", ref.content_hash) is None
        or ref.trust_boundary is not B.BRAINSTORM
        or ref.effective_classification is not C.CONFIDENTIAL
    ):
        raise ValueError("invalid private reference")


def _loopback(endpoint: str) -> None:
    if type(endpoint) is not str or not endpoint.isascii() or len(endpoint) > 60:
        raise ValueError("invalid declared endpoint")
    target = urlsplit(endpoint)
    if (
        target.scheme != "http" or target.hostname != "127.0.0.1"
        or target.port is None or not 1 <= target.port <= 65535
        or endpoint != f"http://127.0.0.1:{target.port}"
        or target.path or target.query or target.fragment or target.username or target.password
    ):
        raise ValueError("invalid declared endpoint")


class ManifestUserParent(_Declaration):
    """Declared human provenance only; actual Source verification is mandatory."""
    kind: Literal["user_instruction_turn"] = "user_instruction_turn"
    reference: EvidenceReference = Field(repr=False)

    @model_validator(mode="after")
    def private_parent(self) -> Self:
        _private_reference(self.reference)
        return self


class NamedFollowupManifest(_Declaration):
    format: Literal["zac-named-followup-manifest-v1"] = "zac-named-followup-manifest-v1"
    action: Literal["ask_caz_locally"] = "ask_caz_locally"
    actor_issuer: Literal["https://accounts.google.com"] = Field(repr=False)
    actor_subject: str = Field(strict=True, min_length=1, max_length=255, repr=False)
    owner_grant_digest: Digest = Field(repr=False)
    conversation_id: UUID
    request_id: UUID
    run_id: UUID
    builder_id: UUID
    nonce_digest: Digest = Field(repr=False)
    issued_at: AwareDatetime
    admission_expires_at: AwareDatetime
    processing_ttl_seconds: int = Field(strict=True, ge=1, le=900)
    packet_reference: EvidenceReference = Field(repr=False)
    packet_receipt_digest: Digest = Field(repr=False)
    evidence_references: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=32, repr=False)
    parents: tuple[ManifestUserParent, ...] = Field(max_length=6, repr=False)
    route: ModelRoute = Field(repr=False)
    model_digest: Digest = Field(repr=False)
    runtime_endpoint: str = Field(strict=True, repr=False)
    tokenizer_digest: Digest = Field(repr=False)
    request_template_digest: Digest = Field(repr=False)
    max_output_tokens: int = Field(strict=True, ge=1, le=1024)
    max_latency_ms: int = Field(strict=True, ge=1, le=120_000)
    max_estimated_cost_usd: float = Field(strict=True, ge=0, le=1, allow_inf_nan=False)

    @model_validator(mode="after")
    def exact_manifest(self) -> Self:
        refs = (self.packet_reference, *self.evidence_references, *(p.reference for p in self.parents))
        for ref in refs:
            _private_reference(ref)
        _loopback(self.runtime_endpoint)
        if (
            any(not 33 <= ord(char) <= 126 for char in self.actor_subject)
            or not timedelta(0) < self.admission_expires_at - self.issued_at <= timedelta(minutes=5)
            or len({ref.source_id for ref in refs}) != len(refs)
            or self.route.destination is not Destination.LOCAL
            or self.route.capabilities != frozenset({"packet_followup"})
            or self.route.available is not True
            or self.max_output_tokens > self.route.max_output_tokens
            or self.route.estimated_latency_ms > self.max_latency_ms
            or self.route.estimated_cost_usd > self.max_estimated_cost_usd
            or len(canonical_bytes(self.model_dump(mode="json"))) > MAX_MANIFEST_BYTES
        ):
            raise ValueError("invalid exact manifest")
        return self


class NamedFollowupDecision(_Declaration):
    format: Literal["zac-named-followup-decision-v1"] = "zac-named-followup-decision-v1"
    kind: Literal["named_owner_processing_decision"] = "named_owner_processing_decision"
    action: Literal["ask_caz_locally"] = "ask_caz_locally"
    manifest: NamedFollowupManifest = Field(repr=False)
    manifest_digest: Digest = Field(repr=False)
    admitted_at: AwareDatetime
    processing_expires_at: AwareDatetime
    bound_at: AwareDatetime
    original_observed_at: AwareDatetime
    session_binding_digest: Digest = Field(repr=False)
    question_kind: Literal["user_instruction_turn"] = "user_instruction_turn"
    question_reference: EvidenceReference = Field(repr=False)
    original_utf8_digest: Digest = Field(repr=False)
    question_receipt_digest: Digest = Field(repr=False)
    prepared_request_digest: Digest = Field(repr=False)
    run_scope: FollowupRunScope = Field(repr=False)

    @model_validator(mode="after")
    def exact_decision(self) -> Self:
        m, s = self.manifest, self.run_scope
        _private_reference(self.question_reference)
        if (
            self.manifest_digest != named_manifest_digest(m)
            or not m.issued_at <= self.admitted_at < m.admission_expires_at
            or self.processing_expires_at != self.admitted_at + timedelta(seconds=m.processing_ttl_seconds)
            or not self.admitted_at <= self.bound_at < self.processing_expires_at
            or not self.admitted_at <= self.original_observed_at <= self.bound_at
            or s.actor_issuer != m.actor_issuer or s.actor_subject != m.actor_subject
            or s.owner_grant_digest != m.owner_grant_digest
            or (s.run_id, s.builder_id, s.conversation_id) != (m.run_id, m.builder_id, m.conversation_id)
            or s.user_reference != self.question_reference
            or s.packet_reference != m.packet_reference
            or s.packet_receipt_digest != m.packet_receipt_digest
            or s.parent_references != tuple(p.reference for p in m.parents)
            or s.context_references != (self.question_reference, *m.evidence_references, *s.parent_references)
            or s.text_receipt_digest != self.question_receipt_digest
            or s.route != m.route or s.model_digest != m.model_digest
            or s.max_output_tokens != m.max_output_tokens or s.max_latency_ms != m.max_latency_ms
            or s.max_estimated_cost_usd != m.max_estimated_cost_usd
            or len(canonical_bytes(self.model_dump(mode="json"))) > MAX_DECISION_BYTES
        ):
            raise ValueError("named decision differs from published scope")
        return self


def _encode[T: _Declaration](value: T, expected: type[T], limit: int) -> bytes:
    result: bytes | None = None
    try:
        if type(value) is expected:
            checked = expected.model_validate(value, strict=True)
            raw = canonical_bytes(checked.model_dump(mode="json"))
            if len(raw) <= limit:
                result = raw
    except Exception:  # noqa: BLE001,S110 - sanitize nested/private contract diagnostics.
        pass
    if result is None:
        raise NamedFollowupDecisionError("named declaration unavailable")
    return result


def encode_named_manifest(value: NamedFollowupManifest) -> bytes:
    return _encode(value, NamedFollowupManifest, MAX_MANIFEST_BYTES)


def encode_named_decision(value: NamedFollowupDecision) -> bytes:
    return _encode(value, NamedFollowupDecision, MAX_DECISION_BYTES)


def named_manifest_digest(value: NamedFollowupManifest) -> str:
    return content_hash_of(_MANIFEST_DOMAIN + encode_named_manifest(value))


def named_decision_digest(value: NamedFollowupDecision) -> str:
    return content_hash_of(_DECISION_DOMAIN + encode_named_decision(value))


def named_decision_consent_id(decision_source_id: UUID) -> UUID:
    """Stable one-consent identity, not allocation/proof of a canonical Source."""
    if type(decision_source_id) is not UUID:
        raise NamedFollowupDecisionError("named consent identity unavailable")
    return uuid5(_CONSENT_NAMESPACE, str(decision_source_id))


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate declaration field")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("nonfinite declaration field")


def _float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("nonfinite declaration number")
    return parsed


def _decode[T: _Declaration](raw: bytes, expected: type[T], limit: int) -> T:
    result: T | None = None
    try:
        if type(raw) is bytes and 0 < len(raw) <= limit:
            # Strict JSON preflight rejects duplicate fields at every depth and
            # nonfinite numbers before Pydantic. Exact re-encoding rejects any
            # coercion/normalization, whitespace or alternate UUID/date syntax.
            json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique,
                       parse_constant=_constant, parse_float=_float)
            checked = expected.model_validate_json(raw, strict=True)
            if _encode(checked, expected, limit) == raw:
                result = checked
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise NamedFollowupDecisionError("named declaration unavailable")
    return result


def decode_named_manifest(raw: bytes) -> NamedFollowupManifest:
    return _decode(raw, NamedFollowupManifest, MAX_MANIFEST_BYTES)


def decode_named_decision(raw: bytes) -> NamedFollowupDecision:
    return _decode(raw, NamedFollowupDecision, MAX_DECISION_BYTES)


def validate_declared_bindings(
    decision: NamedFollowupDecision, *, owner: OwnerGrant, turn: TextTurn,
    turn_source_id: UUID, turn_receipt: TextTurnRecoveryReceipt,
    packet_receipt: ContextualRecoveryReceipt, request: FollowupRequest,
    runtime_endpoint: str, tokenizer_digest: str, request_template_digest: str,
) -> None:
    """Pure consistency check against exact host-supplied objects, NOT authority.

    Host must independently authenticate/read all these objects and prove actual
    nonce consumption/source kinds/current ACL/recovery/runtime pins. A None
    return cannot replace those mandatory gates or the independent semantic gate.
    Original text is checked in memory only; no source/model/log I/O occurs.
    """
    okay = False
    try:
        if (
            type(decision) is not NamedFollowupDecision or type(owner) is not OwnerGrant
            or type(turn) is not TextTurn or type(turn_source_id) is not UUID
            or type(turn_receipt) is not TextTurnRecoveryReceipt
            or type(packet_receipt) is not ContextualRecoveryReceipt
            or type(request) is not FollowupRequest
        ):
            raise ValueError("exact declared inputs required")
        decision = NamedFollowupDecision.model_validate(decision, strict=True)
        turn = TextTurn.model_validate(turn)
        turn_receipt = TextTurnRecoveryReceipt.model_validate(turn_receipt)
        packet_receipt = ContextualRecoveryReceipt.model_validate(packet_receipt)
        m, s = decision.manifest, decision.run_scope
        question = turn.original_text.encode("utf-8", errors="strict")
        if (
            not 0 < len(question) <= MAX_QUESTION_BYTES
            or content_hash_of(question) != decision.original_utf8_digest
            or content_hash_of(encode_text_turn(turn)) != decision.question_reference.content_hash
            or turn_source_id != decision.question_reference.source_id
            or (turn.issuer, turn.subject) != (m.actor_issuer, m.actor_subject)
            or (owner.identity.issuer, owner.identity.subject) != (m.actor_issuer, m.actor_subject)
            or _owner_digest(owner) != m.owner_grant_digest
            or (turn.request_id, turn.conversation_id) != (m.request_id, m.conversation_id)
            or turn.packet_reference != m.packet_reference
            or turn.packet_receipt_digest != m.packet_receipt_digest
            or turn.parent_references != tuple(p.reference for p in m.parents)
            or not decision.admitted_at <= turn.recorded_at <= decision.bound_at
            or turn_receipt.source_id != turn_source_id
            or turn_receipt.turn_digest != decision.question_reference.content_hash
            or turn_receipt.captured_at != turn.recorded_at
            or not turn_receipt.verified_at <= decision.bound_at
            or content_hash_of(canonical_bytes(turn_receipt.model_dump(mode="json"))) != decision.question_receipt_digest
            or packet_receipt.verified_at > m.issued_at
            or packet_receipt.locator.packet_source_id != m.packet_reference.source_id
            or packet_receipt.locator.packet_digest != m.packet_reference.content_hash
            or content_hash_of(encode_recovery_receipt(packet_receipt)) != m.packet_receipt_digest
            or request != prepare_followup_request(request.context)
            or request.digest != decision.prepared_request_digest
            or request.context.task.event.occurred_at != turn.recorded_at
            or request.context.task.event.observed_at != decision.original_observed_at
            or request.context.task.event.correlation_id != m.conversation_id
            or not request.context.task.event.occurred_at <= request.context.task.event.observed_at <= decision.bound_at
            or followup_content_digest(request) != s.content_digest
            or request.context.user_reference != decision.question_reference
            or request.context.packet_reference != m.packet_reference
            or request.context.parent_references != s.parent_references
            or tuple(item.reference for item in request.context.task.context) != s.context_references
            or request.context.task.max_output_tokens != m.max_output_tokens
            or request.context.task.max_latency_ms != m.max_latency_ms
            or request.context.task.max_estimated_cost_usd != m.max_estimated_cost_usd
            or runtime_endpoint != m.runtime_endpoint or tokenizer_digest != m.tokenizer_digest
            or request_template_digest != m.request_template_digest
        ):
            raise ValueError("declared named binding mismatch")
        question_item = next(item for item in request.context.task.context
                             if item.reference == decision.question_reference)
        if question_item.untrusted_text != turn.original_text.strip():
            raise ValueError("declared question projection mismatch")
        okay = True
    except Exception:  # noqa: BLE001,S110 - no original text/manifest/private diagnostics.
        pass
    if not okay:
        raise NamedFollowupDecisionError("named declared binding unavailable")
