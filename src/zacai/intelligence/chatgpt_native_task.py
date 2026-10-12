"""Native ChatGPT request/declaration comparison, never processing admission.

No Source writer, POST observer, claim, backend, reviewer or approval is added.
Current reconstruction reuses actual pair/current Source contracts. Supplied
original-task context remains a trusted host comparison, not source authorship.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from importlib.metadata import version
from pathlib import Path
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from zacai.chatgpt_native_custody import _host, _scope
from zacai.chatgpt_native_source import LoadedChatGPTNativeView, load_chatgpt_native_view_pair
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.chatgpt_native_context import (
    ChatGPTNativeContextProfileV1,
    PreparedChatGPTNativeContext,
    prepare_chatgpt_native_context,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, ModelRoute
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import (
    OllamaQwenContextualTokenCounter,
    render_contextual_prompt,
)
from zacai.intelligence.review_context import _unique_pairs
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

MAX_REQUEST_BYTES = 2_000_000


class ChatGPTNativeTaskError(ValueError):
    """Fixed safe comparison/current-source hold, no private diagnostic chain."""


class ChatGPTNativeTaskRequestV1(Contract):
    format: Literal["zac-chatgpt-native-task-request-v1"] = "zac-chatgpt-native-task-request-v1"
    profile: ChatGPTNativeContextProfileV1 = Field(repr=False)
    route: ModelRoute
    selected_literal: str = Field(strict=True, min_length=1, max_length=100_000, repr=False)
    wire_json: str = Field(strict=True, min_length=1, max_length=64_000, repr=False)
    wire_digest: Digest

    def preparation(self) -> PreparedChatGPTNativeContext:
        p = self.profile
        original = ReviewContext(
            p.original_task, p.original_meeting_source_id, p.original_related_source_ids
        )
        loaded = LoadedChatGPTNativeView(
            p.capture_id,
            p.current_original_reference,
            p.current_companion_reference,
            p.companion,
            self.selected_literal,
            p.source_captured_at,
        )
        return prepare_chatgpt_native_context(
            original, loaded, capture_id=p.capture_id, route=self.route
        )

    @model_validator(mode="after")
    def exact_components(self) -> Self:
        prepared = self.preparation()
        wire = self.wire_json.encode("utf-8")
        if (
            prepared.profile != self.profile
            or prepared.body != wire
            or prepared.body_digest != self.wire_digest
            or len(wire) > 64_000
        ):
            raise ValueError("exact native task reconstruction required")
        # Count renderer support is actual, not a sidecar field ignored by the model.
        render_contextual_prompt(wire)
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def _request_bytes(value: ChatGPTNativeTaskRequestV1) -> bytes:
    if type(value) is not ChatGPTNativeTaskRequestV1:
        raise TypeError("exact native request required")
    data = ChatGPTNativeTaskRequestV1.model_validate(value.model_dump(mode="json")).model_dump(
        mode="json"
    )
    data["profile"]["original_task"]["required_capabilities"] = sorted(
        data["profile"]["original_task"]["required_capabilities"]
    )
    data["profile"]["original_related_source_ids"] = sorted(
        data["profile"]["original_related_source_ids"]
    )
    data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    raw = canonical_bytes(data)
    if not 0 < len(raw) <= MAX_REQUEST_BYTES:
        raise ValueError("bounded native request required")
    return raw


def encode_chatgpt_native_task_request(value: ChatGPTNativeTaskRequestV1) -> bytes:
    result = None
    try:
        result = _request_bytes(value)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task request held")
    return result


def decode_chatgpt_native_task_request(raw: bytes) -> ChatGPTNativeTaskRequestV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST_BYTES:
            raise ValueError("bounded native request required")
        value = ChatGPTNativeTaskRequestV1.model_validate(
            json.loads(raw, object_pairs_hook=_unique_pairs)
        )
        if _request_bytes(value) != raw:
            raise ValueError("canonical native request required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task request held")
    return result


def prepare_chatgpt_native_task_request(
    prepared: PreparedChatGPTNativeContext,
) -> ChatGPTNativeTaskRequestV1:
    result = None
    try:
        if type(prepared) is not PreparedChatGPTNativeContext:
            raise TypeError("exact native preparation required")
        value = ChatGPTNativeTaskRequestV1(
            profile=prepared.profile,
            route=prepared.route,
            selected_literal=prepared.selected_text,
            wire_json=prepared.body.decode("utf-8"),
            wire_digest=prepared.body_digest,
        )
        rebuilt = value.preparation()
        if rebuilt.context != prepared.context or rebuilt._catalog != prepared._catalog:
            raise ValueError("exact full preparation graph required")
        _request_bytes(value)
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task request held")
    return result


def native_task_references(request: ChatGPTNativeTaskRequestV1) -> tuple[EvidenceReference, ...]:
    result = None
    try:
        request = decode_chatgpt_native_task_request(_request_bytes(request))
        p = request.profile
        refs = (
            *p.original_task.event.provenance,
            *(item.reference for item in p.original_task.context),
            p.current_original_reference,
            p.current_companion_reference,
        )
        unique: dict[UUID, EvidenceReference] = {}
        for reference in refs:
            prior = unique.setdefault(reference.source_id, reference)
            if prior != reference:
                raise ValueError("native task reference conflict")
        result = tuple(sorted(unique.values(), key=lambda r: str(r.source_id)))
    except Exception:  # noqa: BLE001,S110 - no private model/error cause escapes.
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task references held")
    return result


def load_chatgpt_native_task_request(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    expected_request: ChatGPTNativeTaskRequestV1,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> ChatGPTNativeTaskRequestV1:
    """Current whole request union BEFORE pair bytes, then actual reconstruction.

    Caller-owned read transaction; no owner lease, capture, commit or permission.
    Original task text is host comparison data: current reference checks do not
    authenticate its arbitrary prose. Pair literal is read from actual artifacts.
    """
    result = None
    try:
        expected = decode_chatgpt_native_task_request(_request_bytes(expected_request))
        refs = native_task_references(expected)
        entry = _physical(session)
        before = _fragment_rows(session, refs, authorized_boundaries, allowed_classifications)
        _same(session, entry)
        p = expected.profile
        loaded = load_chatgpt_native_view_pair(
            session,
            artifacts=artifacts,
            capture_id=p.capture_id,
            original_reference=p.current_original_reference,
            companion_reference=p.current_companion_reference,
            expected_companion=p.companion,
            authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications,
        )
        _same(session, entry)
        original = ReviewContext(
            p.original_task, p.original_meeting_source_id, p.original_related_source_ids
        )
        actual = prepare_chatgpt_native_task_request(
            prepare_chatgpt_native_context(
                original, loaded, capture_id=p.capture_id, route=expected.route
            )
        )
        if _request_bytes(actual) != _request_bytes(expected):
            raise ValueError("actual native request changed")
        if _fragment_rows(session, refs, authorized_boundaries, allowed_classifications) != before:
            raise ValueError("current full native union changed")
        _same(session, entry)
        result = actual
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("current native task unavailable")
    return result


class ChatGPTNativeCounterProfileV1(Contract):
    format: Literal["zac-chatgpt-native-contextual-counter-v1"] = (
        "zac-chatgpt-native-contextual-counter-v1"
    )
    model_digest: Digest
    tokenizer_digest: Digest
    renderer_digest: Digest
    measured_prompt_tokens: int = Field(gt=0, strict=True)
    requested_output_tokens: int = Field(gt=0, strict=True)
    context_tokens: Literal[8192, 16384]

    @model_validator(mode="after")
    def bounded_count(self) -> Self:
        if self.measured_prompt_tokens + self.requested_output_tokens > self.context_tokens:
            raise ValueError("actual complete prompt/output capacity required")
        return self


def _counter_profile(
    counter: OllamaQwenContextualTokenCounter,
    request: ChatGPTNativeTaskRequestV1,
    expected_model_digest: str,
) -> ChatGPTNativeCounterProfileV1:
    from zacai.intelligence import ollama_token_counter as actual

    if type(counter) is not OllamaQwenContextualTokenCounter:
        raise TypeError("exact actual contextual counter required")
    body = request.wire_json.encode("utf-8")
    # Independent configured manifest pin checked before count/file reads.
    import re

    if (
        type(expected_model_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_model_digest) is None
        or counter.model_digest != expected_model_digest
        or json.loads(body)["model"] != request.route.identity.model_id
        or request.route.identity.model_id != actual._MODEL
    ):
        raise ValueError("actual configured counter/model/wire binding required")
    count = counter.count_prompt_tokens(
        body
    )  # real full render/tokenizer/file rehash, no runtime HTTP
    if type(count) is not int or count <= 0:
        raise ValueError("exact actual count required")
    tokenizer = content_hash_of(
        canonical_bytes(
            {
                "model_manifest": counter.model_digest,
                "blobs": sorted((digest, limit) for _, digest, limit in counter._files),
                "tokenizers_version": version("tokenizers"),
                "add_special_tokens": False,
                "padding": False,
                "truncation": False,
            }
        )
    )
    renderer = hashlib.sha256(Path(actual.__file__).read_bytes()).hexdigest()
    return ChatGPTNativeCounterProfileV1(
        model_digest=counter.model_digest,
        tokenizer_digest=tokenizer,
        renderer_digest=renderer,
        measured_prompt_tokens=count,
        requested_output_tokens=json.loads(body)["options"]["num_predict"],
        context_tokens=json.loads(body)["options"]["num_ctx"],
    )


class ChatGPTNativeTaskDeclarationV1(Contract):
    format: Literal["zac-personal-chatgpt-native-task-declaration-v1"] = (
        "zac-personal-chatgpt-native-task-declaration-v1"
    )
    id: UUID
    builder_id: UUID
    request_json: str = Field(strict=True, min_length=1, max_length=MAX_REQUEST_BYTES, repr=False)
    request_digest: Digest
    wire_digest: Digest
    counter: ChatGPTNativeCounterProfileV1
    actor_issuer: str = Field(strict=True, min_length=1, max_length=255, repr=False)
    actor_subject: str = Field(strict=True, min_length=1, max_length=255, repr=False)
    original_session_binding: Digest
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    prepared_at: AwareDatetime
    expires_at: AwareDatetime
    processing_authorized: Literal[False] = False
    reviewer_ready: Literal[False] = False
    runtime_ready: Literal[False] = False

    @field_validator("processing_authorized", "reviewer_ready", "runtime_ready", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("preparation is not permission/readiness")
        return value

    @model_validator(mode="after")
    def exact_declaration(self) -> Self:
        raw = self.request_json.encode("utf-8")
        request = decode_chatgpt_native_task_request(raw)
        task = request.profile.original_task
        refs = native_task_references(request)
        if (
            any(v.int == 0 for v in (self.id, self.builder_id))
            or task.event.trust_boundary is not B.PERSONAL
            or not request.route.available
            or not task.required_capabilities <= request.route.capabilities
            or request.route.estimated_latency_ms > task.max_latency_ms
            or request.route.estimated_cost_usd > task.max_estimated_cost_usd
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or self.request_digest != content_hash_of(raw)
            or self.wire_digest != request.wire_digest
            or self.counter.requested_output_tokens
            != json.loads(request.wire_json)["options"]["num_predict"]
            or self.counter.requested_output_tokens > task.max_output_tokens
            or self.counter.requested_output_tokens > request.route.max_output_tokens
            or self.counter.context_tokens != json.loads(request.wire_json)["options"]["num_ctx"]
            or not self.original_session_issued_at
            <= self.prepared_at
            < self.expires_at
            <= self.original_session_expires_at
            or self.expires_at > self.prepared_at + timedelta(milliseconds=task.max_latency_ms)
            or request.profile.source_captured_at[1] > self.prepared_at
            or any(
                v is not False
                for v in (self.processing_authorized, self.reviewer_ready, self.runtime_ready)
            )
        ):
            raise ValueError("exact original native preparation window required")
        return self


def prepare_chatgpt_native_task_declaration(
    *,
    request: ChatGPTNativeTaskRequestV1,
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    counter: OllamaQwenContextualTokenCounter,
    expected_model_digest: str,
    declaration_id: UUID,
    builder_id: UUID,
    expires_at: AwareDatetime,
) -> ChatGPTNativeTaskDeclarationV1:
    """Actual signed current-owner/count observation, no browser action/admission.

    Caller must first use actual canonical reconstruction/current recovery. This
    pure declaration producer does not counterfeit that proof or issue permission.
    Runtime metadata/readiness and independent review implementation are absent.
    """
    result = None
    try:
        _host(inputs, operation)
        inputs.clock()
        current = operation.establish()
        with inputs.clock._lock:
            at = inputs.clock._last
        if at is None:
            raise ValueError("actual original time required")
        stable = decode_chatgpt_native_task_request(_request_bytes(request))
        for ref in native_task_references(stable):
            _scope(current, ref)
        profile = _counter_profile(counter, stable, expected_model_digest)
        _host(inputs, operation)
        inputs.clock()
        final = operation.recheck(current.binding_digest)
        with inputs.clock._lock:
            now = inputs.clock._last
        if final != current or now is None or not at <= now < expires_at:
            raise ValueError("unchanged current owner/window required")
        result = ChatGPTNativeTaskDeclarationV1(
            id=declaration_id,
            builder_id=builder_id,
            request_json=_request_bytes(stable).decode(),
            request_digest=content_hash_of(_request_bytes(stable)),
            wire_digest=stable.wire_digest,
            counter=profile,
            actor_issuer=current.principal.identity.issuer,
            actor_subject=current.principal.identity.subject,
            original_session_binding=current.binding_digest,
            original_session_issued_at=current.issued_at,
            original_session_expires_at=current.effective_expires_at,
            prepared_at=at,
            expires_at=expires_at,
        )
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task declaration held")
    return result


def encode_chatgpt_native_task_declaration(value: ChatGPTNativeTaskDeclarationV1) -> bytes:
    result = None
    try:
        if type(value) is not ChatGPTNativeTaskDeclarationV1:
            raise TypeError("exact native declaration required")
        raw = canonical_bytes(
            ChatGPTNativeTaskDeclarationV1.model_validate(value.model_dump(mode="json")).model_dump(
                mode="json"
            )
        )
        if not 0 < len(raw) <= MAX_REQUEST_BYTES + 16_000:
            raise ValueError("bounded declaration required")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task declaration held")
    return result


def decode_chatgpt_native_task_declaration(raw: bytes) -> ChatGPTNativeTaskDeclarationV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST_BYTES + 16_000:
            raise ValueError("bounded declaration required")
        value = ChatGPTNativeTaskDeclarationV1.model_validate(
            json.loads(raw, object_pairs_hook=_unique_pairs)
        )
        if encode_chatgpt_native_task_declaration(value) != raw:
            raise ValueError("canonical declaration required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ChatGPTNativeTaskError("native task declaration held")
    return result
