"""D034AF explicit contextual loopback adapter, never an authorization or enabled service.

Shares the existing benchmark wire protocol. Trusted host construction only;
call through the review host with actual authorization/protection adapters.
No configurable endpoint, proxy, redirects, model pulls, tools or fallback.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import UUID, uuid4

from zacai.intelligence.contextual_generation import (
    ContextualDraft,
    ContextualRequest,
    ContextualRequestV2,
    _prepare_contextual_catalog,
    _require_legacy_context,
    parse_contextual_draft,
    prepare_contextual_request,
    validate_native_contextual_request,
)
from zacai.intelligence.contextual_review import ContextualReview
from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.local_review_runtime import (
    LocalPromptTokenCounter,
    Transport,
    _http,
    verify_model,
)
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_generation import prepare_review_request
from zacai.intelligence.runtime_diagnostics import RuntimeDiagnosticError, closed_runtime_code
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F
from zacai.policy import Destination

if TYPE_CHECKING:
    from zacai.intelligence.history_fragment_contextual_codec import (
        HistoryFragmentContextualRequestV1,
    )
    from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

_CONTEXT_TOKENS = 8192


def _context_tokens(route: ModelRoute) -> int:
    # Explicit host profile, bound by consent route identity. Default stays unchanged.
    if route.identity.runtime_id == "mac-loopback-contextual-16k":
        if route.identity.model_id != "qwen3.8:27b-mlx":
            raise LocalContextualRuntimeError("unsupported contextual profile model")
        return 16384
    return _CONTEXT_TOKENS


class LocalContextualRuntimeError(RuntimeDiagnosticError):
    """Fixed diagnostics; no backend/input/output text."""


def _raise_interruption(kind: type[BaseException] | None, exit_code: int) -> None:
    if kind is not None:
        if issubclass(kind, KeyboardInterrupt):
            raise KeyboardInterrupt
        if issubclass(kind, SystemExit):
            raise SystemExit(exit_code)
        if issubclass(kind, asyncio.CancelledError):
            raise asyncio.CancelledError


def prepare_payload(request: ContextualRequest, route: ModelRoute, digest: str) -> bytes:
    if type(request) is not ContextualRequest or request != prepare_contextual_request(request.context):
        raise LocalContextualRuntimeError("modified legacy request")
    return _prepare_payload_body(request, route, digest)


def _prepare_payload_body(request: ContextualRequest, route: ModelRoute, digest: str) -> bytes:
    """Verify host-derived catalog and complete serialized character/byte limits.

    The adapter separately checks exact tokenizer capacity before dispatch and
    compares reported usage afterward; this serializer alone does neither.
    """
    if type(request) is not ContextualRequest:
        raise LocalContextualRuntimeError("unsupported contextual request family")
    if request != _prepare_contextual_catalog(request.context):
        raise LocalContextualRuntimeError("modified review request")
    name = route.identity.model_id
    if (
        "contextual_meeting_review" not in route.capabilities
        or "compact_meeting_review" in route.capabilities
        or route.destination != Destination.LOCAL
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", name)
        or name.endswith(":cloud")
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or request.context.task.max_output_tokens > route.max_output_tokens
    ):
        raise LocalContextualRuntimeError("invalid local route or pin")
    schema = json.loads(request.schema_json)
    body = json.dumps(
        {
            "model": name,
            "stream": False,
            "think": False,
            "truncate": False,
            "shift": False,
            "keep_alive": 0,
            "format": schema,
            "messages": [
                {
                    "role": "system",
                    "content": request.instruction + "\nOutput JSON schema: " + request.schema_json,
                },
                {"role": "user", "content": request.evidence_json.replace("<", "\\u003c")},
            ],
            "options": {
                "temperature": 0,
                "num_predict": request.context.task.max_output_tokens,
                "num_ctx": _context_tokens(route),
            },
        },
        ensure_ascii=False,
    ).encode()
    if len(body.decode()) > route.max_input_characters or len(body) > 64_000:
        raise LocalContextualRuntimeError("serialized request outside capacity")
    return body


def dispatch_draft(
    request: ContextualRequest, route: ModelRoute, body: bytes, transport: Transport
) -> tuple[ContextualDraft, UsageObservation]:
    failure = F.REQUEST_PAYLOAD
    try:
        if type(request) is not ContextualRequest:
            raise ValueError("unsupported contextual request family")
        _require_legacy_context(request.context)
        wire = json.loads(body)
        for message in wire["messages"]:
            if message.get("role") == "user":
                data = json.loads(message["content"])
                if (
                    isinstance(data, dict)
                    and data.get("format") == "zac-native-contextual-request-v2"
                ):
                    raise ValueError("native contextual dispatch not enabled")
        failure = F.TRANSPORT
        started = time.perf_counter()
        reply = transport("POST", "/api/chat", body)
        elapsed = (time.perf_counter() - started) * 1000
        failure = F.RESPONSE_SHAPE
        if not isinstance(reply, dict):
            raise TypeError("invalid reply shape")
        failure = F.RESPONSE_MODEL
        if reply.get("model") != route.identity.model_id:
            raise ValueError("model mismatch")
        failure = F.RESPONSE_INCOMPLETE
        if reply.get("done") is not True:
            raise ValueError("incomplete reply")
        failure = F.RESPONSE_SHAPE
        message = reply["message"]
        if not isinstance(message, dict):
            raise TypeError("invalid message shape")
        failure = F.RESPONSE_AUTHORITY
        if (
            message.get("role") != "assistant"
            or message.get("tool_calls")
            or message.get("thinking")
        ):
            raise ValueError("unexpected response authority")
        if reply.get("done_reason") == "length":
            failure = F.RESPONSE_USAGE
            reported = (reply["prompt_eval_count"], reply["eval_count"])
            if (
                any(type(n) is not int or n < 0 for n in reported)
                or reported[1] > request.context.task.max_output_tokens
                or reported[0] + reported[1] > _context_tokens(route)
            ):
                raise ValueError("invalid usage")
            failure = (
                F.OUTPUT_LIMIT
                if reported[1] == request.context.task.max_output_tokens
                and sum(reported) < _context_tokens(route)
                else F.RESPONSE_LENGTH
            )
            raise ValueError("length completion")
        failure = F.RESPONSE_STOP_REASON
        if reply.get("done_reason") != "stop":
            raise ValueError("nonstop completion")
        failure = F.RESPONSE_LATENCY
        if not 0 <= elapsed <= request.context.task.max_latency_ms:
            raise ValueError("late response")
        failure = F.RESPONSE_USAGE
        counts = (reply["prompt_eval_count"], reply["eval_count"])
        if (
            any(type(count) is not int or count < 0 for count in counts)
            or counts[1] > request.context.task.max_output_tokens
            or counts[0] + counts[1] > _context_tokens(route)
        ):
            raise ValueError("invalid usage")
        failure = F.RESPONSE_SCHEMA
        content = message["content"]
        if not isinstance(content, str):
            raise TypeError("invalid content shape")
        draft = parse_contextual_draft(content.encode())
        return draft, UsageObservation(
            input_tokens=counts[0], output_tokens=counts[1], latency_ms=elapsed, cost_usd=0.0
        )
    except Exception:  # noqa: BLE001, S110 - no raw backend/model diagnostics
        pass
    raise LocalContextualRuntimeError("local contextual response rejected", code=failure)


_INNER_CODES = {
    F.TOKEN_COUNT: frozenset({F.MODEL_PIN, F.TOKEN_COUNT, F.TOKEN_CAPACITY}),
    F.TRANSPORT: frozenset(
        code
        for code in F
        if code == F.TRANSPORT or code == F.OUTPUT_LIMIT or code.value.startswith("RESPONSE_")
    ),
}


class LocalContextualRuntime:
    """One-attempt, host-owned adapter; constructing it grants no permission.

    Synchronous single-owner instance: never share across concurrent callers.
    Error reporters must disable local-variable capture for private inputs.

    Preflight sends only model name metadata, never evidence. It binds the exact
    prepared payload and exact local tokenizer count; generation requires that
    preflight, rechecks model metadata
    before/after one chat call, then consumes the instance even on failure.
    Fixed socket timeouts and late-output rejection are not a process kill deadline.
    Metadata is trusted runtime reporting, not proof against a malicious host.
    """

    def __init__(
        self,
        *,
        route: ModelRoute,
        model_digest: str,
        token_counter: LocalPromptTokenCounter,
    ) -> None:
        self._route = ModelRoute.model_validate(route)
        if not re.fullmatch(r"[0-9a-f]{64}", model_digest):
            raise LocalContextualRuntimeError("invalid local runtime configuration")
        if self._route.destination != Destination.LOCAL:
            raise LocalContextualRuntimeError("invalid local runtime configuration")
        self._model_digest = model_digest
        self._token_counter = token_counter
        self._prepared: bytes | None = None
        self._attempted = False
        self._usage: UsageObservation | None = None

    @property
    def route(self) -> ModelRoute:
        return self._route

    @property
    def model_digest(self) -> str:
        return self._model_digest

    @property
    def usage(self) -> UsageObservation | None:
        return self._usage

    def _token_count(self, body: bytes, request: ContextualRequest) -> int:
        if self._token_counter.model_digest != self.model_digest:
            raise LocalContextualRuntimeError("tokenizer model pin mismatch", code=F.MODEL_PIN)
        count = self._token_counter.count_prompt_tokens(body)
        if type(count) is not int or count <= 0:
            raise LocalContextualRuntimeError("invalid token count", code=F.TOKEN_COUNT)
        if count + request.context.task.max_output_tokens > _context_tokens(self.route):
            raise LocalContextualRuntimeError(
                "prompt/output token budget exceeded", code=F.TOKEN_CAPACITY
            )
        return count

    def preflight(self, request: ContextualRequest) -> None:
        interruption = None
        exit_code = 1
        failure = F.PREFLIGHT_BINDING
        try:
            if self._attempted:
                raise ValueError("attempt consumed")
            # Never retain a successful stale preflight after a failed new one.
            self._prepared = None
            failure = F.REQUEST_PAYLOAD
            body = prepare_payload(request, self.route, self.model_digest)
            failure = F.TOKEN_COUNT
            count = self._token_count(body, request)
            failure = F.RUNTIME_VERSION
            self._token_counter.verify_runtime()
            failure = F.MODEL_PIN
            verify_model(self.route.identity.model_id, self.model_digest, _http)
            # Include exact context/task identity as well as serialized messages.
            self._prepared = hashlib.sha256(
                body + review_context_digest(request.context).encode() + str(count).encode()
            ).digest()
            return
        except BaseException as error:  # noqa: BLE001 - sanitize interruption diagnostics too
            code = closed_runtime_code(error)
            if code in _INNER_CODES.get(failure, frozenset()):
                failure = code
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        raise LocalContextualRuntimeError("local contextual preflight failed", code=failure)

    def generate(self, request: ContextualRequest) -> ContextualDraft:
        interruption = None
        exit_code = 1
        failure = F.PREFLIGHT_BINDING
        try:
            started = time.perf_counter()
            self._usage = None
            if self._attempted:
                raise ValueError("attempt consumed")
            self._attempted = True
            failure = F.REQUEST_PAYLOAD
            body = prepare_payload(request, self.route, self.model_digest)
            failure = F.TOKEN_COUNT
            count = self._token_count(body, request)
            failure = F.PREFLIGHT_BINDING
            expected = hashlib.sha256(
                body + review_context_digest(request.context).encode() + str(count).encode()
            ).digest()
            if self._prepared is None or self._prepared != expected:
                raise ValueError("preflight missing or changed")
            failure = F.RUNTIME_VERSION
            self._token_counter.verify_runtime()
            failure = F.MODEL_PIN
            verify_model(self.route.identity.model_id, self.model_digest, _http)
            failure = F.TRANSPORT
            draft, usage = dispatch_draft(request, self.route, body, _http)
            failure = F.POST_RUNTIME_VERSION
            self._token_counter.verify_runtime()
            failure = F.POST_MODEL_PIN
            verify_model(self.route.identity.model_id, self.model_digest, _http)
            failure = F.PROMPT_COUNT_MISMATCH
            if usage.input_tokens != count:
                raise ValueError("runtime prompt usage disagrees with tokenizer")
            failure = F.TOTAL_LATENCY
            elapsed = (time.perf_counter() - started) * 1000
            if not 0 <= elapsed <= request.context.task.max_latency_ms:
                raise ValueError("late adapter output")
            self._usage = usage.model_copy(update={"latency_ms": elapsed})
            return draft
        except BaseException as error:  # noqa: BLE001 - sanitize interruption diagnostics too
            code = closed_runtime_code(error)
            if code in _INNER_CODES.get(failure, frozenset()):
                failure = code
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        raise LocalContextualRuntimeError("local contextual generation failed", code=failure)


def _prepare_native_payload(request: ContextualRequestV2, route: ModelRoute, digest: str) -> bytes:
    """Pure byte/character capacity ONLY; actual tokenizer/dispatch not enabled."""
    validate_native_contextual_request(request)
    legacy = _prepare_contextual_catalog(request.context)
    if request.schema_json != legacy.schema_json:
        raise ValueError("native catalog grammar differs")
    body = json.loads(_prepare_payload_body(legacy, route, digest))
    body["messages"][0]["content"] = (
        request.instruction + "\nOutput JSON schema: " + request.schema_json
    )
    body["messages"][1]["content"] = json.dumps(
        {
            "format": request.format,
            "provider_passages": json.loads(request.evidence_json),
            "untrusted_noncitable_metadata": _model_native_metadata(request),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).replace("<", "\\u003c")
    raw = json.dumps(body, ensure_ascii=False).encode()
    if len(raw.decode()) > route.max_input_characters or len(raw) > 64000:
        raise LocalContextualRuntimeError("serialized native request outside capacity")
    return raw


def _model_native_metadata(request: ContextualRequestV2) -> dict[str, object]:
    # Map the actual unfiltered quote catalog, including noncitable passages.
    # Retained Source/hash/role metadata is not copied into model-visible data.
    catalog = prepare_review_request(request.context)
    namespace = review_context_digest(request.context)[:32]
    visible_ids = {p["id"] for p in json.loads(request.evidence_json)}
    entries: list[dict[str, object]] = []
    for entry in request.sidecar.entries:
        ids = [
            f"{namespace}:{'meeting' if quote.source_id == request.context.meeting_source_id else 'related'}:{eid}"
            for eid, quote in catalog.quotes
            if quote.source_id == entry.reference.source_id
        ]
        if not ids or any(eid not in visible_ids for eid in ids):
            raise ValueError("native metadata passage mapping differs")
        # Explicit model-visible contract: future retained fields stay private.
        raw = entry.model_dump(mode="json")
        data = {key: raw[key] for key in (
            "source_system", "field", "source_span", "field_length_codepoints",
            "omitted_before_codepoints", "omitted_after_codepoints",
            "provider_occurred_at", "source_captured_at", "batch_observed_at",
            "projection_observed_at", "relevance_reason", "relevance_origin",
            "supersession_status", "untrusted", "citable", "project_link",
            "current_fact", "authorship_verified", "sent_approval_verified",
        )}
        data["passage_ids"] = ids
        entries.append(data)
    return {"format": request.sidecar.format, "entries": entries}


def prepare_native_payload(request: ContextualRequestV2, route: ModelRoute, digest: str) -> bytes:
    """Pure fullbody serializer for future tokenizer; no dispatch or token-fit grant."""
    try:
        return _prepare_native_payload(request, route, digest)
    except Exception:  # noqa: BLE001,S110 - no private request/metadata causes
        pass
    raise LocalContextualRuntimeError(
        "native contextual request unavailable or invalid", code=F.REQUEST_PAYLOAD
    )


class NativeLocalContextualRuntimeError(LocalContextualRuntimeError):
    """Fixed phase diagnostic plus honest local POST-attempt observation."""
    def __init__(self, message: str, *, code: F = F.UNSPECIFIED,
                 did_transport_attempt: bool = False) -> None:
        if type(did_transport_attempt) is not bool:
            raise TypeError("exact transport observation required")
        self.did_transport_attempt = did_transport_attempt
        super().__init__(message, code=code)


@dataclass(frozen=True, slots=True)
class NativeContextualDispatchDescriptor:
    """Exact compatibility inputs to a real host gate; never permission itself."""
    body: bytes = field(repr=False)
    body_digest: str
    retained_request_digest: str
    prompt_tokens: int
    route_json: str
    model_digest: str
    tokenizer_digest: str
    runtime_digest: str
    template_digest: str
    renderer_digest: str


_NATIVE_PHASE_CODES = {
    F.REQUEST_PAYLOAD: frozenset({F.REQUEST_PAYLOAD}),
    F.TOKEN_COUNT: frozenset({F.TOKEN_COUNT, F.TOKEN_CAPACITY, F.MODEL_PIN}),
    F.MODEL_PIN: frozenset({F.MODEL_PIN}),
    F.TRANSPORT: frozenset({F.TRANSPORT}),
    F.RESPONSE_SHAPE: frozenset(code for code in F if code.value.startswith("RESPONSE_")
        or code in {F.OUTPUT_LIMIT, F.PROMPT_COUNT_MISMATCH}),
}


def _native_phase_failure(error: BaseException, phase: F) -> F:
    inner = closed_runtime_code(error)
    return inner if inner in _NATIVE_PHASE_CODES.get(phase, frozenset()) else phase


class NativeContextualDispatchGate(Protocol):
    """Host-owned canonical admission/claim/access check, never schema permission.

    Implementations must finish original current-owner/session, exact request and
    canonical ACL/cancellation checks after metadata/tokenizer callbacks. This
    protocol is an integration requirement, not an authenticated implementation.
    """

    def before_dispatch(self, request: ContextualRequestV2,
                        descriptor: NativeContextualDispatchDescriptor) -> object:
        raise NotImplementedError


class NativeContextualTokenCounter(Protocol):
    """Count complete rendered prompt, not JSON request wrapper tokens.

    Input is the complete model body. Count all actual messages, native metadata,
    schema and model chat-template tokens exactly as the runtime renders them.
    Renderer/template identities must come from the exact approved host profile.
    """
    @property
    def template_digest(self) -> str:
        raise NotImplementedError

    @property
    def renderer_digest(self) -> str:
        raise NotImplementedError

    @property
    def model_digest(self) -> str:
        raise NotImplementedError

    def count_prompt_tokens(self, serialized_body: bytes) -> int:
        raise NotImplementedError

    def verify_runtime(self) -> object:
        raise NotImplementedError

    @property
    def tokenizer_digest(self) -> str:
        raise NotImplementedError


def native_contextual_runtime_digest() -> str:
    """Prospective implementation pin; no runtime or owner permission proof."""
    from pathlib import Path

    from zacai import policy, state
    from zacai.ingestion import artifact_store
    from zacai.intelligence import (
        contextual_diagnostics,
        contextual_generation,
        contextual_review,
        contracts,
        local_review_runtime,
        meeting_review,
        native_context_metadata,
        review_evaluation,
        review_generation,
        runtime_diagnostics,
    )
    modules = (contextual_generation, native_context_metadata, contracts, local_review_runtime,
        review_generation, review_evaluation, contextual_review, meeting_review,
        runtime_diagnostics, contextual_diagnostics, artifact_store, policy, state)
    files = [(Path(__file__).name, Path(__file__).read_bytes())]
    for module in modules:
        file = module.__file__
        if type(file) is not str:
            raise LocalContextualRuntimeError("native implementation path unavailable")
        files.append((Path(file).name, Path(file).read_bytes()))
    return hashlib.sha256(b"zac-native-contextual-runtime-v1\0" + b"".join(
        name.encode() + b"\0" + hashlib.sha256(raw).digest() for name, raw in files
    )).hexdigest()


def _canonical_native_route(route: ModelRoute) -> str:
    """Stable dispatch profile bytes across processes, never route permission."""
    from zacai.ingestion.artifact_store import canonical_bytes

    data = route.model_dump(mode="json")
    data["capabilities"] = sorted(route.capabilities)
    return canonical_bytes(data).decode("utf-8")


class NativeLocalContextualRuntime:
    """Dormant explicit V2 adapter: one instance attempt, no host activation.

    A valid gate implementation/constructor is not a human approval or canonical
    claim. Active host wiring must supply the actual exact V2 authority graph.
    No default gate or token counter exists. Error reporters must disable local-variable
    capture for private inputs. Fixed HTTP timeouts bound individual
    calls; original total latency rejects late results, not a process kill.
    """

    def __init__(self, *, route: ModelRoute, model_digest: str,
                 tokenizer_digest: str, runtime_digest: str,
                 template_digest: str, renderer_digest: str,
                 token_counter: NativeContextualTokenCounter,
                 dispatch_gate: NativeContextualDispatchGate) -> None:
        try:
            self._route = ModelRoute.model_validate(route)
            if any(type(pin) is not str or re.fullmatch(r"[0-9a-f]{64}", pin) is None
                   for pin in (model_digest, tokenizer_digest, runtime_digest,
                               template_digest, renderer_digest)):
                raise ValueError("native configuration pins differ")
            if runtime_digest != native_contextual_runtime_digest() or self._route.destination != Destination.LOCAL:
                raise ValueError("native configuration differs")
            self._model_digest = model_digest
            self._tokenizer_digest = tokenizer_digest
            self._runtime_digest = runtime_digest
            self._template_digest = template_digest
            self._renderer_digest = renderer_digest
            self._route_snapshot = _canonical_native_route(self._route)
            self._token_counter = token_counter
            self._dispatch_gate = dispatch_gate
            self._prepared: tuple[ContextualRequestV2, bytes, bytes, int] | None = None
            self._attempted = False
            self._did_transport_attempt = False
            self._usage: UsageObservation | None = None
            self._lock = threading.Lock()
            return
        except Exception:  # noqa: BLE001,S110 - configuration/input diagnostics stay private
            pass
        raise NativeLocalContextualRuntimeError("invalid native runtime configuration")

    @property
    def route(self) -> ModelRoute:
        return self._route

    @property
    def usage(self) -> UsageObservation | None:
        return self._usage

    @property
    def did_transport_attempt(self) -> bool:
        return self._did_transport_attempt

    def _pins(self) -> None:
        actual = (self._token_counter.model_digest, self._token_counter.tokenizer_digest,
            self._token_counter.template_digest, self._token_counter.renderer_digest,
            native_contextual_runtime_digest())
        expected = (self._model_digest, self._tokenizer_digest, self._template_digest,
            self._renderer_digest, self._runtime_digest)
        if any(type(value) is not str or value != pin for value,pin in zip(actual,expected,strict=True)):
            raise LocalContextualRuntimeError("native implementation pin differs", code=F.MODEL_PIN)

    def _count(self, body: bytes, request: ContextualRequestV2) -> int:
        self._pins()
        value = self._token_counter.count_prompt_tokens(body)
        self._pins()
        if type(value) is not int or value <= 0:
            raise LocalContextualRuntimeError("invalid native token count", code=F.TOKEN_COUNT)
        if value + request.context.task.max_output_tokens > _context_tokens(self._route):
            raise LocalContextualRuntimeError("native token capacity exceeded", code=F.TOKEN_CAPACITY)
        return value

    def _bytes(self, request: ContextualRequestV2) -> tuple[bytes, bytes]:
        from zacai.intelligence.contextual_generation import encode_native_contextual_request
        if _canonical_native_route(self._route) != self._route_snapshot:
            raise LocalContextualRuntimeError("native route changed", code=F.MODEL_PIN)
        return (prepare_native_payload(request, self._route, self._model_digest),
                encode_native_contextual_request(request))

    def preflight_native(self, request: ContextualRequestV2) -> None:
        if not self._lock.acquire(blocking=False):
            raise NativeLocalContextualRuntimeError("native instance busy", code=F.PREFLIGHT_BINDING)
        failure = F.PREFLIGHT_BINDING
        try:
            if self._attempted or self._prepared is not None:
                raise LocalContextualRuntimeError("native preflight consumed", code=F.PREFLIGHT_BINDING)
            failure = F.REQUEST_PAYLOAD
            body, retained = self._bytes(request)
            failure = F.TOKEN_COUNT
            count = self._count(body, request)
            failure = F.RUNTIME_VERSION
            if self._token_counter.verify_runtime() is not None:
                raise ValueError("native runtime acknowledgement differs")
            failure = F.MODEL_PIN
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            self._pins()
            failure = F.REQUEST_PAYLOAD
            if self._bytes(request) != (body, retained):
                raise LocalContextualRuntimeError("native request changed", code=F.REQUEST_PAYLOAD)
            self._prepared = (request, body, retained, count)
        except BaseException as error:  # noqa: BLE001 - never retain private exception causes
            self._prepared = None
            self._attempted = True
            kind = type(error)
            exit_code = error.code if isinstance(error, SystemExit) and type(error.code) is int else 1
            failure = _native_phase_failure(error, failure)
        else:
            return
        finally:
            self._lock.release()
        _raise_interruption(kind, exit_code)
        raise NativeLocalContextualRuntimeError("native contextual preflight failed", code=failure)

    def generate_native(self, request: ContextualRequestV2) -> ContextualDraft:
        if not self._lock.acquire(blocking=False):
            raise NativeLocalContextualRuntimeError("native attempt unavailable", code=F.PREFLIGHT_BINDING)
        try:
            if self._attempted:
                raise NativeLocalContextualRuntimeError("native attempt consumed", code=F.PREFLIGHT_BINDING)
            self._usage = None
            self._attempted = True
            prepared = self._prepared
            self._prepared = None
        finally:
            self._lock.release()
        failure = F.PREFLIGHT_BINDING
        did_transport_attempt = False
        try:
            started = time.perf_counter()
            if prepared is None or prepared[0] is not request:
                raise ValueError("original preflight required")
            failure = F.REQUEST_PAYLOAD
            body, retained = self._bytes(request)
            if (body, retained) != prepared[1:3]:
                raise ValueError("native preflight differs")
            failure = F.TOKEN_COUNT
            if self._count(body, request) != prepared[3]:
                raise ValueError("native tokenizer changed")
            failure = F.RUNTIME_VERSION
            if self._token_counter.verify_runtime() is not None:
                raise ValueError("native runtime acknowledgement differs")
            failure = F.MODEL_PIN
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            # Last tokenizer/provider/policy callbacks precede the actual canonical gate.
            failure = F.TOKEN_COUNT
            if self._count(body, request) != prepared[3]:
                raise ValueError("native tokenizer changed")
            failure = F.MODEL_PIN
            self._pins()
            failure = F.REQUEST_PAYLOAD
            if self._bytes(request) != (body, retained):
                raise ValueError("native request changed before gate")
            descriptor = NativeContextualDispatchDescriptor(body=body,body_digest=hashlib.sha256(body).hexdigest(),
                retained_request_digest=hashlib.sha256(retained).hexdigest(),prompt_tokens=prepared[3],
                route_json=self._route_snapshot,model_digest=self._model_digest,tokenizer_digest=self._tokenizer_digest,
                runtime_digest=self._runtime_digest,template_digest=self._template_digest,renderer_digest=self._renderer_digest)
            failure = F.TOTAL_LATENCY
            if not 0 <= (time.perf_counter()-started)*1000 <= request.context.task.max_latency_ms:
                raise ValueError("native metadata exceeded deadline")
            failure = F.PREFLIGHT_BINDING
            if self._dispatch_gate.before_dispatch(request, descriptor) is not None:
                raise ValueError("native canonical gate did not acknowledge")
            # Pure exact reconstruction and clock only after the canonical gate.
            if self._bytes(request) != (body, retained):
                raise ValueError("native request changed after gate")
            failure = F.TOTAL_LATENCY
            if not 0 <= (time.perf_counter()-started)*1000 <= request.context.task.max_latency_ms:
                raise ValueError("native dispatch exceeded deadline")
            failure = F.TRANSPORT
            did_transport_attempt = True
            self._did_transport_attempt = True
            reply = _http("POST", "/api/chat", body)
            failure = F.RESPONSE_SHAPE
            draft, usage = _parse_native_response(reply, request, self._route,
                (time.perf_counter()-started)*1000, prepared[3])
            failure = F.POST_RUNTIME_VERSION
            if self._token_counter.verify_runtime() is not None:
                raise ValueError("native runtime acknowledgement differs")
            failure = F.POST_MODEL_PIN
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            self._pins()
            failure = F.POST_MODEL_PIN
            if _canonical_native_route(self._route) != self._route_snapshot:
                raise ValueError("native release route changed")
            # Existing audit consumers classify REQUEST_PAYLOAD as preflight.
            # Preserve a post-response code as well as the actual attempt flag.
            failure = F.RESPONSE_AUTHORITY
            if self._bytes(request) != (body, retained):
                raise ValueError("native release request changed")
            failure = F.TOTAL_LATENCY
            elapsed = (time.perf_counter()-started)*1000
            if not 0 <= elapsed <= request.context.task.max_latency_ms:
                raise ValueError("native output exceeded deadline")
            self._usage = UsageObservation.model_validate({**usage.model_dump(),"latency_ms":elapsed})
            return draft
        except BaseException as error:  # noqa: BLE001 - private backend/gate diagnostics stay private
            kind = type(error)
            exit_code = error.code if isinstance(error, SystemExit) and type(error.code) is int else 1
            failure = _native_phase_failure(error, failure)
        _raise_interruption(kind, exit_code)
        raise NativeLocalContextualRuntimeError("native contextual generation failed", code=failure,
            did_transport_attempt=did_transport_attempt)

    # Pure structural resolver only: no instance-origin/display/permission binding.
    def resolve_native(self, draft: ContextualDraft, request: ContextualRequestV2) -> ContextualReview:
        from zacai.intelligence.contextual_generation import resolve_native_contextual_draft
        return resolve_native_contextual_draft(draft, request)


def _parse_native_response(reply: object, request: ContextualRequestV2, route: ModelRoute,
                           elapsed: float, expected_count: int) -> tuple[ContextualDraft, UsageObservation]:
    failure = F.RESPONSE_SHAPE
    try:
        if type(reply) is not dict:
            raise ValueError("native response shape")
        failure = F.RESPONSE_MODEL
        if reply.get("model") != route.identity.model_id:
            raise ValueError("native response model")
        failure = F.RESPONSE_INCOMPLETE
        if reply.get("done") is not True:
            raise ValueError("native response incomplete")
        failure = F.RESPONSE_SHAPE
        message = reply.get("message")
        if type(message) is not dict:
            raise ValueError("native response message shape")
        failure = F.RESPONSE_AUTHORITY
        if message.get("role") != "assistant" or message.get("tool_calls") or message.get("thinking"):
            raise ValueError("native response authority")
        if reply.get("done_reason") == "length":
            failure = F.RESPONSE_USAGE
            length_input = reply.get("prompt_eval_count")
            length_output = reply.get("eval_count")
            if type(length_input) is not int or type(length_output) is not int:
                raise ValueError("native length count type")
            reported = (length_input, length_output)
            if (any(n < 0 for n in reported)
                or reported[1] > request.context.task.max_output_tokens
                or sum(reported) > _context_tokens(route)):
                raise ValueError("native length usage")
            failure = (F.OUTPUT_LIMIT
                if reported[1] == request.context.task.max_output_tokens
                and sum(reported) < _context_tokens(route)
                else F.RESPONSE_LENGTH)
            raise ValueError("native length completion")
        failure = F.RESPONSE_STOP_REASON
        if reply.get("done_reason") != "stop":
            raise ValueError("native response stop")
        failure = F.RESPONSE_USAGE
        input_count = reply.get("prompt_eval_count")
        output_count = reply.get("eval_count")
        if type(input_count) is not int or type(output_count) is not int or input_count < 0 or output_count < 0:
            raise ValueError("native response counts")
        counts = (input_count, output_count)
        if counts[0] != expected_count:
            raise LocalContextualRuntimeError("native prompt count mismatch", code=F.PROMPT_COUNT_MISMATCH)
        if counts[1] > request.context.task.max_output_tokens or sum(counts) > _context_tokens(route):
            raise ValueError("native response capacity")
        failure = F.RESPONSE_LATENCY
        if not 0 <= elapsed <= request.context.task.max_latency_ms:
            raise ValueError("native response latency")
        failure = F.RESPONSE_SCHEMA
        content = message.get("content")
        if type(content) is not str:
            raise ValueError("native response content")
        draft = parse_contextual_draft(content.encode())
        return draft, UsageObservation(input_tokens=counts[0], output_tokens=counts[1], latency_ms=elapsed, cost_usd=0)
    except Exception as error:  # noqa: BLE001 - no model/provider causes escape
        failure = closed_runtime_code(error) or failure
    raise LocalContextualRuntimeError("native contextual response rejected", code=failure)


class FragmentLocalContextualRuntimeError(LocalContextualRuntimeError):
    """Fixed phase diagnostic plus honest local POST-attempt observation."""

    def __init__(
        self, message: str, *, code: F = F.UNSPECIFIED, did_transport_attempt: bool = False
    ) -> None:
        if type(did_transport_attempt) is not bool:
            raise TypeError("exact transport observation required")
        self.did_transport_attempt = did_transport_attempt
        super().__init__(message, code=code)


def fragment_contextual_counter_pins(
    counter: OllamaQwenContextualTokenCounter,
) -> tuple[str, str, str]:
    """Declared concrete tokenizer/template/source pins, never approval or parity proof."""
    from importlib.metadata import version
    from pathlib import Path

    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.intelligence import ollama_token_counter as base
    from zacai.intelligence.native_prompt_counter import _TEMPLATE

    if type(counter) is not base.OllamaQwenContextualTokenCounter:
        raise ValueError("concrete contextual tokenizer required")
    tokenizer = hashlib.sha256(
        b"zac-fragment-tokenizer-v1\0"
        + canonical_bytes(
            {
                "model_manifest": counter.model_digest,
                "blobs": sorted((digest, limit) for _, digest, limit in counter._files),
                "tokenizers_version": version("tokenizers"),
                "add_special_tokens": False,
                "padding": False,
                "truncation": False,
            }
        )
    ).hexdigest()
    template = hashlib.sha256(
        b"zac-fragment-template-v1\0"
        + canonical_bytes(
            {
                "model": base._MODEL,
                "version": base._VERSION,
                "text": _TEMPLATE,
                "trim_space": base._SPACE,
            }
        )
    ).hexdigest()
    files = (
        Path(base.__file__),
        Path(__file__).with_name("local_review_runtime.py"),
        Path(__file__).with_name("native_prompt_counter.py"),
    )
    renderer = hashlib.sha256(
        b"zac-fragment-renderer-v1\0"
        + canonical_bytes(
            {"files": [(f.name, hashlib.sha256(f.read_bytes()).hexdigest()) for f in files]}
        )
    ).hexdigest()
    return tokenizer, template, renderer


def fragment_contextual_runtime_digest() -> str:
    """Prospective implementation inventory only, not a granted model profile."""
    from pathlib import Path

    files = [
        Path(__file__),
        *(
            Path(__file__).with_name(name + ".py")
            for name in (
                "contextual_generation",
                "contextual_evaluation",
                "history_fragment_contextual_codec",
                "history_contextual_codec",
                "history_context_metadata",
                "contextual_review",
                "review_generation",
                "review_evaluation",
                "contracts",
                "ollama_token_counter",
                "native_prompt_counter",
                "local_review_runtime",
                "runtime_diagnostics",
                "contextual_diagnostics",
                "meeting_review",
                "native_context_metadata",
            )
        ),
    ]
    root = Path(__file__).parent.parent
    files += [
        root / name
        for name in (
            "claude_historical_fragment.py",
            "claude_large_original_message.py",
            "claude_original_read.py",
            "claude_original_capture.py",
            "claude_history_index.py",
            "history_manifest.py",
            "claude_custody_selection.py",
            "claude_message_projection.py",
            "policy.py",
            "gateway.py",
            "state.py",
            "ingestion/artifact_store.py",
        )
    ]
    return hashlib.sha256(
        b"zac-fragment-runtime-v1\0"
        + b"".join(
            str(f.relative_to(root)).encode() + b"\0" + hashlib.sha256(f.read_bytes()).digest()
            for f in files
        )
    ).hexdigest()


def _fragment_http_post(body: bytes, remaining_seconds: float) -> object:
    """Literal loopback only, no proxies/redirects/retry; original remaining task budget."""
    import http.client
    import math

    from zacai.intelligence.local_review_runtime import _json

    if not math.isfinite(remaining_seconds) or remaining_seconds <= 0:
        raise ValueError("fragment deadline exhausted")
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=remaining_seconds)
    try:
        connection.request(
            "POST", "/api/chat", body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Encoding", "identity") != "identity"
        ):
            raise ValueError("fragment runtime unavailable")
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("fragment response too large")
        return _json(raw)
    finally:
        connection.close()



def _fragment_verify_runtime(counter: OllamaQwenContextualTokenCounter) -> None:
    # Broad return annotation makes the strict None runtime contract observable
    # even for a replaced trusted callback; no shape is accepted as authority.
    verify: Callable[[], object] = counter.verify_runtime
    if verify() is not None:
        raise ValueError("fragment runtime verification contract differs")


@dataclass(frozen=True, repr=False)
class FragmentContextualDispatchDescriptor:
    """Exact runtime observations for a host gate, never an authority capability."""

    phase: Literal["PRE_DISPATCH", "RELEASE"]
    attempt_id: UUID
    body_digest: str
    retained_request_digest: str
    prompt_tokens: int
    route_json: str
    model_digest: str
    tokenizer_digest: str
    runtime_digest: str
    template_digest: str
    renderer_digest: str
    output_digest: str | None = None
    usage_digest: str | None = None


def _fragment_descriptor(
    phase: Literal["PRE_DISPATCH", "RELEASE"], attempt_id: UUID,
    body: bytes, retained: bytes, count: int,
    configuration: tuple[str, str, str, str, str, str],
    draft: ContextualDraft | None = None, usage: UsageObservation | None = None,
) -> FragmentContextualDispatchDescriptor:
    from zacai.ingestion.artifact_store import canonical_bytes

    if (phase == "RELEASE") != (draft is not None and usage is not None):
        raise ValueError("exact descriptor phase observations required")
    return FragmentContextualDispatchDescriptor(
        phase=phase, attempt_id=attempt_id,
        body_digest=hashlib.sha256(body).hexdigest(),
        retained_request_digest=hashlib.sha256(retained).hexdigest(),
        prompt_tokens=count, route_json=configuration[5],
        model_digest=configuration[0], tokenizer_digest=configuration[1],
        runtime_digest=configuration[2], template_digest=configuration[3],
        renderer_digest=configuration[4],
        output_digest=None if draft is None else hashlib.sha256(
            canonical_bytes(draft.model_dump(mode="json"))).hexdigest(),
        usage_digest=None if usage is None else hashlib.sha256(
            canonical_bytes(usage.model_dump(mode="json"))).hexdigest(),
    )


class FragmentLocalContextualRuntime:
    """Dormant one-fragment LOCAL adapter; one instance attempt, no host activation.

    Construction/counting are not human approval, protected Source access or a canonical
    claim. A future authenticated host must own those gates before calling this adapter.
    No default token counter, host recheck or model profile exists. The mandatory
    callable must be the future host's actual canonical Source/owner/consent/recovery
    recheck. Its return value is not authenticated permission or a proof receipt.
    It runs after external predispatch checks and again after response callbacks;
    only pure retained/configuration reconstruction and a monotonic deadline read
    follow each call. No host or authority is activated here. Error reporters must disable local-variable
    capture for private inputs. The POST uses remaining original task time; metadata uses existing bounded calls.
    Total latency rejects late results, not a process sandbox or hard kill.
    """

    def __init__(
        self,
        *,
        route: ModelRoute,
        model_digest: str,
        tokenizer_digest: str,
        runtime_digest: str,
        template_digest: str,
        renderer_digest: str,
        token_counter: OllamaQwenContextualTokenCounter,
        recheck: Callable[[HistoryFragmentContextualRequestV1, FragmentContextualDispatchDescriptor], None],
    ) -> None:
        from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

        try:
            if not callable(recheck):
                raise TypeError("explicit host recheck required")
            if type(token_counter) is not OllamaQwenContextualTokenCounter:
                raise ValueError("concrete contextual tokenizer required")
            self._route = ModelRoute.model_validate(route)
            if any(
                type(pin) is not str or re.fullmatch(r"[0-9a-f]{64}", pin) is None
                for pin in (
                    model_digest,
                    tokenizer_digest,
                    runtime_digest,
                    template_digest,
                    renderer_digest,
                )
            ):
                raise ValueError("fragment configuration pins differ")
            if (
                runtime_digest != fragment_contextual_runtime_digest()
                or self._route.destination != Destination.LOCAL
                or not self._route.available
            ):
                raise ValueError("fragment configuration differs")
            self._model_digest = model_digest
            self._tokenizer_digest = tokenizer_digest
            self._runtime_digest = runtime_digest
            self._template_digest = template_digest
            self._renderer_digest = renderer_digest
            self._route_snapshot = _canonical_native_route(self._route)
            self._token_counter = token_counter
            self._recheck = recheck
            self._publication_window: tuple[object, float] | None = None
            self._configuration = (model_digest, tokenizer_digest, runtime_digest,
                                   template_digest, renderer_digest, self._route_snapshot)
            self._prepared: tuple[HistoryFragmentContextualRequestV1, bytes, bytes, int] | None = (
                None
            )
            self._attempted = False
            self._did_transport_attempt = False
            self._usage: UsageObservation | None = None
            self._lock = threading.Lock()
            return
        except Exception:  # noqa: BLE001,S110 - configuration/input diagnostics stay private
            pass
        raise FragmentLocalContextualRuntimeError("invalid fragment runtime configuration")

    @property
    def route(self) -> ModelRoute:
        return self._route

    @property
    def usage(self) -> UsageObservation | None:
        return self._usage

    @property
    def did_transport_attempt(self) -> bool:
        return self._did_transport_attempt

    def _pins(self) -> None:
        actual = (
            self._token_counter.model_digest,
            *fragment_contextual_counter_pins(self._token_counter),
            fragment_contextual_runtime_digest(),
        )
        expected = (
            self._model_digest,
            self._tokenizer_digest,
            self._template_digest,
            self._renderer_digest,
            self._runtime_digest,
        )
        if any(
            type(value) is not str or value != pin
            for value, pin in zip(actual, expected, strict=True)
        ):
            raise LocalContextualRuntimeError(
                "fragment implementation pin differs", code=F.MODEL_PIN
            )

    def _count(self, body: bytes, request: HistoryFragmentContextualRequestV1) -> int:
        self._pins()
        value = self._token_counter.count_prompt_tokens(body)
        self._pins()
        if type(value) is not int or value <= 0:
            raise LocalContextualRuntimeError("invalid fragment token count", code=F.TOKEN_COUNT)
        if value + request.task.max_output_tokens > _context_tokens(self._route):
            raise LocalContextualRuntimeError(
                "fragment token capacity exceeded", code=F.TOKEN_CAPACITY
            )
        return value

    def _bytes(self, request: HistoryFragmentContextualRequestV1) -> tuple[bytes, bytes]:
        from zacai.intelligence.history_fragment_contextual_codec import (
            HistoryFragmentContextualRequestV1,
            encode_history_fragment_contextual_request,
        )

        if type(request) is not HistoryFragmentContextualRequestV1:
            raise ValueError("exact fragment request required")
        if (
            _canonical_native_route(self._route) != self._route_snapshot
            or request.route != self._route
        ):
            raise LocalContextualRuntimeError("fragment route changed", code=F.MODEL_PIN)
        retained = encode_history_fragment_contextual_request(request)
        body = request.prompt_body.encode()
        wire = json.loads(body)
        if wire["model"] != self._route.identity.model_id:
            raise ValueError("fragment model differs")
        return body, retained

    def _after_host_recheck(
        self, request: HistoryFragmentContextualRequestV1, body: bytes, retained: bytes,
        counter: OllamaQwenContextualTokenCounter,
        recheck: Callable[[HistoryFragmentContextualRequestV1, FragmentContextualDispatchDescriptor], None],
        configuration: tuple[str, str, str, str, str, str],
    ) -> None:
        """Pure retained bytes/configuration check, never invokes a host/provider callback."""
        if (self._token_counter is not counter or self._recheck is not recheck
            or (self._model_digest, self._tokenizer_digest, self._runtime_digest,
                self._template_digest, self._renderer_digest, self._route_snapshot) != configuration or self._configuration != configuration
            or counter._digest != self._model_digest
            or self._bytes(request) != (body, retained)):
            raise ValueError("fragment changed during host recheck")

    def preflight_fragment(self, request: HistoryFragmentContextualRequestV1) -> None:
        if not self._lock.acquire(blocking=False):
            raise FragmentLocalContextualRuntimeError(
                "fragment instance busy", code=F.PREFLIGHT_BINDING
            )
        failure = F.PREFLIGHT_BINDING
        try:
            if self._attempted or self._prepared is not None:
                raise LocalContextualRuntimeError(
                    "fragment preflight consumed", code=F.PREFLIGHT_BINDING
                )
            failure = F.REQUEST_PAYLOAD
            body, retained = self._bytes(request)
            failure = F.TOKEN_COUNT
            count = self._count(body, request)
            failure = F.RUNTIME_VERSION
            _fragment_verify_runtime(self._token_counter)
            failure = F.MODEL_PIN
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            self._pins()
            failure = F.REQUEST_PAYLOAD
            if self._bytes(request) != (body, retained):
                raise LocalContextualRuntimeError(
                    "fragment request changed", code=F.REQUEST_PAYLOAD
                )
            self._prepared = (request, body, retained, count)
        except BaseException as error:  # noqa: BLE001 - never retain private exception causes
            self._prepared = None
            self._attempted = True
            kind = type(error)
            exit_code = (
                error.code if isinstance(error, SystemExit) and type(error.code) is int else 1
            )
            failure = _native_phase_failure(error, failure)
        else:
            return
        finally:
            self._lock.release()
        _raise_interruption(kind, exit_code)
        raise FragmentLocalContextualRuntimeError(
            "fragment contextual preflight failed", code=failure
        )

    def generate_fragment(self, request: HistoryFragmentContextualRequestV1) -> ContextualDraft:
        if not self._lock.acquire(blocking=False):
            raise FragmentLocalContextualRuntimeError(
                "fragment attempt unavailable", code=F.PREFLIGHT_BINDING
            )
        try:
            if self._attempted:
                raise FragmentLocalContextualRuntimeError(
                    "fragment attempt consumed", code=F.PREFLIGHT_BINDING
                )
            self._usage = None
            self._attempted = True
            prepared = self._prepared
            self._prepared = None
        finally:
            self._lock.release()
        failure = F.PREFLIGHT_BINDING
        did_transport_attempt = False
        try:
            started = time.perf_counter()
            counter, recheck = self._token_counter, self._recheck
            publication_window = self._publication_window
            configuration = self._configuration
            attempt_id = uuid4()
            if prepared is None or prepared[0] is not request:
                raise ValueError("original preflight required")
            failure = F.REQUEST_PAYLOAD
            body, retained = self._bytes(request)
            if (body, retained) != prepared[1:3]:
                raise ValueError("fragment preflight differs")
            failure = F.TOKEN_COUNT
            if self._count(body, request) != prepared[3]:
                raise ValueError("fragment tokenizer changed")
            failure = F.RUNTIME_VERSION
            _fragment_verify_runtime(self._token_counter)
            failure = F.MODEL_PIN
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            # Last tokenizer/provider/policy callbacks precede the actual canonical gate.
            failure = F.TOKEN_COUNT
            if self._count(body, request) != prepared[3]:
                raise ValueError("fragment tokenizer changed")
            failure = F.MODEL_PIN
            self._pins()
            failure = F.REQUEST_PAYLOAD
            if self._bytes(request) != (body, retained):
                raise ValueError("fragment request changed before dispatch")
            failure = F.TOTAL_LATENCY
            if not 0 <= (time.perf_counter() - started) * 1000 <= request.task.max_latency_ms:
                raise ValueError("fragment dispatch exceeded deadline")
            failure = F.PREFLIGHT_BINDING
            descriptor = _fragment_descriptor("PRE_DISPATCH", attempt_id, body, retained,
                                              prepared[3], configuration)
            if recheck(request, descriptor) is not None:
                raise ValueError("host recheck contract differs")
            self._after_host_recheck(request, body, retained, counter, recheck, configuration)
            if descriptor != _fragment_descriptor("PRE_DISPATCH", attempt_id, body, retained,
                                                 prepared[3], configuration):
                raise ValueError("dispatch descriptor changed during host recheck")
            failure = F.TOTAL_LATENCY
            remaining = request.task.max_latency_ms / 1000 - (time.perf_counter() - started)
            if not 0 < remaining <= request.task.max_latency_ms / 1000:
                raise ValueError("fragment dispatch deadline exhausted")
            remaining = _publication_remaining(self, publication_window, remaining)
            failure = F.TRANSPORT
            did_transport_attempt = True
            self._did_transport_attempt = True
            reply = _fragment_http_post(body, remaining)
            failure = F.RESPONSE_SHAPE
            draft, usage = _parse_fragment_response(
                reply, request, self._route, (time.perf_counter() - started) * 1000, prepared[3]
            )
            failure = F.POST_RUNTIME_VERSION
            _fragment_verify_runtime(self._token_counter)
            failure = F.POST_MODEL_PIN
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            self._pins()
            failure = F.POST_MODEL_PIN
            if _canonical_native_route(self._route) != self._route_snapshot:
                raise ValueError("fragment release route changed")
            # Existing audit consumers classify REQUEST_PAYLOAD as preflight.
            # Preserve a post-response code as well as the actual attempt flag.
            failure = F.RESPONSE_AUTHORITY
            if self._bytes(request) != (body, retained):
                raise ValueError("fragment release request changed")
            failure = F.TOTAL_LATENCY
            elapsed = (time.perf_counter() - started) * 1000
            if not 0 <= elapsed <= request.task.max_latency_ms:
                raise ValueError("fragment output exceeded deadline")
            # Construct privately before the last canonical host callback.
            result_usage = UsageObservation.model_validate({**usage.model_dump(), "latency_ms": elapsed})
            failure = F.RESPONSE_AUTHORITY
            descriptor = _fragment_descriptor("RELEASE", attempt_id, body, retained,
                                              prepared[3], configuration, draft, result_usage)
            if recheck(request, descriptor) is not None:
                raise ValueError("host recheck contract differs")
            self._after_host_recheck(request, body, retained, counter, recheck, configuration)
            if descriptor != _fragment_descriptor("RELEASE", attempt_id, body, retained,
                                                 prepared[3], configuration, draft, result_usage):
                raise ValueError("release descriptor changed during host recheck")
            failure = F.TOTAL_LATENCY
            elapsed = (time.perf_counter() - started) * 1000
            if not 0 <= elapsed <= request.task.max_latency_ms:
                raise ValueError("fragment release exceeded deadline")
            _publication_remaining(self, publication_window, 1.0)
            self._usage = result_usage
            return draft
        except BaseException as error:  # noqa: BLE001 - private backend/gate diagnostics stay private
            kind = type(error)
            exit_code = (
                error.code if isinstance(error, SystemExit) and type(error.code) is int else 1
            )
            from zacai.contextual_protection import PersonalFragmentCleanupUncertain

            cleanup_uncertain = isinstance(error, PersonalFragmentCleanupUncertain)
            failure = _native_phase_failure(error, failure)
        if cleanup_uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL recovery cleanup uncertain; operator review required"
            ) from None
        _raise_interruption(kind, exit_code)
        raise FragmentLocalContextualRuntimeError(
            "fragment contextual generation failed",
            code=failure,
            did_transport_attempt=did_transport_attempt,
        )

    # Pure structural resolver only: no instance-origin/display/permission binding.
    def resolve_fragment(
        self, draft: ContextualDraft, request: HistoryFragmentContextualRequestV1
    ) -> ContextualReview:
        from zacai.intelligence.contextual_generation import (
            resolve_history_fragment_contextual_draft,
        )

        return resolve_history_fragment_contextual_draft(draft, request)


def _parse_fragment_response(
    reply: object,
    request: HistoryFragmentContextualRequestV1,
    route: ModelRoute,
    elapsed: float,
    expected_count: int,
) -> tuple[ContextualDraft, UsageObservation]:
    failure = F.RESPONSE_SHAPE
    try:
        if type(reply) is not dict:
            raise ValueError("fragment response shape")
        failure = F.RESPONSE_MODEL
        if reply.get("model") != route.identity.model_id:
            raise ValueError("fragment response model")
        failure = F.RESPONSE_INCOMPLETE
        if reply.get("done") is not True:
            raise ValueError("fragment response incomplete")
        failure = F.RESPONSE_SHAPE
        message = reply.get("message")
        if type(message) is not dict:
            raise ValueError("fragment response message shape")
        failure = F.RESPONSE_AUTHORITY
        if (
            message.get("role") != "assistant"
            or message.get("tool_calls")
            or message.get("thinking")
        ):
            raise ValueError("fragment response authority")
        if reply.get("done_reason") == "length":
            failure = F.RESPONSE_USAGE
            length_input = reply.get("prompt_eval_count")
            length_output = reply.get("eval_count")
            if type(length_input) is not int or type(length_output) is not int:
                raise ValueError("fragment length count type")
            reported = (length_input, length_output)
            if (
                any(n < 0 for n in reported)
                or reported[1] > request.task.max_output_tokens
                or sum(reported) > _context_tokens(route)
            ):
                raise ValueError("fragment length usage")
            failure = (
                F.OUTPUT_LIMIT
                if reported[1] == request.task.max_output_tokens
                and sum(reported) < _context_tokens(route)
                else F.RESPONSE_LENGTH
            )
            raise ValueError("fragment length completion")
        failure = F.RESPONSE_STOP_REASON
        if reply.get("done_reason") != "stop":
            raise ValueError("fragment response stop")
        failure = F.RESPONSE_USAGE
        input_count = reply.get("prompt_eval_count")
        output_count = reply.get("eval_count")
        if (
            type(input_count) is not int
            or type(output_count) is not int
            or input_count < 0
            or output_count < 0
        ):
            raise ValueError("fragment response counts")
        counts = (input_count, output_count)
        if counts[0] != expected_count:
            raise LocalContextualRuntimeError(
                "fragment prompt count mismatch", code=F.PROMPT_COUNT_MISMATCH
            )
        if counts[1] > request.task.max_output_tokens or sum(counts) > _context_tokens(route):
            raise ValueError("fragment response capacity")
        failure = F.RESPONSE_LATENCY
        if not 0 <= elapsed <= request.task.max_latency_ms:
            raise ValueError("fragment response latency")
        failure = F.RESPONSE_SCHEMA
        content = message.get("content")
        if type(content) is not str:
            raise ValueError("fragment response content")
        draft = parse_contextual_draft(content.encode())
        return draft, UsageObservation(
            input_tokens=counts[0], output_tokens=counts[1], latency_ms=elapsed, cost_usd=0
        )
    except Exception as error:  # noqa: BLE001 - no model/provider causes escape
        failure = closed_runtime_code(error) or failure
    raise LocalContextualRuntimeError("fragment contextual response rejected", code=failure)


def _publication_remaining(
    runtime: FragmentLocalContextualRuntime, window: tuple[object, float] | None, remaining: float,
) -> float:
    """Scalar original publication cap; no caller clock or renewable authority."""
    from zacai.intelligence.fragment_publication_generation import (
        CanonicalPersonalFragmentPublicationAuthorization,
    )
    from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

    parent = getattr(runtime._recheck, "__self__", None)
    if type(parent) is not CanonicalPersonalFragmentPublicationAuthorization:
        if window is not None or runtime._publication_window is not None:
            raise ValueError("publication runtime origin changed")
        return remaining
    if (window is None or runtime._publication_window is not window
        or window[0] is not parent or parent._runtime is not runtime
        or parent._generation_window is not window
        or getattr(runtime._recheck, "__func__", None) is not type(parent).recheck):
        raise ValueError("original publication processing window required")
    bounded = min(remaining, window[1] - _AUTHENTICATED_MONOTONIC())
    if not 0 < bounded <= remaining:
        raise ValueError("original publication processing interval exhausted")
    return bounded
