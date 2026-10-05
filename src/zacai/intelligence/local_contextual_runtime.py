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
import time

from zacai.intelligence.contextual_generation import (
    ContextualDraft,
    ContextualRequest,
    parse_contextual_draft,
    prepare_contextual_request,
)
from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.local_review_runtime import (
    LocalPromptTokenCounter,
    Transport,
    _http,
    verify_model,
)
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.runtime_diagnostics import RuntimeDiagnosticError, closed_runtime_code
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F
from zacai.policy import Destination

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
    """Verify host-derived catalog and complete serialized character/byte limits.

    The adapter separately checks exact tokenizer capacity before dispatch and
    compares reported usage afterward; this serializer alone does neither.
    """
    if request != prepare_contextual_request(request.context):
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
    schema = ContextualDraft.model_json_schema()
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
                {"role": "system", "content": request.instruction + json.dumps(schema)},
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
    failure = F.TRANSPORT
    try:
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
        if message.get("role") != "assistant" or message.get("tool_calls") or message.get("thinking"):
            raise ValueError("unexpected response authority")
        if reply.get("done_reason") == "length":
            failure = F.RESPONSE_USAGE
            reported = (reply["prompt_eval_count"], reply["eval_count"])
            if (any(type(n) is not int or n < 0 for n in reported)
                or reported[1] > request.context.task.max_output_tokens
                or reported[0] + reported[1] > _context_tokens(route)):
                raise ValueError("invalid usage")
            failure = F.OUTPUT_LIMIT if reported[1] == request.context.task.max_output_tokens and sum(reported) < _context_tokens(route) else F.RESPONSE_LENGTH
            raise ValueError("length completion")
        failure = F.RESPONSE_STOP_REASON
        if reply.get("done_reason") != "stop":
            raise ValueError("nonstop completion")
        failure = F.RESPONSE_LATENCY
        if not 0 <= elapsed <= request.context.task.max_latency_ms:
            raise ValueError("late response")
        failure = F.RESPONSE_USAGE
        counts = (reply["prompt_eval_count"], reply["eval_count"])
        if (any(type(count) is not int or count < 0 for count in counts)
            or counts[1] > request.context.task.max_output_tokens
            or counts[0] + counts[1] > _context_tokens(route)):
            raise ValueError("invalid usage")
        failure = F.RESPONSE_SCHEMA
        content = message["content"]
        if not isinstance(content, str):
            raise TypeError("invalid content shape")
        draft = parse_contextual_draft(content.encode())
        return draft, UsageObservation(input_tokens=counts[0], output_tokens=counts[1],
                                       latency_ms=elapsed, cost_usd=0.0)
    except Exception:  # noqa: BLE001, S110 - no raw backend/model diagnostics
        pass
    raise LocalContextualRuntimeError("local contextual response rejected", code=failure)


_INNER_CODES = {
    F.TOKEN_COUNT: frozenset({F.MODEL_PIN, F.TOKEN_COUNT, F.TOKEN_CAPACITY}),
    F.TRANSPORT: frozenset(code for code in F if code == F.TRANSPORT or code == F.OUTPUT_LIMIT
                         or code.value.startswith("RESPONSE_")),
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
            raise LocalContextualRuntimeError("prompt/output token budget exceeded", code=F.TOKEN_CAPACITY)
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
