"""D034H explicit loopback adapter, never an authorization or enabled service.

Shares the existing benchmark wire protocol. Trusted host construction only;
call through the review host with actual authorization/protection adapters.
No configurable endpoint, proxy, redirects, model pulls, tools or fallback.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import time
from collections.abc import Callable
from typing import Any, Protocol

from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_generation import ReviewDraft, ReviewRequest, prepare_review_request
from zacai.policy import Destination

_CONTEXT_TOKENS = 8192
Transport = Callable[[str, str, bytes | None], Any]


class LocalReviewRuntimeError(ValueError):
    """Fixed diagnostics; no backend/input/output text."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LocalReviewRuntimeError("invalid local response")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise LocalReviewRuntimeError("invalid local response")


def _json(raw: bytes | str) -> Any:
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)


def _http(method: str, path: str, body: bytes | None = None) -> Any:
    # Literal loopback bypasses proxy environment; no redirect handling exists.
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=120)
    try:
        connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Encoding", "identity") != "identity"
        ):
            raise LocalReviewRuntimeError("local runtime unavailable")
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise LocalReviewRuntimeError("local response too large")
        return _json(raw)
    finally:
        connection.close()


def prepare_payload(request: ReviewRequest, route: ModelRoute, digest: str) -> bytes:
    """Verify host-derived catalog and complete serialized character/byte limits.

    The adapter separately checks exact tokenizer capacity before dispatch and
    compares reported usage afterward; this serializer alone does neither.
    """
    if request != prepare_review_request(request.context):
        raise LocalReviewRuntimeError("modified review request")
    name = route.identity.model_id
    if (
        route.destination != Destination.LOCAL
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", name)
        or name.endswith(":cloud")
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or request.context.task.max_output_tokens > route.max_output_tokens
    ):
        raise LocalReviewRuntimeError("invalid local route or pin")
    schema = ReviewDraft.model_json_schema()
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
                {"role": "user", "content": request.evidence_json},
            ],
            "options": {
                "temperature": 0,
                "num_predict": request.context.task.max_output_tokens,
                "num_ctx": _CONTEXT_TOKENS,
            },
        },
        ensure_ascii=False,
    ).encode()
    if len(body.decode()) > route.max_input_characters or len(body) > 64_000:
        raise LocalReviewRuntimeError("serialized request outside capacity")
    return body


def verify_model(name: str, digest: str, transport: Transport) -> None:
    models = transport("GET", "/api/tags", None)["models"]
    # Ambiguous same-name registrations reject even if one reports the right hash.
    matching = [model for model in models if model.get("name") == name]
    if len(matching) != 1 or matching[0].get("digest") != digest:
        raise LocalReviewRuntimeError("installed model pin mismatch")
    metadata = transport("POST", "/api/show", json.dumps({"model": name}).encode())
    if metadata.get("remote_model") or metadata.get("remote_host"):
        raise LocalReviewRuntimeError("remote model forbidden")


def dispatch_draft(
    request: ReviewRequest, route: ModelRoute, body: bytes, transport: Transport
) -> tuple[ReviewDraft, UsageObservation]:
    started = time.perf_counter()
    reply = transport("POST", "/api/chat", body)
    elapsed = (time.perf_counter() - started) * 1000
    if (
        reply.get("model") != route.identity.model_id
        or reply.get("done") is not True
        or reply.get("done_reason") != "stop"
        or not 0 <= elapsed <= request.context.task.max_latency_ms
    ):
        raise LocalReviewRuntimeError("incomplete or late local output")
    message = reply["message"]
    if message.get("role") != "assistant" or message.get("tool_calls") or message.get("thinking"):
        raise LocalReviewRuntimeError("unexpected model authority or thinking output")
    counts = (reply["prompt_eval_count"], reply["eval_count"])
    if (
        any(type(count) is not int or count < 0 for count in counts)
        or counts[1] > request.context.task.max_output_tokens
        or counts[0] + counts[1] > _CONTEXT_TOKENS
    ):
        raise LocalReviewRuntimeError("invalid local usage or context capacity")
    draft = ReviewDraft.model_validate(_json(message["content"]))
    return draft, UsageObservation(
        input_tokens=counts[0], output_tokens=counts[1], latency_ms=elapsed, cost_usd=0.0
    )


class LocalPromptTokenCounter(Protocol):
    """Trusted local tokenizer tied to the exact installed model/template.

    Count the complete rendered prompt, including chat template and schema,
    without sending evidence to a model or remote service. No backend/default is
    shipped. Reported runtime input usage must match this count after dispatch.
    """

    @property
    def model_digest(self) -> str: ...
    def count_prompt_tokens(self, serialized_body: bytes) -> int: ...
    def verify_runtime(self) -> None:
        """Reject runtime/template incompatibility using metadata only."""
        ...


class LocalReviewRuntime:
    """One-attempt, host-owned adapter; constructing it grants no permission.

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
            raise LocalReviewRuntimeError("invalid local runtime configuration")
        if self._route.destination != Destination.LOCAL:
            raise LocalReviewRuntimeError("invalid local runtime configuration")
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

    def _token_count(self, body: bytes, request: ReviewRequest) -> int:
        if self._token_counter.model_digest != self.model_digest:
            raise ValueError("tokenizer model pin mismatch")
        count = self._token_counter.count_prompt_tokens(body)
        if (
            type(count) is not int
            or count <= 0
            or (count + request.context.task.max_output_tokens > _CONTEXT_TOKENS)
        ):
            raise ValueError("prompt/output token budget exceeded")
        return count

    def preflight(self, request: ReviewRequest) -> None:
        try:
            if self._attempted:
                raise ValueError("attempt consumed")
            # Never retain a successful stale preflight after a failed new one.
            self._prepared = None
            body = prepare_payload(request, self.route, self.model_digest)
            count = self._token_count(body, request)
            self._token_counter.verify_runtime()
            verify_model(self.route.identity.model_id, self.model_digest, _http)
            # Include exact context/task identity as well as serialized messages.
            self._prepared = hashlib.sha256(
                body + review_context_digest(request.context).encode() + str(count).encode()
            ).digest()
        except Exception:  # noqa: BLE001 - model/backend errors may echo data
            raise LocalReviewRuntimeError("local review preflight failed") from None

    def generate(self, request: ReviewRequest) -> ReviewDraft:
        try:
            self._usage = None
            if self._attempted:
                raise ValueError("attempt consumed")
            self._attempted = True
            body = prepare_payload(request, self.route, self.model_digest)
            count = self._token_count(body, request)
            expected = hashlib.sha256(
                body + review_context_digest(request.context).encode() + str(count).encode()
            ).digest()
            if self._prepared is None or self._prepared != expected:
                raise ValueError("preflight missing or changed")
            started = time.perf_counter()
            self._token_counter.verify_runtime()
            verify_model(self.route.identity.model_id, self.model_digest, _http)
            draft, usage = dispatch_draft(request, self.route, body, _http)
            self._token_counter.verify_runtime()
            verify_model(self.route.identity.model_id, self.model_digest, _http)
            if usage.input_tokens != count:
                raise ValueError("runtime prompt usage disagrees with tokenizer")
            elapsed = (time.perf_counter() - started) * 1000
            if not 0 <= elapsed <= request.context.task.max_latency_ms:
                raise ValueError("late adapter output")
            self._usage = usage.model_copy(update={"latency_ms": elapsed})
            return draft
        except Exception:  # noqa: BLE001 - never expose backend/private text
            raise LocalReviewRuntimeError("local review generation failed") from None
