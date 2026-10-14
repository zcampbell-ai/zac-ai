"""Passive finite LOCAL email wire, count and response resolution.

No transport, invocation, grants or state writes. Supplied route/digest/count/time
are host declarations, not authenticated runtime observations. Complete offline
prompt count governs capacity and must equal backend prompt_eval_count. Optional
prompt_eval_cached_count is only an exact-int subset of that full count. Hosts must suppress traceback-local capture.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.email_draft import EmailDraftPacketV1
from zacai.intelligence.email_generation import (
    EmailGenerationRequestV1,
    EmailModelOutputV1,
    parse_email_model_output,
    prepare_email_generation_request,
    resolve_email_model_output,
)
from zacai.intelligence.local_review_runtime import _json
from zacai.intelligence.ollama_token_counter import OllamaQwenEmailTokenCounter
from zacai.policy import Destination

MODEL = "qwen3.8:27b-mlx"
RUNTIME = "mac-loopback-email-8k"
CAPABILITY = "email_draft"
CONTEXT_TOKENS = 8192
LARGE_RUNTIME = "mac-loopback-email-16k"
LARGE_CONTEXT_TOKENS = 16384
MAX_PAYLOAD_BYTES = 64000
MAX_RESPONSE_BYTES = 128000


class EmailLocalWireError(ValueError):
    """Fixed public diagnostics, no provider/source prose or traceback causes."""


@dataclass(frozen=True)
class ParsedEmailLocalResponseV1:
    """Parsed declarations only, never authenticated generation/usage."""

    output: EmailModelOutputV1
    usage: UsageObservation
    reported_prompt_eval_cached_count: int | None


def context_tokens_for_route(route: ModelRoute) -> int:
    """Exact finite runtime identity capacity, never a default or inferred upgrade."""
    runtime = route.identity.runtime_id
    if runtime == RUNTIME:
        return CONTEXT_TOKENS
    if runtime == LARGE_RUNTIME:
        return LARGE_CONTEXT_TOKENS
    raise ValueError("unsupported email runtime")


def _payload(request: EmailGenerationRequestV1, route: ModelRoute, model_digest: str) -> bytes:
    if type(request) is not EmailGenerationRequestV1:
        raise ValueError("wrong request family")
    if request != prepare_email_generation_request(request.specification):
        raise ValueError("modified request")
    if isinstance(route, ModelRoute):
        context_tokens_for_route(route)  # Reject lookalikes before contract normalization.
    route = ModelRoute.model_validate(route)
    context_tokens = context_tokens_for_route(route)
    task = request.specification.task()
    if (
        route.destination != Destination.LOCAL
        or route.identity.provider_id != "ollama"
        or route.identity.model_id != MODEL
        or route.capabilities != frozenset({CAPABILITY})
        or not task.required_capabilities <= route.capabilities
        or not route.available
        or type(model_digest) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", model_digest)
        or not 0 < task.max_output_tokens <= route.max_output_tokens < context_tokens
        or task.max_latency_ms < route.estimated_latency_ms
        or task.max_estimated_cost_usd < route.estimated_cost_usd
    ):
        raise ValueError("unsupported route/budget declarations")
    body = json.dumps(
        {
            "model": MODEL,
            "stream": False,
            "think": False,
            "truncate": False,
            "shift": False,
            "keep_alive": 0,
            "format": _json(request.schema_json),
            "messages": [
                {
                    "role": "system",
                    "content": request.instruction + "\nOutput JSON schema: " + request.schema_json,
                },
                {"role": "user", "content": request.input_json.replace("<", "\\u003c")},
            ],
            "options": {
                "temperature": 0,
                "num_predict": task.max_output_tokens,
                "num_ctx": context_tokens,
            },
        },
        ensure_ascii=False,
    ).encode("utf-8", errors="strict")
    if len(body) > MAX_PAYLOAD_BYTES or len(body.decode()) > route.max_input_characters:
        raise ValueError("complete serialized payload outside capacity")
    return body


def prepare_email_local_payload(
    request: EmailGenerationRequestV1, route: ModelRoute, model_digest: str
) -> bytes:
    """Exact two-turn no-thinking payload. Constructing it grants no dispatch."""
    try:
        return _payload(request, route, model_digest)
    except Exception:  # noqa: BLE001,S110 - fixed boundary, cancellation propagates
        pass
    raise EmailLocalWireError("email local payload unavailable or invalid")


def count_email_local_prompt(
    request: EmailGenerationRequestV1,
    route: ModelRoute,
    model_digest: str,
    counter: OllamaQwenEmailTokenCounter,
) -> int:
    """Hash-verified offline tokenizer count of the actual serialized payload.

    Does not call verify_runtime() or any network method. The future admitted host
    must bind this exact body/counter/pin and independently check runtime metadata.
    """
    try:
        if type(counter) is not OllamaQwenEmailTokenCounter or counter.model_digest != model_digest:
            raise ValueError("explicit email counter/pin required")
        body = _payload(request, route, model_digest)
        context_tokens = context_tokens_for_route(route)
        count = counter.count_prompt_tokens(body)
        if type(count) is not int or not 0 < count <= context_tokens:
            raise ValueError("invalid exact count")
        if count + request.specification.task().max_output_tokens > context_tokens:
            raise ValueError("full prompt and output reservation exceed context")
        return count
    except Exception:  # noqa: BLE001,S110 - no source/tokenizer diagnostics
        pass
    raise EmailLocalWireError("email local count unavailable or invalid")


def _parse(
    raw: bytes,
    request: EmailGenerationRequestV1,
    route: ModelRoute,
    model_digest: str,
    expected_prompt_tokens: int,
    elapsed_ms: float,
) -> ParsedEmailLocalResponseV1:
    _payload(request, route, model_digest)
    context_tokens = context_tokens_for_route(route)
    task = request.specification.task()
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_RESPONSE_BYTES
        or type(expected_prompt_tokens) is not int
        or expected_prompt_tokens <= 0
        or expected_prompt_tokens + task.max_output_tokens > context_tokens
        or type(elapsed_ms) not in (int, float)
        or not math.isfinite(elapsed_ms)
        or not 0 <= elapsed_ms <= task.max_latency_ms
    ):
        raise ValueError("bounded response and host count/time required")
    data = _json(raw.decode("utf-8", errors="strict"))
    required = {"model", "message", "done", "done_reason", "prompt_eval_count", "eval_count"}
    optional = {
        "created_at",
        "total_duration",
        "load_duration",
        "prompt_eval_duration",
        "eval_duration",
        "prompt_eval_cached_count",
    }
    if (
        type(data) is not dict
        or not required <= set(data)
        or not set(data) <= required | optional
        or data["model"] != MODEL
        or data["done"] is not True
        or data["done_reason"] != "stop"
    ):
        raise ValueError("closed completed response required")
    message = data["message"]
    if (
        type(message) is not dict
        or set(message) != {"role", "content"}
        or message["role"] != "assistant"
        or type(message["content"]) is not str
    ):
        raise ValueError("closed assistant message without tools/thinking required")
    for key in optional - {"created_at", "prompt_eval_cached_count"}:
        if key in data and (type(data[key]) is not int or data[key] < 0):
            raise ValueError("exact nonnegative duration required")
    if "created_at" in data and (
        type(data["created_at"]) is not str or len(data["created_at"]) > 100
    ):
        raise ValueError("bounded reported date declaration required")
    incoming, outgoing = data["prompt_eval_count"], data["eval_count"]
    if (
        type(incoming) is not int
        or incoming != expected_prompt_tokens
        or type(outgoing) is not int
        or not 0 < outgoing <= task.max_output_tokens
        or expected_prompt_tokens + outgoing > context_tokens
    ):
        raise ValueError("full count parity/output capacity required")
    cached = data.get("prompt_eval_cached_count")
    if "prompt_eval_cached_count" in data and (
        type(cached) is not int or not 0 <= cached <= incoming
    ):
        raise ValueError("cached subset must be exact nonnegative int within full count")
    output = parse_email_model_output(message["content"].encode("utf-8", errors="strict"))
    return ParsedEmailLocalResponseV1(
        output,
        UsageObservation(
            input_tokens=expected_prompt_tokens,
            output_tokens=outgoing,
            latency_ms=float(elapsed_ms),
            cost_usd=0.0,
        ),
        cached,
    )


def parse_email_local_response(
    raw: bytes,
    request: EmailGenerationRequestV1,
    route: ModelRoute,
    model_digest: str,
    *,
    expected_prompt_tokens: int,
    elapsed_ms: float,
) -> ParsedEmailLocalResponseV1:
    """Closed finite response. Caller-supplied count/time does not prove invocation."""
    try:
        return _parse(raw, request, route, model_digest, expected_prompt_tokens, elapsed_ms)
    except Exception:  # noqa: BLE001,S110 - no response/input text, no exception context
        pass
    raise EmailLocalWireError("email local response unavailable or invalid")


def resolve_email_local_response(
    raw: bytes,
    request: EmailGenerationRequestV1,
    route: ModelRoute,
    model_digest: str,
    *,
    expected_prompt_tokens: int,
    elapsed_ms: float,
    builder_id: UUID,
    created_at: datetime,
) -> tuple[EmailDraftPacketV1, ParsedEmailLocalResponseV1]:
    """Parse and use existing email resolver/packet validation; every grant stays false."""
    try:
        parsed = _parse(raw, request, route, model_digest, expected_prompt_tokens, elapsed_ms)
        packet = resolve_email_model_output(
            parsed.output, request, builder_id=builder_id, created_at=created_at
        )
        return packet, parsed
    except Exception:  # noqa: BLE001,S110 - no nested private diagnostics
        pass
    raise EmailLocalWireError("email local candidate unavailable or invalid")
