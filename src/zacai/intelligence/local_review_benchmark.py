"""D034B synthetic-only local review benchmark, not production dispatch.

Only SHARED/PUBLIC declared fixtures are accepted. No real content, credentials,
tools, auto-pulls, fallback, state writes or service configuration changes.
The fixed loopback runtime is trusted; locality cannot be proved against a
malicious server/host by an HTTP client or self-reported model metadata.
"""

from __future__ import annotations

import http.client
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.eligibility import ApprovedRouteRegistry, assess_routes
from zacai.intelligence.meeting_review import MeetingReview, ReviewContext
from zacai.intelligence.review_generation import (
    ReviewDraft,
    prepare_review_request,
    resolve_review_draft,
)
from zacai.policy import DataClassification, Destination, TrustBoundary

_CONTEXT_TOKENS = 8192


class BenchmarkError(ValueError):
    """Fixed safe failure; never retains server text or a model exception."""


@dataclass(frozen=True)
class BenchmarkResult:
    review: MeetingReview
    usage: UsageObservation
    model_digest: str


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError("invalid benchmark response")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise BenchmarkError("invalid benchmark response")


def _json(raw: bytes | str) -> Any:
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)


def _http(method: str, path: str, body: bytes | None = None) -> Any:
    # HTTPConnection uses a literal loopback address and ignores proxy env vars.
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=120)
    try:
        connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Encoding", "identity") != "identity"
        ):
            raise BenchmarkError("local benchmark unavailable")
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise BenchmarkError("benchmark response too large")
        return _json(raw)
    finally:
        connection.close()


def benchmark_local_review(
    context: ReviewContext,
    *,
    route: ModelRoute,
    registry: ApprovedRouteRegistry,
    expected_model_digest: str,
) -> BenchmarkResult:
    """One bounded synthetic attempt; a failure never triggers a retry/escalation.

    Registry/spec and fixture labels are trusted operator inputs, not declarations
    accepted from agents. Input capacity checks include the serialized schema and
    messages. The socket timeout is not a hard whole-process execution deadline;
    late responses are discarded. No confidential route is enabled by a pass.
    """
    try:
        return _benchmark(context, route, registry, expected_model_digest)
    except Exception:  # noqa: BLE001 - model/backend errors can echo full input
        raise BenchmarkError("local synthetic review benchmark failed") from None


def _benchmark(
    context: ReviewContext,
    route: ModelRoute,
    registry: ApprovedRouteRegistry,
    digest: str,
) -> BenchmarkResult:
    context = ReviewContext(context.task, context.meeting_source_id, context.related_source_ids)
    task = context.task
    route = ModelRoute.model_validate(route)
    if (
        task.event.trust_boundary != TrustBoundary.SHARED
        or (task.event.data_classification != DataClassification.PUBLIC)
        or any(
            ref.effective_classification != DataClassification.PUBLIC
            for ref in task.event.provenance
        )
    ):
        raise BenchmarkError("synthetic public fixtures only")
    if (
        route.destination != Destination.LOCAL
        or not any(registration.route == route for registration in registry.routes)
        or route.identity
        not in assess_routes(
            task, registry=registry, authorized_boundaries=frozenset({TrustBoundary.SHARED})
        ).eligible_routes
    ):
        raise BenchmarkError("benchmark route ineligible")
    name = route.identity.model_id
    if (
        not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", name)
        or name.endswith(":cloud")
        or not (re.fullmatch(r"[0-9a-f]{64}", digest))
    ):
        raise BenchmarkError("invalid model pin")
    request = prepare_review_request(context)
    schema = ReviewDraft.model_json_schema()
    body = json.dumps(
        {
            "model": name,
            "stream": False,
            "think": False,
            "keep_alive": 0,
            "format": schema,
            "messages": [
                {"role": "system", "content": request.instruction + json.dumps(schema)},
                {"role": "user", "content": request.evidence_json},
            ],
            "options": {
                "temperature": 0,
                "num_predict": task.max_output_tokens,
                "num_ctx": _CONTEXT_TOKENS,
            },
        },
        ensure_ascii=False,
    ).encode()
    if len(body.decode()) > route.max_input_characters or len(body) > 64_000:
        raise BenchmarkError("serialized request outside capacity")
    models = _http("GET", "/api/tags")["models"]
    matching = [
        model for model in models if model.get("name") == name and model.get("digest") == digest
    ]
    if len(matching) != 1:
        raise BenchmarkError("installed model pin mismatch")
    metadata = _http("POST", "/api/show", json.dumps({"model": name}).encode())
    if metadata.get("remote_model") or metadata.get("remote_host"):
        raise BenchmarkError("remote model forbidden")
    started = time.perf_counter()
    reply = _http("POST", "/api/chat", body)
    elapsed = (time.perf_counter() - started) * 1000
    if (
        reply.get("model") != name
        or reply.get("done") is not True
        or (reply.get("done_reason") != "stop")
        or elapsed > task.max_latency_ms
    ):
        raise BenchmarkError("incomplete or late local output")
    message = reply["message"]
    if message.get("role") != "assistant" or message.get("tool_calls") or message.get("thinking"):
        raise BenchmarkError("unexpected model authority or thinking output")
    counts = (reply["prompt_eval_count"], reply["eval_count"])
    if (
        any(type(count) is not int or count < 0 for count in counts)
        or counts[1] > task.max_output_tokens
    ):
        raise BenchmarkError("invalid usage")
    if counts[0] + counts[1] > _CONTEXT_TOKENS:
        raise BenchmarkError("model context capacity exceeded")
    draft = ReviewDraft.model_validate(_json(message["content"]))
    return BenchmarkResult(
        resolve_review_draft(draft, request),
        UsageObservation(
            input_tokens=counts[0], output_tokens=counts[1], latency_ms=elapsed, cost_usd=0.0
        ),
        digest,
    )
