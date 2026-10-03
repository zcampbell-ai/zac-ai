"""D034B synthetic-only local review benchmark, not production dispatch.

Only SHARED/PUBLIC declared fixtures are accepted. No real content, credentials,
tools, auto-pulls, fallback, state writes or service configuration changes.
The fixed loopback runtime is trusted; locality cannot be proved against a
malicious server/host by an HTTP client or self-reported model metadata.
"""

from __future__ import annotations

import http.client  # noqa: F401 - compatibility for existing transport tests
import time  # noqa: F401 - compatibility for existing timing tests
from dataclasses import dataclass
from typing import Any

from zacai.intelligence import local_review_runtime as local_runtime
from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.eligibility import ApprovedRouteRegistry, assess_routes
from zacai.intelligence.meeting_review import MeetingReview, ReviewContext
from zacai.intelligence.review_generation import (
    prepare_review_request,
    resolve_review_draft,
)
from zacai.policy import DataClassification, Destination, TrustBoundary


class BenchmarkError(ValueError):
    """Fixed safe failure; never retains server text or a model exception."""


@dataclass(frozen=True)
class BenchmarkResult:
    review: MeetingReview
    usage: UsageObservation
    model_digest: str


def _http(method: str, path: str, body: bytes | None = None) -> Any:
    try:
        return local_runtime._http(method, path, body)
    except Exception:  # noqa: BLE001 - retain benchmark's safe public error
        raise BenchmarkError("local benchmark unavailable") from None


_json = local_runtime._json


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
    request = prepare_review_request(context)
    body = local_runtime.prepare_payload(request, route, digest)
    local_runtime.verify_model(route.identity.model_id, digest, _http)
    draft, usage = local_runtime.dispatch_draft(request, route, body, _http)
    return BenchmarkResult(resolve_review_draft(draft, request), usage, digest)
