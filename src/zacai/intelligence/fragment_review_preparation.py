"""Dormant full-answer reviewer input; no authority, runtime or recovery.

Inputs/route/pins are trusted-host declarations, not authenticated provenance.
No model output may supply task/builder/reviewer IDs or packet/body digests.
Never capture traceback locals: private packet/text arguments remain in frames.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualAssessment, ContextualCriterion
from zacai.intelligence.contracts import Contract, ModelRoute
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_packet,
)
from zacai.policy import AccessRequest, Destination, evaluate_access

PURPOSE = "history_fragment_independent_review"
MAX_REVIEW_BODY_BYTES = 64_000
MAX_JUDGMENTS_BYTES = 8_000
MAX_INSTRUCTION_BYTES = 4_000


class FragmentReviewPreparationError(ValueError):
    """Fixed diagnostics; input declarations confer no permission."""


class FragmentReviewJudgments(Contract):
    """Only the10 closed judgments, never model-authored host provenance."""

    format: Literal["zac-history-fragment-review-judgments-v1"]
    assessments: tuple[ContextualAssessment, ...] = Field(min_length=10, max_length=10, repr=False)

    @model_validator(mode="after")
    def criteria_once(self) -> Self:
        if {v.criterion for v in self.assessments} != set(ContextualCriterion):
            raise ValueError("each criterion once")
        return self


@dataclass(frozen=True, repr=False)
class PreparedFragmentReviewRequest:
    task_id: UUID
    builder_id: UUID
    reviewer_id: UUID
    run_id: UUID
    packet_digest: str
    rubric_digest: str
    template_digest: str
    model_digest: str
    reviewer_wire_digest: str
    route: ModelRoute
    max_output_tokens: int
    max_latency_ms: int
    body: bytes
    body_digest: str
    request_digest: str
    processing_authorized: Literal[False] = field(default=False, init=False)
    reviewer_authenticated: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def _digest(value: object) -> None:
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("exact digest required")


def _text(raw: bytes) -> str:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INSTRUCTION_BYTES:
        raise ValueError("bounded exact instruction required")
    text = raw.decode("utf-8", errors="strict")
    if not text.strip():
        raise ValueError("nonblank instruction required")
    return text


def prepare_fragment_review_request(
    packet_raw: bytes,
    *,
    expected_packet_digest: str,
    expected_task_id: UUID,
    expected_builder_id: UUID,
    reviewer_id: UUID,
    run_id: UUID,
    route: ModelRoute,
    max_output_tokens: int,
    max_latency_ms: int,
    rubric_utf8: bytes,
    template_utf8: bytes,
    expected_rubric_digest: str,
    expected_template_digest: str,
    model_digest: str,
    reviewer_wire_digest: str,
) -> PreparedFragmentReviewRequest:
    """Exact whole packet plus schema/rubric, never truncate or dispatch.

    Model-facing body is canonical input for a future family-specific adapter;
    it is not an Ollama/OpenAI transport body and has no enabled consumer. Any
    future wire adds overhead and needs exact tokenizer/transport capacity checks.
    These host-declared scope/pins are comparison data, not approval or review.
    Requested budgets are preparation ceilings, not enforced runtime deadlines;
    advertised route capacity may exceed the requested output budget.
    Cost admission and actual tokenizer/wire/timing enforcement remain deferred.
    """
    result = None
    try:
        for digest in (
            expected_packet_digest,
            model_digest,
            reviewer_wire_digest,
            expected_rubric_digest,
            expected_template_digest,
        ):
            _digest(digest)
        for uid in (expected_task_id, expected_builder_id, reviewer_id, run_id):
            if type(uid) is not UUID or uid.int == 0:
                raise ValueError("exact nonzero host identity required")
        if reviewer_id == expected_builder_id or run_id == expected_task_id:
            raise ValueError("distinct assigned reviewer/run required")
        packet = decode_history_fragment_contextual_packet(packet_raw)
        request = packet.request()
        if (
            content_hash_of(packet_raw) != expected_packet_digest
            or packet.builder_id != expected_builder_id
            or request.task.task_id != expected_task_id
        ):
            raise ValueError("exact retained packet binding required")
        if type(route) is not ModelRoute:
            raise ValueError("typed declared local route required")
        route = ModelRoute.model_validate(route)
        if (
            type(max_output_tokens) is not int
            or not 1 <= max_output_tokens <= 2048
            or type(max_latency_ms) is not int
            or not 1 <= max_latency_ms <= 60_000
        ):
            raise ValueError("bounded requested review budget required")
        if (
            route.destination is not Destination.LOCAL
            or route.available is not True
            or route.capabilities != frozenset({PURPOSE})
            or max_output_tokens > route.max_output_tokens
            or route.estimated_latency_ms > max_latency_ms
        ):
            raise ValueError("closed local reviewer candidate required")
        event = request.task.event
        checks = [
            (event.trust_boundary, event.data_classification),
            *(
                (i.reference.trust_boundary, i.reference.effective_classification)
                for i in request.task.context
            ),
        ]
        if any(
            boundary is not event.trust_boundary
            or not evaluate_access(
                AccessRequest(
                    data_boundary=boundary,
                    data_classification=label,
                    requestor_boundaries=frozenset({event.trust_boundary}),
                    destination=Destination.LOCAL,
                )
            ).allowed
            for boundary, label in checks
        ):
            raise ValueError("single declared source boundary required")
        rubric, template = _text(rubric_utf8), _text(template_utf8)
        if (
            content_hash_of(rubric_utf8) != expected_rubric_digest
            or content_hash_of(template_utf8) != expected_template_digest
        ):
            raise ValueError("exact declared rubric/template required")
        body = canonical_bytes(
            {
                "format": "zac-history-fragment-independent-review-input-v1",
                "purpose": PURPOSE,
                "packet_digest": expected_packet_digest,
                "task_id": str(expected_task_id),
                "builder_id": str(expected_builder_id),
                "reviewer_id": str(reviewer_id),
                "run_id": str(run_id),
                "packet": json.loads(packet_raw),
                "review_budgets": {
                    "max_output_tokens": max_output_tokens,
                    "max_latency_ms": max_latency_ms,
                },
                "review_instruction": template,
                "rubric": rubric,
                "rubric_digest": content_hash_of(rubric_utf8),
                "template_digest": content_hash_of(template_utf8),
                "route": {
                    **route.model_dump(mode="json"),
                    "capabilities": sorted(route.capabilities),
                },
                "model_digest": model_digest,
                "reviewer_wire_digest": reviewer_wire_digest,
                "judgments_schema": FragmentReviewJudgments.model_json_schema(),
            }
        )
        if len(body) > MAX_REVIEW_BODY_BYTES or len(body.decode()) > route.max_input_characters:
            raise ValueError("whole review input too large; never truncate")
        result = PreparedFragmentReviewRequest(
            expected_task_id,
            expected_builder_id,
            reviewer_id,
            run_id,
            expected_packet_digest,
            content_hash_of(rubric_utf8),
            content_hash_of(template_utf8),
            model_digest,
            reviewer_wire_digest,
            route,
            max_output_tokens,
            max_latency_ms,
            body,
            content_hash_of(body),
            content_hash_of(b"zac-history-fragment-independent-review-request-v1\x00" + body),
        )
    except Exception:  # noqa: BLE001,S110 - fixed private-safe diagnostics outside handler
        pass
    if result is None:
        raise FragmentReviewPreparationError(
            "fragment reviewer preparation unavailable or mismatched"
        )
    return result


def parse_fragment_review_judgments(raw: bytes) -> FragmentReviewJudgments:
    """Closed returned judgments only; no evaluator/provenance construction."""
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_JUDGMENTS_BYTES:
            raise ValueError("bounded exact response required")

        def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
            data: dict[str, object] = {}
            for key, value in values:
                if key in data:
                    raise ValueError("duplicate key")
                data[key] = value
            return data

        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        result = FragmentReviewJudgments.model_validate(data)
    except Exception:  # noqa: BLE001,S110 - no raw response diagnostics
        pass
    if result is None:
        raise FragmentReviewPreparationError("fragment review judgments unavailable or invalid")
    return result


def verify_fragment_review_request(
    value: PreparedFragmentReviewRequest,
    *,
    packet_raw: bytes,
    rubric_utf8: bytes,
    template_utf8: bytes,
) -> None:
    """Pure reconstruction only; declaration consistency is not permission."""
    failed = True
    try:
        if type(value) is not PreparedFragmentReviewRequest:
            raise TypeError("exact prepared declaration required")
        rebuilt = prepare_fragment_review_request(
            packet_raw,
            expected_packet_digest=value.packet_digest,
            expected_task_id=value.task_id,
            expected_builder_id=value.builder_id,
            reviewer_id=value.reviewer_id,
            run_id=value.run_id,
            route=value.route,
            max_output_tokens=value.max_output_tokens,
            max_latency_ms=value.max_latency_ms,
            rubric_utf8=rubric_utf8,
            template_utf8=template_utf8,
            expected_rubric_digest=value.rubric_digest,
            expected_template_digest=value.template_digest,
            model_digest=value.model_digest,
            reviewer_wire_digest=value.reviewer_wire_digest,
        )
        if value != rebuilt:
            raise ValueError("full declared body changed")
        failed = False
    except Exception:  # noqa: BLE001,S110 - no raw declared body diagnostics
        pass
    if failed:
        raise FragmentReviewPreparationError(
            "fragment reviewer preparation unavailable or mismatched"
        )
