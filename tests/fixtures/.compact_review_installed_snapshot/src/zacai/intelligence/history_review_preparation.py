"""Dormant full-answer reviewer input; no authority, runtime or recovery.

Inputs/route/pins are trusted-host declarations, not authenticated provenance.
No model output may supply task/builder/reviewer IDs or packet/body digests.
Never capture traceback locals: private packet/text arguments remain in frames.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualAssessment, ContextualCriterion
from zacai.intelligence.contracts import Contract, ModelRoute
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualRequestV1,
    decode_history_contextual_packet,
    encode_history_contextual_request,
)
from zacai.intelligence.history_generation_review_declaration import (
    HistoryReviewPurposeProfileV1,
    history_review_profile_digest,
)
from zacai.policy import AccessRequest, Destination, evaluate_access

PURPOSE = "history_complete_independent_review"
MAX_REVIEW_BODY_BYTES = 64_000
MAX_JUDGMENTS_BYTES = 8_000
MAX_INSTRUCTION_BYTES = 4_000


class HistoryReviewPreparationError(ValueError):
    """Fixed diagnostics; input declarations confer no permission."""


class HistoryReviewJudgments(Contract):
    """Only the10 closed judgments, never model-authored host provenance."""

    format: Literal["zac-history-complete-review-judgments-v1"]
    assessments: tuple[ContextualAssessment, ...] = Field(min_length=10, max_length=10, repr=False)

    @model_validator(mode="after")
    def criteria_once(self) -> Self:
        if {v.criterion for v in self.assessments} != set(ContextualCriterion):
            raise ValueError("each criterion once")
        return self


@dataclass(frozen=True, repr=False)
class PreparedHistoryReviewRequest:
    task_id: UUID
    builder_id: UUID
    reviewer_id: UUID
    run_id: UUID
    packet_digest: str
    rubric_digest: str
    template_digest: str
    model_digest: str
    reviewer_wire_digest: str
    purpose: HistoryReviewPurposeProfileV1
    purpose_digest: str
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


def _packet_review_view(packet_raw: bytes) -> dict[str, object]:
    """Lossless review-only view, never a new retained packet codec.

    Avoid re-escaping the embedded canonical request JSON as a string. All
    request/packet fields remain present. The original packet bytes and digest
    are reconstructed and compared before preparation/rendering.
    """
    packet = decode_history_contextual_packet(packet_raw)
    data: dict[str, object] = json.loads(packet_raw)
    data.pop("request_json")
    data["request"] = json.loads(encode_history_contextual_request(packet.request()))
    return data


def _packet_from_review_view(value: object) -> bytes:
    if type(value) is not dict or "request_json" in value or type(value.get("request")) is not dict:
        raise ValueError("exact packet review representation required")
    data = dict(value)
    data["request_json"] = canonical_bytes(data.pop("request")).decode("utf-8")
    raw = canonical_bytes(data)
    decode_history_contextual_packet(raw)
    if _packet_review_view(raw) != value:
        raise ValueError("lossless complete packet representation required")
    return raw


LEGACY_PACKET_REPRESENTATION = "canonical-history-request-object-v1"
PREVIOUS_LOSSLESS_PACKET_REPRESENTATION = "canonical-history-derived-prompt-json-view-v2"
LOSSLESS_PACKET_REPRESENTATION = "canonical-history-visible-segments-json-view-v3"
_HISTORY_SEGMENTS_MARKER = "zac_review_history_segments_v3"
_JSON_STRING_MARKER = "zac_review_canonical_json_string_v2"
_PROMPT_MARKER = "zac_review_derived_prompt_body_v2"


def _parse_canonical_strings(value: object) -> object:
    """Parse only the validated request's typed canonical projection profiles.

    Never inspect or transform arbitrary source text, instruction, draft text,
    rendered preview or any other string that happens to contain JSON.
    """
    if type(value) is not dict or type(value.get("request")) is not dict:
        raise ValueError("exact typed request view required")
    result = deepcopy(value)
    request = result["request"]
    profiles = request.get("projection_profiles")
    if type(profiles) is not list:
        raise ValueError("typed projection profile array required")
    parsed_profiles = []
    for raw in profiles:
        if type(raw) is not str:
            raise ValueError("canonical profile string required")
        parsed = json.loads(raw)
        if type(parsed) is not dict or canonical_bytes(parsed).decode("utf-8") != raw:
            raise ValueError("canonical profile object required")
        parsed_profiles.append({_JSON_STRING_MARKER: parsed})
    request["projection_profiles"] = parsed_profiles
    return result


def _restore_canonical_strings(value: object) -> object:
    if type(value) is not dict or type(value.get("request")) is not dict:
        raise ValueError("exact typed request view required")
    result = deepcopy(value)
    request = result["request"]
    profiles = request.get("projection_profiles")
    if type(profiles) is not list:
        raise ValueError("typed projection profile array required")
    restored = []
    for profile in profiles:
        if (
            type(profile) is not dict
            or set(profile) != {_JSON_STRING_MARKER}
            or type(profile[_JSON_STRING_MARKER]) is not dict
        ):
            raise ValueError("closed canonical profile marker required")
        restored.append(canonical_bytes(profile[_JSON_STRING_MARKER]).decode("utf-8"))
    request["projection_profiles"] = restored
    return result


def _segment_history_tail(view: dict[str, object]) -> None:
    request = view["request"]
    if type(request) is not dict:
        raise ValueError("exact history request required")
    entries = request["sidecar"]["entries"]
    tail = request["task"]["context"][-1]
    text = tail["untrusted_text"]
    if type(text) is not str:
        raise ValueError("literal history text required")
    tail["untrusted_text"] = {
        _HISTORY_SEGMENTS_MARKER: [
            {
                "index": i,
                "message_id": e["message_id"],
                "historical_role": e["historical_role"],
                "reported_created_at": e["reported_created_at"],
                "reported_updated_at": e["reported_updated_at"],
                "text": text[e["context_character_start"] : e["context_character_end"]],
            }
            for i, e in enumerate(entries)
        ]
    }


def _restore_history_tail(view: dict[str, object]) -> None:
    request = view["request"]
    if type(request) is not dict:
        raise ValueError("exact history request required")
    entries = request["sidecar"]["entries"]
    tail = request["task"]["context"][-1]
    marker = tail["untrusted_text"]
    if type(marker) is not dict or set(marker) != {_HISTORY_SEGMENTS_MARKER}:
        raise ValueError("closed history segments marker required")
    segments = marker[_HISTORY_SEGMENTS_MARKER]
    if type(segments) is not list or len(segments) != len(entries):
        raise ValueError("one exact visible segment per sidecar entry required")
    texts = []
    fields = {
        "index",
        "message_id",
        "historical_role",
        "reported_created_at",
        "reported_updated_at",
        "text",
    }
    for i, (segment, entry) in enumerate(zip(segments, entries, strict=True)):
        if (
            type(segment) is not dict
            or set(segment) != fields
            or type(segment["index"]) is not int
            or segment["index"] != i
            or type(segment["text"]) is not str
        ):
            raise ValueError("closed index-aligned history segment required")
        if any(segment[k] != entry[k] for k in fields - {"index", "text"}):
            raise ValueError("visible history role/date/identity differs")
        texts.append(segment["text"])
    tail["untrusted_text"] = "\n".join(texts)


def _lossless_packet_view(packet_raw: bytes, *, segments: bool = True) -> object:
    view = _packet_review_view(packet_raw)
    request = view["request"]
    if type(request) is not dict or _PROMPT_MARKER in request:
        raise ValueError("exact request representation required")
    prompt = request.pop("prompt_body")
    if type(prompt) is not str:
        raise ValueError("exact prompt required")
    request[_PROMPT_MARKER] = {
        "format": "installed-history-context-body-v1",
        "sha256": content_hash_of(prompt.encode("utf-8")),
    }
    if segments:
        _segment_history_tail(view)
    result = _parse_canonical_strings(view)
    if _packet_from_lossless_view(result, segments=segments) != packet_raw:
        raise ValueError("exact packet roundtrip required")
    return result


def _packet_from_lossless_view(value: object, *, segments: bool = True) -> bytes:
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.history_context_metadata import (
        ClaudeMessageMetadata,
        render_history_context_body,
    )
    from zacai.intelligence.meeting_review import ReviewContext

    view = _restore_canonical_strings(value)
    if type(view) is not dict or type(view.get("request")) is not dict:
        raise ValueError("closed complete review view required")
    if segments:
        _restore_history_tail(view)
    request = view["request"]
    if "prompt_body" in request:
        raise ValueError("conflicting derived prompt")
    marker = request.pop(_PROMPT_MARKER)
    if (
        type(marker) is not dict
        or set(marker) != {"format", "sha256"}
        or marker["format"] != "installed-history-context-body-v1"
    ):
        raise ValueError("exact prompt derivation required")
    context = ReviewContext(
        IntelligenceTask.model_validate(request["task"]),
        UUID(request["meeting_source_id"]),
        frozenset(UUID(x) for x in request["related_source_ids"]),
    )
    body = render_history_context_body(
        context,
        tuple(ClaudeMessageMetadata.model_validate(e) for e in request["sidecar"]["entries"]),
        ModelRoute.model_validate(request["route"]),
    )
    if content_hash_of(body) != marker["sha256"]:
        raise ValueError("derived prompt digest differs")
    request["prompt_body"] = body.decode("utf-8")
    return _packet_from_review_view(view)


def _review_packet_raw(value: object, representation: str) -> bytes:
    if representation == LEGACY_PACKET_REPRESENTATION:
        return _packet_from_review_view(value)
    if representation in (LOSSLESS_PACKET_REPRESENTATION, PREVIOUS_LOSSLESS_PACKET_REPRESENTATION):
        segments = representation == LOSSLESS_PACKET_REPRESENTATION
        raw = _packet_from_lossless_view(value, segments=segments)
        # Require canonical marker placement and every complete field exactly once.
        legacy = _packet_review_view(raw)
        request = legacy["request"]
        if type(request) is not dict:
            raise ValueError("exact request required")
        prompt = request.pop("prompt_body")
        request[_PROMPT_MARKER] = {
            "format": "installed-history-context-body-v1",
            "sha256": content_hash_of(str(prompt).encode("utf-8")),
        }
        if segments:
            _segment_history_tail(legacy)
        if _parse_canonical_strings(legacy) != value:
            raise ValueError("noncanonical review representation")
        return raw
    raise ValueError("unsupported complete review representation")


def prepare_history_review_request(
    packet_raw: bytes,
    *,
    expected_packet_digest: str,
    expected_task_id: UUID,
    expected_builder_id: UUID,
    expected_request: HistoryContextualRequestV1,
    review: HistoryReviewPurposeProfileV1,
    rubric_utf8: bytes,
    template_utf8: bytes,
    packet_representation: str = LOSSLESS_PACKET_REPRESENTATION,
) -> PreparedHistoryReviewRequest:
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
        if type(review) is not HistoryReviewPurposeProfileV1:
            raise ValueError("exact complete review purpose required")
        review = HistoryReviewPurposeProfileV1.model_validate(review.model_dump(mode="json"))
        reviewer_id, run_id, route = review.reviewer_id, review.run_id, review.route
        max_output_tokens, max_latency_ms = review.max_output_tokens, review.max_latency_ms
        model_digest, reviewer_wire_digest = review.model_digest, review.reviewer_wire_digest
        expected_rubric_digest, expected_template_digest = (
            review.rubric_digest,
            review.template_digest,
        )
        for digest in (expected_packet_digest,):
            _digest(digest)
        for uid in (expected_task_id, expected_builder_id, reviewer_id, run_id):
            if type(uid) is not UUID or uid.int == 0:
                raise ValueError("exact nonzero host identity required")
        if reviewer_id == expected_builder_id or run_id == expected_task_id:
            raise ValueError("distinct assigned reviewer/run required")
        packet = decode_history_contextual_packet(packet_raw)
        request = packet.request()
        if (
            content_hash_of(packet_raw) != expected_packet_digest
            or packet.builder_id != expected_builder_id
            or request.task.task_id != expected_task_id
            or type(expected_request) is not HistoryContextualRequestV1
            or encode_history_contextual_request(request)
            != encode_history_contextual_request(expected_request)
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
                "format": "zac-history-complete-independent-review-input-v1",
                "purpose": PURPOSE,
                "packet_digest": expected_packet_digest,
                "task_id": str(expected_task_id),
                "builder_id": str(expected_builder_id),
                "reviewer_id": str(reviewer_id),
                "run_id": str(run_id),
                "packet_representation": packet_representation,
                "packet": (
                    _packet_review_view(packet_raw)
                    if packet_representation == LEGACY_PACKET_REPRESENTATION
                    else _lossless_packet_view(
                        packet_raw,
                        segments=packet_representation != PREVIOUS_LOSSLESS_PACKET_REPRESENTATION,
                    )
                ),
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
                "review_purpose": {
                    **review.model_dump(mode="json"),
                    "route": {
                        **review.route.model_dump(mode="json"),
                        "capabilities": sorted(review.route.capabilities),
                    },
                },
                "review_purpose_digest": history_review_profile_digest(review),
            }
        )
        if _review_packet_raw(json.loads(body)["packet"], packet_representation) != packet_raw:
            raise ValueError("original packet bytes must survive representation")
        if len(body) > MAX_REVIEW_BODY_BYTES or len(body.decode()) > route.max_input_characters:
            raise ValueError("whole review input too large; never truncate")
        result = PreparedHistoryReviewRequest(
            expected_task_id,
            expected_builder_id,
            reviewer_id,
            run_id,
            expected_packet_digest,
            content_hash_of(rubric_utf8),
            content_hash_of(template_utf8),
            model_digest,
            reviewer_wire_digest,
            review,
            history_review_profile_digest(review),
            route,
            max_output_tokens,
            max_latency_ms,
            body,
            content_hash_of(body),
            content_hash_of(b"zac-history-complete-independent-review-request-v1\x00" + body),
        )
    except Exception:  # noqa: BLE001,S110 - fixed private-safe diagnostics outside handler
        pass
    if result is None:
        raise HistoryReviewPreparationError(
            "history reviewer preparation unavailable or mismatched"
        )
    return result


def parse_history_review_judgments(raw: bytes) -> HistoryReviewJudgments:
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
        result = HistoryReviewJudgments.model_validate(data)
    except Exception:  # noqa: BLE001,S110 - no raw response diagnostics
        pass
    if result is None:
        raise HistoryReviewPreparationError("history review judgments unavailable or invalid")
    return result


def verify_history_review_request(
    value: PreparedHistoryReviewRequest,
    *,
    packet_raw: bytes,
    expected_request: HistoryContextualRequestV1,
    rubric_utf8: bytes,
    template_utf8: bytes,
) -> None:
    """Pure reconstruction only; declaration consistency is not permission."""
    failed = True
    try:
        if type(value) is not PreparedHistoryReviewRequest:
            raise TypeError("exact prepared declaration required")
        rebuilt = prepare_history_review_request(
            packet_raw,
            expected_packet_digest=value.packet_digest,
            expected_task_id=value.task_id,
            expected_builder_id=value.builder_id,
            expected_request=expected_request,
            review=value.purpose,
            packet_representation=json.loads(value.body)["packet_representation"],
            rubric_utf8=rubric_utf8,
            template_utf8=template_utf8,
        )
        if value != rebuilt:
            raise ValueError("full declared body changed")
        failed = False
    except Exception:  # noqa: BLE001,S110 - no raw declared body diagnostics
        pass
    if failed:
        raise HistoryReviewPreparationError(
            "history reviewer preparation unavailable or mismatched"
        )
