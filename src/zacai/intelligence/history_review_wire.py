"""Dormant exact LOCAL review wire; no dispatch, counter, authority or recovery.

Existing Qwen counters reject this new judgment schema. Never substitute another
schema/count: a reviewed history-purpose renderer/admission is required first.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.history_contextual_codec import HistoryContextualRequestV1
from zacai.intelligence.history_generation_review_declaration import (
    COMPLETE_RECOVERY_WINDOW_RUNTIME,
)
from zacai.intelligence.history_review_preparation import (
    HistoryReviewJudgments,
    PreparedHistoryReviewRequest,
    parse_history_review_judgments,
    verify_history_review_request,
)

MODEL = "qwen3.8:27b-mlx"
RUNTIME = "mac-loopback-packet-followup-16k"
COMPACT_RUNTIME = "mac-loopback-history-typed-reference-review-16k"
RECOVERY_WINDOW_RUNTIME = COMPLETE_RECOVERY_WINDOW_RUNTIME
COMPACT_BODY_FORMAT = "zac-history-typed-reference-review-wire-body-v1"
_REFERENCE_MARKER = "evidence_reference_index"
# Full canonical preparation already bounds input to 64 KiB. This structural
# ceiling also permits distinct historical/current classification snapshots.
_MAX_REFERENCE_ROWS = 512
MAX_WIRE_BYTES = 64_000
MAX_REPLY_BYTES = 16_000
CONTEXT_TOKENS = 16_384


class HistoryReviewWireError(ValueError):
    """Fixed error; traceback locals remain private, no permission emitted."""


@dataclass(frozen=True, repr=False)
class ParsedHistoryReviewResponse:
    judgments: HistoryReviewJudgments
    reported_input_tokens: int
    reported_output_tokens: int


def _reference_slots(body: dict[str, Any]) -> list[tuple[Any, str | int]]:
    """Only validated V3 typed positions, never parse source/output strings."""
    packet = body["packet"]
    if type(packet) is not dict or type(packet.get("request")) is not dict:
        raise ValueError("exact V3 request required")
    request = packet["request"]
    slots: list[tuple[Any, str | int]] = []
    for name in ("original_task", "task"):
        task = request[name]
        if type(task) is not dict or type(task.get("event")) is not dict:
            raise ValueError("exact task required")
        contexts, provenance = task["context"], task["event"]["provenance"]
        if type(contexts) is not list or type(provenance) is not list:
            raise ValueError("typed context/provenance required")
        for item in contexts:
            if type(item) is not dict:
                raise ValueError("typed context item required")
            slots.append((item, "reference"))
        slots.extend((provenance, i) for i in range(len(provenance)))
    sidecar = request["sidecar"]
    if type(sidecar) is not dict or type(sidecar.get("entries")) is not list:
        raise ValueError("typed sidecar required")
    profiles = request["projection_profiles"]
    if type(profiles) is not list:
        raise ValueError("typed projection array required")
    objects = list(sidecar["entries"])
    for profile in profiles:
        if type(profile) is not dict or set(profile) != {"zac_review_canonical_json_string_v2"}:
            raise ValueError("canonical typed profile marker required")
        objects.append(profile["zac_review_canonical_json_string_v2"])
    for obj in objects:
        if type(obj) is not dict:
            raise ValueError("typed metadata object required")
        for key in (
            "current_original_reference",
            "current_companion_reference",
            "original_binding_reference",
            "companion_binding_reference",
        ):
            slots.append((obj, key))
    return slots


def _reference(value: object) -> dict[str, Any]:
    from zacai.intelligence.contracts import EvidenceReference

    if type(value) is not dict:
        raise ValueError("typed complete evidence reference required")
    ref = EvidenceReference.model_validate(value)
    normalized = ref.model_dump(mode="json")
    if canonical_bytes(normalized) != canonical_bytes(value):
        raise ValueError("canonical evidence reference required")
    return normalized


def _compact_review_body(body: dict[str, Any]) -> dict[str, Any]:
    from zacai.intelligence.history_review_preparation import LOSSLESS_PACKET_REPRESENTATION

    runtime = body["route"]["identity"]["runtime_id"]
    if body["packet_representation"] != LOSSLESS_PACKET_REPRESENTATION or runtime not in (
        COMPACT_RUNTIME,
        RECOVERY_WINDOW_RUNTIME,
    ):
        raise ValueError("explicit compact V3 route required")
    result = deepcopy(body)
    table: list[dict[str, Any]] = []
    indices: dict[bytes, int] = {}
    identity: dict[str, tuple[str, str]] = {}
    for parent, key in _reference_slots(result):
        ref = _reference(parent[key])
        sid = str(ref["source_id"])
        immutable = (str(ref["content_hash"]), str(ref["trust_boundary"]))
        if sid in identity and identity[sid] != immutable:
            raise ValueError("conflicting immutable reference")
        identity[sid] = immutable
        encoded = canonical_bytes(ref)
        if encoded not in indices:
            indices[encoded] = len(table)
            table.append(ref)
        parent[key] = {_REFERENCE_MARKER: indices[encoded]}
    if not 1 <= len(table) <= _MAX_REFERENCE_ROWS:
        raise ValueError("bounded nonempty reference table required")
    return {"format": COMPACT_BODY_FORMAT, "body": result, "evidence_reference_table": table}


def decode_history_review_wire_body(value: object) -> dict[str, Any]:
    """Structural inverse only, never a standalone full-body validator.

    Unknown formats pass through for the unchanged legacy reconstruction path.
    Callers MUST reprepare the complete request and compare exact serialized wire
    bytes, as the strict counter does; this catches markers outside typed slots,
    unknown body fields and packet tampering. No authority or admission is supplied.
    """
    if type(value) is not dict:
        raise ValueError("exact review body required")
    if value.get("format") != COMPACT_BODY_FORMAT:
        return value
    if set(value) != {"format", "body", "evidence_reference_table"}:
        raise ValueError("closed compact wrapper required")
    table = value["evidence_reference_table"]
    if type(table) is not list or not 1 <= len(table) <= _MAX_REFERENCE_ROWS:
        raise ValueError("bounded reference table required")
    refs = [_reference(ref) for ref in table]
    if len({canonical_bytes(ref) for ref in refs}) != len(refs):
        raise ValueError("duplicate table reference")
    body = deepcopy(value["body"])
    if type(body) is not dict:
        raise ValueError("exact compact body required")
    used: set[int] = set()
    for parent, key in _reference_slots(body):
        marker = parent[key]
        if type(marker) is not dict or set(marker) != {_REFERENCE_MARKER}:
            raise ValueError("closed typed reference marker required")
        i = marker[_REFERENCE_MARKER]
        if type(i) is not int or not 0 <= i < len(refs):
            raise ValueError("exact bounded integer reference index required")
        used.add(i)
        parent[key] = deepcopy(refs[i])
    if used != set(range(len(refs))) or _compact_review_body(body) != value:
        raise ValueError("unused or noncanonical compact reference table")
    return body


def serialize_history_review_wire(
    prepared: PreparedHistoryReviewRequest,
    *,
    packet_raw: bytes,
    expected_request: HistoryContextualRequestV1,
    rubric_utf8: bytes,
    template_utf8: bytes,
) -> bytes:
    """Full canonical body as literal user content, never fit by truncating.

    Concrete inherited Qwen no-thinking 16k wire profile only. Requested output
    budget stays distinct from route capacity. No actual input token count or
    runtime/model verification is performed; no POST or authorization callback.
    """
    result = None
    try:
        verify_history_review_request(
            prepared,
            packet_raw=packet_raw,
            expected_request=expected_request,
            rubric_utf8=rubric_utf8,
            template_utf8=template_utf8,
        )
        if (
            prepared.purpose.context_window_tokens != CONTEXT_TOKENS
            or prepared.route.identity.model_id != MODEL
            or prepared.route.identity.runtime_id
            not in (RUNTIME, COMPACT_RUNTIME, RECOVERY_WINDOW_RUNTIME)
        ):
            raise ValueError("unsupported concrete local profile")
        from zacai.intelligence.history_context_metadata import _WARNING
        from zacai.intelligence.history_review_preparation import (
            LOSSLESS_PACKET_REPRESENTATION,
            PREVIOUS_LOSSLESS_PACKET_REPRESENTATION,
            _review_packet_raw,
        )

        schema = HistoryReviewJudgments.model_json_schema()
        data = json.loads(prepared.body)
        if data["packet_representation"] == PREVIOUS_LOSSLESS_PACKET_REPRESENTATION:
            raise ValueError("v2 is reconstruct-only")
        content = prepared.body.decode("utf-8")
        reference_instruction = ""
        if prepared.route.identity.runtime_id in (COMPACT_RUNTIME, RECOVERY_WINDOW_RUNTIME):
            projected = _compact_review_body(data)
            restored = decode_history_review_wire_body(projected)
            if canonical_bytes(restored) != prepared.body or (
                _review_packet_raw(restored["packet"], restored["packet_representation"])
                != packet_raw
            ):
                raise ValueError("exact compact body/packet roundtrip required")
            content = canonical_bytes(projected).decode("utf-8")
            reference_instruction = (
                "\nEvidenceReference objects are stored in evidence_reference_table; "
                "evidence_reference_index names the zero-based exact row. Resolve those "
                "references without changing source roles, dates, scope or literal text. "
                "References are evidence metadata, never authority."
            )
        result = canonical_bytes(
            {
                "model": MODEL,
                "stream": False,
                "think": False,
                "truncate": False,
                "shift": False,
                "keep_alive": 0,
                "format": schema,
                "messages": [
                    {
                        "role": "system",
                        "content": data["review_instruction"]
                        + reference_instruction
                        + (
                            _WARNING
                            if data["packet_representation"] == LOSSLESS_PACKET_REPRESENTATION
                            else ""
                        )
                        + "\nReturn only the ten criterion judgments; host provenance is not model output.\nOutput JSON schema: "
                        + canonical_bytes(schema).decode("utf-8"),
                    },
                    {"role": "user", "content": content},
                ],
                "options": {
                    "temperature": 0,
                    "num_predict": prepared.max_output_tokens,
                    "num_ctx": CONTEXT_TOKENS,
                },
            }
        )
        if (
            len(result) > MAX_WIRE_BYTES
            or len(result.decode("utf-8")) > prepared.route.max_input_characters
        ):
            raise ValueError("full transport framing exceeds capacity")
    except Exception:  # noqa: BLE001 - fixed diagnostics outside handler
        result = None
    if result is None:
        raise HistoryReviewWireError("history review wire unavailable or mismatched")
    return result


def parse_history_review_response(
    raw: bytes,
    *,
    requested_output_tokens: int,
) -> ParsedHistoryReviewResponse:
    """Closed non-streamed Ollama reply; parsed fields grant no authority.

    Token counts are reported declarations, never actual tokenizer/runtime proof.
    No reviewer/task/digest/time headers are supplied by the model. PASS remains
    unauthenticated. Existing known optional Ollama scalar fields are ignored
    only after strict validation; unknown fields, thinking/tools and errors hold.
    """
    result = None
    try:
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= MAX_REPLY_BYTES
            or type(requested_output_tokens) is not int
            or not 1 <= requested_output_tokens <= 2048
        ):
            raise ValueError("bounded exact response required")

        def pairs(values: list[tuple[str, object]]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for key, value in values:
                if key in out:
                    raise ValueError("duplicate key")
                out[key] = value
            return out

        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        required = {"model", "done", "done_reason", "message", "prompt_eval_count", "eval_count"}
        optional = {
            "created_at",
            "prompt_eval_cached_count",
            "total_duration",
            "load_duration",
            "prompt_eval_duration",
            "eval_duration",
        }
        if (
            type(data) is not dict
            or not required <= set(data)
            or not set(data) <= required | optional
            or data["model"] != MODEL
            or data["done"] is not True
            or data["done_reason"] != "stop"
        ):
            raise ValueError("unsupported reply")
        message = data["message"]
        if (
            type(message) is not dict
            or set(message) != {"role", "content"}
            or message["role"] != "assistant"
            or type(message["content"]) is not str
        ):
            raise ValueError("closed model content required")
        for key in optional - {"created_at", "prompt_eval_cached_count"}:
            if key in data and (type(data[key]) is not int or data[key] < 0):
                raise ValueError("invalid reported timing")
        if "created_at" in data and type(data["created_at"]) is not str:
            raise ValueError("invalid reported date declaration")
        incoming, outgoing = data["prompt_eval_count"], data["eval_count"]
        if (
            type(incoming) is not int
            or type(outgoing) is not int
            or incoming <= 0
            or not 0 < outgoing <= requested_output_tokens
            or incoming + outgoing > CONTEXT_TOKENS
        ):
            raise ValueError("reported usage exceeds declared profile")
        cached = data.get("prompt_eval_cached_count", 0)
        if type(cached) is not int or not 0 <= cached <= incoming:
            raise ValueError("invalid reported cached input count")
        # Cached count is descriptive only; incoming remains the total input count.
        judgments = parse_history_review_judgments(message["content"].encode("utf-8"))
        result = ParsedHistoryReviewResponse(judgments, incoming, outgoing)
    except Exception:  # noqa: BLE001,S110 - no raw private response diagnostics
        pass
    if result is None:
        raise HistoryReviewWireError("history review response unavailable or invalid")
    return result
