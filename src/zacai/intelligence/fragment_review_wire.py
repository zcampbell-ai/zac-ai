"""Dormant exact LOCAL review wire; no dispatch, counter, authority or recovery.

Existing Qwen counters reject this new judgment schema. Never substitute another
schema/count: a reviewed fragment-purpose renderer/admission is required first.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.fragment_review_preparation import (
    FragmentReviewJudgments,
    PreparedFragmentReviewRequest,
    parse_fragment_review_judgments,
    verify_fragment_review_request,
)

MODEL = "qwen3.8:27b-mlx"
RUNTIME = "mac-loopback-packet-followup-16k"
MAX_WIRE_BYTES = 64_000
MAX_REPLY_BYTES = 16_000
CONTEXT_TOKENS = 16_384


class FragmentReviewWireError(ValueError):
    """Fixed error; traceback locals remain private, no permission emitted."""


@dataclass(frozen=True, repr=False)
class ParsedFragmentReviewResponse:
    judgments: FragmentReviewJudgments
    reported_input_tokens: int
    reported_output_tokens: int


def serialize_fragment_review_wire(
    prepared: PreparedFragmentReviewRequest,
    *,
    packet_raw: bytes,
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
        verify_fragment_review_request(
            prepared,
            packet_raw=packet_raw,
            rubric_utf8=rubric_utf8,
            template_utf8=template_utf8,
        )
        if (
            prepared.route.identity.model_id != MODEL
            or prepared.route.identity.runtime_id != RUNTIME
        ):
            raise ValueError("unsupported concrete local profile")
        schema = FragmentReviewJudgments.model_json_schema()
        data = json.loads(prepared.body)
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
                        + "\nReturn only the ten criterion judgments; host provenance is not model output.\nOutput JSON schema: "
                        + canonical_bytes(schema).decode("utf-8"),
                    },
                    {"role": "user", "content": prepared.body.decode("utf-8")},
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
        raise FragmentReviewWireError("fragment review wire unavailable or mismatched")
    return result


def parse_fragment_review_response(
    raw: bytes,
    *,
    requested_output_tokens: int,
) -> ParsedFragmentReviewResponse:
    """Closed hypothetical non-streamed Ollama reply, not observed dispatch.

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

        def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in values:
                if key in out:
                    raise ValueError("duplicate key")
                out[key] = value
            return out

        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        required = {"model", "done", "done_reason", "message", "prompt_eval_count", "eval_count"}
        optional = {
            "created_at",
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
        for key in optional - {"created_at"}:
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
        judgments = parse_fragment_review_judgments(message["content"].encode("utf-8"))
        result = ParsedFragmentReviewResponse(judgments, incoming, outgoing)
    except Exception:  # noqa: BLE001,S110 - no raw private response diagnostics
        pass
    if result is None:
        raise FragmentReviewWireError("fragment review response unavailable or invalid")
    return result
