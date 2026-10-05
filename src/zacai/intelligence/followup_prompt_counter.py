"""Offline exact packet-follow-up wire counter, never processing authority.

Reuses the reviewed Qwen3.8/Ollama0.35.1 renderer and pinned installed tokenizer.
No weights, template execution, source reads or model calls occur while counting.
Runtime version verification remains a separate prerequisite, not conformance.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.contextual_review import ContextualReview
from zacai.intelligence.contracts import ContextItem, EvidenceReference
from zacai.intelligence.local_review_runtime import Transport
from zacai.intelligence.ollama_token_counter import (
    _VERSION,
    LocalTokenCounterError,
    OllamaQwenReviewTokenCounter,
    _render_prompt,
)
from zacai.intelligence.runtime_diagnostics import (
    RuntimeDiagnosticError,
    RuntimeFailureCode,
    closed_runtime_code,
)
from zacai.intelligence.text_followup import FOLLOWUP_INSTRUCTION, FollowupDraft


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate")
        result[name] = value
    return result


def _float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("nonfinite")
    return value


def _constant(raw: str) -> None:
    raise ValueError("nonfinite")


def _json(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant)


def render_followup_prompt(serialized_body: bytes) -> str:
    """Only exact serializer shape; original host bindings are still mandatory."""
    try:
        if type(serialized_body) is not bytes or len(serialized_body) > 64_000:
            raise ValueError("size")
        body = _json(serialized_body.decode("utf-8"))
        if not isinstance(body, dict):
            raise TypeError("shape")
        schema = body["format"]
        expected = FollowupDraft.model_json_schema()
        if not isinstance(schema, dict):
            raise TypeError("schema")
        identities: dict[str, str] = {}
        for name in ("task_id", "user_source_id", "user_content_hash", "packet_digest"):
            value = schema["properties"][name]["const"]
            if type(value) is not str:
                raise TypeError("identity")
            if name.endswith("_id"):
                if str(UUID(value)) != value:
                    raise ValueError("UUID")
            elif not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("digest")
            identities[name] = value
            expected["properties"][name]["const"] = value
        # Canonical bytes distinguish bool/int schema substitutions as well.
        if canonical_bytes(schema) != canonical_bytes(expected):
            raise ValueError("schema")
        schema_text = canonical_bytes(expected).decode("utf-8")
        messages = body["messages"]
        if messages[0]["content"] != FOLLOWUP_INSTRUCTION + "\nOutput JSON schema: " + schema_text:
            raise ValueError("schema injection")
        user_text = messages[1]["content"]
        evidence = _json(user_text)
        if not isinstance(evidence, dict) or set(evidence) != {
            "format",
            "task_id",
            "current_user_question_projection",
            "user_parent_projection",
            "original_evidence",
            "historical_parent_turns",
            "historical_generated_review",
        }:
            raise ValueError("evidence shape")
        if (
            evidence["format"] != "zac-packet-followup-input-v1"
            or evidence["task_id"] != identities["task_id"]
        ):
            raise ValueError("evidence identity")
        question = ContextItem.model_validate(evidence["current_user_question_projection"])
        if len(question.untrusted_text) > 2000:
            raise ValueError("question budget")
        if (
            str(question.reference.source_id) != identities["user_source_id"]
            or question.reference.content_hash != identities["user_content_hash"]
        ):
            raise ValueError("question identity")
        if evidence["user_parent_projection"] != {
            "operation": "strip surrounding whitespace from canonical original text",
            "quote_offsets": "indices in the supplied projection, not stored turn JSON",
            "canonical_envelope": "host retains exact original; declared hash identifies envelope",
        }:
            raise ValueError("projection")
        originals = evidence["original_evidence"]
        parents = evidence["historical_parent_turns"]
        if (
            not isinstance(originals, list)
            or not originals
            or not isinstance(parents, list)
            or len(parents) > 6
        ):
            raise ValueError("context shape")
        for item in [evidence["current_user_question_projection"]] + originals + parents:
            validated = ContextItem.model_validate(item)
            if canonical_bytes(validated.model_dump(mode="json")) != canonical_bytes(item):
                raise ValueError("modified projection")
        review = evidence["historical_generated_review"]
        if not isinstance(review, dict) or set(review) != {
            "reference",
            "created_at",
            "review",
            "status",
        }:
            raise ValueError("review shape")
        if (
            review["status"]
            != "historical generated context; not original evidence or current truth"
        ):
            raise ValueError("review label")
        for model, value in (
            (EvidenceReference, review["reference"]),
            (ContextualReview, review["review"]),
        ):
            if canonical_bytes(
                model.model_validate(value).model_dump(mode="json")
            ) != canonical_bytes(value):
                raise ValueError("review declaration")
        if review["reference"]["content_hash"] != identities["packet_digest"]:
            raise ValueError("packet identity")
        if (
            type(review["created_at"]) is not str
            or datetime.fromisoformat(review["created_at"]).utcoffset() is None
        ):
            raise ValueError("review timestamp")
        if canonical_bytes(evidence).decode("utf-8").replace("<", "\\u003c") != user_text:
            raise ValueError("canonical evidence")
        options = body["options"]
        if type(options["num_predict"]) is not int or not 0 < options["num_predict"] <= 1024:
            raise ValueError("output budget")
        return _render_prompt(serialized_body, expected, context_tokens=frozenset({16384}))
    except Exception:  # noqa: BLE001,S110 - closed diagnostics, no private payload
        pass
    raise LocalTokenCounterError("unsupported local follow-up prompt")


class OllamaQwenFollowupTokenCounter(OllamaQwenReviewTokenCounter):
    """Exact fixed16K follow-up shape; never grants owner/source authority.

    Inherits per-count manifest/blob hash checks and special-token rejection.
    The installed renderer/template pin is manifest-bound; inherited version
    metadata verification must be composed under the trusted host deadline.
    """

    def __init__(self, *, models_root: Path, model_digest: str) -> None:
        super().__init__(models_root=models_root, model_digest=model_digest)

    def verify_runtime_with_transport(self, transport: Transport) -> None:
        """Exact reviewed version through an explicit host deadline transport.

        This metadata check grants no processing or source access. No default
        transport exists here; inherited historical verification is unchanged.
        """
        failure: RuntimeFailureCode | None = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = None
        try:
            reply = transport("GET", "/api/version", None)
            if type(reply) is not dict or set(reply) != {"version"}:
                raise ValueError("version shape")
            if type(reply["version"]) is not str or reply["version"] != _VERSION:
                raise ValueError("version mismatch")
            return
        except BaseException as error:  # noqa: BLE001 - sanitize interruption diagnostics too
            code = closed_runtime_code(error)
            if code in (RuntimeFailureCode.TRANSPORT, RuntimeFailureCode.TOTAL_LATENCY):
                failure = code
            if not isinstance(error, Exception):
                interruption = type(error)
                if isinstance(error, SystemExit) and type(error.code) is int:
                    exit_code = error.code
        if interruption is not None:
            if issubclass(interruption, SystemExit):
                raise SystemExit(exit_code)
            if issubclass(interruption, asyncio.CancelledError):
                raise asyncio.CancelledError
            raise KeyboardInterrupt
        if failure is not None:
            raise RuntimeDiagnosticError("local tokenizer metadata unavailable", code=failure)
        raise LocalTokenCounterError("local tokenizer runtime mismatch")

    def _render(self, serialized_body: bytes) -> str:
        return render_followup_prompt(serialized_body)

    def count_prompt_tokens(self, serialized_body: bytes) -> int:
        count = super().count_prompt_tokens(serialized_body)
        try:
            body = _json(serialized_body.decode("utf-8"))
            assert isinstance(body, dict)
            if count + body["options"]["num_predict"] > 16384:
                raise ValueError("capacity")
            return count
        except Exception:  # noqa: BLE001,S110
            pass
        raise LocalTokenCounterError("local follow-up prompt outside capacity")
