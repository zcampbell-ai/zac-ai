"""Pure provider-neutral packet follow-up preparation and strict JSON parsing.

No capture, consent, runtime or release is supplied. The trusted host must still
verify canonical Sources, authorize processing and use release_text_followup with
its independent gate before presenting anything. Never log private frame locals.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Literal

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.text_followup import (
    FOLLOWUP_INSTRUCTION,
    FollowupContext,
    FollowupDraft,
    TextFollowupError,
)
from zacai.intelligence.work_proposals import packet_fingerprint


@dataclass(frozen=True)
class FollowupRequest:
    context: FollowupContext = field(repr=False)
    evidence_json: bytes = field(repr=False)
    schema_json: bytes = field(repr=False)
    digest: str
    instruction: str = field(default=FOLLOWUP_INSTRUCTION, init=False, repr=False)

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


def prepare_followup_request(context: FollowupContext) -> FollowupRequest:
    """Bind all exact inputs and budgets; exceeding bounds holds, never truncates."""
    result: FollowupRequest | None = None
    try:
        if type(context) is not FollowupContext:
            raise ValueError("exact follow-up context required")
        context = FollowupContext(
            context.task, context.packet, context.user_reference,
            context.packet_reference, context.parent_references,
        )
        items = {item.reference.source_id: item for item in context.task.context}
        evidence = {
            "format": "zac-packet-followup-input-v1",
            "task_id": str(context.task.task_id),
            "current_user_question_projection": items[context.user_reference.source_id].model_dump(mode="json"),
            "user_parent_projection": {
                "operation": "strip surrounding whitespace from canonical original text",
                "quote_offsets": "indices in the supplied projection, not stored turn JSON",
                "canonical_envelope": "host retains exact original; declared hash identifies envelope",
            },
            "original_evidence": [item.model_dump(mode="json") for item in context.packet.task.context],
            "historical_parent_turns": [items[ref.source_id].model_dump(mode="json") for ref in context.parent_references],
            "historical_generated_review": {
                "reference": context.packet_reference.model_dump(mode="json"),
                "created_at": context.packet.created_at.isoformat(),
                "review": context.packet.review.model_dump(mode="json"),
                "status": "historical generated context; not original evidence or current truth",
            },
        }
        schema = FollowupDraft.model_json_schema()
        identities = {
            "task_id": str(context.task.task_id),
            "user_source_id": str(context.user_reference.source_id),
            "user_content_hash": context.user_reference.content_hash,
            "packet_digest": packet_fingerprint(context.packet),
        }
        for name, value in identities.items():
            schema["properties"][name]["const"] = value
        evidence_raw, schema_raw = canonical_bytes(evidence), canonical_bytes(schema)
        prepared = canonical_bytes({
            "format": "zac-packet-followup-request-v1",
            "instruction": FOLLOWUP_INSTRUCTION,
            "evidence": evidence,
            "schema": schema,
            "event": context.task.event.model_dump(mode="json"),
            "max_output_tokens": context.task.max_output_tokens,
            "max_latency_ms": context.task.max_latency_ms,
            "max_estimated_cost_usd": context.task.max_estimated_cost_usd,
        })
        if len(prepared) > 64_000:
            raise ValueError("prepared input too large")
        result = FollowupRequest(context, evidence_raw, schema_raw, content_hash_of(prepared))
    except Exception:  # noqa: BLE001,S110 - closed private-safe diagnostics
        pass
    if result is None:
        raise TextFollowupError("follow-up request unavailable or invalid")
    return result


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate field")
        result[name] = value
    return result


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite numeric literal")
    return parsed


def _constant(value: str) -> None:
    raise ValueError("non-finite constant")


def parse_followup_draft(payload: bytes, *, expected: FollowupRequest) -> FollowupDraft:
    """Parse shape and exact identity only; citations/semantics require release gate."""
    result: FollowupDraft | None = None
    try:
        if type(expected) is not FollowupRequest:
            raise ValueError("exact prepared request required")
        fresh = prepare_followup_request(expected.context)
        if fresh != expected or type(payload) is not bytes or not 0 < len(payload) <= 32_000:
            raise ValueError("invalid request or output bounds")
        json.loads(
            payload.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant,
            parse_float=_finite_float,
        )
        draft = FollowupDraft.model_validate_json(payload, strict=True)
        if (
            draft.task_id != fresh.context.task.task_id
            or draft.user_source_id != fresh.context.user_reference.source_id
            or draft.user_content_hash != fresh.context.user_reference.content_hash
            or draft.packet_digest != packet_fingerprint(fresh.context.packet)
        ):
            raise ValueError("output identity mismatch")
        # JSON permits escaped lone surrogates; explicitly reject unencodable strings.
        json.dumps(draft.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
        result = draft
    except Exception:  # noqa: BLE001,S110 - no chained private provider diagnostics
        pass
    if result is None:
        raise TextFollowupError("follow-up draft unavailable or invalid")
    return result
