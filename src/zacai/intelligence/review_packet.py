"""Exact versioned evaluation packets; no storage, approval or freshness grant.

Packets contain full private evidence. Hosts must protect them like their sources,
not log them. Digests bind content but do not authenticate a reviewer or restore
current source permissions. This codec cannot reconstruct historical lost inputs.
Hosts must not capture traceback locals: even a safe error frame holds inputs.
"""

from __future__ import annotations

import json
from typing import Literal, Self
from uuid import UUID

from pydantic import ConfigDict, model_validator

from zacai.intelligence.contracts import Contract, Digest, IntelligenceTask
from zacai.intelligence.meeting_review import MeetingReview, ReviewContext
from zacai.intelligence.review_evaluation import review_evaluation_digests


class ReviewPacket(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)

    contract_version: Literal[1] = 1
    task: IntelligenceTask
    meeting_source_id: UUID
    related_source_ids: frozenset[UUID]
    review: MeetingReview
    review_digest: Digest
    context_digest: Digest

    def context(self) -> ReviewContext:
        return ReviewContext(self.task, self.meeting_source_id, self.related_source_ids)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        digests = review_evaluation_digests(self.review, self.context())
        if digests != (self.review_digest, self.context_digest):
            raise ValueError("review packet binding mismatch")
        return self


def encode_review_packet(review: MeetingReview, context: ReviewContext) -> bytes:
    """Capture exact structured draft and context; caller owns protected storage."""
    try:
        output_digest, context_digest = review_evaluation_digests(review, context)
        packet = ReviewPacket(
            task=context.task,
            meeting_source_id=context.meeting_source_id,
            related_source_ids=context.related_source_ids,
            review=review,
            review_digest=output_digest,
            context_digest=context_digest,
        )
        data = packet.model_dump(mode="json")
        data["related_source_ids"] = sorted(data["related_source_ids"])
        data["task"]["required_capabilities"] = sorted(data["task"]["required_capabilities"])
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    except Exception:  # noqa: BLE001, S110 - never log private validation diagnostics
        pass
    # Raise outside the handler so private ValidationError is not __context__.
    raise ValueError("review packet unavailable or invalid")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate packet field")
        result[key] = value
    return result


def decode_review_packet(payload: bytes) -> ReviewPacket:
    """Validate bindings on reload, without approving, refreshing or grading them."""
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or type(data.get("contract_version")) is not int:
            raise ValueError("explicit packet version required")
        packet = ReviewPacket.model_validate(data)
        if encode_review_packet(packet.review, packet.context()) != payload:
            raise ValueError("noncanonical packet encoding")
        return packet
    except Exception:  # noqa: BLE001, S110 - never log private input or validation text
        pass
    raise ValueError("review packet unavailable or invalid")
