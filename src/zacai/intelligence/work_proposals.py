"""Offline proposed work and user preferences, never execution authorization.

All plan text is proposed, not established by the linked meeting evidence. The
trusted host must refresh source ACLs/recovery before display, and separately
bind/review concrete actions through the gateway before any dispatch. These
objects are presentation inputs, not canonical tasks, approvals or status rows.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated

from pydantic import Field, StringConstraints

from zacai.gateway import ActionType
from zacai.intelligence.contextual_evaluation import ContextualPacket, encode_contextual_packet
from zacai.intelligence.contracts import Contract, Digest

PlanText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=400)]
ItemIndex = Annotated[int, Field(ge=0, le=15, strict=True)]


class ProposedStep(Contract):
    instruction: PlanText
    action_type: ActionType
    destination: PlanText
    # Describes a suggested method/model/tool, never a registered/eligible route.
    method: PlanText


class WorkProposal(Contract):
    packet_digest: Digest
    item_index: ItemIndex
    outcome: PlanText
    steps: tuple[ProposedStep, ...] = Field(min_length=1, max_length=3)
    completion_check: PlanText


class WorkChoice(str, Enum):
    AS_PROPOSED = "Approve as proposed"
    WITH_CHANGES = "Approve with changes"
    REVIEW_FIRST = "Review before it ships"
    MYSELF = "I'll do it myself"


class WorkPreference(Contract):
    """Exact draft preference only; no authentication, approval or dispatch power."""

    proposal_digest: Digest
    choice: WorkChoice
    changes: PlanText | None = None


def packet_fingerprint(packet: ContextualPacket) -> str:
    packet = ContextualPacket.model_validate(packet)
    return hashlib.sha256(
        encode_contextual_packet(
            packet.review,
            packet.context(),
            builder_id=packet.builder_id,
            created_at=packet.created_at,
        )
    ).hexdigest()


def proposal_fingerprint(proposal: WorkProposal) -> str:
    proposal = WorkProposal.model_validate(proposal)
    return hashlib.sha256(
        json.dumps(
            proposal.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def render_work_proposals(
    packet: ContextualPacket,
    proposals: tuple[WorkProposal, ...],
    preferences: tuple[WorkPreference, ...] = (),
) -> str:
    """Compatibility wrapper for the offline work projection."""
    from zacai.intelligence.work_briefing import render_work_proposals as render

    return render(packet, proposals, preferences)
