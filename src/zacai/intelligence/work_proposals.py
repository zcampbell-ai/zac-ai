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
from html import escape
from typing import Annotated

from pydantic import Field, StringConstraints

from zacai.gateway import ActionType
from zacai.intelligence.contextual_evaluation import ContextualPacket, encode_contextual_packet
from zacai.intelligence.contracts import Contract, Digest
from zacai.intelligence.meeting_review import ItemKind

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
    """Brief cards, retained details, explicit unknown completion and missing plans.

    Changes require a revised proposal and a fresh preference. A review-first
    preference is not a send approval. Taking work yourself does not close it.
    No supplied preference can imply in-progress/completed/blocked status.
    """
    try:
        packet = ContextualPacket.model_validate(packet)
        proposals = tuple(WorkProposal.model_validate(p) for p in proposals)
        preferences = tuple(WorkPreference.model_validate(p) for p in preferences)
        fingerprint = packet_fingerprint(packet)
        by_item: dict[int, WorkProposal] = {}
        by_digest: dict[str, WorkPreference] = {}
        for candidate in proposals:
            if (
                candidate.packet_digest != fingerprint
                or candidate.item_index in by_item
                or candidate.item_index >= len(packet.review.items)
                or packet.review.items[candidate.item_index].kind
                not in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP)
            ):
                raise ValueError("invalid proposal binding")
            by_item[candidate.item_index] = candidate
        digests = {proposal_fingerprint(p) for p in proposals}
        for selection in preferences:
            if (
                selection.proposal_digest not in digests
                or selection.proposal_digest in by_digest
                or (selection.choice == WorkChoice.WITH_CHANGES) != (selection.changes is not None)
            ):
                raise ValueError("invalid preference binding")
            by_digest[selection.proposal_digest] = selection
        if packet.review.conflicts or packet.review.clarifications:
            return ""  # The existing material-question display holds all work.
        actionable = tuple(
            (i, item)
            for i, item in enumerate(packet.review.items)
            if item.kind in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP)
        )
        lines = [
            "<h2>How Zac proposes to get it done</h2>",
            (
                '<p class="note">Draft work plans. Choices are preferences only; execution is not connected yet. '
                "Existing owners remain unchanged. Source references support the original item, not the proposed approach.</p>"
            ),
            (
                "<p><strong>Did everything get done?</strong> Not verified. "
                f"{len(actionable)} selected commitment/follow-up item(s) need completion checks; "
                "this is not coverage of all your work.</p>"
            ),
        ]
        if not actionable:
            lines.append(
                "<p>No actionable items in this selected review; other work has not been checked.</p>"
            )
        for position, (index, item) in enumerate(actionable):
            if position == 2:
                lines.append(
                    f"<details><summary>{len(actionable) - 2} more selected work items "
                    "(review order, not ranked)</summary>"
                )
            proposal = by_item.get(index)
            lines.append(
                "<article><p><strong>"
                + ("Possible: " if item.inferred else "")
                + escape(proposal.outcome if proposal else item.text)
                + "</strong></p>"
            )
            if proposal is None:
                lines.append(
                    '<p class="meta">Approach not prepared · completion unverified. '
                    "Zac needs a concrete approach before asking you to approve.</p></article>"
                )
                continue
            if item.owner:
                lines.append(
                    '<p class="meta">'
                    + ("Suggested owner: " if item.inferred else "Owner from review: ")
                    + escape(item.owner)
                    + "</p>"
                )
            else:
                lines.append('<p class="meta">Owner unconfirmed</p>')
            preference = by_digest.get(proposal_fingerprint(proposal))
            first = proposal.steps[0]
            lines.append(
                '<p><span class="tag">Proposed first step:</span> '
                + escape(first.instruction)
                + "</p>"
            )
            if preference is None:
                lines.append('<p class="meta">Awaiting your preference · completion unverified</p>')
                lines.append(
                    "<p><strong>Your choices:</strong> "
                    + " · ".join(escape(c.value) for c in WorkChoice)
                    + "</p>"
                )
            else:
                lines.append(
                    "<p><strong>Your preference:</strong> "
                    + escape(preference.choice.value)
                    + "</p>"
                )
                if preference.choice == WorkChoice.WITH_CHANGES:
                    lines.append(
                        "<p>Requested change: "
                        + escape(preference.changes or "")
                        + " · revised plan and fresh preference needed.</p>"
                    )
                elif preference.choice == WorkChoice.REVIEW_FIRST:
                    lines.append("<p>Prepare for your review; shipping remains unapproved.</p>")
                elif preference.choice == WorkChoice.MYSELF:
                    lines.append("<p>You plan to handle this; completion remains unverified.</p>")
                else:
                    lines.append(
                        "<p>Approach accepted as a preference; no execution authorized.</p>"
                    )
            lines.append("<details><summary>Approach and completion check</summary><ol>")
            for step in proposal.steps:
                lines.append(
                    "<li>"
                    + escape(step.instruction)
                    + '<span class="owner">Proposed method: '
                    + escape(step.method)
                    + " · Action: "
                    + escape(step.action_type.value)
                    + " · Destination: "
                    + escape(step.destination)
                    + "</span></li>"
                )
            lines.append(
                "</ol><p><strong>Before calling it done:</strong> "
                + escape(proposal.completion_check)
                + "</p>"
            )
            lines.append(
                '<p class="meta">Original review item: '
                + ("Possible: " if item.inferred else "")
                + escape(item.text)
                + " · Evidence retained in the selected review below.</p></details></article>"
            )
        if len(actionable) > 2:
            lines.append("</details>")
        return "\n".join(lines)
    except Exception:  # noqa: BLE001, S110 - fixed diagnostic, no private locals
        pass
    raise ValueError("work proposals unavailable or invalid")
