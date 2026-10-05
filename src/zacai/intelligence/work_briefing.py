"""Pure proposed-work and reported-history projection, never verified execution.

Trusted hosts must separately ACL-load and recovery-protect each journal snapshot
and the packet before release. Caller-supplied models alone prove no authority,
current permissions, current coverage, authenticity or outcome verification.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

from zacai.intelligence.contextual_evaluation import ContextualPacket
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.work_proposals import (
    WorkChoice,
    WorkPreference,
    WorkProposal,
    packet_fingerprint,
    proposal_fingerprint,
)
from zacai.intelligence.work_tracking import WorkJournal, WorkStatus, validate_journal_packet

_STATUS_LABELS = {
    WorkStatus.PROPOSED: "Proposed",
    WorkStatus.AWAITING_USER: "Reported awaiting your input",
    WorkStatus.IN_PROGRESS_REPORTED: "Reported underway",
    WorkStatus.BLOCKED_REPORTED: "Reported blocked",
    WorkStatus.REVIEW_READY_REPORTED: "Reported ready for review",
    WorkStatus.USER_HANDLING_REPORTED: "Reported being handled by you",
    WorkStatus.COMPLETION_REPORTED: "Reported complete — outcome still unverified",
    WorkStatus.REOPENED: "Reported reopened",
}


def _history(journal: WorkJournal) -> str:
    lines = ["<details><summary>Reported work history and evidence references</summary>"]
    if not journal.observations:
        lines.append('<p class="meta">No progress observations recorded.</p>')
    else:
        lines.append("<ol>")
        for observation in journal.observations:
            lines.append(
                "<li><strong>"
                + _STATUS_LABELS[observation.status]
                + "</strong> · "
                + escape(observation.reason)
                + '<span class="meta">Observed '
                + observation.observed_at.astimezone(UTC).isoformat()
                + " · Recorded "
                + observation.recorded_at.astimezone(UTC).isoformat()
                + "</span><ul>"
            )
            for ref in observation.evidence:
                lines.append(
                    '<li class="meta">Observation evidence reference: Source '
                    + escape(str(ref.source_id))
                    + " · SHA-256 "
                    + escape(ref.content_hash)
                    + " · "
                    + ref.trust_boundary.value
                    + " / "
                    + ref.effective_classification.value
                    + "</li>"
                )
            lines.append("</ul></li>")
        lines.append("</ol>")
    lines.append(
        '<p class="meta">References support reported observations, not authenticated approvals '
        "or independently verified outcomes. Previous reports remain historical.</p></details>"
    )
    return "\n".join(lines)


def render_work_proposals(
    packet: ContextualPacket,
    proposals: tuple[WorkProposal, ...],
    preferences: tuple[WorkPreference, ...] = (),
    *,
    journals: tuple[WorkJournal, ...] = (),
    as_of: datetime | None = None,
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
        journals = tuple(WorkJournal.model_validate(j) for j in journals)
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
        by_journal: dict[int, WorkJournal] = {}
        work_ids = set()
        if journals and (as_of is None or as_of.utcoffset() is None):
            raise ValueError("journal display needs aware host time")
        for journal in journals:
            index = journal.proposal.item_index
            proposal = by_item.get(index)
            if (
                proposal is None
                or index in by_journal
                or journal.work_id in work_ids
                or proposal_fingerprint(proposal) != proposal_fingerprint(journal.proposal)
                or journal.proposal.packet_digest != fingerprint
                or journal.packet_reference.effective_classification
                != packet.review.data_classification
                or journal.trust_boundary != packet.task.event.trust_boundary
                or journal.data_classification != packet.review.data_classification
                or journal.created_at < packet.created_at
                or as_of is None
                or journal.created_at > as_of
                or any(o.recorded_at > as_of for o in journal.observations)
            ):
                raise ValueError("journal display binding mismatch")
            by_journal[index] = journal
            work_ids.add(journal.work_id)
        if packet.review.conflicts or packet.review.clarifications:
            return ""  # The existing material-question display holds all work.
        for checked_journal in journals:
            validate_journal_packet(checked_journal, packet)
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
            item_journal = by_journal.get(index)
            if item_journal is not None:
                lines.append(
                    '<p class="meta"><strong>Work status:</strong> '
                    + _STATUS_LABELS[item_journal.status]
                    + " · completion unverified</p>"
                )
                if item_journal.observations:
                    latest = item_journal.observations[-1]
                    lines.append(
                        '<p><span class="tag">Latest report:</span> '
                        + escape(latest.reason)
                        + "</p>"
                    )
                    lines.append(
                        '<p class="meta">Recorded '
                        + latest.recorded_at.astimezone(UTC).isoformat(timespec="minutes")
                        + " · this report does not establish current status.</p>"
                    )
            preference = by_digest.get(proposal_fingerprint(proposal))
            first = proposal.steps[0]
            lines.append(
                '<p><span class="tag">Proposed first step:</span> '
                + escape(first.instruction)
                + "</p>"
            )
            if preference is None:
                if item_journal is None or item_journal.status == WorkStatus.PROPOSED:
                    lines.append(
                        '<p class="meta">Awaiting your preference · completion unverified</p>'
                    )
                else:
                    lines.append(
                        '<p class="meta">No preference recorded; this does not override the reported work status.</p>'
                    )
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
            if item_journal is not None:
                lines.append(_history(item_journal))
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
