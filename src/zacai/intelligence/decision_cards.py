"""One-card offline decision presentation; no approval issuer or execution.

Radio navigation changes only which retained review item is visible. No swipe,
script, form submission, endpoint, state write or gateway decision exists here.
The trusted host must separately refresh protected source ACLs/recovery before
release. Draft approach text is not supported by the original item's citations.
"""

from __future__ import annotations

from enum import Enum
from html import escape

from zacai.intelligence.contextual_evaluation import ContextualPacket
from zacai.intelligence.meeting_review import Claim, ItemKind
from zacai.intelligence.work_proposals import (
    WorkChoice,
    WorkPreference,
    WorkProposal,
    packet_fingerprint,
    proposal_fingerprint,
)
from zacai.interfaces.presentation import CAZ_STYLE as _STYLE

_ACTIONABLE = (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP)


def _evidence(claim: Claim) -> str:
    lines = []
    for quote in claim.quotes:
        lines.append(
            "<blockquote>"
            + escape(quote.text)
            + '</blockquote><p class="meta">Source '
            + escape(str(quote.source_id))
            + " · passage "
            + str(quote.start)
            + ":"
            + str(quote.end)
            + "</p>"
        )
    return "\n".join(lines)


def _plan_details(proposal: WorkProposal) -> str:
    lines = ["<details><summary>Proposed approach and completion check</summary><ol>"]
    for step in proposal.steps:
        lines.append(
            "<li>"
            + escape(step.instruction)
            + '<p class="meta">Proposed method: '
            + escape(step.method)
            + " · Action: "
            + escape(step.action_type.value)
            + " · Destination: "
            + escape(step.destination)
            + "</p></li>"
        )
    lines.append(
        "</ol><p><strong>Before calling it done:</strong> "
        + escape(proposal.completion_check)
        + '</p><p class="meta">The approach is proposed; source quotes support the original review item.</p></details>'
    )
    return "\n".join(lines)


class DecisionCardRenderMode(str, Enum):
    """Trusted composition choice, never a work permission or user preference.

    HOST_LOGOUT is exclusively for a protected host adding its own same-origin
    logout form. Source content remains escaped; this renderer emits no forms.
    Offline artifacts must retain the default, which denies all submissions.
    """

    OFFLINE = "offline"
    HOST_LOGOUT = "host_logout"


def render_decision_cards(
    packet: ContextualPacket,
    proposals: tuple[WorkProposal, ...] = (),
    preferences: tuple[WorkPreference, ...] = (),
    *,
    selected_item: int = 0,
    render_mode: DecisionCardRenderMode = DecisionCardRenderMode.OFFLINE,
) -> str:
    """Retain all original items; one initially selected card, native navigation.

    CSS radio selection presents one item at a time without JavaScript. With CSS
    disabled or for print, all retained cards remain accessible. Browser/mobile
    behavior needs separate visual verification; shape tests cannot prove it.
    """
    try:
        if type(render_mode) is not DecisionCardRenderMode:
            raise ValueError("invalid render mode")
        form_action = "self" if render_mode == DecisionCardRenderMode.HOST_LOGOUT else "none"
        packet = ContextualPacket.model_validate(packet)
        proposals = tuple(WorkProposal.model_validate(p) for p in proposals)
        preferences = tuple(WorkPreference.model_validate(p) for p in preferences)
        items = packet.review.items
        if (
            type(selected_item) is not int
            or selected_item < 0
            or selected_item >= max(1, len(items))
        ):
            raise ValueError("invalid selected item")
        fingerprint = packet_fingerprint(packet)
        plans: dict[int, WorkProposal] = {}
        for candidate in proposals:
            if (
                candidate.packet_digest != fingerprint
                or candidate.item_index in plans
                or candidate.item_index >= len(items)
                or items[candidate.item_index].kind not in _ACTIONABLE
            ):
                raise ValueError("invalid candidate")
            plans[candidate.item_index] = candidate
        digests = {proposal_fingerprint(p) for p in proposals}
        choices: dict[str, WorkPreference] = {}
        for selection in preferences:
            if (
                selection.proposal_digest not in digests
                or selection.proposal_digest in choices
                or (selection.choice == WorkChoice.WITH_CHANGES) != (selection.changes is not None)
            ):
                raise ValueError("invalid selection")
            choices[selection.proposal_digest] = selection
        lines = [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
            '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;'
            + form_action
            + '&#39;">',
            "<title>Caz AI: draft decision cards</title><style>"
            + _STYLE
            + "</style></head><body><main>",
            '<h1>One thing at a time</h1><p class="meta">'
            + packet.review.data_classification.value
            + " · One selected review, not coverage of all your work. Completion remains unverified.</p>",
        ]
        gaps = (*packet.review.conflicts, *packet.review.clarifications)
        if gaps:
            lines.append(
                "<h2>One question first</h2><p>All work cards and their evidence are held.</p>"
            )
            for gap in gaps:
                lines.append(
                    "<details"
                    + (" open" if gap is gaps[0] else "")
                    + "><summary>"
                    + escape(gap.question)
                    + "</summary><p>"
                    + ("Possible: " if gap.inferred else "")
                    + escape(gap.text)
                    + "</p><p>Why it matters: "
                    + escape(gap.reason)
                    + "</p>"
                    + _evidence(gap)
                    + "</details>"
                )
        elif not items:
            lines.append("<p>No selected items. Other work has not been checked.</p>")
        else:
            lines.append(
                '<p class="meta">Navigation only: Previous/Next or arrow keys change the displayed item. '
                "They never approve work.</p><fieldset><legend>Selected review order, not a priority ranking</legend>"
            )
            for index, item in enumerate(items):
                proposal = plans.get(index)
                lines.append(
                    '<input class="card-radio" type="radio" name="caz-work-card" id="card-'
                    + str(index)
                    + '" aria-label="Item '
                    + str(index + 1)
                    + " of "
                    + str(len(items))
                    + '"'
                    + (" checked" if index == selected_item else "")
                    + ">"
                )
                lines.append(
                    '<article class="decision-card"><p class="meta">Item '
                    + str(index + 1)
                    + " of "
                    + str(len(items))
                    + " · "
                    + item.kind.value
                    + "</p><h2>"
                    + ("Possible: " if item.inferred else "")
                    + escape(item.text)
                    + "</h2>"
                )
                if item.owner:
                    lines.append(
                        '<p class="meta">'
                        + ("Suggested owner: " if item.inferred else "Owner from review: ")
                        + escape(item.owner)
                        + "</p>"
                    )
                elif item.kind in _ACTIONABLE:
                    lines.append('<p class="meta">Owner unconfirmed</p>')
                if item.due_date:
                    lines.append(
                        '<p class="meta">'
                        + ("Suggested date: " if item.inferred else "Date from review: ")
                        + item.due_date.isoformat()
                        + " · current status unverified</p>"
                    )
                if proposal:
                    lines.append(
                        "<p><strong>Proposed outcome:</strong> " + escape(proposal.outcome) + "</p>"
                    )
                    lines.append(
                        "<p><strong>Proposed first step:</strong> "
                        + escape(proposal.steps[0].instruction)
                        + "</p>"
                    )
                    preference = choices.get(proposal_fingerprint(proposal))
                    if preference:
                        lines.append(
                            "<p><strong>Recorded draft preference:</strong> "
                            + escape(preference.choice.value)
                            + " · no execution authorized.</p>"
                        )
                        if preference.changes:
                            lines.append(
                                "<p>Requested change: "
                                + escape(preference.changes)
                                + " · revised plan and fresh preference needed.</p>"
                            )
                    lines.append(
                        '<div class="choices" role="group" aria-label="Presentation-only actions">'
                        '<button type="button" disabled>Approve</button><button type="button" disabled>Change</button>'
                        '<button type="button" disabled>Decline</button><button type="button" disabled>Defer</button></div>'
                    )
                    lines.append(
                        "<details><summary>What these draft choices mean</summary><p>Presentation only; no approval is recorded.</p><ul>"
                        + "".join("<li>" + escape(choice.value) + "</li>" for choice in WorkChoice)
                        + "</ul><p>Approve as proposed remains a draft preference. Changes require a revised exact plan. "
                        "Review before shipping leaves shipping unapproved. Handling it yourself does not mean done. "
                        "Decline/defer are navigation or recommendation preferences, not a gateway denial or permission.</p></details>"
                    )
                    lines.append(_plan_details(proposal))
                elif item.kind in _ACTIONABLE:
                    lines.append(
                        '<p class="meta">Approach not prepared; no approval choice yet.</p>'
                    )
                else:
                    lines.append(
                        '<p class="meta">Informational review item; no work approval control.</p>'
                    )
                lines.append(
                    "<details><summary>Original item and source evidence</summary><p>"
                    + ("Possible: " if item.inferred else "")
                    + escape(item.text)
                    + "</p>"
                    + _evidence(item)
                    + "</details>"
                )
                lines.append('<nav aria-label="Card navigation">')
                if index:
                    lines.append('<label for="card-' + str(index - 1) + '">Previous item</label>')
                if index + 1 < len(items):
                    lines.append('<label for="card-' + str(index + 1) + '">Next item</label>')
                lines.append("</nav></article>")
            lines.append("</fieldset>")
            lines.append("<details><summary>Selected context and possible connections</summary>")
            for label, claims in (
                ("Overview", packet.review.overview),
                ("Candidate earlier context", packet.review.background),
                ("Possible connection", packet.review.continuity),
            ):
                for claim in claims:
                    lines.append(
                        "<p><strong>"
                        + label
                        + ":</strong> "
                        + (
                            "Possible: "
                            if claim.inferred and label != "Possible connection"
                            else ""
                        )
                        + escape(claim.text)
                        + "</p>"
                        + _evidence(claim)
                    )
            lines.append("</details>")
        lines.append("</main></body></html>")
        return "\n".join(lines)
    except Exception:  # noqa: BLE001, S110 - fixed private-safe diagnostic
        pass
    raise ValueError("decision cards unavailable or invalid")
