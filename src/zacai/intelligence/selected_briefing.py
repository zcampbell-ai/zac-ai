"""Offline selected-review briefing display, not a daily-coverage assertion.

Trusted hosts must load packets through source ACLs and verify retained recovery
before releasing output. This pure renderer performs no retrieval, model dispatch,
authorization, fact promotion, storage or delivery. Private HTML stays private.
Never log exception locals. Canonical packet/preview contracts remain unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

from zacai.intelligence.contextual_evaluation import ContextualPacket
from zacai.intelligence.contextual_review import Clarification, EvidenceConflict
from zacai.intelligence.meeting_review import Claim, ItemKind
from zacai.intelligence.work_briefing import render_work_proposals
from zacai.intelligence.work_proposals import WorkPreference, WorkProposal
from zacai.intelligence.work_tracking import WorkJournal

_STYLE = """
body{font:16px/1.55 system-ui,sans-serif;color:#1c2934;background:#f4f6f8;margin:0}
main{overflow-wrap:anywhere;max-width:760px;margin:24px auto;padding:28px;background:white;border-radius:16px}
h1{font-size:26px;line-height:1.2;margin:8px 0 16px}h2{font-size:19px;margin-top:26px}
p{margin:10px 0}.note,.meta{font-size:14px;color:#52616e}.note{background:#eef3f6;padding:14px;border-radius:8px}
ul{padding-left:22px}li{margin:12px 0}.tag{font-size:13px;font-weight:650;color:#435664}
.owner{display:block;font-size:14px;color:#52616e;margin-top:4px}a{color:#245fa0;padding:4px;display:inline-block}
summary{cursor:pointer;font-weight:650}details{margin:18px 0}blockquote{margin:10px 0;padding-left:14px;border-left:3px solid #cbd8e1;white-space:pre-wrap}
@media(max-width:600px){main{margin:0;padding:20px;border-radius:0}}
@media print{body{background:white}main{margin:0;padding:0;max-width:none}li,blockquote{break-inside:avoid}}
"""


def render_selected_briefing(
    packet: ContextualPacket,
    *,
    as_of: datetime,
    work_proposals: tuple[WorkProposal, ...] = (),
    work_preferences: tuple[WorkPreference, ...] = (),
    work_view: bool = False,
    work_journals: tuple[WorkJournal, ...] = (),
) -> str:
    """Preserve every selected claim/item; material gaps hold the full briefing.

    Dates are reported from the reviewed proposal, never converted into overdue,
    completion or current-status assertions. Review creation is not meeting time.
    No deduplication/re-ranking of business claims or automatic entity linkage.
    """
    try:
        packet = ContextualPacket.model_validate(packet)
        if as_of.tzinfo is None or as_of.utcoffset() is None or as_of < packet.created_at:
            raise ValueError("invalid display time")
        if type(work_view) is not bool or (
            not work_view and (work_proposals or work_preferences or work_journals)
        ):
            raise ValueError("work inputs require work view")
        work_html = (
            render_work_proposals(
                packet, work_proposals, work_preferences, journals=work_journals, as_of=as_of
            )
            if work_view
            else ""
        )
        review = packet.review
        references: dict[tuple[str, int, int, str], int] = {}

        def claim_html(claim: Claim, *, labelled_provisional: bool = False) -> str:
            refs = []
            for quote in claim.quotes:
                key = (str(quote.source_id), quote.start, quote.end, quote.text)
                number = references.setdefault(key, len(references) + 1)
                refs.append(f'<a href="#e{number}" aria-label="Evidence {number}">[{number}]</a>')
            return (
                ("Possible: " if claim.inferred and not labelled_provisional else "")
                + escape(claim.text)
                + " <small>"
                + " ".join(refs)
                + "</small>"
            )

        lines = [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
            "<title>Zac AI — selected meeting briefing</title>",
            "<style>" + _STYLE + "</style></head><body><main>",
            '<p class="meta">Selected review • ' + review.data_classification.value + "</p>",
            "<h1>Work briefing</h1>" if work_view else "<h1>Selected meeting briefing</h1>",
            '<p class="meta">Prepared '
            + packet.created_at.astimezone(UTC).isoformat(timespec="minutes")
            + " · Displayed "
            + as_of.astimezone(UTC).isoformat(timespec="minutes")
            + "</p>",
            (
                '<p class="note">Coverage: one selected meeting review and its selected earlier context. '
                "Other meetings, messages and calendar activity have not been checked. "
                "Decisions and commitments remain review proposals; current completion or overdue status has not been verified.</p>"
            ),
        ]
        gaps = (*review.conflicts, *review.clarifications)
        if gaps:
            gap: Clarification = gaps[0]
            label = (
                "Conflicting accounts" if isinstance(gap, EvidenceConflict) else "Missing context"
            )
            lines.extend(
                (
                    "<h2>One question first</h2>",
                    '<p class="note">The rest of this briefing is held until this is answered.</p>',
                    '<p><span class="tag">' + label + ":</span> " + claim_html(gap) + "</p>",
                    "<p><strong>" + escape(gap.question) + "</strong></p>",
                    '<p class="meta">Why it matters: ' + escape(gap.reason) + "</p>",
                )
            )
            if len(gaps) > 1:
                lines.append(
                    f'<p class="meta">{len(gaps) - 1} more question{"s" if len(gaps) > 2 else ""} retained.</p>'
                )
        else:
            if work_view:
                lines.append(work_html)
                lines.append("<details><summary>Selected review and context</summary>")
            lines.append("<h2>Context and changes</h2>")
            lines.extend("<p>" + claim_html(claim) + "</p>" for claim in review.overview)
            if review.background or review.continuity:
                lines.append("<details><summary>Earlier context and possible connections</summary>")
                lines.extend(
                    '<p><span class="tag">Candidate earlier context:</span> '
                    + claim_html(claim)
                    + "</p>"
                    for claim in review.background
                )
                lines.extend(
                    '<p><span class="tag">Possible connection:</span> '
                    + claim_html(claim, labelled_provisional=True)
                    + "</p>"
                    for claim in review.continuity
                )
                lines.append("</details>")
            for heading, kinds in (
                ("Decisions and commitments", (ItemKind.DECISION, ItemKind.COMMITMENT)),
                ("Risks and follow-ups", (ItemKind.RISK, ItemKind.FOLLOW_UP)),
            ):
                lines.append("<h2>" + heading + "</h2>")
                items = tuple(item for item in review.items if item.kind in kinds)
                if not items:
                    lines.append(
                        '<p class="meta">None recorded in this selected review; completeness still needs review.</p>'
                    )
                    continue
                lines.append("<ul>")
                for item in items:
                    label = (
                        "Suggested follow-up"
                        if item.kind == ItemKind.FOLLOW_UP
                        else item.kind.value.title()
                    )
                    text = claim_html(item, labelled_provisional=item.kind == ItemKind.FOLLOW_UP)
                    lines.append('<li><span class="tag">' + label + ":</span> " + text)
                    details = []
                    if item.owner:
                        details.append(
                            ("Suggested owner: " if item.inferred else "Owner: ")
                            + escape(item.owner)
                        )
                    elif item.kind in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP):
                        details.append("Owner unconfirmed")
                    if item.due_date:
                        details.append(
                            ("Suggested date: " if item.inferred else "Date from review: ")
                            + item.due_date.isoformat()
                        )
                    if details:
                        lines.append('<span class="owner">' + " · ".join(details) + "</span>")
                    lines.append("</li>")
                lines.append("</ul>")
            if work_view:
                lines.append("</details>")
        # Only quotes of visible claims are disclosed; held review text never leaks.
        if references:
            lines.append("<details><summary>Supporting evidence</summary><ol>")
            for (source, start, end, quote), number in references.items():
                lines.append(
                    f'<li id="e{number}"><p class="meta">Source {escape(source)} · characters {start}–{end}</p><blockquote>'
                    + escape(quote)
                    + "</blockquote></li>"
                )
            lines.append("</ol></details>")
        lines.append("</main></body></html>")
        return "\n".join(lines)
    except Exception:  # noqa: BLE001, S110 - fixed diagnostics only
        pass
    raise ValueError("selected briefing unavailable or invalid")
