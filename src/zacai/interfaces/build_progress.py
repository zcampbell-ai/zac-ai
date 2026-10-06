"""Pure presentation of the existing four D034AC first-usable-v1 gates.

Snapshots are supplied and reviewed by the trusted host. References/status labels
are assertions to present, not independent verification, permission or canonical
memory. No roadmap parsing, source loading, test/commit counting or release occurs.
The completed-gate count is an acceptance count, not effort, time or full-product
completion. Never include private actual source text in this operational snapshot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from html import escape


class AcceptanceGate(str, Enum):
    REVIEW = "review"
    BRIEFING = "briefing"
    PRIVATE_ACCESS = "private_access"
    QUALITY = "quality"


class GateStatus(str, Enum):
    VERIFIED = "Verified complete"
    CURRENT = "In progress"
    NEEDS_OWNER = "Needs your input"
    PENDING = "Pending"


_GATE_ORDER = tuple(AcceptanceGate)
_TITLES = {
    AcceptanceGate.REVIEW: "Useful source-backed meeting review",
    AcceptanceGate.BRIEFING: "Daily briefing and current source coverage",
    AcceptanceGate.PRIVATE_ACCESS: "Private text and iPhone access",
    AcceptanceGate.QUALITY: "Representative quality and operational validation",
}


def _text(value: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit:
        raise ValueError("invalid progress text")
    if any(ord(char) < 32 and char != "\n" for char in value):
        raise ValueError("invalid progress text")


@dataclass(frozen=True)
class GateEvidence:
    reference: str
    statement: str
    checked_at: datetime

    def __post_init__(self) -> None:
        _text(self.reference, 160)
        _text(self.statement, 500)
        if type(self.checked_at) is not datetime or self.checked_at.utcoffset() is None:
            raise ValueError("invalid evidence time")


@dataclass(frozen=True)
class GateProgress:
    gate: AcceptanceGate
    status: GateStatus
    next_step: str
    evidence: tuple[GateEvidence, ...] = ()

    def __post_init__(self) -> None:
        if type(self.gate) is not AcceptanceGate or type(self.status) is not GateStatus:
            raise ValueError("invalid acceptance gate")
        _text(self.next_step, 300)
        if (
            type(self.evidence) is not tuple
            or len(self.evidence) > 6
            or any(type(item) is not GateEvidence for item in self.evidence)
            or (self.status is GateStatus.VERIFIED and not self.evidence)
        ):
            raise ValueError("invalid gate evidence")


@dataclass(frozen=True)
class BuildProgressSnapshot:
    as_of: datetime
    gates: tuple[GateProgress, ...]
    broader_roadmap_href: str | None = None

    def __post_init__(self) -> None:
        if type(self.as_of) is not datetime or self.as_of.utcoffset() is None:
            raise ValueError("invalid progress time")
        if (
            type(self.gates) is not tuple
            or len(self.gates) != len(_GATE_ORDER)
            or any(type(record) is not GateProgress for record in self.gates)
            or tuple(record.gate for record in self.gates) != _GATE_ORDER
            or any(item.checked_at > self.as_of for record in self.gates for item in record.evidence)
        ):
            raise ValueError("invalid exact acceptance gates")
        href = self.broader_roadmap_href
        if href is not None and (
            type(href) is not str
            or re.fullmatch(r"/[a-z0-9][a-z0-9/_-]{0,199}", href) is None
        ):
            raise ValueError("invalid broader roadmap link")


def render_build_progress(snapshot: BuildProgressSnapshot) -> str:
    """Escaped native progress/details fragment, compatible with CAZ_STYLE.

    Caller mounts only in its reviewed page, with current authentication if
    needed. No link is emitted unless the host supplies a real same-origin route.
    This function does not install a route or claim browser/iPhone validation.
    """
    if type(snapshot) is not BuildProgressSnapshot:
        raise TypeError("invalid progress snapshot")
    count = sum(record.status is GateStatus.VERIFIED for record in snapshot.gates)
    total = len(_GATE_ORDER)
    text = f"{count} of {total} acceptance gates verified"
    parts = [
        '<section class="caz-build-status" aria-labelledby="caz-build-heading"><h2 id="caz-build-heading">'
        'First usable iPhone version</h2><p class="meta">Evidence as of '
        + escape(snapshot.as_of.isoformat()) + "</p>",
        '<label for="caz-build-progress">' + text + '</label><progress id="caz-build-progress" '
        + f'value="{count}" max="{total}" aria-describedby="caz-build-currentness" '
        + f'style="display:block;width:100%;max-width:100%">{text}</progress>',
        '<p class="meta">Accepted release gates, not estimated effort or the full vision.</p>',
        '<p class="meta" id="caz-build-currentness">Past acceptance does not verify current source access or recovery.</p>',
        '<details><summary>What is done and what comes next</summary><ol>',
    ]
    for record in snapshot.gates:
        parts.append(
            "<li><strong>" + _TITLES[record.gate] + "</strong> · "
            + escape(record.status.value) + "<p>" + escape(record.next_step) + "</p>"
        )
        if record.evidence:
            parts.append("<ul>")
            for item in record.evidence:
                parts.append("<li>" + escape(item.reference) + ": " + escape(item.statement)
                             + '<br><small>Checked ' + escape(item.checked_at.isoformat())
                             + "</small></li>")
            parts.append("</ul>")
        else:
            parts.append("<p><small>Completion evidence not yet recorded.</small></p>")
        parts.append("</li>")
    parts.append("</ol><p>The broader vision: relevant context, planning, model delegation, "
                 "delivery and verified completion. Personal/financial access and persistent-agent "
                 "control remain separately gated.</p>")
    if snapshot.broader_roadmap_href is not None:
        parts.append('<p><a href="' + escape(snapshot.broader_roadmap_href, quote=True)
                     + '">Broader roadmap</a></p>')
    parts.append("</details></section>")
    return "".join(parts)
