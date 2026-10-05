"""Unmounted host work-choice forms; draft preferences never execute work.

The outer host authenticates the current session and checks exact Origin and
session CSRF before submit; it strips CSRF from the controller field dictionary.
Trusted selection callbacks establish receipt origin, not browser hashes. Fresh
canonical packet ACL/recovery binding is checked before every issue/render/submit.
Only canonical capture's protected result permits a saved acknowledgement.
Handles are volatile bounded operational correlations, not grants or memory.
Distinct forms for the exact owner/canonical packet/plan share one request UUID;
rotated recovery receipts cannot create a second contradictory choice.
a changed plan requires a new request, while conflicting old-plan choices deny.
Restart/expiry requires a new form; same-UID isolation remains a host concern.
Never log handles, forms, principals, plans, callback locals or backend errors.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html import escape
from threading import RLock
from uuid import UUID, uuid5

from sqlalchemy.orm import Session, sessionmaker

from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.ingestion.artifact_store import ArtifactStore
from zacai.intelligence.briefing_delivery import load_retained_packet
from zacai.intelligence.contextual_evaluation import ContextualPacket
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.work_proposals import (
    WorkChoice,
    WorkPreference,
    WorkProposal,
    packet_fingerprint,
    proposal_fingerprint,
)
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.work_choice_capture import CanonicalWorkChoiceCapture, SavedWorkChoice
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation

_REQUEST_NAMESPACE = UUID("293a0b83-3e88-5a61-b9d5-775e673a371c")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class WorkChoiceWebError(ValueError):
    """Fixed closed diagnostic without private backend exception chains."""


@dataclass(frozen=True)
class HostWorkSelection:
    receipt: ContextualRecoveryReceipt = field(repr=False)
    receipt_digest: str = field(repr=False)
    proposal: WorkProposal = field(repr=False)


@dataclass(frozen=True, repr=False)
class _Handle:
    grant: OwnerGrant
    selection: HostWorkSelection
    request_id: UUID
    issued_at: datetime
    expires_at: datetime


class WorkChoiceWeb:
    """Trusted controller only; no request authentication, routing or dispatch."""

    def __init__(
        self,
        *,
        capture: CanonicalWorkChoiceCapture,
        factory: sessionmaker[Session],
        artifacts: ArtifactStore,
        owner: Callable[[], OwnerGrant],
        selection: Callable[[InterfacePrincipal], HostWorkSelection],
        clock: Callable[[], datetime],
        ttl: timedelta = timedelta(minutes=5),
        capacity: int = 128,
    ) -> None:
        if (
            type(capture) is not CanonicalWorkChoiceCapture
            or type(ttl) is not timedelta
            or not timedelta(0) < ttl <= timedelta(minutes=5)
            or type(capacity) is not int
            or not 1 <= capacity <= 128
            or not all(callable(x) for x in (factory, owner, selection, clock))
        ):
            raise WorkChoiceWebError("work choice form unavailable")
        self._capture, self._factory, self._artifacts = capture, factory, artifacts
        self._owner, self._selection, self._clock = owner, selection, clock
        self._ttl, self._capacity = ttl, capacity
        self._handles: dict[str, _Handle] = {}
        self._inflight: set[UUID] = set()
        self._last_time: datetime | None = None
        self._lock = RLock()

    def _now(self) -> datetime:
        now = self._clock()
        if type(now) is not datetime or now.utcoffset() is None:
            raise ValueError("invalid host clock")
        if self._last_time is not None and now < self._last_time:
            self._handles.clear()
            raise ValueError("host clock rollback")
        self._last_time = now
        self._handles = {k: v for k, v in self._handles.items() if now < v.expires_at}
        return now

    def _current(
        self, principal: InterfacePrincipal, now: datetime
    ) -> tuple[OwnerGrant, HostWorkSelection, ContextualPacket]:
        if type(principal) is not InterfacePrincipal:
            raise ValueError("invalid principal")
        current = self._owner()
        grant = OwnerGrant(current.identity, current.scopes)
        if OwnerGrant(principal.identity, principal.scopes) != grant:
            raise ValueError("owner changed")
        scope = next(s for s in grant.scopes if s.boundary == B.BRAINSTORM)
        if C.CONFIDENTIAL not in scope.classifications:
            raise ValueError("classification denied")
        selection = self._selection(principal)
        if type(selection) is not HostWorkSelection:
            raise ValueError("invalid host selection")
        receipt = ContextualRecoveryReceipt.model_validate(selection.receipt)
        proposal = WorkProposal.model_validate(selection.proposal)
        with self._factory() as session:
            _assert_ledger_isolation(session)
            packet = load_retained_packet(
                session,
                artifacts=self._artifacts,
                retained_receipt=receipt,
                expected_receipt_digest=selection.receipt_digest,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
                as_of=now,
            )
        if (
            packet.review.conflicts
            or packet.review.clarifications
            or proposal.packet_digest != packet_fingerprint(packet)
            or proposal.item_index >= len(packet.review.items)
            or packet.review.items[proposal.item_index].kind
            not in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP)
        ):
            raise ValueError("held or changed plan")
        return grant, HostWorkSelection(receipt, selection.receipt_digest, proposal), packet

    def _resolve(
        self, handle: str, principal: InterfacePrincipal
    ) -> tuple[_Handle, ContextualPacket]:
        now = self._now()
        if type(handle) is not str or _TOKEN.fullmatch(handle) is None:
            raise ValueError("invalid handle")
        bound = self._handles[handle]
        grant, selected, packet = self._current(principal, now)
        if grant != bound.grant or selected != bound.selection or now < bound.issued_at:
            raise ValueError("changed form binding")
        return bound, packet

    def issue(self, principal: InterfacePrincipal) -> str:
        result: str | None = None
        try:
            with self._lock:
                now = self._now()
                grant, selection, _packet = self._current(principal, now)
                # Fresh ACL/owner checks still happen on every GET. Reusing exact
                # unexpired bindings avoids refresh-driven capacity exhaustion;
                # never extend expiry or match only the stable request UUID.
                for handle, bound in self._handles.items():
                    if grant == bound.grant and selection == bound.selection:
                        return handle
                if len(self._handles) >= self._capacity:
                    raise ValueError("form capacity exceeded")
                request_id = uuid5(
                    _REQUEST_NAMESPACE,
                    json.dumps(
                        [
                            "caz-work-choice-request-v1",
                            grant.identity.issuer,
                            grant.identity.subject,
                            str(selection.receipt.locator.packet_source_id),
                            selection.receipt.locator.packet_digest,
                            proposal_fingerprint(selection.proposal),
                        ],
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                )
                result = secrets.token_urlsafe(32)
                if result in self._handles:
                    result = None
                    raise ValueError("handle collision")
                self._handles[result] = _Handle(grant, selection, request_id, now, now + self._ttl)
        except Exception:  # noqa: BLE001,S110 - no private errors or context
            pass
        if result is None:
            raise WorkChoiceWebError("work choice form unavailable")
        return result

    def render(self, *, handle: str, principal: InterfacePrincipal, csrf: str) -> str:
        result: str | None = None
        try:
            with self._lock:
                bound, packet = self._resolve(handle, principal)
                if type(csrf) is not str or _TOKEN.fullmatch(csrf) is None:
                    raise ValueError("invalid host csrf")
                choices = "".join(
                    '<label><input type="radio" name="choice" value="'
                    + escape(choice.value, quote=True)
                    + '" required>'
                    + escape(choice.value)
                    + "</label>"
                    for choice in WorkChoice
                )
                proposal = bound.selection.proposal
                steps = "".join(
                    "<li><p>" + escape(step.instruction) + "</p><p>"
                    "<strong>Proposed action:</strong> "
                    + escape(step.action_type.value)
                    + "<br><strong>Proposed destination:</strong> "
                    + escape(step.destination)
                    + "<br><strong>Proposed method:</strong> "
                    + escape(step.method)
                    + "</p></li>"
                    for step in proposal.steps
                )
                plan = (
                    "<details><summary>How Caz proposes getting it done</summary><ol>"
                    + steps
                    + "</ol><p><strong>Completion check:</strong> "
                    + escape(proposal.completion_check)
                    + "</p><p>These are proposed steps, not eligible routes or completed work.</p></details>"
                )
                item = packet.review.items[proposal.item_index]
                evidence = (
                    "<details><summary>Evidence for this proposal</summary><p><strong>"
                    + (
                        "Interpretation; not established"
                        if item.inferred
                        else "Selected meeting item"
                    )
                    + ":</strong> "
                    + escape(item.text)
                    + "</p>"
                    + "".join(
                        '<blockquote style="white-space:pre-wrap">'
                        + escape(quote.text)
                        + "</blockquote><p>Source "
                        + escape(str(quote.source_id))
                        + ", characters "
                        + str(quote.start)
                        + "–"
                        + str(quote.end)
                        + "</p>"
                        for quote in item.quotes
                    )
                    + "<p>These quotes support the selected meeting item; they do not verify completion.</p></details>"
                )
                result = (
                    '<form method="post" action="/work-choice" class="caz-work-choice">'
                    "<p>"
                    + escape(proposal.outcome)
                    + "</p>"
                    + plan
                    + evidence
                    + '<input type="hidden" name="handle" value="'
                    + escape(handle, quote=True)
                    + '">'
                    '<input type="hidden" name="csrf" value="' + escape(csrf, quote=True) + '">'
                    "<fieldset><legend>Your preferred approach</legend>" + choices + "</fieldset>"
                    "<label>Changes (only for approve with changes)"
                    '<textarea name="changes" maxlength="400" rows="2"></textarea></label>'
                    "<p>This records your preference. It does not execute or send work.</p>"
                    '<button type="submit">Record preference</button></form>'
                )
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise WorkChoiceWebError("work choice form unavailable")
        return result

    def submit(self, *, principal: InterfacePrincipal, fields: dict[str, str]) -> SavedWorkChoice:
        """Outer route validates session, Origin/CSRF/body bounds/duplicate fields first."""
        result: SavedWorkChoice | None = None
        try:
            with self._lock:
                if (
                    type(fields) is not dict
                    or set(fields) not in ({"handle", "choice"}, {"handle", "choice", "changes"})
                    or any(type(v) is not str for v in fields.values())
                ):
                    raise ValueError("invalid form fields")
                bound, _packet = self._resolve(fields["handle"], principal)
                choice = WorkChoice(fields["choice"])
                changes = fields.get("changes", "").replace("\r\n", "\n")
                if (
                    len(changes) > 400
                    or (choice == WorkChoice.WITH_CHANGES and not changes.strip())
                    or (choice != WorkChoice.WITH_CHANGES and changes.strip())
                ):
                    raise ValueError("invalid changes")
                preference = WorkPreference(
                    proposal_digest=proposal_fingerprint(bound.selection.proposal),
                    choice=choice,
                    changes=changes if choice == WorkChoice.WITH_CHANGES else None,
                )
                if bound.request_id in self._inflight or len(self._inflight) >= self._capacity:
                    raise ValueError("choice capture already in progress or at capacity")
                self._inflight.add(bound.request_id)
            # Never hold the registry lock across slow protection. SQL advisory
            # locks retain cross-controller/process serialization; this bounded
            # local guard prevents simultaneous duplicate protection work.
            try:
                captured = self._capture.capture(
                    principal=principal,
                    request_id=bound.request_id,
                    retained_receipt=bound.selection.receipt,
                    expected_receipt_digest=bound.selection.receipt_digest,
                    proposal=bound.selection.proposal,
                    preference=preference,
                )
                with self._lock:
                    # TTL limits admission, not successful protection duration.
                    # Still require monotonic time and exact fresh host authority.
                    now = self._now()
                    grant, selected, _packet = self._current(principal, now)
                    if grant != bound.grant or selected != bound.selection or now < bound.issued_at:
                        raise ValueError("choice changed during protection")
                    result = captured
            finally:
                with self._lock:
                    self._inflight.discard(bound.request_id)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise WorkChoiceWebError("work choice unavailable or unprotected")
        return result
