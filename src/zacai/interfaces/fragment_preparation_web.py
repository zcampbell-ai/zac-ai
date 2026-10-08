"""Dormant request-bound preparation; never browser processing admission."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from html import escape
from threading import RLock
from urllib.parse import parse_qs, urlsplit

from starlette.requests import Request

from zacai.claude_local_custody import _SCOPE
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.intelligence.fragment_review_retention import _parts
from zacai.interfaces.fragment_publication_web import FragmentPublicationWeb
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import _USER, _cookie


class FragmentPreparationError(ValueError):
    """Fixed preparation hold; a committed declaration may need reconciliation."""


def _instruction(value: object) -> str:
    """Exact bounded owner wording; never an approval or inferred selection."""
    if (type(value) is not str or value != value.strip()
        or not 0 < len(value.encode("utf-8", errors="strict")) <= 2048):
        raise ValueError("exact nonblank bounded owner instruction required")
    return value


class FragmentPreparationWeb:
    """One trusted factory call after exact current owner POST, not consent.

    Root routes must bound the actual request stream before calling prepare and
    recheck the returned controller before displaying or consuming publication.
    Source custody, recovery configuration and factory body are separate host
    prerequisites. This wrapper neither performs nor acknowledges them.
    """

    def __init__(
        self,
        *,
        inputs: NamedOwnerHostInputs,
        factory: Callable[[NamedOwnerHostInputs, NamedSessionOperation, str], FragmentPublicationWeb],
    ) -> None:
        if (
            type(inputs) is not NamedOwnerHostInputs
            or not callable(factory)
            or type(inputs.owners) is not OwnerGrantStore
            or getattr(inputs.owner, "__self__", None) is not inputs.owners
            or getattr(inputs.owner, "__func__", None) is not OwnerGrantStore.load
        ):
            raise FragmentPreparationError("local task preparation unavailable")
        self._inputs, self._factory = inputs, factory
        self.continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        self._pins = (inputs, factory, self.continuity)
        c = self.continuity
        self._continuity_pins = (c._sessions, c._owner, c._clock, c._context, c._key)
        self._phase = "NEW"
        self._controller: FragmentPublicationWeb | None = None
        self._lock = RLock()

    @staticmethod
    def page(*, csrf: str) -> str:
        """Pure form; root GET supplies actual current-session CSRF separately."""
        if type(csrf) is not str or not 1 <= len(csrf) <= 128:
            raise FragmentPreparationError("local task preparation unavailable")
        return (
            "<p>Describe the task for the configured context. This encrypts and backs up the full PERSONAL "
            "inventory and retains a plaintext recovery copy in a separate local folder. "
            "It does not approve "
            'AI processing.</p><form method="post" action="/prepare-caz-task" accept-charset="UTF-8">'
            '<input type="hidden" name="action" value="prepare">'
            '<input type="hidden" name="csrf" value="'
            + escape(csrf, quote=True)
            + '"><label for="task-instruction">What would you like Caz to do?</label>'
            '<textarea id="task-instruction" name="instruction" spellcheck="false" autocomplete="off" autocapitalize="off" required></textarea>'
            '<button type="submit">Prepare task</button></form>'
        )

    def prepared_controller(self) -> FragmentPublicationWeb:
        """Transient exact result only; never session or processing authority."""
        # PREPARED is terminal and its controller never changes. Do not block
        # or refuse withdrawal because an unrelated request holds this lock.
        if self._phase == "PREPARED" and self._controller is not None:
            return self._controller
        if not self._lock.acquire(blocking=False):
            raise FragmentPreparationError("local task preparation unavailable")
        try:
            if self._phase != "PREPARED" or self._controller is None:
                raise FragmentPreparationError("local task preparation unavailable")
            return self._controller
        finally:
            self._lock.release()

    def prepare(self, *, request: Request, body: bytes) -> FragmentPublicationWeb:
        if not self._lock.acquire(blocking=False):
            raise FragmentPreparationError("local task preparation unavailable")
        try:
            if self._phase != "NEW":
                raise FragmentPreparationError("local task preparation unavailable")
            result = None
            uncertain = False
            try:
                self._phase = "ENTERED"
                i, c = self._inputs, self.continuity
                if (
                    any(a is not b for a, b in zip(self._pins, (i, self._factory, c), strict=True))
                    or type(request) is not Request
                    or type(body) is not bytes
                    or not 0 < len(body) <= 2048
                    or request.method != "POST"
                    or request.url.path != "/prepare-caz-task"
                    or request.scope.get("query_string", b"")
                    or request.headers.getlist("host") != [urlsplit(i.origin).netloc]
                    or request.headers.getlist("origin") != [i.origin]
                    or request.headers.getlist("content-type")
                    != ["application/x-www-form-urlencoded"]
                ):
                    raise ValueError("exact preparation POST required")
                fields = parse_qs(
                    body.decode("ascii", errors="strict"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    encoding="utf-8",
                    errors="strict",
                )
                if (
                    set(fields) != {"action", "csrf", "instruction"}
                    or any(len(v) != 1 for v in fields.values())
                    or fields["action"] != ["prepare"]
                ):
                    raise ValueError("closed preparation fields required")
                instruction = _instruction(fields["instruction"][0])
                cookie = _cookie(request, _USER)
                operation = c.for_cookie(cookie)
                if operation._source is not c:
                    raise ValueError("original operation continuity required")
                operation_pins = (operation._read, operation._host_clock, operation._source)
                before = operation.establish()
                current = i.sessions.peek_user(cookie, i.clock())
                after = operation.recheck(before.binding_digest)
                if (
                    current is None
                    or before != after
                    or after.principal.scopes != _SCOPE
                    or current.identity != after.principal.identity
                    or not secrets.compare_digest(fields["csrf"][0], current.csrf)
                    or self._phase != "ENTERED"
                ):
                    raise ValueError("current exact owner preparation required")
                controller = self._factory(i, operation, instruction)
                if self._phase != "ENTERED" or type(controller) is not FragmentPublicationWeb:
                    raise ValueError("exact once-only controller required")
                if (
                    controller._continuity is not c
                    or controller.host_clock is not i.clock
                    or controller._protector._operation is not operation
                    or controller._protector._clock is not i.clock
                ):
                    raise ValueError("original operation graph required")
                _, _, prepared_request = _parts(controller._publication)
                if (prepared_request.original_task.instruction != instruction
                    or prepared_request.task.instruction != instruction):
                    raise ValueError("exact submitted instruction required")
                controller._pins()
                i.clock()
                final = operation.recheck(before.binding_digest)
                with i.clock._lock:
                    observed = i.clock._last
                _, generation, final_request = _parts(controller._publication)
                if (
                    self._phase != "ENTERED"
                    or final != before
                    or final_request.original_task.instruction != instruction
                    or final_request.task.instruction != instruction
                    or observed is None
                    or any(
                        a is not b
                        for a, b in zip(
                            self._pins, (self._inputs, self._factory, self.continuity), strict=True
                        )
                    )
                    or operation._source is not c
                    or controller._continuity is not c
                    or controller._protector._operation is not operation
                    or controller._protector._clock is not i.clock
                    or c._owner is not i.owner
                    or c._sessions is not i.sessions
                    or c._clock is not i.clock
                    or (c._sessions, c._owner, c._clock, c._context, c._key)
                    != self._continuity_pins
                    or any(
                        a is not b
                        for a, b in zip(
                            operation_pins,
                            (operation._read, operation._host_clock, operation._source),
                            strict=True,
                        )
                    )
                    or generation.owner_issuer != final.principal.identity.issuer
                    or generation.owner_subject != final.principal.identity.subject
                    or generation.original_session_binding != final.binding_digest
                    or generation.original_session_issued_at != final.issued_at
                    or generation.original_session_expires_at != final.effective_expires_at
                    or not generation.approved_at
                    <= observed
                    < generation.expires_at
                    <= final.effective_expires_at
                ):
                    raise ValueError("original declaration session/window required")
                self._controller = controller
                self._phase = "PREPARED"
                result = controller
            except PersonalFragmentCleanupUncertain:
                self._phase = "HELD"
                self._controller = None
                uncertain = True
            except BaseException:  # noqa: BLE001 - hold and sanitize interrupted callbacks too
                self._phase = "HELD"
                self._controller = None
            if result is None:
                if uncertain:
                    raise PersonalFragmentCleanupUncertain(
                        "PERSONAL recovery cleanup uncertain; operator review required"
                    )
                raise FragmentPreparationError("local task preparation unavailable")
            return result
        finally:
            self._lock.release()
