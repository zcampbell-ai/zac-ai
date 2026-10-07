"""Current dual-domain pairing for one concrete Gmail recovery consumer.

A newly paired original-domain session preserves its CONFIDENTIAL grant. It is
not the historical OAuth actor. Only the dedicated foreground host captures this
composition under both actual operator contexts; Python object shape is not a
sandbox against dishonest same-UID host code. No credentials/provider are read.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from typing import Any, Literal
from urllib.parse import parse_qs

from starlette.requests import Request

from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.private_web import InterfacePrincipal, _cookie
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class GmailRecoveryAuthorizationError(RuntimeError):
    pass


class GmailRecoveryAuthorizationCancelled(BaseException):
    pass


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - no session/request/owner frames
            failure = GmailRecoveryAuthorizationError
        except BaseException:  # noqa: BLE001 - preserve sanitized cancellation
            failure = GmailRecoveryAuthorizationCancelled
        del args, kwargs
        raise failure("Gmail original-domain recovery authorization unavailable")

    return call


@dataclass(frozen=True, init=False, repr=False)
class GmailRecoveryAction:
    _join: GmailRecoveryJoin
    _issuer: object
    _original_operation: NamedSessionOperation
    _original_binding: str
    _original_principal: InterfacePrincipal
    _hr_operation: NamedSessionOperation
    _hr_binding: str
    _hr_principal: InterfacePrincipal
    _hr_cookie: str
    _original_cookie: str
    _authority: OAuthTransactionAuthority
    _configuration: OAuthConfiguration
    _generation: str
    _expires: datetime

    def __init__(self) -> None:
        raise TypeError("actual paired recovery action required")

    def __repr__(self) -> str:
        return "GmailRecoveryAction(newly_paired=True, installed=False)"

    @property
    def original_actor_verified(self) -> Literal[False]:
        return False

    @property
    def installed(self) -> Literal[False]:
        return False

    def current(self) -> datetime:
        """Recheck both actual sessions; return their bounded CURRENT action deadline."""
        return self._join._current(self)

    def _scope(self) -> datetime:
        return self.current()


class GmailRecoveryJoin:
    """Host-owned pairing; exact host/inputs must come from the actual contexts."""

    @_closed
    def __init__(
        self,
        *,
        host: Any,
        authority: OAuthTransactionAuthority,
        hr_continuity: NamedSessionContinuity,
        configuration: OAuthConfiguration,
        action_generation: str,
    ) -> None:
        from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostPlan

        if (
            type(host) is not GmailRecoveryHostPlan
            or type(authority) is not OAuthTransactionAuthority
            or type(hr_continuity) is not NamedSessionContinuity
            or type(configuration) is not OAuthConfiguration
            or type(action_generation) is not str
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", action_generation) is None
        ):
            raise ValueError("exact captured recovery host required")
        self._host, self._authority, self._hr = host, authority, hr_continuity
        self._configuration = OAuthConfiguration.model_validate(configuration)
        self._generation = action_generation
        self._issuer = object()
        self._action: GmailRecoveryAction | None = None
        self._pairing_spent = False
        self._original = (
            host,
            authority,
            authority._continuity,
            hr_continuity,
            self._configuration.configuration_digest,
            action_generation,
            authority._directory,
            authority._cipher,
            authority._context,
        )

    def _check(self) -> None:
        if self._original != (
            self._host,
            self._authority,
            self._authority._continuity,
            self._hr,
            self._configuration.configuration_digest,
            self._generation,
            self._authority._directory,
            self._authority._cipher,
            self._authority._context,
        ):
            raise ValueError("original recovery composition changed")
        if self._host._recovery_current() is not None:
            raise ValueError("both actual owner leases required")
        if (
            self._host._original_continuity is not self._authority._continuity
            or self._host._hr_continuity is not self._hr
        ):
            raise ValueError("actual captured owner continuities required")

    def _owners(self, hr_operation: Any, hr_binding: str) -> tuple[Any, Any, Any]:
        self._check()
        original_owner = self._authority._continuity._grant()
        self._check()
        hr = hr_operation.recheck(hr_binding)
        self._check()
        current_original = self._authority._continuity._grant()
        self._check()
        if (
            original_owner != current_original
            or original_owner.identity != hr.principal.identity
            or not any(
                s.boundary is B.BRAINSTORM and C.HIGHLY_RESTRICTED in s.classifications
                for s in hr.principal.scopes
            )
            or not any(
                s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
                for s in original_owner.scopes
            )
        ):
            raise ValueError("same exact original owner and separate HR scope required")
        final_hr = hr_operation.recheck(hr_binding)
        self._check()
        if final_hr.principal != hr.principal:
            raise ValueError("current HR owner changed")
        return original_owner, hr, final_hr

    def _form(self, request: Request, body: bytes, path: str) -> tuple[Any, Any]:
        if (
            type(request) is not Request
            or type(body) is not bytes
            or not 1 <= len(body) <= 512
            or request.method != "POST"
            or request.url.scheme != "https"
            or request.url.path != path
            or request.headers.getlist("host") != [self._authority._host]
            or request.headers.getlist("origin") != [self._authority._origin]
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("actual bounded recovery form required")
        fields = parse_qs(
            body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=4
        )
        if (
            set(fields)
            != {"csrf", "reviewed_configuration_digest", "action_generation", "confirmation"}
            or any(len(v) != 1 for v in fields.values())
            or fields["reviewed_configuration_digest"][0]
            != self._configuration.configuration_digest
            or fields["action_generation"][0] != self._generation
            or fields["confirmation"][0]
            != (
                "RECOVER ORIGINAL GMAIL ONCE"
                if path.endswith("/begin")
                else "PAIR ORIGINAL GMAIL DOMAIN FOR ONE RECOVERY"
            )
        ):
            raise ValueError("explicit original-domain recovery pairing required")
        cookie = _cookie(request, "__Host-zac-session")
        self._check()
        operation = self._hr.for_cookie(cookie)
        verified = operation.establish()
        self._check()
        _, verified, _ = self._owners(operation, verified.binding_digest)
        session = self._hr._sessions.peek_user(cookie, self._hr._clock())
        self._check()
        if (
            session is None
            or session.identity != verified.principal.identity
            or not hmac.compare_digest(fields["csrf"][0], session.csrf)
        ):
            raise ValueError("actual HR owner CSRF required")
        self._owners(operation, verified.binding_digest)
        return operation, verified

    @_closed
    def pair_once(self, request: Request, body: bytes) -> GmailRecoveryAction:
        if self._pairing_spent or self._action is not None:
            raise ValueError("one explicit pairing required")
        hr_operation, hr = self._form(request, body, "/connections/gmail/recover/pair")
        original_owner, hr, _ = self._owners(hr_operation, hr.binding_digest)
        self._pairing_spent = True  # never repeat a session write after uncertainty
        now = self._authority._continuity._clock()
        self._owners(hr_operation, hr.binding_digest)
        cookie = self._authority._continuity._sessions.start_user(hr.principal.identity, now)
        self._owners(hr_operation, hr.binding_digest)
        original_operation = self._authority._continuity.for_cookie(cookie)
        original = original_operation.establish()
        self._owners(hr_operation, hr.binding_digest)
        if (
            original.principal.identity != hr.principal.identity
            or original.principal.scopes != original_owner.scopes
        ):
            raise ValueError("newly paired original scope changed")
        action = object.__new__(GmailRecoveryAction)
        for name, value in (
            ("_join", self),
            ("_issuer", self._issuer),
            ("_original_operation", original_operation),
            ("_original_binding", original.binding_digest),
            ("_original_principal", original.principal),
            ("_hr_operation", hr_operation),
            ("_hr_binding", hr.binding_digest),
            ("_hr_principal", hr.principal),
            ("_hr_cookie", _cookie(request, "__Host-zac-session")),
            ("_original_cookie", cookie),
            ("_authority", self._authority),
            ("_configuration", self._configuration),
            ("_generation", self._generation),
            ("_expires", min(original.effective_expires_at, hr.effective_expires_at)),
        ):
            object.__setattr__(action, name, value)
        self._action = action
        action.current()
        return action

    def _current(self, action: GmailRecoveryAction) -> datetime:
        if (
            type(action) is not GmailRecoveryAction
            or action is not self._action
            or action._issuer is not self._issuer
        ):
            raise ValueError("exact private paired action required")
        self._owners(action._hr_operation, action._hr_binding)
        original = action._original_operation.recheck(action._original_binding)
        self._owners(action._hr_operation, action._hr_binding)
        if original.principal != action._original_principal:
            raise ValueError("paired original owner changed")
        hr = action._hr_operation.recheck(action._hr_binding)
        self._check()
        if hr.principal != action._hr_principal:
            raise ValueError("paired HR owner changed")
        deadline = min(action._expires, original.effective_expires_at, hr.effective_expires_at)
        original_store = self._authority._continuity._sessions
        hr_store = self._hr._sessions
        # Capture session material before the last trusted clock/host callbacks.
        original_before = original_store.peek_user(
            action._original_cookie, self._authority._continuity._clock()
        )
        hr_before = hr_store.peek_user(action._hr_cookie, self._hr._clock())
        self._check()
        original_grant = self._authority._continuity._grant()
        hr_grant = self._hr._grant()
        original_now = self._authority._continuity._clock()
        hr_now = self._hr._clock()
        # No trusted callback follows these actual read-only session lookups.
        original_after = original_store.peek_user(action._original_cookie, original_now)
        hr_after = hr_store.peek_user(action._hr_cookie, hr_now)
        for before, after, verified, grant in (
            (original_before, original_after, original, original_grant),
            (hr_before, hr_after, hr, hr_grant),
        ):
            if (
                before is None
                or after is None
                or before != after
                or after.identity != verified.principal.identity
                or grant.identity != verified.principal.identity
                or grant.scopes != verified.principal.scopes
                or after.issued_at != verified.issued_at
                or after.expires_at != verified.expires_at
            ):
                raise ValueError("terminal paired owner session changed")
        if max(original_now, hr_now) >= deadline:
            raise ValueError("paired recovery action expired")
        return deadline

    def select_original(
        self, action: GmailRecoveryAction, reconciliation: HeldGmailReconciliation
    ) -> Any:
        action.current()
        if (
            type(reconciliation) is not HeldGmailReconciliation
            or reconciliation._authority is not self._authority
        ):
            raise ValueError("original reconciliation required")
        result = reconciliation.select_only_held_recovery(action=action)
        action.current()
        return result
