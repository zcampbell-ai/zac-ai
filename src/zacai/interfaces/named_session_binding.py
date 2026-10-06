"""Actual current session continuity for trusted named-action composition.

No new authentication framework or credential loading. The existing enrolled
owner and encrypted SqliteSessionStore remain authoritative. A digest is only
correlation, never a bearer/session/processing grant. The raw cookie is transient
in one hidden operation closure; it is never persisted or returned as metadata.
Call only outside canonical SQL/restore leases; host logging must exclude locals.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import UserSession
from zacai.interfaces.sqlite_sessions import SqliteSessionStore

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class NamedSessionBindingError(ValueError):
    """Fixed private-safe diagnostics without chained provider/store details."""


@dataclass(frozen=True)
class VerifiedNamedSession:
    principal: InterfacePrincipal = field(repr=False)
    binding_digest: str = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    effective_expires_at: datetime

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class NamedSessionOperation:
    """Host-created per-operation closure, not client supplied authentication."""

    def __init__(self, source: NamedSessionContinuity, cookie: str) -> None:
        if (
            type(source) is not NamedSessionContinuity
            or type(cookie) is not str
            or _TOKEN.fullmatch(cookie) is None
        ):
            raise NamedSessionBindingError("named session operation unavailable")
        self._read: Callable[[], VerifiedNamedSession] = lambda: source._current(cookie)
        self._host_clock: Callable[[], HostObservedClock] = lambda: source._clock

    @property
    def host_clock(self) -> HostObservedClock:
        """Exact original host clock, never cookie/session/processing authority."""
        return self._host_clock()

    def establish(self) -> VerifiedNamedSession:
        """Actually verify the current session for first admitted owner action."""
        return self._read()

    def recheck(self, expected_binding: str) -> VerifiedNamedSession:
        """Same original actual cookie/session required; digest alone denies."""
        result: VerifiedNamedSession | None = None
        try:
            if type(expected_binding) is not str or _DIGEST.fullmatch(expected_binding) is None:
                raise ValueError("exact original binding required")
            verified = self._read()
            if not hmac.compare_digest(expected_binding, verified.binding_digest):
                raise ValueError("original browser session changed")
            result = verified
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedSessionBindingError("original named session unavailable")
        return result

    def receipt_only(self, expected_principal: InterfacePrincipal) -> VerifiedNamedSession:
        """Current exact owner session for preservation only; no renewed action.

        May be a new actual cookie. Original named action must still pass recheck
        to process. Canonical repair independently verifies immutable actor/ACL.
        """
        result: VerifiedNamedSession | None = None
        try:
            if type(expected_principal) is not InterfacePrincipal:
                raise ValueError("exact canonical principal required")
            checked = self._read()
            if checked.principal != expected_principal:
                raise ValueError("canonical owner changed")
            result = checked
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedSessionBindingError("named recovery session unavailable")
        return result


class NamedSessionContinuity:
    def __init__(
        self,
        *,
        sessions: SqliteSessionStore,
        owner: Callable[[], OwnerGrant],
        clock: HostObservedClock,
        key: bytes,
        origin: str,
        client_id: str,
    ) -> None:
        okay = False
        try:
            target = urlsplit(origin)
            if (
                type(sessions) is not SqliteSessionStore
                or not callable(owner)
                or type(clock) is not HostObservedClock
                or type(key) is not bytes
                or len(key) != 32
                or type(origin) is not str
                or target.scheme != "https"
                or not target.hostname
                or target.netloc != target.hostname
                or target.path
                or target.query
                or target.fragment
                or type(client_id) is not str
                or re.fullmatch(r"[A-Za-z0-9._-]{1,255}", client_id) is None
            ):
                raise ValueError("trusted host dependencies required")
            self._sessions, self._owner, self._clock = sessions, owner, clock
            self._context = canonical_bytes({"origin": origin, "client_id": client_id})
            self._key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"zac-named-session-binding-key-v1",
                info=b"zac-named-session-binding-v1\x00" + self._context,
            ).derive(key)
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedSessionBindingError("named session host unavailable")

    def _grant(self) -> OwnerGrant:
        configured = self._owner()
        if type(configured) is not OwnerGrant:
            raise ValueError("exact enrolled owner required")
        return OwnerGrant(configured.identity, configured.scopes)

    def _current(self, cookie: str) -> VerifiedNamedSession:
        result: VerifiedNamedSession | None = None
        try:
            if type(cookie) is not str or _TOKEN.fullmatch(cookie) is None:
                raise ValueError("actual browser cookie required")
            before = self._grant()  # owner FIRST: denied cookies cannot idle-refresh
            now = self._clock()
            session = self._sessions.peek_user(cookie, now)
            after = self._grant()
            # Owner callbacks finish before the final actual session lookup;
            # a revocation during the post-call owner check cannot pass.
            second_now = self._clock()
            refreshed = self._sessions.peek_user(cookie, second_now) if before == after else None
            checked_now = self._clock()
            if (
                type(session) is not UserSession
                or type(refreshed) is not UserSession
                or before != after
                or session.identity != before.identity
                or (session.identity, session.issued_at, session.expires_at, session.csrf)
                != (refreshed.identity, refreshed.issued_at, refreshed.expires_at, refreshed.csrf)
                or not session.issued_at
                <= session.last_seen_at
                <= now
                <= second_now
                <= checked_now
                < session.expires_at
                or not session.last_seen_at <= refreshed.last_seen_at <= second_now
                or checked_now - refreshed.last_seen_at
                >= self._sessions.user_idle_timeout
                or type(session.csrf) is not str
                or _TOKEN.fullmatch(session.csrf) is None
            ):
                raise ValueError("current browser session unavailable")
            binding = hmac.new(
                self._key,
                b"zac-named-session-correlation-v1\x00"
                + self._context
                + canonical_bytes(
                    {
                        "cookie": cookie,
                        "issuer": session.identity.issuer,
                        "subject": session.identity.subject,
                        "issued_at": session.issued_at.isoformat(),
                        "expires_at": session.expires_at.isoformat(),
                        "csrf": session.csrf,
                        "scopes": [
                            {
                                "boundary": scope.boundary.value,
                                "classifications": sorted(c.value for c in scope.classifications),
                            }
                            for scope in sorted(
                                before.scopes, key=lambda scope: scope.boundary.value
                            )
                        ],
                    }
                ),
                "sha256",
            ).hexdigest()
            result = VerifiedNamedSession(
                InterfacePrincipal(after.identity, after.scopes),
                binding,
                session.issued_at,
                session.expires_at,
                min(refreshed.expires_at,
                    refreshed.last_seen_at + self._sessions.user_idle_timeout),
            )
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedSessionBindingError("current named session unavailable")
        return result

    def for_cookie(self, cookie: str) -> NamedSessionOperation:
        """Raw cookie remains only in hidden transient closure, never disk/record.

        Construction itself validates no identity. Every operation rechecks the
        actual current owner/session. Do not persist, log or expose this closure.
        """
        if type(cookie) is not str or _TOKEN.fullmatch(cookie) is None:
            raise NamedSessionBindingError("current named session unavailable")
        return NamedSessionOperation(self, cookie)
