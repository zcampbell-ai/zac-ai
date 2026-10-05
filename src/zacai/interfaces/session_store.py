"""Opaque server sessions for an unmounted interface, not agent authority.

The bounded in-memory adapter is for rehearsal only: restart invalidates sessions.
A production store needs host-only access, atomic consumption/revocation, no raw
cookie persistence and a reviewed rollout. This does not authenticate identities.
"""

from __future__ import annotations

import copy
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Protocol


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str


@dataclass(frozen=True)
class UserSession:
    identity: Identity
    issued_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    csrf: str = field(repr=False)


class SessionStore(Protocol):
    def start_login(self, data: dict[str, object], now: datetime) -> str: ...
    def consume_login(self, token: str, now: datetime) -> dict[str, object] | None: ...
    def start_user(self, identity: Identity, now: datetime) -> str: ...
    def user(self, token: str, now: datetime) -> UserSession | None: ...
    def revoke(self, token: str) -> None: ...
    def revoke_identity(self, identity: Identity) -> None: ...


def _digest(token: str) -> str | None:
    if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _aware(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("invalid session time")


class InMemorySessionStore:
    """Bounded rehearsal adapter; no database, credentials or production setup."""

    def __init__(
        self,
        *,
        capacity: int = 128,
        idle: timedelta = timedelta(minutes=30),
        lifetime: timedelta = timedelta(hours=8),
    ) -> None:
        if (
            type(capacity) is not int
            or not 1 <= capacity <= 1024
            or not timedelta(0) < idle <= lifetime <= timedelta(hours=24)
        ):
            raise ValueError("invalid session limits")
        self._capacity = capacity
        self._idle = idle
        self._lifetime = lifetime
        self._login: dict[str, tuple[datetime, dict[str, object]]] = {}
        self._users: dict[str, UserSession] = {}
        self._lock = Lock()

    def _new(self) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        digest = _digest(token)
        if digest is None or digest in self._login or digest in self._users:
            raise ValueError("session creation unavailable")
        return token, digest

    def _purge(self, now: datetime) -> None:
        self._login = {k: v for k, v in self._login.items() if now < v[0]}
        self._users = {
            k: v
            for k, v in self._users.items()
            if now < v.expires_at and now - v.last_seen_at < self._idle
        }

    def start_login(self, data: dict[str, object], now: datetime) -> str:
        _aware(now)
        with self._lock:
            self._purge(now)
            # Independent pending capacity cannot consume authenticated slots.
            if len(self._login) >= self._capacity:
                oldest = min(self._login, key=lambda item: self._login[item][0])
                del self._login[oldest]
            token, digest = self._new()
            self._login[digest] = (now + timedelta(minutes=5), copy.deepcopy(data))
            return token

    def consume_login(self, token: str, now: datetime) -> dict[str, object] | None:
        _aware(now)
        digest = _digest(token)
        with self._lock:
            item = self._login.pop(digest, None) if digest else None
            if item is None or now >= item[0] or now < item[0] - timedelta(minutes=5):
                return None
            return copy.deepcopy(item[1])

    def start_user(self, identity: Identity, now: datetime) -> str:
        _aware(now)
        with self._lock:
            self._purge(now)
            if len(self._users) >= self._capacity:
                raise ValueError("session capacity unavailable")
            token, digest = self._new()
            self._users[digest] = UserSession(
                identity, now, now, now + self._lifetime, secrets.token_urlsafe(32)
            )
            return token

    def user(self, token: str, now: datetime) -> UserSession | None:
        _aware(now)
        digest = _digest(token)
        with self._lock:
            item = self._users.get(digest) if digest else None
            if item is None:
                return None
            if (
                now < item.last_seen_at
                or now >= item.expires_at
                or now - item.last_seen_at >= self._idle
            ):
                if digest:
                    self._users.pop(digest, None)
                return None
            updated = UserSession(item.identity, item.issued_at, now, item.expires_at, item.csrf)
            if digest:
                self._users[digest] = updated
            return updated

    def revoke(self, token: str) -> None:
        digest = _digest(token)
        with self._lock:
            if digest:
                self._login.pop(digest, None)
                self._users.pop(digest, None)

    def revoke_identity(self, identity: Identity) -> None:
        with self._lock:
            self._users = {k: v for k, v in self._users.items() if v.identity != identity}
