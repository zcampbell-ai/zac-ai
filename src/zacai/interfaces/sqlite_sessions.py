"""Disposable encrypted operational sessions; never canonical business memory.

Only authentication transaction/user state is persisted. No access/refresh/ID
provider tokens, grants or source context. Host injects a 32-byte approved Keychain
key; this adapter neither loads/creates keys nor puts them in files or backups.
Loss of key/store requires signing in again. SQLite initialization here is not a
Zac State migration. Do not mount this backend without separate rollout review.
Filesystem restrictions protect other OS users, not processes sharing the host UID.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zacai.interfaces.session_store import Identity, UserSession, _aware, _digest

_T = TypeVar("_T")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _stamp(now: datetime) -> int:
    _aware(now)
    delta = now.astimezone(UTC) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _time(stamp: int) -> datetime:
    return _EPOCH + timedelta(microseconds=stamp)


def _login(data: dict[str, object]) -> dict[str, object]:
    if type(data) is not dict or len(data) != 2 or not isinstance(data.get("zac_nonce"), str):
        raise ValueError("invalid transaction")
    keys = [key for key in data if key != "zac_nonce"]
    key = keys[0]
    if not re.fullmatch(r"_state_[a-zA-Z0-9]{1,32}_[A-Za-z0-9_-]{20,128}", key):
        raise ValueError("invalid transaction")
    state = data[key]
    if type(state) is not dict or set(state) != {"data", "exp"}:
        raise ValueError("invalid transaction")
    expiry, values = state["exp"], state["data"]
    if type(expiry) not in (float, int) or not math.isfinite(expiry):
        raise ValueError("invalid transaction")
    required = {"nonce", "code_verifier", "redirect_uri"}
    if type(values) is not dict or not required <= set(values) <= required | {"url"}:
        raise ValueError("invalid transaction")
    if any(not isinstance(values[k], str) for k in required):
        raise ValueError("invalid transaction")
    if (
        values["nonce"] != data["zac_nonce"]
        or not 20 <= len(values["nonce"]) <= 128
        or not 43 <= len(values["code_verifier"]) <= 128
        or not 1 <= len(values["redirect_uri"]) <= 2048
    ):
        raise ValueError("invalid transaction")
    # Authlib doesn't need its saved authorization URL during callback validation.
    return {
        "zac_nonce": data["zac_nonce"],
        key: {"exp": expiry, "data": {k: values[k] for k in required}},
    }


class SqliteSessionStore:
    """Atomic cross-process sessions with authenticated payload/metadata binding.

    Existing paths with unexpected permissions, links or schema fail closed rather
    than being silently repaired. The directory must be a trusted host path, never
    client input; same-UID malicious filesystem replacement remains a host threat.
    Runtime key recovery, owner enrollment, safe access logging and private serving
    must be approved/verified separately. No auth-state backups are performed.
    """

    def __init__(
        self,
        directory: Path,
        *,
        key: bytes,
        capacity: int = 128,
        idle: timedelta = timedelta(minutes=30),
        lifetime: timedelta = timedelta(hours=8),
    ) -> None:
        if (
            type(key) is not bytes
            or len(key) != 32
            or type(capacity) is not int
            or not 1 <= capacity <= 1024
            or not timedelta(0) < idle <= lifetime <= timedelta(hours=24)
            or not directory.is_absolute()
        ):
            raise ValueError("session store unavailable")
        self._directory = directory
        self._path = directory / "sessions.sqlite"
        self._cipher = AESGCM(key)
        self._capacity = capacity
        self._idle = int(idle.total_seconds() * 1_000_000)
        self._lifetime = int(lifetime.total_seconds() * 1_000_000)
        okay = False
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            self._guard(directory, directory=True)
            created = False
            try:
                fd = os.open(
                    self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                os.close(fd)
                created = True
            except FileExistsError:
                pass
            self._guard(self._path)
            with self._transaction() as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if created:
                    if version != 0:
                        raise ValueError("unexpected store schema")
                    connection.execute(
                        "CREATE TABLE sessions(digest TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('login','user')), issued INTEGER NOT NULL, seen INTEGER NOT NULL, expires INTEGER NOT NULL, sealed BLOB NOT NULL)"
                    )
                    connection.execute("PRAGMA user_version=1")
                elif version != 1:
                    raise ValueError("unexpected store schema")
                columns = connection.execute("PRAGMA table_info(sessions)").fetchall()
                if [row[1] for row in columns] != [
                    "digest",
                    "kind",
                    "issued",
                    "seen",
                    "expires",
                    "sealed",
                ]:
                    raise ValueError("unexpected store schema")
            okay = True
        except Exception:  # noqa: BLE001, S110 - never expose keys/paths/backend diagnostics
            pass
        if not okay:
            raise ValueError("session store unavailable")

    @staticmethod
    def _guard(path: Path, *, directory: bool = False) -> None:
        info = path.lstat()
        if (
            info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)
        ):
            raise ValueError("unsafe store path")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._guard(self._directory, directory=True)
        self._guard(self._path)
        connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        try:
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA synchronous=FULL")
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("unexpected journal mode")
            connection.execute("BEGIN IMMEDIATE")
            self._guard(self._directory, directory=True)
            self._guard(self._path)
            yield connection
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _run(self, operation: Callable[[sqlite3.Connection], _T]) -> _T:
        try:
            with self._transaction() as connection:
                return operation(connection)
        except Exception:  # noqa: BLE001, S110 - no private operational diagnostics
            pass
        raise ValueError("session store unavailable")

    @staticmethod
    def _aad(digest: str, kind: str, issued: int, seen: int, expires: int) -> bytes:
        return json.dumps(
            ["zac-session-row-v1", digest, kind, issued, seen, expires], separators=(",", ":")
        ).encode()

    def _seal(self, data: dict[str, object], aad: bytes) -> bytes:
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > 16_000:
            raise ValueError("payload outside limits")
        nonce = secrets.token_bytes(12)
        return nonce + self._cipher.encrypt(nonce, raw, aad)

    def _open(self, sealed: bytes, aad: bytes) -> dict[str, object]:
        if not 28 <= len(sealed) <= 16_028:
            raise ValueError("payload outside limits")
        data = json.loads(self._cipher.decrypt(sealed[:12], sealed[12:], aad))
        if type(data) is not dict:
            raise ValueError("invalid payload")
        return data

    def _purge(self, connection: sqlite3.Connection, now: int) -> None:
        connection.execute(
            "DELETE FROM sessions WHERE expires<=? OR (kind='user' AND seen<=?)",
            (now, now - self._idle),
        )

    def _create(
        self,
        connection: sqlite3.Connection,
        kind: str,
        data: dict[str, object],
        now: int,
        lifetime: int,
    ) -> str:
        self._purge(connection, now)
        count = connection.execute(
            "SELECT COUNT(*) FROM sessions WHERE kind=?", (kind,)
        ).fetchone()[0]
        if count >= self._capacity:
            if kind != "login":
                raise ValueError("session capacity unavailable")
            # Only oldest pending state is displaced; owner sessions are reserved.
            connection.execute(
                "DELETE FROM sessions WHERE digest IN (SELECT digest FROM sessions WHERE kind='login' ORDER BY issued,digest LIMIT 1)"
            )
        token = secrets.token_urlsafe(32)
        digest = _digest(token)
        if digest is None:
            raise ValueError("invalid generated token")
        expires = now + lifetime
        sealed = self._seal(data, self._aad(digest, kind, now, now, expires))
        connection.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?)", (digest, kind, now, now, expires, sealed)
        )
        return token

    def start_login(self, data: dict[str, object], now: datetime) -> str:
        stamp = _stamp(now)
        return self._run(
            lambda connection: self._create(connection, "login", _login(data), stamp, 300_000_000)
        )

    def consume_login(self, token: str, now: datetime) -> dict[str, object] | None:
        stamp, digest = _stamp(now), _digest(token)
        if digest is None:
            return None

        def consume(connection: sqlite3.Connection) -> dict[str, object] | None:
            row = connection.execute(
                "SELECT kind,issued,seen,expires,sealed FROM sessions WHERE digest=?", (digest,)
            ).fetchone()
            if row is None or row[0] != "login":
                return None
            data = _login(self._open(row[4], self._aad(digest, *row[:4])))
            connection.execute("DELETE FROM sessions WHERE digest=?", (digest,))
            return data if row[1] <= stamp < row[3] else None

        return self._run(consume)

    def start_user(self, identity: Identity, now: datetime) -> str:
        stamp = _stamp(now)
        if (
            not isinstance(identity.issuer, str)
            or not isinstance(identity.subject, str)
            or not 1 <= len(identity.issuer) <= 2048
            or not 1 <= len(identity.subject) <= 255
        ):
            raise ValueError("session store unavailable")
        data: dict[str, object] = {
            "issuer": identity.issuer,
            "subject": identity.subject,
            "csrf": secrets.token_urlsafe(32),
        }
        return self._run(
            lambda connection: self._create(connection, "user", data, stamp, self._lifetime)
        )

    def user(self, token: str, now: datetime) -> UserSession | None:
        stamp, digest = _stamp(now), _digest(token)
        if digest is None:
            return None

        def lookup(connection: sqlite3.Connection) -> UserSession | None:
            row = connection.execute(
                "SELECT kind,issued,seen,expires,sealed FROM sessions WHERE digest=?", (digest,)
            ).fetchone()
            if row is None or row[0] != "user":
                return None
            data = self._open(row[4], self._aad(digest, *row[:4]))
            issuer, subject, csrf = data.get("issuer"), data.get("subject"), data.get("csrf")
            if (
                set(data) != {"issuer", "subject", "csrf"}
                or not isinstance(issuer, str)
                or not isinstance(subject, str)
                or not isinstance(csrf, str)
                or _digest(csrf) is None
            ):
                raise ValueError("invalid user payload")
            if stamp < row[2] or stamp >= row[3] or stamp - row[2] >= self._idle:
                connection.execute("DELETE FROM sessions WHERE digest=?", (digest,))
                return None
            sealed = self._seal(data, self._aad(digest, "user", row[1], stamp, row[3]))
            connection.execute(
                "UPDATE sessions SET seen=?,sealed=? WHERE digest=?", (stamp, sealed, digest)
            )
            return UserSession(
                Identity(issuer, subject),
                _time(row[1]),
                _time(stamp),
                _time(row[3]),
                csrf,
            )

        return self._run(lookup)

    def revoke(self, token: str) -> None:
        digest = _digest(token)
        if digest:
            self._run(
                lambda connection: connection.execute(
                    "DELETE FROM sessions WHERE digest=?", (digest,)
                )
            )

    def revoke_identity(self, identity: Identity) -> None:
        def remove(connection: sqlite3.Connection) -> None:
            rows = connection.execute(
                "SELECT digest,kind,issued,seen,expires,sealed FROM sessions WHERE kind='user'"
            ).fetchall()
            for row in rows:
                invalid = False
                try:
                    data = self._open(row[5], self._aad(*row[:5]))
                    csrf = data.get("csrf")
                    invalid = (
                        set(data) != {"issuer", "subject", "csrf"}
                        or not isinstance(data.get("issuer"), str)
                        or not isinstance(data.get("subject"), str)
                        or not isinstance(csrf, str)
                        or _digest(csrf) is None
                    )
                except Exception:  # noqa: BLE001 - fail closed on corrupt/wrong-key rows
                    invalid = True
                    data = {}
                if invalid or (
                    data.get("issuer") == identity.issuer
                    and data.get("subject") == identity.subject
                ):
                    connection.execute("DELETE FROM sessions WHERE digest=?", (row[0],))

        self._run(remove)

    def revoke_all(self) -> None:
        """Trusted host lifecycle only: atomically invalidate users and logins.

        No browser endpoint invokes this. Explicit owner recovery/re-enrollment
        must call it before confirming a replacement, so old cookies and pending
        transactions cannot revive under the same identity. Auth state only;
        canonical sources and owner grants are untouched.
        """
        self._run(lambda connection: connection.execute("DELETE FROM sessions"))
