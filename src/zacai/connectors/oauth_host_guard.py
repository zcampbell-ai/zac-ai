"""Explicit one-way operational OAuth stop gate, never token authority.

Construction is inert. The trusted operator initializes a NEW private directory
once; missing/corrupt state thereafter denies. Halt persists across instances and
restarts, with no reset/release API. All participating adapters must check ready;
this observation does not serialize an entire provider request or stop adapters
that ignore it. Use the existing exclusive operator lease and per-operation
checks. A failed halt is fatal: stop the host and reconcile, never acknowledge it.
Same-UID malicious file replacement/rollback requires host isolation. No tokens,
identities, request material or canonical data are stored here.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from zacai.connectors.connector_authority import _guard, _json
from zacai.interfaces.private_startup import _configuration


class OAuthHostGuardError(RuntimeError):
    """Fixed closed readiness error."""


class OAuthHostHaltUnconfirmed(BaseException):
    """Fatal: persistence is uncertain; host must stop and reconcile."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException] = OAuthHostGuardError
        try:
            return method(*args, **kwargs)
        except OAuthHostHaltUnconfirmed:
            failure = OAuthHostHaltUnconfirmed
        except Exception:  # noqa: BLE001,S110
            pass
        except BaseException:  # noqa: BLE001 - private-safe fatal interruption
            failure = OAuthHostHaltUnconfirmed
        del args, kwargs
        raise failure("OAuth host stopped; local reconciliation required")

    return call


class OAuthHostGuard:
    """Authenticated fixed readiness marker plus a sticky stop marker.

    Initialize is for a fresh operator-approved location only. Creation of the
    exclusive lock spends initialization before ready state is written; failure
    cannot be repaired by retrying initialization. Never delete lock/markers to
    restart. Halt has no automatic recovery or alternate directory fallback.
    """

    @_closed
    def __init__(self, directory: Path, *, key: bytes, origin: str, client_id: str) -> None:
        _configuration(client_id, origin)
        if (
            not isinstance(directory, Path)
            or not directory.is_absolute()
            or type(key) is not bytes
            or len(key) != 32
        ):
            raise ValueError("explicit trusted host configuration required")
        self._directory = directory
        self._lock_path = directory / "oauth-host.lock"
        self._ready_path = directory / "oauth-host.ready"
        self._halt_path = directory / "oauth-host.halted"
        context = _json({"origin": origin, "client_id": client_id})
        self._ready_bytes = hmac.digest(
            key, b"zac-oauth-host-ready-v1\x00" + context, hashlib.sha256
        )
        self._halt_bytes = b"zac-oauth-host-halted-v1\n"
        self._stopped = False

    def _directory_guard(self) -> None:
        _guard(self._directory, directory=True)
        if self._directory.resolve(strict=True) != self._directory:
            raise ValueError("exact trusted directory required")

    def _sync_directory(self) -> None:
        fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _create(self, path: Path, value: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, value) != len(value):
                raise ValueError("incomplete marker")
            os.fsync(fd)
        finally:
            os.close(fd)
        _guard(path)
        self._sync_directory()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._directory_guard()
        expected = _guard(self._lock_path)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValueError("lock changed")
            fcntl.flock(fd, fcntl.LOCK_EX)
            after = _guard(self._lock_path)
            if (after.st_dev, after.st_ino) != (actual.st_dev, actual.st_ino):
                raise ValueError("lock replaced")
            yield
        finally:
            os.close(fd)

    @_closed
    def initialize(self) -> None:
        if self._stopped:
            raise ValueError("host already stopped")
        self._stopped = True
        spent = okay = False
        try:
            self._directory_guard()
            if (
                self._ready_path.exists()
                or self._ready_path.is_symlink()
                or self._halt_path.exists()
                or self._halt_path.is_symlink()
            ):
                raise ValueError("existing host state")
            fd = os.open(
                self._lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            spent = True
            try:
                value = b"zac-oauth-host-lock-v1\n"
                if os.write(fd, value) != len(value):
                    raise ValueError("incomplete lock")
                os.fsync(fd)
            finally:
                os.close(fd)
            _guard(self._lock_path)
            self._sync_directory()
            with self._locked():
                if self._halt_path.exists() or self._halt_path.is_symlink():
                    raise ValueError("host stopped during initialization")
                self._create(self._ready_path, self._ready_bytes)
            self._stopped = False
            self.ready()
            okay = True
        except BaseException:  # noqa: BLE001,S110 - reconcile any ambiguous publication
            pass
        if not okay:
            self._stopped = True
            if spent:
                self.halt_unconfirmed()
            raise OAuthHostGuardError("OAuth host initialization not acknowledged")

    @_closed
    def ready(self) -> None:
        if self._stopped:
            raise ValueError("host stopped")
        with self._locked():
            if self._halt_path.exists() or self._halt_path.is_symlink():
                self._stopped = True
                raise ValueError("host stopped")
            expected = _guard(self._ready_path)
            if expected.st_size != len(self._ready_bytes):
                raise ValueError("invalid marker")
            fd = os.open(self._ready_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                actual = os.fstat(fd)
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    raise ValueError("marker changed")
                value = os.read(fd, len(self._ready_bytes) + 1)
            finally:
                os.close(fd)
            final = _guard(self._ready_path)
            if (final.st_dev, final.st_ino) != (
                actual.st_dev,
                actual.st_ino,
            ) or not hmac.compare_digest(value, self._ready_bytes):
                raise ValueError("host binding differs")

    @_closed
    def halt_unconfirmed(self) -> None:
        self._stopped = True
        okay = False
        try:
            with self._locked():
                if self._halt_path.exists() or self._halt_path.is_symlink():
                    _guard(self._halt_path)
                    # Existing stop state still needs durability acknowledgement.
                    fd = os.open(self._halt_path, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    self._sync_directory()
                else:
                    self._create(self._halt_path, self._halt_bytes)
                okay = True
        except BaseException:  # noqa: BLE001,S110 - fatal, no unsafe retry
            pass
        if not okay:
            raise OAuthHostHaltUnconfirmed("OAuth host halt not acknowledged; stop and reconcile")
