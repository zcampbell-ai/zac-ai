"""Host-only private-interface credential load seam, not a mounted application.

The two fixed Keychain services are proposed future entries, not installed by
this module. Never call this from agents or API handlers. No environment-secret
fallback, credentials in argv, identity/grant inference or source authority.
No app, provider client, session store, listener or service is constructed here.
"""

from __future__ import annotations

import hmac
import os
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from zacai.config import get_secret
from zacai.policy import TrustBoundary

_ACCOUNT = "zac-owner-sign-in"
_CLIENT_SECRET = "SHARED_OWNER_GOOGLE_CLIENT_SECRET"
_SESSION_KEY = "SHARED_OWNER_SESSION_KEY"
_SERVICES = {
    _CLIENT_SECRET: "zacai-shared-owner-google-client-secret",
    _SESSION_KEY: "zacai-shared-owner-session-key",
}
_TIMEOUT_SECONDS = 5
_MAX_SECRET_BYTES = 4_096


class PrivateStartupError(RuntimeError):
    """Closed diagnostics without credentials, Keychain output or input values."""


@dataclass(frozen=True)
class OwnerStartupConfiguration:
    client_id: str
    origin: str
    client_secret: str = field(repr=False)
    session_key: bytes = field(repr=False)

    @property
    def private_interface_ready(self) -> Literal[False]:
        return False

    @property
    def owner_verified(self) -> Literal[False]:
        return False

    @property
    def source_access_authorized(self) -> Literal[False]:
        return False


def _configuration(client_id: str, origin: str) -> None:
    if (
        type(client_id) is not str
        or len(client_id) > 200
        or re.fullmatch(
            r"[0-9]{1,32}-[A-Za-z0-9_-]{1,128}\.apps\.googleusercontent\.com", client_id
        )
        is None
    ):
        raise ValueError("invalid client identifier")
    if type(origin) is not str or not 1 <= len(origin) <= 261 or not origin.isascii():
        raise ValueError("invalid private origin")
    target = urlsplit(origin)
    host = target.hostname
    if (
        target.scheme != "https"
        or not host
        or target.netloc != host
        or target.path
        or target.query
        or target.fragment
        or origin != "https://" + host
        or len(host) > 253
    ):
        raise ValueError("invalid private origin")
    labels = host.split(".")
    if len(labels) < 2 or all(label.isdecimal() for label in labels):
        raise ValueError("invalid private hostname")
    for label in labels:
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None:
            raise ValueError("invalid private hostname")


def _keychain_secret(name: str) -> str:
    # No public service/account selector; name comes only from fixed load calls.
    service = _SERVICES[name]
    completed = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-a", _ACCOUNT, "-s", service, "-w"],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=_TIMEOUT_SECONDS,
        check=False,
        env={},
    )
    if completed.returncode != 0 or type(completed.stdout) is not bytes:
        raise ValueError("credential unavailable")
    raw = completed.stdout
    # security appends a single output newline. Do not strip actual secret spaces
    # or multiple newlines into a seemingly valid replacement credential.
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not 1 <= len(raw) <= _MAX_SECRET_BYTES:
        raise ValueError("credential size")
    value = raw.decode("ascii")
    if any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("invalid credential characters")
    # An explicit ephemeral mapping prevents any os.environ fallback. This
    # accessor enforces the logical SHARED name against the declared boundary.
    checked = get_secret(name, TrustBoundary.SHARED, env={name: value})
    if checked is None:
        raise ValueError("credential unavailable")
    return checked


def load_owner_startup(*, client_id: str, origin: str) -> OwnerStartupConfiguration:
    """Read only the fixed two entries after validating non-secret inputs.

    Captured stdout is memory only, stderr discarded, timeout bounded. Python
    objects cannot promise secure memory zeroization; no secret is written to
    files/logs/environment or retained in an exception diagnostic by this seam.
    Tests replace subprocess.run and never touch actual Keychain entries.
    Actual escrow/recovery, enrollment and private serving remain separate gates.
    """
    result: OwnerStartupConfiguration | None = None
    try:
        _configuration(client_id, origin)
        client_secret = _keychain_secret(_CLIENT_SECRET)
        key_hex = _keychain_secret(_SESSION_KEY)
        if re.fullmatch(r"[0-9a-fA-F]{64}", key_hex) is None:
            raise ValueError("invalid session key")
        result = OwnerStartupConfiguration(client_id, origin, client_secret, bytes.fromhex(key_hex))
    except Exception:  # noqa: BLE001,S110 - suppress private subprocess diagnostics and chaining
        pass
    if result is None:
        raise PrivateStartupError("private interface startup configuration unavailable")
    return result


# Explicit reviewed-path contract, separate from the unchanged legacy loader.


class PrivateStartupCancelled(BaseException):
    """Sanitized interruption; the host must not automatically retry."""


def _explicit_closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return function(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard secret-bearing inner frames
            kind = PrivateStartupError
        except BaseException:  # noqa: BLE001 - discard interrupted private diagnostics
            kind = PrivateStartupCancelled
        del args, kwargs
        raise kind("private interface startup configuration unavailable")

    return call


def _explicit_configuration(client_id: str, origin: str) -> None:
    if (
        type(client_id) is not str
        or len(client_id) > 200
        or re.fullmatch(
            r"[0-9]{1,32}-[A-Za-z0-9_-]{1,128}\.apps\.googleusercontent\.com", client_id
        )
        is None
    ):
        raise ValueError("invalid client identifier")
    if type(origin) is not str or not 1 <= len(origin) <= 261 or not origin.isascii():
        raise ValueError("invalid private origin")
    target = urlsplit(origin)
    host = target.hostname
    if (
        target.scheme != "https"
        or not host
        or target.netloc != host
        or target.path
        or target.query
        or target.fragment
        or origin != "https://" + host
        or len(host) > 253
    ):
        raise ValueError("invalid private origin")
    labels = host.split(".")
    if len(labels) < 2 or re.fullmatch(r"[a-z]+", labels[-1]) is None:
        raise ValueError("invalid private hostname")
    for label in labels:
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None:
            raise ValueError("invalid private hostname")


def _path(value: Path) -> Path:
    if not isinstance(value, Path):
        raise TypeError("explicit reviewed keychain path required")
    path = Path(str(value))
    if (
        not path.is_absolute()
        or ".." in path.parts
        or not 1 <= len(str(path)) <= 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in str(path))
    ):
        raise ValueError("explicit absolute reviewed keychain path required")
    return path


def _file_policy(path: Path, value: str) -> str:
    if type(value) is not str or value not in {"owner_only", "reviewed_login"}:
        raise ValueError("explicit reviewed keychain file policy required")
    if value == "reviewed_login" and path.name != "login.keychain-db":
        raise ValueError("reviewed login keychain basename required")
    return value


def _path_witness(path: Path, policy: str) -> tuple[tuple[int, int, int, int, int], ...]:
    # Metadata only. Never inspect contents or discover another keychain. This
    # does not prevent malicious same-UID/root races or attest an item's ACL.
    uid = os.getuid()
    witnesses: list[tuple[int, int, int, int, int]] = []
    private_owner_ancestor = False
    for component in reversed(path.parents):
        metadata = component.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, uid}
            or (metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX)
        ):
            raise ValueError("trusted keychain parent namespace required")
        if metadata.st_uid == uid and not metadata.st_mode & 0o077:
            private_owner_ancestor = True
        witnesses.append((metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode, 0))
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_nlink != 1
        or (policy == "owner_only" and metadata.st_mode & 0o077)
        or (
            policy == "reviewed_login"
            and (stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644} or not private_owner_ancestor)
        )
    ):
        raise ValueError("protected owner keychain file required")
    witnesses.append(
        (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode, metadata.st_nlink)
    )
    return tuple(witnesses)


def _timeout(mode: str, foreground: int) -> int:
    if (
        type(mode) is not str
        or mode not in {"background", "foreground"}
        or type(foreground) is not int
        or not 1 <= foreground <= 120
    ):
        raise ValueError("bounded host interaction mode required")
    return 5 if mode == "background" else foreground


def _explicit_keychain_secret(name: str, path: Path, timeout: int) -> str:
    service = _SERVICES[name]
    completed = subprocess.run(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            _ACCOUNT,
            "-s",
            service,
            "-w",
            str(path),
        ],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
        env={},
    )
    if completed.returncode != 0 or type(completed.stdout) is not bytes:
        raise ValueError("credential unavailable")
    raw = completed.stdout.removesuffix(b"\n")
    if not 1 <= len(raw) <= _MAX_SECRET_BYTES:
        raise ValueError("credential size")
    value = raw.decode("ascii")
    if any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("invalid credential characters")
    if name == _CLIENT_SECRET:
        # Apple SecurityTool converts all bytes to unmarked lowercase hex if
        # any byte is nonprintable. Refuse ambiguous literal/converted output.
        if len(value) % 2 == 0 and all(char in "0123456789abcdef" for char in value):
            raise ValueError("ambiguous client secret output")
    elif name == _SESSION_KEY:
        # New host items use tagged printable text, never raw binary or an
        # untagged hex value indistinguishable from SecurityTool conversion.
        if re.fullmatch(r"hex:[0-9a-fA-F]{64}", value) is None:
            raise ValueError("tagged session key required")
    else:
        raise ValueError("fixed credential role required")
    checked = get_secret(name, TrustBoundary.SHARED, env={name: value})
    if type(checked) is not str or not checked:
        raise ValueError("credential unavailable")
    return checked


@dataclass(frozen=True, repr=False, kw_only=True)
class OwnerStartupLoader:
    """Inert fixed owner loader; metadata acceptance is not native policy proof.

    No default search list or discovery. Original host identifiers and selected
    path/interaction/file policy are pinned before any metadata or credential I/O.
    reviewed_login accepts only the named owner-held 0600/0644 file beneath a
    private owner ancestor; live enabling requires explicit owner approval.
    Metadata does not attest extended filesystem ACLs, item ACLs or the console
    client association, and cannot prevent malicious same-UID/root races.

    Foreground permission must use Allow Once, since Always Allow may persist
    /usr/bin/security trust. Actual policy must be rechecked before readiness.
    Timeouts bound each of two subprocess waits, not the total startup duration.
    Stdout is captured before validation; the byte limit is not a streaming cap.
    No programmatic ACL editing, installation, automatic retry or serving occurs.
    Host reporters must not capture traceback locals. Python memory zeroization
    is not promised. Tests replace subprocess and never access real Keychains.
    """

    client_id: str
    origin: str
    keychain_path: Path
    mode: Literal["background", "foreground"] = "background"
    foreground_timeout_seconds: int = 60
    keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    _settings: tuple[str, str, str, str, int, str] = field(init=False, repr=False)

    @_explicit_closed
    def __post_init__(self) -> None:
        _explicit_configuration(self.client_id, self.origin)
        path = _path(self.keychain_path)
        _timeout(self.mode, self.foreground_timeout_seconds)
        policy = _file_policy(path, self.keychain_file_policy)
        object.__setattr__(self, "keychain_path", path)
        object.__setattr__(
            self,
            "_settings",
            (
                self.client_id,
                self.origin,
                str(path),
                self.mode,
                self.foreground_timeout_seconds,
                policy,
            ),
        )

    @_explicit_closed
    def __call__(self, *, client_id: str, origin: str) -> OwnerStartupConfiguration:
        _explicit_configuration(self.client_id, self.origin)
        _explicit_configuration(client_id, origin)
        path = _path(self.keychain_path)
        timeout = _timeout(self.mode, self.foreground_timeout_seconds)
        policy = _file_policy(path, self.keychain_file_policy)
        if (
            not hmac.compare_digest(self.client_id, self._settings[0])
            or not hmac.compare_digest(client_id, self._settings[0])
            or not hmac.compare_digest(self.origin, self._settings[1])
            or not hmac.compare_digest(origin, self._settings[1])
            or not hmac.compare_digest(str(path).encode(), self._settings[2].encode())
            or self.mode != self._settings[3]
            or self.foreground_timeout_seconds != self._settings[4]
            or policy != self._settings[5]
        ):
            raise ValueError("original reviewed startup settings required")
        witness = _path_witness(path, policy)
        client_secret = _explicit_keychain_secret(_CLIENT_SECRET, path, timeout)
        if _path_witness(path, policy) != witness:
            raise ValueError("keychain changed during client load")
        key_text = _explicit_keychain_secret(_SESSION_KEY, path, timeout)
        if _path_witness(path, policy) != witness:
            raise ValueError("keychain changed during session key load")
        return OwnerStartupConfiguration(
            client_id, origin, client_secret, bytes.fromhex(key_text[4:])
        )
