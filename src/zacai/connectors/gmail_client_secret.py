"""Fixed read-only BRAINSTORM Gmail client-secret startup for a trusted host.

Construction is inert. Only an explicitly invoked host loader reads the proposed
Keychain entry. No programmatic installation or ACL editing, environment
fallback, provider request or approval authority. Configuration binding is correlation,
not proof the item belongs to the actual console client. The host independently
attests that association, approved private origin and exact read-only grants.

The strict owner_only file policy is the default. reviewed_login is an explicit
host selection for an owner-held login.keychain-db with mode 0600 or 0644 and a
private owner directory ancestor. This metadata acceptance does not establish
item ACLs, encrypted storage, installation or owner authorization; enabling it
in a live host requires explicit owner approval. No existing file is modified.

Foreground mode provides a bounded interaction window for one Mac permission
prompt. The owner must choose Allow Once (or the one-time Allow option), since
Always Allow can widen the item access policy for /usr/bin/security. This loader
does not inspect or verify the item ACL; the host must hold readiness until
actual access policy is rechecked. Denial, timeout and cancellation never retry.
Background mode fails closed after five seconds. Do not log traceback locals or
HTTP debug output. Python cannot guarantee secret memory zeroization. Actual
runtime access policy, secure installation and recovery remain host gates.

Apple SecurityTool can emit an unmarked lowercase hex representation for a
password containing nonprintable bytes. Ambiguous even-length lowercase hex-only
output is refused, including a literal credential with that shape; never decode
or guess. A refused item needs host review, not automatic retry.
"""

from __future__ import annotations

import hmac
import os
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Literal

from pydantic import SecretStr

from zacai.config import get_secret
from zacai.connectors.account_preflight import Provider
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.policy import TrustBoundary

_ACCOUNT = "zac-owner-source-access"
_SERVICE = "zacai-brainstorm-gmail-client-secret"
_NAME = "BRAINSTORM_GMAIL_CLIENT_SECRET"
_MAX_BYTES = 4096


class GmailClientSecretError(RuntimeError):
    """Fixed unavailable diagnostic without output or private host frames."""


class GmailClientSecretCancelled(BaseException):
    """Sanitized interruption; host must not automatically retry."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return function(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard secret-bearing subprocess frames
            kind = GmailClientSecretError
        except BaseException:  # noqa: BLE001 - discard interrupted private diagnostics
            kind = GmailClientSecretCancelled
        del args, kwargs
        raise kind("Gmail client secret unavailable; host review required")

    return call


def _configuration(value: OAuthConfiguration) -> OAuthConfiguration:
    if type(value) is not OAuthConfiguration:
        raise ValueError("exact host configuration required")
    checked = OAuthConfiguration.model_validate(value)
    if checked.provider is not Provider.GMAIL or checked.grant_profile != "read":
        raise ValueError("approved Gmail read configuration required")
    return checked


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


@dataclass(frozen=True, repr=False, kw_only=True)
class GmailClientSecretLoader:
    """Host-owned exact configuration binding, no credential/install proof.

    The immutable digest pins the effective client, registration, mailbox,
    origin, callback, confidential mode and grants. No public account/service
    selectors exist. The reviewed absolute Keychain file is explicit and checked
    before and after loading; no default search list or path discovery is used.
    File metadata does not verify item ACLs or console client association. The
    result is transient SecretStr, never stored on this loader. Supply this callable to exchange_initial only inside independently
    authenticated original-operation checks. Tests replace subprocess exclusively.
    """

    configuration: OAuthConfiguration = field(repr=False)
    keychain_path: Path = field(repr=False)
    mode: Literal["background", "foreground"] = "background"
    foreground_timeout_seconds: int = 60
    keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    _digest: str = field(init=False, repr=False)
    _settings: tuple[str, str, int, str] = field(init=False, repr=False)

    @_closed
    def __post_init__(self) -> None:
        checked = _configuration(self.configuration)
        path = _path(self.keychain_path)
        _timeout(self.mode, self.foreground_timeout_seconds)
        policy = _file_policy(path, self.keychain_file_policy)
        object.__setattr__(self, "configuration", checked)
        object.__setattr__(self, "keychain_path", path)
        object.__setattr__(self, "_digest", checked.configuration_digest)
        object.__setattr__(
            self, "_settings", (str(path), self.mode, self.foreground_timeout_seconds, policy)
        )

    @_closed
    def __call__(self, configuration: OAuthConfiguration) -> SecretStr:
        original = _configuration(self.configuration)
        current = _configuration(configuration)
        if not hmac.compare_digest(
            original.configuration_digest, self._digest
        ) or not hmac.compare_digest(current.configuration_digest, self._digest):
            raise ValueError("original exact configuration required")
        timeout = _timeout(self.mode, self.foreground_timeout_seconds)
        path = _path(self.keychain_path)
        policy = _file_policy(path, self.keychain_file_policy)
        if (
            not hmac.compare_digest(str(path).encode(), self._settings[0].encode())
            or self.mode != self._settings[1]
            or self.foreground_timeout_seconds != self._settings[2]
            or policy != self._settings[3]
        ):
            raise ValueError("original reviewed startup settings required")
        witness = _path_witness(path, policy)
        completed = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-a",
                _ACCOUNT,
                "-s",
                _SERVICE,
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
        if _path_witness(path, policy) != witness:
            raise ValueError("keychain file changed during load")
        if completed.returncode != 0 or type(completed.stdout) is not bytes:
            raise ValueError("credential unavailable")
        raw = completed.stdout.removesuffix(b"\n")
        if not 1 <= len(raw) <= _MAX_BYTES:
            raise ValueError("bounded credential required")
        secret = raw.decode("ascii")
        if any(not 33 <= ord(character) <= 126 for character in secret):
            raise ValueError("invalid credential characters")
        # Apple SecurityTool/macOS/keychain_find.c do_password_item_printing
        # prints every byte as unmarked lowercase hex if any byte is nonprintable.
        # Literal hex and converted bytes cannot be distinguished; refuse both.
        if len(secret) % 2 == 0 and all(character in "0123456789abcdef" for character in secret):
            raise ValueError("ambiguous credential output")
        checked = get_secret(_NAME, TrustBoundary.BRAINSTORM, env={_NAME: secret})
        if type(checked) is not str or not checked:
            raise ValueError("boundary-bound credential unavailable")
        return SecretStr(checked)
