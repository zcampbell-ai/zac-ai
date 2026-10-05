"""Host-only private-interface credential load seam, not a mounted application.

The two fixed Keychain services are proposed future entries, not installed by
this module. Never call this from agents or API handlers. No environment-secret
fallback, credentials in argv, identity/grant inference or source authority.
No app, provider client, session store, listener or service is constructed here.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
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
