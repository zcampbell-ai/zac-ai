"""Pure strict parsing of untrusted held Gmail password data, never authority.

This does not read a Keychain, authenticate a held ledger or native item, call a
provider, prove escrow, or install/release/refresh credentials. A separately
approved host must bind the actual same-item read and current owner first.
Serialized subject/pin/expiry claims are untrusted metadata. Expired claims are
preserved; expiry flags compare only with the explicit supplied observation.
Unknown refresh expiry means unknown, never unlimited or authorized access.
Equal token values are accepted because the existing writer permits them; their
format or equality cannot prove credential type. No clock or environment lookup.
Python cannot guarantee secret-memory zeroization; never log traceback locals.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from typing import Any, Literal

from pydantic import SecretStr

from zacai.connectors.oauth_configuration import OAuthConfiguration

_MAX_DATA = 16_384
_ACCESS = "BRAINSTORM_GMAIL_ACCESS_TOKEN"
_REFRESH = "BRAINSTORM_GMAIL_REFRESH_TOKEN"
_GENERATION = re.compile(r"[0-9a-f]{32}")
_SUBJECT = re.compile(r"[A-Za-z0-9_-]{1,255}")
_KEYS = {
    "version",
    "state",
    "generation",
    "boundary",
    "provider",
    "configuration_digest",
    "client_id",
    "subject_id",
    "scopes",
    "expires_at",
    "refresh_expires_at",
    "subject_pin_verified",
    "tokens",
}


class GmailHeldPayloadError(RuntimeError):
    """Fixed private-safe pure-parser rejection."""


class GmailHeldPayloadCancelled(BaseException):
    """Fixed private-safe interrupted parsing; no automatic retry."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return function(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard raw tokens/private callback frames
            failure = GmailHeldPayloadError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failure = GmailHeldPayloadCancelled
        del args, kwargs
        raise failure("Gmail held payload unavailable; host review required")

    return call


@dataclass(frozen=True, repr=False)
class HeldGmailPayload:
    generation: str
    configuration_digest: str
    client_id: str
    subject_id_hint: str
    scopes: frozenset[str]
    access_token: SecretStr
    refresh_token: SecretStr
    expires_at: datetime
    refresh_expires_at: datetime | None
    observed_at: datetime
    subject_pin_claimed: bool
    access_expired: bool
    refresh_expired: bool | None
    held: Literal[True] = field(default=True, init=False)
    installed: Literal[False] = field(default=False, init=False)
    subject_pin_verified: Literal[False] = field(default=False, init=False)
    read_identity_verified: Literal[False] = field(default=False, init=False)
    live_access_proven: Literal[False] = field(default=False, init=False)
    native_material_verified: Literal[False] = field(default=False, init=False)
    original_actor_verified: Literal[False] = field(default=False, init=False)
    source_subject_verified: Literal[False] = field(default=False, init=False)
    credential_authority: Literal[False] = field(default=False, init=False)
    provenance_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    execution_authorized: Literal[False] = field(default=False, init=False)

    def __repr__(self) -> str:
        return "HeldGmailPayload(held=True, installed=False)"


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate payload field")
        result[name] = value
    return result


def _finite(_: str) -> object:
    raise ValueError("nonfinite payload field")


def _time(value: object) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise ValueError("bounded canonical timestamp required")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() is None or result.isoformat() != value:
        raise ValueError("canonical aware timestamp required")
    return result


def _token(value: object) -> SecretStr:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 4096
        or any(not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError("bounded printable held credential required")
    return SecretStr(value)


def _configuration(value: OAuthConfiguration) -> OAuthConfiguration:
    if type(value) is not OAuthConfiguration:
        raise ValueError("exact read configuration required")
    checked = OAuthConfiguration.model_validate(value)
    if checked.provider.value != "gmail" or checked.grant_profile != "read":
        raise ValueError("exact read Gmail configuration required")
    return checked


@_closed
def parse_held_gmail_payload(
    data: bytes, *, configuration: OAuthConfiguration, generation: str, observed_at: datetime
) -> HeldGmailPayload:
    checked = _configuration(configuration)
    digest, client, scopes = checked.configuration_digest, checked.client_id, checked.scopes
    if (
        type(data) is not bytes
        or not 1 <= len(data) <= _MAX_DATA
        or type(generation) is not str
        or _GENERATION.fullmatch(generation) is None
        or type(observed_at) is not datetime
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise ValueError("bounded held payload and explicit aware observation required")
    value = json.loads(
        data.decode("ascii", errors="strict"), object_pairs_hook=_unique, parse_constant=_finite
    )
    if (
        type(value) is not dict
        or set(value) != _KEYS
        or type(value["version"]) is not int
        or value["version"] != 1
        or any(
            type(value[name]) is not str
            for name in (
                "state",
                "generation",
                "boundary",
                "provider",
                "configuration_digest",
                "client_id",
                "subject_id",
            )
        )
        or value["state"] != "held_uninstalled"
        or value["boundary"] != "BRAINSTORM"
        or value["provider"] != "gmail"
        or value["generation"] != generation
        or value["configuration_digest"] != digest
        or value["client_id"] != client
        or _SUBJECT.fullmatch(value["subject_id"]) is None
        or type(value["scopes"]) is not list
        or any(type(scope) is not str for scope in value["scopes"])
        or value["scopes"] != sorted(scopes)
        or type(value["subject_pin_verified"]) is not bool
        or type(value["tokens"]) is not dict
        or set(value["tokens"]) != {_ACCESS, _REFRESH}
    ):
        raise ValueError("exact original held payload schema required")
    expires = _time(value["expires_at"])
    refresh_expires = (
        None if value["refresh_expires_at"] is None else _time(value["refresh_expires_at"])
    )
    access = _token(value["tokens"][_ACCESS])
    refresh = _token(value["tokens"][_REFRESH])
    access_expired = expires <= observed_at
    refresh_expired = None if refresh_expires is None else refresh_expires <= observed_at
    # The explicit observation may carry a host-supplied tzinfo callback. Recheck
    # the original exact configuration after the comparisons; no clock reads.
    final = _configuration(configuration)
    if final.configuration_digest != digest or final.client_id != client or final.scopes != scopes:
        raise ValueError("original configuration changed")
    return HeldGmailPayload(
        generation,
        digest,
        client,
        value["subject_id"],
        scopes,
        access,
        refresh,
        expires,
        refresh_expires,
        observed_at,
        value["subject_pin_verified"],
        access_expired,
        refresh_expired,
    )
