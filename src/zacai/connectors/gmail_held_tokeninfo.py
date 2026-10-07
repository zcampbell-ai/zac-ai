"""Pure old-held access-token metadata parsing, never token or provider proof.

Only a separately reviewed same-token adapter may supply the response and
observation interval. Recorded expiry is an untrusted conservative ceiling,
not fresh evidence. No exchange, token material, refresh, clock lookup, native,
storage or provider calls occur. A matching independently supplied subject is
only a comparison; caller metadata cannot grant provenance or installation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Literal

from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.provider_oauth_evidence import _object, _scopes, _seconds

_SUBJECT = re.compile(r"[A-Za-z0-9_-]{1,255}")
_TOLERANCE = timedelta(seconds=10)
_ALLOWED = {
    "azp",
    "aud",
    "sub",
    "scope",
    "exp",
    "expires_in",
    "access_type",
    "email",
    "email_verified",
}


class GmailHeldTokenInfoError(RuntimeError):
    """Fixed private-safe pure parsing denial."""


class GmailHeldTokenInfoCancelled(BaseException):
    """Fixed private-safe parsing interruption; no automatic retry."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return function(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard raw response/subject/custom timezone frames
            failure = GmailHeldTokenInfoError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failure = GmailHeldTokenInfoCancelled
        del args, kwargs
        raise failure("Gmail held tokeninfo unavailable; host review required")

    return call


@dataclass(frozen=True, init=False, repr=False)
class HeldGmailTokenInfo:
    configuration_digest: str
    client_id: str
    subject_id_hint: str
    scopes: frozenset[str]
    recorded_expires_at: datetime
    request_started_at: datetime
    response_observed_at: datetime
    expires_at: datetime
    expected_subject_matches: Literal[True] | None
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

    def __init__(self) -> None:
        raise GmailHeldTokenInfoError("Gmail held tokeninfo receipt unavailable")

    def __repr__(self) -> str:
        return "HeldGmailTokenInfo(held=True, installed=False)"


def _configuration(value: OAuthConfiguration) -> OAuthConfiguration:
    if type(value) is not OAuthConfiguration:
        raise ValueError("exact read configuration required")
    checked = OAuthConfiguration.model_validate(value)
    if checked.provider.value != "gmail" or checked.grant_profile != "read":
        raise ValueError("exact read Gmail configuration required")
    return checked


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("explicit aware observation required")
    return value.astimezone(UTC)


@_closed
def parse_held_gmail_tokeninfo(
    data: bytes,
    *,
    configuration: OAuthConfiguration,
    expected_subject: str | None,
    recorded_expires_at: datetime,
    request_started_at: datetime,
    response_observed_at: datetime,
) -> HeldGmailTokenInfo:
    checked = _configuration(configuration)
    digest, client, scopes = checked.configuration_digest, checked.client_id, checked.scopes
    if expected_subject is not None and (
        type(expected_subject) is not str or _SUBJECT.fullmatch(expected_subject) is None
    ):
        raise ValueError("independent subject comparison required")
    recorded, start, end = map(
        _utc, (recorded_expires_at, request_started_at, response_observed_at)
    )
    if not start <= end <= start + timedelta(minutes=5) or recorded <= end:
        raise ValueError("bounded current observation interval required")
    info = _object(data)  # accepted bounded strict duplicate/nonfinite JSON parser
    subject = info.get("sub")
    if (
        set(info) - _ALLOWED
        or type(subject) is not str
        or _SUBJECT.fullmatch(subject) is None
        or (expected_subject is not None and subject != expected_subject)
    ):
        raise ValueError("actual stable subject required")
    clients = [info[name] for name in ("azp", "aud") if name in info]
    if not clients or any(type(value) is not str or value != client for value in clients):
        raise ValueError("exact client required")
    _scopes(info.get("scope"), scopes, " ")
    if "access_type" in info and info["access_type"] != "offline":
        raise ValueError("unexpected access metadata")
    if "email" in info and (
        type(info["email"]) is not str or info["email"] != checked.gmail_mailbox
    ):
        raise ValueError("unexpected optional mailbox claim")
    if "email_verified" in info and not (
        info["email_verified"] is True
        or (type(info["email_verified"]) is str and info["email_verified"] == "true")
    ):
        raise ValueError("unverified optional mailbox claim")
    expiries = [recorded]
    absolute = None
    if "exp" in info:
        absolute = datetime.fromtimestamp(_seconds(info["exp"], 253_402_300_799, strings=True), UTC)
        if (
            absolute <= end
            or absolute > end + timedelta(seconds=3600)
            or abs(absolute - recorded) > _TOLERANCE
        ):
            raise ValueError("inconsistent absolute access expiry")
        expiries.append(absolute)
    if "expires_in" in info:
        ttl = timedelta(seconds=_seconds(info["expires_in"], 3600, strings=True))
        lower, upper = start + ttl, end + ttl
        if not lower - _TOLERANCE <= recorded <= upper + _TOLERANCE:
            raise ValueError("inconsistent recorded relative expiry")
        if absolute is not None and not lower - _TOLERANCE <= absolute <= upper + _TOLERANCE:
            raise ValueError("inconsistent provider expiry observations")
        expiries.append(lower)
    if len(expiries) == 1:
        raise ValueError("fresh provider expiry required")
    effective = min(expiries)
    if effective <= end:
        raise ValueError("access expired during observation")
    final = _configuration(configuration)  # after every supplied timezone callback
    if final.configuration_digest != digest or final.client_id != client or final.scopes != scopes:
        raise ValueError("original configuration changed")
    receipt = object.__new__(HeldGmailTokenInfo)
    for name, value in {
        "configuration_digest": digest,
        "client_id": client,
        "subject_id_hint": subject,
        "scopes": scopes,
        "recorded_expires_at": recorded,
        "request_started_at": start,
        "response_observed_at": end,
        "expires_at": effective,
        "expected_subject_matches": True if expected_subject is not None else None,
    }.items():
        object.__setattr__(receipt, name, value)
    return receipt
