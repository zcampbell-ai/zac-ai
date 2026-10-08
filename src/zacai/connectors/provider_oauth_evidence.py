"""Pure parsing of trusted adapter responses, never live OAuth proof or authority.

Only a separately reviewed fixed-TLS exchange/introspection adapter may supply
these bytes. Caller JSON, requested scopes, owner OIDC and token prefixes are
not evidence. The candidate remains UNINSTALLED: the same access token must
pass installed Gmail profile or Slack auth.test/scope-header verification and
secure credential-generation installation before a gateway may attest it.
No HTTP, Keychain, grant changes, refresh, canonical writes or fallback exists.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Literal

from pydantic import SecretStr

from zacai.connectors.account_preflight import Provider
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic, _phase
from zacai.connectors.oauth_configuration import OAuthConfiguration

_MAX_RESPONSE = 65_536
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,255}")
_SLACK_USER = re.compile(r"[UW][A-Z0-9]{8,20}")
_SLACK_APP = re.compile(r"A[A-Z0-9]{8,20}")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,11})")


class OAuthEvidenceError(ValueError):
    """Fixed error without response bytes, tokens or private inner frames."""


class OAuthEvidenceCancelled(BaseException):
    """Sanitized parser cancellation; no credential lifecycle is established."""


class SlackRotation(str, Enum):
    ROTATING = "rotating"
    NONROTATING = "nonrotating"


@dataclass(frozen=True)
class UninstalledOAuthCandidate:
    """Parsed response candidate, not VerifiedCredential or authentication.

    Trusted adapter provenance and same-token identity checks remain mandatory.
    No construction of this dataclass independently proves its field claims.
    """

    provider: Provider
    configuration_digest: str
    client_id: str
    subject_id: str = field(repr=False)
    scopes: frozenset[str]
    access_token: SecretStr = field(repr=False)
    refresh_token: SecretStr | None = field(repr=False)
    expires_at: datetime | None
    refresh_expires_at: datetime | None
    token_kind: Literal["oauth_access", "slack_user"]
    subject_pin_verified: bool
    slack_app_id: str | None = None
    slack_team_id: str | None = None
    slack_rotation: SlackRotation | None = None

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def read_identity_verified(self) -> Literal[False]:
        return False

    @property
    def live_access_proven(self) -> Literal[False]:
        return False


def _object(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_RESPONSE:
        raise ValueError("bounded response required")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate field")
            result[name] = value
        return result

    def finite(_: str) -> object:
        raise ValueError("nonfinite response")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=finite)
    if type(value) is not dict or "error" in value:
        raise ValueError("invalid provider response")
    return value


def _secret(value: object) -> SecretStr:
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("bounded token required")
    if any(not 33 <= ord(c) <= 126 for c in value):
        raise ValueError("invalid token")
    return SecretStr(value)


def _seconds(value: object, maximum: int, *, strings: bool = False) -> int:
    if strings and type(value) is str and _DECIMAL.fullmatch(value):
        value = int(value)
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("bounded expiry required")
    return value


def _time(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware observation time required")
    return value


def _scopes(value: object, expected: frozenset[str], delimiter: str) -> None:
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("actual scopes required")
    scopes = value.split(delimiter)
    if not all(scopes) or len(set(scopes)) != len(scopes) or frozenset(scopes) != expected:
        raise ValueError("exact grants required")


def _configuration(value: OAuthConfiguration, provider: Provider) -> OAuthConfiguration:
    if type(value) is not OAuthConfiguration:
        raise ValueError("exact configuration required")
    checked = OAuthConfiguration.model_validate(value)
    if checked.provider is not provider:
        raise ValueError("provider mismatch")
    return checked


def _google(
    configuration: OAuthConfiguration,
    exchange_bytes: bytes,
    tokeninfo_bytes: bytes,
    *,
    expected_subject: str | None,
    exchange_observed_at: datetime,
    evidence_observed_at: datetime,
    diagnostic: OAuthCallbackDiagnostic | None = None,
) -> UninstalledOAuthCandidate:
    _phase(diagnostic, "evidence_configuration")
    configuration = _configuration(configuration, Provider.GMAIL)
    _phase(diagnostic, "evidence_observation")
    start, observed = _time(exchange_observed_at), _time(evidence_observed_at)
    if not start <= observed <= start + timedelta(minutes=5):
        raise ValueError("bounded observation interval required")
    if expected_subject is not None and (
        type(expected_subject) is not str or _IDENTIFIER.fullmatch(expected_subject) is None
    ):
        raise ValueError("reviewed stable subject required")
    _phase(diagnostic, "evidence_response")
    exchange, info = _object(exchange_bytes), _object(tokeninfo_bytes)
    _phase(diagnostic, "evidence_exchange")
    if set(exchange) - {
        "access_token",
        "refresh_token",
        "expires_in",
        "scope",
        "token_type",
        "refresh_token_expires_in",
    }:
        raise ValueError("unexpected exchange fields")
    if type(exchange.get("token_type")) is not str or exchange["token_type"].casefold() != "bearer":
        raise ValueError("access token required")
    access, refresh = _secret(exchange.get("access_token")), _secret(exchange.get("refresh_token"))
    if access.get_secret_value() == refresh.get_secret_value():
        raise ValueError("distinct credential material required")
    expiry = start + timedelta(seconds=_seconds(exchange.get("expires_in"), 3600))
    if "scope" in exchange:
        _scopes(exchange["scope"], configuration.scopes, " ")
    allowed = {
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
    _phase(diagnostic, "evidence_subject")
    actual_subject = info.get("sub")
    if (
        set(info) - allowed
        or type(actual_subject) is not str
        or _IDENTIFIER.fullmatch(actual_subject) is None
        or (expected_subject is not None and actual_subject != expected_subject)
    ):
        raise ValueError("stable subject evidence required")
    _phase(diagnostic, "evidence_client")
    clients = [info[k] for k in ("azp", "aud") if k in info]
    if not clients or any(type(c) is not str or c != configuration.client_id for c in clients):
        raise ValueError("exact client evidence required")
    _phase(diagnostic, "evidence_scope")
    _scopes(info.get("scope"), configuration.scopes, " ")
    _phase(diagnostic, "evidence_time")
    expiries: list[datetime] = []
    if "expires_in" in info:
        expiries.append(
            observed + timedelta(seconds=_seconds(info["expires_in"], 3600, strings=True))
        )
    if "exp" in info:
        epoch = _seconds(info["exp"], 253_402_300_799, strings=True)
        expiries.append(datetime.fromtimestamp(epoch, UTC))
    if not expiries or any(
        e <= observed or abs((e - expiry).total_seconds()) > 10 for e in expiries
    ):
        raise ValueError("consistent unexpired access required")
    candidate_expiry = min([expiry, *expiries])
    if candidate_expiry <= observed:
        raise ValueError("candidate access already expired")
    _phase(diagnostic, "evidence_optional")
    if "access_type" in info and info["access_type"] != "offline":
        raise ValueError("offline grant required")
    if "email" in info and info["email"] != configuration.gmail_mailbox:
        raise ValueError("unexpected mailbox claim")
    if "email_verified" in info and not (
        info["email_verified"] is True
        or (type(info["email_verified"]) is str and info["email_verified"] == "true")
    ):
        raise ValueError("unverified optional email claim")
    refresh_expiry = None
    if "refresh_token_expires_in" in exchange:
        refresh_expiry = start + timedelta(
            seconds=_seconds(exchange["refresh_token_expires_in"], 31_536_000)
        )
        if refresh_expiry <= observed:
            raise ValueError("expired refresh material")
    return UninstalledOAuthCandidate(
        Provider.GMAIL,
        configuration.configuration_digest,
        configuration.client_id,
        actual_subject,
        configuration.scopes,
        access,
        refresh,
        candidate_expiry,
        refresh_expiry,
        "oauth_access",
        expected_subject is not None,
    )


def parse_google_oauth_evidence(
    configuration: OAuthConfiguration,
    exchange_bytes: bytes,
    tokeninfo_bytes: bytes,
    *,
    expected_subject: str | None,
    exchange_observed_at: datetime,
    evidence_observed_at: datetime,
    diagnostic: OAuthCallbackDiagnostic | None = None,
) -> UninstalledOAuthCandidate:
    """Pure response parsing; adapter must bind tokeninfo to exchanged access token.

    Missing stable sub holds. expected_subject=None explicitly discovers a
    candidate subject with subject_pin_verified=False; it creates no authority.
    Installation must verify the same-token mailbox and owner-bound transaction
    before persisting that actual subject. No owner-OIDC/email/user_id fallback.
    Requires refresh material for this planned persistent connection lifecycle.
    Ten-second expiry tolerance accounts for response observation/rounding only.
    """
    result: UninstalledOAuthCandidate | None = None
    cancelled = False
    try:
        result = _google(
            configuration,
            exchange_bytes,
            tokeninfo_bytes,
            expected_subject=expected_subject,
            exchange_observed_at=exchange_observed_at,
            evidence_observed_at=evidence_observed_at,
            diagnostic=diagnostic,
        )
    except Exception:  # noqa: BLE001,S110 - discard raw response and token frames
        pass
    except BaseException:  # noqa: BLE001 - closed cancellation boundary
        cancelled = True
    del exchange_bytes, tokeninfo_bytes
    if cancelled:
        raise OAuthEvidenceCancelled("OAuth evidence parsing cancelled")
    if result is None:
        raise OAuthEvidenceError("OAuth response candidate unavailable")
    return result


def _slack(
    configuration: OAuthConfiguration,
    exchange_bytes: bytes,
    *,
    expected_user_id: str | None,
    rotation: SlackRotation,
    observed_at: datetime,
) -> UninstalledOAuthCandidate:
    configuration = _configuration(configuration, Provider.SLACK)
    observed = _time(observed_at)
    if type(rotation) is not SlackRotation:
        raise ValueError("reviewed rotation required")
    if expected_user_id is not None and (
        type(expected_user_id) is not str or _SLACK_USER.fullmatch(expected_user_id) is None
    ):
        raise ValueError("exact user required")
    value = _object(exchange_bytes)
    if value.get("ok") is not True or value.get("app_id") != configuration.registration_id:
        raise ValueError("exact application required")
    if _SLACK_APP.fullmatch(configuration.registration_id) is None:
        raise ValueError("actual Slack application required")
    if value.get("is_enterprise_install", False) is not False:
        raise ValueError("workspace install required")
    allowed_root = {"ok", "app_id", "team", "authed_user", "enterprise", "is_enterprise_install"}
    if set(value) - allowed_root:
        raise ValueError("unexpected installation fields")
    team, user = value.get("team"), value.get("authed_user")
    if type(team) is not dict or team.get("id") != configuration.slack_team_id:
        raise ValueError("exact workspace required")
    if (
        type(user) is not dict
        or type(user.get("id")) is not str
        or _SLACK_USER.fullmatch(user["id"]) is None
        or (expected_user_id is not None and user["id"] != expected_user_id)
        or user.get("token_type") != "user"
    ):
        raise ValueError("exact exchanged user token required")
    if set(user) - {"id", "scope", "access_token", "token_type", "expires_in", "refresh_token"}:
        raise ValueError("unexpected user token fields")
    _scopes(user.get("scope"), configuration.scopes, ",")
    access = _secret(user.get("access_token"))
    # Do not accept a simultaneous bot installation or choose top-level secrets.
    if any(
        k in value
        for k in (
            "access_token",
            "refresh_token",
            "bot_user_id",
            "scope",
            "token_type",
            "incoming_webhook",
        )
    ):
        raise ValueError("unexpected bot or provider write grant")
    refresh = None
    expires = None
    if rotation is SlackRotation.ROTATING:
        refresh = _secret(user.get("refresh_token"))
        if refresh.get_secret_value() == access.get_secret_value():
            raise ValueError("distinct credential material required")
        expires = observed + timedelta(seconds=_seconds(user.get("expires_in"), 43_200))
    elif "expires_in" in user or "refresh_token" in user:
        raise ValueError("reviewed nonrotating mode mismatch")
    return UninstalledOAuthCandidate(
        Provider.SLACK,
        configuration.configuration_digest,
        configuration.client_id,
        user["id"],
        configuration.scopes,
        access,
        refresh,
        expires,
        None,
        "slack_user",
        expected_user_id is not None,
        configuration.registration_id,
        configuration.slack_team_id,
        rotation,
    )


def parse_slack_oauth_evidence(
    configuration: OAuthConfiguration,
    exchange_bytes: bytes,
    *,
    expected_user_id: str | None,
    rotation: SlackRotation,
    observed_at: datetime,
) -> UninstalledOAuthCandidate:
    """Initial OAuth-v2 user installation only, not a refresh-response parser.

    expected_user_id=None explicitly discovers only a candidate user. App/team
    pins remain mandatory and subject_pin_verified remains False until compared
    against a reviewed pin. Rotation comes from actual reviewed app settings.
    Workspace/account, scope headers and secure installation remain live gates.
    """
    result: UninstalledOAuthCandidate | None = None
    cancelled = False
    try:
        result = _slack(
            configuration,
            exchange_bytes,
            expected_user_id=expected_user_id,
            rotation=rotation,
            observed_at=observed_at,
        )
    except Exception:  # noqa: BLE001,S110 - discard raw response and token frames
        pass
    except BaseException:  # noqa: BLE001 - closed cancellation boundary
        cancelled = True
    del exchange_bytes
    if cancelled:
        raise OAuthEvidenceCancelled("OAuth evidence parsing cancelled")
    if result is None:
        raise OAuthEvidenceError("OAuth response candidate unavailable")
    return result
