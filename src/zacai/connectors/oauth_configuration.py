"""Offline consent request preparation, separate from owner sign-in and grants.

These values are proposals requiring host/owner review, not authorization. No
browser, token exchange, secret storage or source access is performed. Host must
issue single-use expiring state bound to the actual current owner session and
this exact configuration before using a request. Never log URLs or PKCE secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from zacai.connectors.account_preflight import (
    GMAIL_COMMUNICATION_SCOPES,
    GMAIL_SCOPES,
    SLACK_COMMUNICATION_SCOPES,
    SLACK_SCOPES,
    Provider,
)

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}")
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")


class OAuthConfigurationError(ValueError):
    """Fixed diagnostics without transient authorization material."""


class OAuthConfigurationCancelled(BaseException):
    """Cancellation without authorization-bearing inner traceback frames."""


class OAuthConfiguration(BaseModel):
    """Actual nonsecret configuration to review before any grant change.

    Client registration and callback must be verified in the provider console.
    The callback has a fixed path on the independently reviewed private origin.
    The Gmail account hint and Slack team selector are not identity proof.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    provider: Provider
    registration_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+$")
    client_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+$")
    private_origin: str = Field(min_length=1, max_length=253)
    oauth_mode: Literal["confidential"] = "confidential"
    grant_profile: Literal["read", "approved_communications"] = "read"
    gmail_mailbox: Literal["zcampbell@brainstormtech.io"] = "zcampbell@brainstormtech.io"
    slack_team_id: str | None = Field(default=None, pattern=r"^T[A-Z0-9]{8,20}$")

    @model_validator(mode="after")
    def exact_registration(self) -> OAuthConfiguration:
        parsed = urlsplit(self.private_origin)
        if (
            not parsed.hostname
            or parsed.scheme != "https"
            or self.private_origin != "https://" + str(parsed.hostname)
            or re.fullmatch(r"[a-z][a-z0-9-]*", str(parsed.hostname).split(".")[-1]) is None
            or any(len(label) > 63 for label in str(parsed.hostname).split("."))
            or _HOST.fullmatch(parsed.hostname) is None
            or parsed.netloc != parsed.hostname
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("reviewed private HTTPS origin required")
        if self.provider is Provider.GMAIL:
            if (
                re.fullmatch(r"[A-Za-z0-9_-]+\.apps\.googleusercontent\.com", self.client_id)
                is None
                or self.slack_team_id is not None
            ):
                raise ValueError("exact Google registration required")
        elif re.fullmatch(r"[0-9]+\.[0-9]+", self.client_id) is None or self.slack_team_id is None:
            raise ValueError("exact Slack client and team required")
        return self

    @property
    def callback(self) -> str:
        return self.private_origin + "/connections/" + self.provider.value + "/callback"

    @property
    def scopes(self) -> frozenset[str]:
        if self.provider is Provider.GMAIL:
            return GMAIL_SCOPES if self.grant_profile == "read" else GMAIL_COMMUNICATION_SCOPES
        return SLACK_SCOPES if self.grant_profile == "read" else SLACK_COMMUNICATION_SCOPES

    @property
    def configuration_digest(self) -> str:
        if type(self) is not OAuthConfiguration:
            raise OAuthConfigurationError("exact configuration required")
        checked = OAuthConfiguration.model_validate(self)
        endpoint, parameters = _public_request(checked)
        return _effective_digest(checked, endpoint, parameters)


@dataclass(frozen=True)
class ConsentRequest:
    """Transient request; neither the URL nor its digest is an approval grant."""

    url: SecretStr = field(repr=False)
    configuration_digest: str
    callback: str
    provider: Provider


def _public_request(configuration: OAuthConfiguration) -> tuple[str, dict[str, str]]:
    common = {
        "client_id": configuration.client_id,
        "redirect_uri": configuration.callback,
    }
    if configuration.provider is Provider.GMAIL:
        return "https://accounts.google.com/o/oauth2/v2/auth", common | {
            "response_type": "code",
            "scope": " ".join(sorted(configuration.scopes)),
            "code_challenge_method": "S256",
            "access_type": "offline",
            "include_granted_scopes": "false",
            "login_hint": configuration.gmail_mailbox,
            "prompt": "consent",
        }
    return "https://slack.com/oauth/v2/authorize", common | {
        "user_scope": ",".join(sorted(configuration.scopes)),
        "team": str(configuration.slack_team_id),
    }


def _effective_digest(
    configuration: OAuthConfiguration, endpoint: str, parameters: dict[str, str]
) -> str:
    # Bind the actual public request, including imported scopes and fixed policy.
    # Transient state/verifier/challenge are bound by the separate host transaction.
    public = {
        "version": 1,
        "configuration": configuration.model_dump(mode="json"),
        "endpoint": endpoint,
        "parameters": parameters,
    }
    return hashlib.sha256(
        json.dumps(public, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def _prepare_consent(
    configuration: OAuthConfiguration,
    *,
    state: SecretStr,
    google_code_verifier: SecretStr | None,
) -> ConsentRequest:
    # Revalidate even model_construct/copied objects at this public boundary.
    if type(configuration) is not OAuthConfiguration:
        raise ValueError("exact configuration required")
    configuration = OAuthConfiguration.model_validate(configuration)
    if type(state) is not SecretStr or _TOKEN.fullmatch(state.get_secret_value()) is None:
        raise ValueError("host-issued state required")
    endpoint, parameters = _public_request(configuration)
    digest = _effective_digest(configuration, endpoint, parameters)
    parameters = parameters | {"state": state.get_secret_value()}
    if configuration.provider is Provider.GMAIL:
        if (
            type(google_code_verifier) is not SecretStr
            or _VERIFIER.fullmatch(google_code_verifier.get_secret_value()) is None
        ):
            raise ValueError("Google S256 verifier required")
        challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(google_code_verifier.get_secret_value().encode("ascii")).digest()
            )
            .decode("ascii")
            .rstrip("=")
        )
        parameters = parameters | {"code_challenge": challenge}
    elif google_code_verifier is not None:
        # Confidential mode never implicitly enables Slack's reviewed PKCE option.
        raise ValueError("unexpected Google verifier")
    return ConsentRequest(
        SecretStr(endpoint + "?" + urlencode(parameters)),
        digest,
        configuration.callback,
        configuration.provider,
    )


def prepare_consent(
    configuration: OAuthConfiguration,
    *,
    state: SecretStr,
    google_code_verifier: SecretStr | None = None,
) -> ConsentRequest:
    """Prepare offline only. Caller must not infer state entropy/authentication.

    A valid-looking caller string is not trusted state. The host must create and
    bind it, keep the verifier confidential, enforce expiry/callback replay, and
    independently verify actual identity and returned grants before storage.
    Existing provider grants may be wider; this request cannot narrow them.
    Cancellation is deliberately normalized to the dedicated BaseException so
    the host aborts safely without inner secret-bearing frames or an unsafe
    provider-supplied SystemExit string. It does not preserve process exit codes.
    Offline access is requested; a refresh token is never promised. A missing
    refresh token must hold durable readiness until host lifecycle verification.
    """
    result: ConsentRequest | None = None
    cancelled = False
    try:
        result = _prepare_consent(
            configuration, state=state, google_code_verifier=google_code_verifier
        )
    except BaseException as error:  # noqa: BLE001 - discard transient inner frames
        cancelled = not isinstance(error, Exception)
    if cancelled:
        raise OAuthConfigurationCancelled("consent preparation cancelled")
    if result is None:
        raise OAuthConfigurationError("consent request unavailable")
    return result
