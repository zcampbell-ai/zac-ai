"""Inert fixed TLS initial provider exchange, no installation or credential store.

Host must approve actual network/secret loading separately before invoking this
unmounted seam. Trusted injected factories/loaders are not a Python sandbox.
Never enable HTTP debug logging. Direct TLS ignores proxy variables, redirects,
and retries; socket timeout is not a hard total-duration bound. Transient code
release and every exchange are single attempt, even when acknowledgements fail.
No token, raw response, header or grant is persisted. Successful return remains
uninstalled: secure lifecycle storage, installation authority and reconciliation
are separate missing gates. An unconfirmed hold requires durable host-wide halt.
"""

from __future__ import annotations

import http.client
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Literal, Protocol
from urllib.parse import urlencode

from pydantic import SecretStr

from zacai.connectors.account_preflight import GMAIL_COMMUNICATION_SCOPES, Provider
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import ExchangeMaterial, OAuthExchangeOperation
from zacai.connectors.provider_oauth_evidence import (
    UninstalledOAuthCandidate,
    _object,
    _secret,
    parse_google_oauth_evidence,
    parse_slack_oauth_evidence,
)
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.connectors.slack_wire import SlackAccount, prepare_account_reply
from zacai.policy import DataClassification, TrustBoundary

_MAX_BYTES = 262_144


class OAuthExchangeError(RuntimeError):
    """Fixed diagnostics, never provider prose or transient secrets."""


class OAuthExchangeCancelled(BaseException):
    """Sanitized interrupted exchange, no retry."""


class OAuthExchangeHoldUnconfirmed(OAuthExchangeError):
    """Hold not durably confirmed: mandatory host-wide halt and reconciliation."""


class OAuthExchangeCancellationHoldUnconfirmed(OAuthExchangeCancelled):
    """Interrupted exchange with unconfirmed hold: mandatory host-wide halt."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return function(*args, **kwargs)
        except OAuthExchangeCancellationHoldUnconfirmed:
            kind = OAuthExchangeCancellationHoldUnconfirmed
        except OAuthExchangeHoldUnconfirmed:
            kind = OAuthExchangeHoldUnconfirmed
        except Exception:  # noqa: BLE001 - discard source/secret-bearing inner frames
            kind = OAuthExchangeError
        except BaseException:  # noqa: BLE001 - discard private interrupted diagnostics
            kind = OAuthExchangeCancelled
        del args, kwargs
        raise kind("provider exchange held; host reconciliation required")

    return call


class Response(Protocol):
    status: int

    def getheaders(self) -> list[tuple[str, str]]: ...
    def getheader(self, name: str) -> str | None: ...
    def read(self, amount: int) -> bytes: ...


class Connection(Protocol):
    def request(
        self, method: str, url: str, body: bytes | None, headers: dict[str, str]
    ) -> None: ...
    def getresponse(self) -> Response: ...
    def close(self) -> None: ...


def _direct_tls(host: str) -> Connection:
    if host not in {"oauth2.googleapis.com", "gmail.googleapis.com", "slack.com"}:
        raise ValueError("fixed provider host required")
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    return http.client.HTTPSConnection(host, port=443, timeout=20, context=context)


def _headers(response: Response, *, provider_host: str) -> None:
    if type(response.status) is not int or response.status != 200:
        raise ValueError("provider response rejected")
    pairs = response.getheaders()
    if type(pairs) is not list or len(pairs) > 64:
        raise ValueError("bounded response headers required")
    security = {
        "content-type",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "location",
        "x-oauth-scopes",
        "x-accepted-oauth-scopes",
    }
    seen: set[str] = set()
    total = 0
    for pair in pairs:
        if type(pair) is not tuple or len(pair) != 2 or any(type(x) is not str for x in pair):
            raise ValueError("invalid response headers")
        name, value = pair
        total += len(name) + len(value)
        if (
            total > 16_384
            or re.fullmatch(r"[A-Za-z0-9-]{1,128}", name) is None
            or any(ord(c) < 32 or ord(c) > 126 for c in value)
        ):
            raise ValueError("invalid bounded header")
        lower = name.lower()
        if lower in security and lower in seen:
            raise ValueError("duplicate security header")
        seen.add(lower)
    if (
        response.getheader("Location") is not None
        or response.getheader("Transfer-Encoding") is not None
    ):
        raise ValueError("redirect/streaming response rejected")
    if (response.getheader("Content-Type") or "").split(";", 1)[
        0
    ].strip().lower() != "application/json":
        raise ValueError("JSON response required")
    if (response.getheader("Content-Encoding") or "identity").strip().lower() != "identity":
        raise ValueError("compressed response rejected")
    length = response.getheader("Content-Length")
    if length is not None and (
        re.fullmatch(r"[0-9]{1,8}", length) is None or int(length) > _MAX_BYTES
    ):
        raise ValueError("bounded response required")
    scopes = response.getheader("X-OAuth-Scopes")
    if scopes is not None:
        values = [value.strip() for value in scopes.split(",")]
        if (
            len(values) > 100
            or len(set(values)) != len(values)
            or any(
                value not in GMAIL_COMMUNICATION_SCOPES
                if provider_host in {"oauth2.googleapis.com", "gmail.googleapis.com"}
                else re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is None
                for value in values
            )
        ):
            raise ValueError("exact bounded scope header required")


class _CheckedResponse:
    def __init__(self, response: Response) -> None:
        self._response = response
        self.status = response.status

    def getheaders(self) -> list[tuple[str, str]]:
        return self._response.getheaders()

    def getheader(self, name: str) -> str | None:
        return self._response.getheader(name)

    def read(self, amount: int) -> bytes:
        raw = self._response.read(min(amount, _MAX_BYTES + 1))
        length = self.getheader("Content-Length")
        if (
            type(raw) is not bytes
            or not 1 <= len(raw) <= _MAX_BYTES
            or (length is not None and len(raw) != int(length))
        ):
            raise ValueError("incomplete bounded response")
        return raw


class _CheckedConnection:
    """Apply strict envelope checks also to the reused identity read transports."""

    def __init__(self, connection: Connection, *, provider_host: str) -> None:
        if type(provider_host) is not str or provider_host not in {
            "oauth2.googleapis.com",
            "gmail.googleapis.com",
            "slack.com",
        }:
            raise ValueError("fixed provider response host required")
        self._connection = connection
        self._provider_host = provider_host

    def request(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> None:
        self._connection.request(method, url, body, headers)

    def getresponse(self) -> Response:
        response = self._connection.getresponse()
        _headers(response, provider_host=self._provider_host)
        return _CheckedResponse(response)

    def close(self) -> None:
        self._connection.close()


@dataclass(frozen=True)
class CheckedOAuthExchange:
    candidate: UninstalledOAuthCandidate = field(repr=False)

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def read_identity_verified(self) -> Literal[True]:
        return True

    @property
    def processing_authorized(self) -> Literal[False]:
        return False


class OAuthExchangeTransport:
    """Inert host transport; supplying a factory neither grants nor proves access."""

    def __init__(self, *, connection_factory: Callable[[str], Connection] = _direct_tls) -> None:
        if not callable(connection_factory):
            raise OAuthExchangeError("trusted connection factory required")
        self._factory = connection_factory

    def _connection(self, host: str) -> _CheckedConnection:
        return _CheckedConnection(self._factory(host), provider_host=host)

    def _post(
        self, host: str, path: str, values: dict[str, str], key: SecretStr | None = None
    ) -> bytes:
        connection = self._connection(host)
        try:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            }
            if key is not None:
                headers["Authorization"] = (
                    "Bearer " + _secret(key.get_secret_value()).get_secret_value()
                )
            connection.request("POST", path, urlencode(values).encode("ascii"), headers)
            response = connection.getresponse()
            raw = response.read(_MAX_BYTES + 1)
            length = response.getheader("Content-Length")
            if (
                type(raw) is not bytes
                or not 1 <= len(raw) <= _MAX_BYTES
                or (length is not None and len(raw) != int(length))
            ):
                raise ValueError("incomplete bounded response")
            _object(raw)
            return raw
        finally:
            connection.close()

    @_closed
    def exchange(self, material: ExchangeMaterial, client_secret: SecretStr) -> bytes:
        if type(material) is not ExchangeMaterial or type(client_secret) is not SecretStr:
            raise ValueError("trusted exact exchange material required")
        config = OAuthConfiguration.model_validate(material.configuration)
        if material.callback != config.callback:
            raise ValueError("exact callback required")
        values = {
            "client_id": config.client_id,
            "client_secret": _secret(client_secret.get_secret_value()).get_secret_value(),
            "code": _secret(material.code.get_secret_value()).get_secret_value(),
            "redirect_uri": config.callback,
        }
        if config.provider is Provider.GMAIL:
            if type(material.google_code_verifier) is not SecretStr:
                raise ValueError("PKCE required")
            values |= {
                "grant_type": "authorization_code",
                "code_verifier": material.google_code_verifier.get_secret_value(),
            }
            return self._post("oauth2.googleapis.com", "/token", values)
        if material.google_code_verifier is not None:
            raise ValueError("unexpected Gmail verifier")
        return self._post("slack.com", "/api/oauth.v2.access", values)

    @_closed
    def google_tokeninfo(self, access_token: SecretStr) -> bytes:
        return self._post("oauth2.googleapis.com", "/tokeninfo", {}, access_token)

    @_closed
    def gmail_profile(self, access_token: SecretStr, configuration: OAuthConfiguration) -> None:
        scope = GmailScope(
            configuration.registration_id,
            configuration.gmail_mailbox,
            TrustBoundary.BRAINSTORM,
            DataClassification.HIGHLY_RESTRICTED,
            frozenset({TrustBoundary.BRAINSTORM}),
            frozenset({DataClassification.HIGHLY_RESTRICTED}),
        )
        GmailReadTransport(
            connection_factory=lambda: self._connection("gmail.googleapis.com")
        ).profile_reply(access_token, scope=scope)

    @_closed
    def slack_account(self, access_token: SecretStr, candidate: UninstalledOAuthCandidate) -> None:
        reply = SlackReadTransport(
            connection_factory=lambda: self._connection("slack.com")
        ).account_reply(access_token)
        if reply.declared_scopes != candidate.scopes:
            raise ValueError("exact independently reported scopes required")
        prepare_account_reply(
            reply.response_bytes,
            expected=SlackAccount(
                team_id=candidate.slack_team_id, user_id=candidate.subject_id, token_kind="user"
            ),
        )


@_closed
def exchange_initial(
    operation: OAuthExchangeOperation,
    *,
    client_secret_loader: Callable[[OAuthConfiguration], SecretStr],
    transport: OAuthExchangeTransport,
    expected_subject: str | None = None,
) -> CheckedOAuthExchange:
    """One initial exchange, checked same-token identity, no installation authority.

    Loader must independently authenticate actual reviewed client registration;
    caller strings and candidates cannot approve storage or grant processing.
    Host must not reuse released code/material or retry any uncertain operation.
    """
    if (
        type(operation) is not OAuthExchangeOperation
        or type(transport) is not OAuthExchangeTransport
        or not callable(client_secret_loader)
    ):
        raise ValueError("actual original transaction and trusted host adapters required")
    cancelled = failed = unconfirmed = False
    result: CheckedOAuthExchange | None = None
    try:
        material = operation.take_exchange()
        config = material.configuration
        operation.current()
        client_secret = client_secret_loader(config)
        operation.current()
        if type(client_secret) is not SecretStr:
            raise ValueError("trusted exact client secret required")
        operation.current()
        observed = operation.observed_at()
        exchange = transport.exchange(material, client_secret)
        operation.current()
        if config.provider is Provider.GMAIL:
            access = _secret(_object(exchange).get("access_token"))
            operation.current()
            evidence_at = operation.observed_at()
            evidence = transport.google_tokeninfo(access)
            operation.current()
            candidate = parse_google_oauth_evidence(
                config,
                exchange,
                evidence,
                expected_subject=expected_subject,
                exchange_observed_at=observed,
                evidence_observed_at=evidence_at,
            )
            operation.current()
            transport.gmail_profile(candidate.access_token, config)
            operation.current()
        else:
            rotation = operation._rotation
            if rotation is None:
                raise ValueError("reviewed Slack rotation required")
            candidate = parse_slack_oauth_evidence(
                config,
                exchange,
                expected_user_id=expected_subject,
                rotation=rotation,
                observed_at=observed,
            )
            operation.current()
            transport.slack_account(candidate.access_token, candidate)
            operation.current()
        operation.current()
        final_now = operation.observed_at()
        if any(
            expiry is not None and expiry <= final_now
            for expiry in (candidate.expires_at, candidate.refresh_expires_at)
        ):
            raise ValueError("candidate expired during identity checks")
        result = CheckedOAuthExchange(candidate)
    except BaseException as error:  # noqa: BLE001 - preserve only fixed failure categories
        failed, cancelled = True, not isinstance(error, Exception)
    if failed:
        try:
            operation.hold()
        except BaseException as error:  # noqa: BLE001 - host-wide halt if preservation unconfirmed
            operation.halt_unconfirmed()
            unconfirmed = True
            cancelled = cancelled or not isinstance(error, Exception)
        if cancelled:
            kind: type[BaseException] = (
                OAuthExchangeCancellationHoldUnconfirmed if unconfirmed else OAuthExchangeCancelled
            )
        else:
            kind = OAuthExchangeHoldUnconfirmed if unconfirmed else OAuthExchangeError
        raise kind("provider exchange held; host reconciliation required")
    if result is None:
        raise ValueError("checked result missing")
    return result
