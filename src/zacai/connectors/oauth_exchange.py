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

import hashlib
import http.client
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from typing import Any, Literal, Protocol
from urllib.parse import urlencode

from pydantic import SecretStr

from zacai.connectors.account_preflight import GMAIL_COMMUNICATION_SCOPES, Provider
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic, _phase
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


def _headers(response: Response, *, provider_host: str, diagnostic: object = None, error_response: bool = False) -> None:
    _phase(diagnostic, "exchange_status")
    if type(response.status) is not int or (response.status != 200 and not (
        error_response is True and response.status in {400, 401}
    )):
        raise ValueError("provider response rejected")
    _phase(diagnostic, "exchange_headers")
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
    _phase(diagnostic, "exchange_framing")
    transfer = response.getheader("Transfer-Encoding")
    if response.getheader("Location") is not None:
        raise ValueError("redirect response rejected")
    if transfer is not None and (
        transfer != "chunked"
        or response.getheader("Content-Length") is not None
        or type(response) is not http.client.HTTPResponse
        or response.chunked is not True
        or response.length is not None
        or response.chunk_left is not None
    ):
        raise ValueError("unsupported response framing")
    _phase(diagnostic, "exchange_media")
    if (response.getheader("Content-Type") or "").split(";", 1)[
        0
    ].strip().lower() != "application/json":
        raise ValueError("JSON response required")
    _phase(diagnostic, "exchange_encoding")
    if (response.getheader("Content-Encoding") or "identity").strip().lower() != "identity":
        raise ValueError("compressed response rejected")
    _phase(diagnostic, "exchange_length")
    length = response.getheader("Content-Length")
    if length is not None and (
        re.fullmatch(r"[0-9]{1,8}", length) is None or int(length) > _MAX_BYTES
    ):
        raise ValueError("bounded response required")
    _phase(diagnostic, "exchange_scopes")
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


class _ChunkStream(Protocol):
    def read(self, amount: int) -> bytes: ...
    def readline(self, amount: int) -> bytes: ...
    def close(self) -> None: ...
    def flush(self) -> None: ...


class _StrictChunkStream:
    """Validate framing while genuine HTTPResponse performs decoded reads.

    Closed initial support accepts bounded hexadecimal chunks with CRLF and an
    empty trailer section. Extensions and nonempty trailers remain unsupported.
    No raw framing bytes or provider prose leave this in-memory observer.
    """

    def __init__(self, stream: _ChunkStream) -> None:
        self._stream = stream
        self._state = "size"
        self._left = 0
        self._chunks = 0
        self.complete = False

    def readline(self, amount: int) -> bytes:
        line = self._stream.readline(min(amount, 130))
        if self._state == "trailer":
            if line != b"\r\n":
                raise ValueError("unsupported chunk trailer")
            self.complete = True
            self._state = "done"
            return line
        if self._state != "size" or re.fullmatch(rb"[0-9A-Fa-f]{1,8}\r\n", line) is None:
            raise ValueError("invalid chunk framing")
        self._chunks += 1
        if self._chunks > _MAX_BYTES + 1:
            raise ValueError("bounded chunk count required")
        self._left = int(line[:-2], 16)
        self._state = "data" if self._left else "trailer"
        return line

    def read(self, amount: int) -> bytes:
        if self._state == "separator":
            if amount != 2 or self._stream.read(amount) != b"\r\n":
                raise ValueError("invalid chunk separator")
            self._state = "size"
            return b"\r\n"
        if self._state != "data" or not 0 < amount <= self._left:
            raise ValueError("invalid chunk read")
        value = self._stream.read(amount)
        if type(value) is not bytes or len(value) != amount:
            raise ValueError("incomplete chunk data")
        self._left -= amount
        if not self._left:
            self._state = "separator"
        return value

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


class _CheckedResponse:
    def __init__(self, response: Response, *, diagnostic: object = None) -> None:
        self._diagnostic = diagnostic
        self._response = response
        self._chunk_stream: _StrictChunkStream | None = None
        if type(response) is http.client.HTTPResponse and response.chunked:
            if response.fp is None:
                raise ValueError("unavailable chunk stream")
            self._chunk_stream = _StrictChunkStream(response.fp)
            response.fp = self._chunk_stream  # type: ignore[assignment]
        self.status = response.status

    def getheaders(self) -> list[tuple[str, str]]:
        return self._response.getheaders()

    def getheader(self, name: str) -> str | None:
        return self._response.getheader(name)

    def read(self, amount: int) -> bytes:
        _phase(self._diagnostic, "exchange_body")
        raw = self._response.read(min(amount, _MAX_BYTES + 1))
        _phase(self._diagnostic, "exchange_body_validation")
        if self._chunk_stream is not None and (
            not self._chunk_stream.complete
            or type(self._response) is not http.client.HTTPResponse
            or not self._response.isclosed()
        ):
            raise ValueError("incomplete chunk response")
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

    def __init__(self, connection: Connection, *, provider_host: str, diagnostic: object = None, error_response: bool = False) -> None:
        self._error_response = error_response
        self._diagnostic = diagnostic
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
        _phase(self._diagnostic, "exchange_response")
        response = self._connection.getresponse()
        _headers(response, provider_host=self._provider_host, diagnostic=self._diagnostic, error_response=self._error_response)
        return _CheckedResponse(response, diagnostic=self._diagnostic)

    def close(self) -> None:
        self._connection.close()


def _profile_operation(operation: OAuthExchangeOperation) -> tuple[object, ...]:
    return (
        operation._authority,
        operation._configuration,
        operation._operation,
        operation._authority._continuity,
        operation._authority._backend,
        getattr(operation, "_recovery_admission", None),
        getattr(operation, "_original_recovery_admission", None),
        operation._state_hash,
        operation._capability,
        operation._configuration.configuration_digest,
    )


def _same_profile_operation(
    operation: OAuthExchangeOperation, original: tuple[object, ...]
) -> None:
    current = _profile_operation(operation)
    if (
        any(a is not b for a, b in zip(current[:7], original[:7], strict=True))
        or current[7:] != original[7:]
    ):
        raise ValueError("original profile operation composition required")


def _profile_candidate(candidate: UninstalledOAuthCandidate) -> tuple[object, ...]:
    if (
        type(candidate) is not UninstalledOAuthCandidate
        or type(candidate.access_token) is not SecretStr
    ):
        raise ValueError("original checked Gmail candidate required")
    return (
        candidate.provider,
        candidate.configuration_digest,
        candidate.client_id,
        candidate.subject_id,
        candidate.scopes,
        candidate.token_kind,
        candidate.expires_at,
        candidate.refresh_expires_at,
        candidate.subject_pin_verified,
        candidate.slack_app_id,
        candidate.slack_team_id,
        candidate.slack_rotation,
        hashlib.sha256(candidate.access_token.get_secret_value().encode("ascii")).digest(),
        None
        if candidate.refresh_token is None
        else hashlib.sha256(
            _secret(candidate.refresh_token.get_secret_value()).get_secret_value().encode("ascii")
        ).digest(),
    )


@dataclass(frozen=True, init=False, repr=False)
class GmailProfileObservation:
    """Private same-exchange profile observation; never installed authority.

    Issued only after the existing checked profile call and final current checks.
    A consumer verifies this while the original exchange remains current, then
    must independently verify its durable hold and owner before publication.
    No token, mailbox, response bytes or private correlation is a public field.
    """

    observed_at: datetime
    _issuer: CheckedOAuthExchange
    _operation: OAuthExchangeOperation
    _authority: object
    _named_operation: object
    _configuration: OAuthConfiguration
    _continuity: object
    _backend: object
    _recovery_admission: object
    _original_recovery_admission: object
    _state_hash: str
    _capability: str
    _candidate: UninstalledOAuthCandidate
    _candidate_values: tuple[object, ...]
    _binding: str
    _principal: object

    def __init__(self) -> None:
        raise TypeError("private exchange-issued profile observation required")

    def __repr__(self) -> str:
        return "GmailProfileObservation()"

    @property
    def profile_verified(self) -> Literal[True]:
        return True

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False

    def _pins(self, issuer: CheckedOAuthExchange, operation: OAuthExchangeOperation) -> None:
        if (
            type(issuer) is not CheckedOAuthExchange
            or type(operation) is not OAuthExchangeOperation
            or issuer is not self._issuer
            or issuer._gmail_observation is not self
            or issuer.candidate is not self._candidate
            or operation is not self._operation
            or operation._authority is not self._authority
            or operation._operation is not self._named_operation
            or operation._configuration is not self._configuration
            or operation._authority._continuity is not self._continuity
            or operation._authority._backend is not self._backend
            or getattr(operation, "_recovery_admission", None) is not self._recovery_admission
            or getattr(operation, "_original_recovery_admission", None)
            is not self._original_recovery_admission
            or operation._state_hash != self._state_hash
            or operation._capability != self._capability
            or operation._configuration.configuration_digest != self._candidate.configuration_digest
            or _profile_candidate(self._candidate) != self._candidate_values
        ):
            raise ValueError("original same-token profile observation required")

    def _current(self, issuer: CheckedOAuthExchange, operation: OAuthExchangeOperation) -> None:
        self._pins(issuer, operation)
        operation.current()
        self._pins(issuer, operation)
        verified = operation._operation.recheck(self._binding)
        if verified.principal != self._principal:
            raise ValueError("original profile owner required")
        self._pins(issuer, operation)
        now = operation.observed_at()
        if (
            now < self.observed_at
            or self._candidate.expires_at is None
            or now >= self._candidate.expires_at
        ):
            raise ValueError("current profile observation required")
        operation.current()
        self._pins(issuer, operation)


@dataclass(frozen=True)
class CheckedOAuthExchange:
    candidate: UninstalledOAuthCandidate = field(repr=False)
    _gmail_observation: GmailProfileObservation | None = field(default=None, init=False, repr=False)

    @_closed
    def gmail_profile_observation(
        self, operation: OAuthExchangeOperation
    ) -> GmailProfileObservation:
        observation = self._gmail_observation
        if type(observation) is not GmailProfileObservation:
            raise ValueError("original Gmail profile observation required")
        observation._current(self, operation)
        return observation

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def read_identity_verified(self) -> Literal[True]:
        return True

    @property
    def processing_authorized(self) -> Literal[False]:
        return False


def _google_error_phase(raw: bytes) -> str:
    """Bounded classification only; never return provider descriptions or values."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate error field")
            result[name] = value
        return result

    def finite(value: str) -> None:
        raise ValueError("nonfinite error value")

    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 65_536:
            raise ValueError("bounded error response required")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=finite)
        if type(value) is not dict or type(value.get("error")) is not str:
            return "exchange_error_unavailable"
        code = value["error"]
        assert isinstance(code, str)
        if code in {"invalid_client", "invalid_grant", "invalid_request"}:
            return "exchange_error_" + code
        return "exchange_error_other"
    except Exception:  # noqa: BLE001 - fixed classification discards private error JSON
        return "exchange_error_unavailable"


class OAuthExchangeTransport:
    """Inert host transport; supplying a factory neither grants nor proves access."""

    def __init__(self, *, connection_factory: Callable[[str], Connection] = _direct_tls) -> None:
        if not callable(connection_factory):
            raise OAuthExchangeError("trusted connection factory required")
        self._factory = connection_factory

    def _connection(self, host: str, *, diagnostic: object = None, error_response: bool = False) -> _CheckedConnection:
        _phase(diagnostic, "exchange_connection")
        return _CheckedConnection(self._factory(host), provider_host=host, diagnostic=diagnostic, error_response=error_response)

    def _post(
        self, host: str, path: str, values: dict[str, str], key: SecretStr | None = None,
        *, diagnostic: object = None
    ) -> bytes:
        classify_error = (host == "oauth2.googleapis.com" and path == "/token"
                          and type(diagnostic) is OAuthCallbackDiagnostic)
        connection = self._connection(host, diagnostic=diagnostic, error_response=classify_error)
        primary_failed = False
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
            _phase(diagnostic, "exchange_request")
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
            if classify_error and response.status in {400, 401}:
                _phase(diagnostic, _google_error_phase(raw))
                raise ValueError("provider initial exchange denied")
            _phase(diagnostic, "exchange_json")
            _object(raw)
        except BaseException:
            primary_failed = True
            raise
        finally:
            previous = diagnostic.phase if type(diagnostic) is OAuthCallbackDiagnostic else None
            if not primary_failed:
                _phase(diagnostic, "exchange_close")
            try:
                connection.close()
            except Exception:
                if not primary_failed:
                    raise
            except BaseException:
                raise
            finally:
                if primary_failed and previous is not None:
                    _phase(diagnostic, previous)
        _phase(diagnostic, "exchange_return")
        return raw

    @_closed
    def exchange(self, material: ExchangeMaterial, client_secret: SecretStr, *, diagnostic: OAuthCallbackDiagnostic | None = None) -> bytes:
        _phase(diagnostic, "exchange_material")
        if type(material) is not ExchangeMaterial or type(client_secret) is not SecretStr:
            raise ValueError("trusted exact exchange material required")
        _phase(diagnostic, "exchange_configuration")
        config = OAuthConfiguration.model_validate(material.configuration)
        if material.callback != config.callback:
            raise ValueError("exact callback required")
        _phase(diagnostic, "exchange_secret")
        values = {
            "client_id": config.client_id,
            "client_secret": _secret(client_secret.get_secret_value()).get_secret_value(),
            "code": _secret(material.code.get_secret_value()).get_secret_value(),
            "redirect_uri": config.callback,
        }
        _phase(diagnostic, "exchange_pkce")
        if config.provider is Provider.GMAIL:
            if type(material.google_code_verifier) is not SecretStr:
                raise ValueError("PKCE required")
            values |= {
                "grant_type": "authorization_code",
                "code_verifier": material.google_code_verifier.get_secret_value(),
            }
            return self._post("oauth2.googleapis.com", "/token", values, diagnostic=diagnostic)
        if material.google_code_verifier is not None:
            raise ValueError("unexpected Gmail verifier")
        return self._post("slack.com", "/api/oauth.v2.access", values, diagnostic=diagnostic)

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
    diagnostic: OAuthCallbackDiagnostic | None = None,
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
    profile_owner = None
    profile_values = None
    try:
        _phase(diagnostic, "exchange_release")
        profile_operation = _profile_operation(operation)
        material = operation.take_exchange()
        config = material.configuration
        operation.current()
        _phase(diagnostic, "exchange_credential")
        client_secret = client_secret_loader(config)
        operation.current()
        if type(client_secret) is not SecretStr:
            raise ValueError("trusted exact client secret required")
        operation.current()
        observed = operation.observed_at()
        _phase(diagnostic, "exchange_provider")
        exchange = transport.exchange(material, client_secret, diagnostic=diagnostic)
        _phase(diagnostic, "exchange_current")
        operation.current()
        exchange_end = operation.observed_at()
        if config.provider is Provider.GMAIL:
            access = _secret(_object(exchange).get("access_token"))
            operation.current()
            evidence_start = operation.observed_at()
            _phase(diagnostic, "tokeninfo_provider")
            evidence = transport.google_tokeninfo(access)
            evidence_at = operation.observed_at()
            _phase(diagnostic, "exchange_current")
            operation.current()
            candidate = parse_google_oauth_evidence(
                config,
                exchange,
                evidence,
                expected_subject=expected_subject,
                exchange_observed_at=observed,
                evidence_observed_at=evidence_at,
                exchange_completed_at=exchange_end,
                evidence_started_at=evidence_start,
                diagnostic=diagnostic,
            )
            operation.current()
            _phase(diagnostic, "profile_current")
            _same_profile_operation(operation, profile_operation)
            profile_owner = operation._operation.establish()
            profile_values = _profile_candidate(candidate)
            operation.current()
            _same_profile_operation(operation, profile_operation)
            _phase(diagnostic, "profile_provider")
            transport.gmail_profile(candidate.access_token, config)
            _phase(diagnostic, "profile_current")
            operation.current()
            _same_profile_operation(operation, profile_operation)
            if _profile_candidate(candidate) != profile_values:
                raise ValueError("original profile token changed")
            verified = operation._operation.recheck(profile_owner.binding_digest)
            if verified.principal != profile_owner.principal:
                raise ValueError("original profile owner changed")
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
        if config.provider is Provider.GMAIL:
            if (
                profile_owner is None
                or profile_values is None
                or _profile_candidate(candidate) != profile_values
            ):
                raise ValueError("original checked profile observation required")
            _same_profile_operation(operation, profile_operation)
            observation = object.__new__(GmailProfileObservation)
            values = {
                "observed_at": final_now,
                "_issuer": result,
                "_operation": operation,
                "_authority": operation._authority,
                "_named_operation": operation._operation,
                "_configuration": operation._configuration,
                "_continuity": operation._authority._continuity,
                "_backend": operation._authority._backend,
                "_recovery_admission": getattr(operation, "_recovery_admission", None),
                "_original_recovery_admission": getattr(
                    operation, "_original_recovery_admission", None
                ),
                "_state_hash": operation._state_hash,
                "_capability": operation._capability,
                "_candidate": candidate,
                "_candidate_values": profile_values,
                "_binding": profile_owner.binding_digest,
                "_principal": profile_owner.principal,
            }
            for name, value in values.items():
                object.__setattr__(observation, name, value)
            object.__setattr__(result, "_gmail_observation", observation)
    except BaseException as error:  # noqa: BLE001 - preserve only fixed failure categories
        failed, cancelled = True, not isinstance(error, Exception)
    if failed:
        previous_phase = (
            diagnostic.phase if type(diagnostic) is OAuthCallbackDiagnostic else "unavailable"
        )
        _phase(diagnostic, "hold_preservation")
        try:
            operation.hold()
            _phase(diagnostic, previous_phase)
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
