"""Actual disposable owner transactions with invented fixed-TLS exchange replies."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
from pydantic import SecretStr

from tests.test_oauth_transactions import CODE
from tests.test_oauth_transactions import Fixture as Transactions
from tests.test_provider_oauth_evidence import (
    ACCESS,
    REFRESH,
    SUBJECT,
    USER,
    google,
    google_responses,
    slack,
    slack_response,
)
from zacai.connectors.account_preflight import VerifiedCredential
from zacai.connectors.oauth_exchange import (
    OAuthExchangeCancellationHoldUnconfirmed,
    OAuthExchangeCancelled,
    OAuthExchangeError,
    OAuthExchangeHoldUnconfirmed,
    OAuthExchangeTransport,
    exchange_initial,
)
from zacai.connectors.oauth_transactions import OAuthTransactionError
from zacai.connectors.provider_oauth_evidence import SlackRotation

CLIENT_SECRET = "invented-private-client-secret"
PRIVATE = "invented-private-provider-prose"


class Response:
    def __init__(
        self, value: Any, *, status: int = 200, headers: list[tuple[str, str]] | None = None
    ) -> None:
        self.body = json.dumps(value).encode() if type(value) is not bytes else value
        self.status = status
        self.headers = headers or [("Content-Type", "application/json")]
        self.reads = []

    def getheader(self, name: str) -> str | None:
        return next((value for key, value in self.headers if key.lower() == name.lower()), None)

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers

    def read(self, amount: int) -> bytes:
        self.reads.append(amount)
        return self.body[:amount]


class Connection:
    def __init__(self, fixture: Fixture, host: str, response: Response) -> None:
        self.fixture, self.host, self.response = fixture, host, response
        self.closed = False

    def request(self, method: str, path: str, body: bytes | None, headers: dict[str, str]) -> None:
        self.fixture.calls.append((self.host, method, path, body, headers))
        if self.fixture.failure:
            raise self.fixture.failure
        if self.fixture.revoke_after_request == len(self.fixture.calls):
            self.fixture.transactions.sessions.sessions.revoke(
                self.fixture.transactions.sessions.cookie
            )

    def getresponse(self) -> Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class Fixture:
    def __init__(self, temporary: Path, provider: str = "gmail") -> None:
        self.transactions = Transactions(temporary)
        self.transactions.configuration = google() if provider == "gmail" else slack()
        self.transactions.rotation = None if provider == "gmail" else SlackRotation.ROTATING
        self.provider = provider
        self.calls: list[Any] = []
        self.connections: list[Connection] = []
        self.failure: BaseException | None = None
        self.revoke_after_request: int | None = None
        self.loads = 0
        self.expected = SUBJECT if provider == "gmail" else USER
        if provider == "gmail":
            token, info = google_responses()
            self.responses = [
                Response(token),
                Response(info),
                Response(
                    {
                        "emailAddress": "zcampbell@brainstormtech.io",
                        "messagesTotal": 0,
                        "threadsTotal": 0,
                        "historyId": "123",
                    }
                ),
            ]
        else:
            scopes = ",".join(sorted(self.transactions.configuration.scopes))
            self.responses = [
                Response(slack_response()),
                Response(
                    {
                        "ok": True,
                        "team_id": "T12345678",
                        "user_id": USER,
                        "url": "https://invented.slack.com/",
                        "team": "invented",
                        "user": "invented",
                    },
                    headers=[("Content-Type", "application/json"), ("X-OAuth-Scopes", scopes)],
                ),
            ]
        self.state = self.transactions.state()
        self.operation = self.transactions.callback(self.state)
        self.transport = OAuthExchangeTransport(connection_factory=self.connect)

    def connect(self, host: str) -> Connection:
        assert host in {"oauth2.googleapis.com", "gmail.googleapis.com", "slack.com"}
        response = self.responses[len(self.connections)]
        connection = Connection(self, host, response)
        self.connections.append(connection)
        return connection

    def load(self, configuration: Any) -> SecretStr:
        assert configuration == self.transactions.configuration
        self.loads += 1
        return SecretStr(CLIENT_SECRET)

    def execute(self, **changes: Any) -> Any:
        fields = {
            "client_secret_loader": self.load,
            "transport": self.transport,
            "expected_subject": self.expected,
        }
        fields.update(changes)
        return exchange_initial(self.operation, **fields)

    def row(self) -> Any:
        with self.transactions.authority._locked():
            return next(iter(self.transactions.authority._read()["rows"].values()))


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    return Fixture(tmp_path)


def safe(error: BaseException) -> None:
    assert error.__cause__ is None and error.__context__ is None
    assert all(
        secret not in str(error) and secret not in repr(error)
        for secret in [CODE, CLIENT_SECRET, ACCESS, REFRESH, PRIVATE]
    )
    current = error.__traceback__
    while current:
        frame = current.tb_frame
        if frame.f_globals.get("__name__") == "zacai.connectors.oauth_exchange":
            assert "args" not in frame.f_locals and "kwargs" not in frame.f_locals
            assert frame.f_code.co_name in {"call", "wrapped"}
        current = current.tb_next


@pytest.mark.parametrize("provider", ["gmail", "slack"])
def test_initial_exchange_fixed_routes_same_token_identity_and_uninstalled(
    tmp_path: Path, provider: str
) -> None:
    fixture = Fixture(tmp_path, provider)
    result = fixture.execute()
    candidate = result.candidate
    assert result.read_identity_verified is True and result.installed is False
    assert candidate.installed is False and not isinstance(candidate, VerifiedCredential)
    assert candidate.access_token.get_secret_value() == ACCESS
    assert candidate.refresh_token.get_secret_value() == REFRESH
    assert candidate.subject_id == fixture.expected
    assert fixture.loads == 1 and all(connection.closed for connection in fixture.connections)
    assert ACCESS not in repr(result) and REFRESH not in repr(result)
    host, method, path, body, headers = fixture.calls[0]
    assert method == "POST" and "?" not in path
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    form = parse_qs(body.decode(), strict_parsing=True)
    assert form["client_id"] == [fixture.transactions.configuration.client_id]
    assert form["client_secret"] == [CLIENT_SECRET] and form["code"] == [CODE]
    assert form["redirect_uri"] == [fixture.transactions.configuration.callback]
    if provider == "gmail":
        assert (host, path) == ("oauth2.googleapis.com", "/token")
        assert form["grant_type"] == ["authorization_code"]
        assert set(form) == {
            "client_id",
            "client_secret",
            "code",
            "redirect_uri",
            "grant_type",
            "code_verifier",
        }
        assert len(form["code_verifier"][0]) >= 43
        assert fixture.calls[1][0:3] == ("oauth2.googleapis.com", "POST", "/tokeninfo")
        assert fixture.calls[2][0:3] == (
            "gmail.googleapis.com",
            "GET",
            "/gmail/v1/users/me/profile",
        )
    else:
        assert (host, path) == ("slack.com", "/api/oauth.v2.access")
        assert "code_verifier" not in form
        assert fixture.calls[1][0:3] == ("slack.com", "POST", "/api/auth.test")
    for _, _, route, _, request_headers in fixture.calls[1:]:
        assert ACCESS not in route
        assert request_headers["Authorization"] == "Bearer " + ACCESS
    assert fixture.row()["state"] == "exchange_started" and fixture.row()["loaded"] is True
    with pytest.raises(OAuthExchangeError):
        fixture.execute()
    assert fixture.loads == 1


@pytest.mark.parametrize("revoke", ["session", "registration", "expired"])
def test_revoked_original_operation_denies_before_loader_and_any_io(
    fixture: Fixture, revoke: str
) -> None:
    if revoke == "session":
        fixture.transactions.sessions.sessions.revoke(fixture.transactions.sessions.cookie)
    elif revoke == "registration":
        fixture.transactions.registration.current = "invented-registration-generation-2"
    else:
        fixture.transactions.sessions.now += timedelta(minutes=6)
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert fixture.loads == 0 and not fixture.calls
    assert fixture.row()["state"] == "held"


def test_loader_revokes_session_before_first_socket(fixture: Fixture) -> None:
    def revoked(configuration: Any) -> SecretStr:
        secret = fixture.load(configuration)
        fixture.transactions.sessions.sessions.revoke(fixture.transactions.sessions.cookie)
        return secret

    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute(client_secret_loader=revoked)
    safe(raised.value)
    assert fixture.loads == 1 and not fixture.calls and fixture.row()["state"] == "held"


@pytest.mark.parametrize(
    "provider,stage", [("gmail", 1), ("gmail", 2), ("gmail", 3), ("slack", 1), ("slack", 2)]
)
def test_revocation_after_every_provider_io_prevents_candidate_release(
    tmp_path: Path, provider: str, stage: int
) -> None:
    fixture = Fixture(tmp_path, provider)
    fixture.revoke_after_request = stage
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert len(fixture.calls) == stage and fixture.row()["state"] == "held"
    assert all(connection.closed for connection in fixture.connections)


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 429, 500])
def test_no_redirect_retry_or_provider_error_prose(fixture: Fixture, status: int) -> None:
    fixture.responses[0] = Response(
        {"error": PRIVATE},
        status=status,
        headers=[
            ("Content-Type", "application/json"),
            ("Location", "https://evil.example/"),
            ("Retry-After", "1"),
        ],
    )
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert len(fixture.calls) == 1 and fixture.row()["state"] == "held"


@pytest.mark.parametrize(
    "body",
    [
        b"x" * 65537,
        b'{"access_token":"x","access_token":"y"}',
        b'{"error":"invented-private-provider-prose"}',
        b'{"expires_in":NaN}',
    ],
)
def test_bounded_unique_finite_provider_exchange_response(fixture: Fixture, body: bytes) -> None:
    fixture.responses[0] = Response(body)
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert len(fixture.calls) == 1 and fixture.row()["state"] == "held"


@pytest.mark.parametrize(
    "stage,field,value",
    [
        (1, "aud", "other.apps.googleusercontent.com"),
        (1, "sub", "other-subject"),
        (1, "scope", "https://mail.google.com/"),
        (1, "expires_in", "999999"),
        (2, "emailAddress", "other@example.invalid"),
    ],
)
def test_same_token_google_exact_client_subject_grants_expiry_and_mailbox(
    fixture: Fixture, stage: int, field: str, value: Any
) -> None:
    body = json.loads(fixture.responses[stage].body)
    body[field] = value
    fixture.responses[stage].body = json.dumps(body).encode()
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert fixture.row()["state"] == "held"


@pytest.mark.parametrize("change", ["team", "user", "bot", "scope", "missing_scope_header"])
def test_slack_exact_workspace_user_and_scope_header(tmp_path: Path, change: str) -> None:
    fixture = Fixture(tmp_path, "slack")
    if change == "scope":
        body = json.loads(fixture.responses[0].body)
        body["authed_user"]["scope"] = "chat:write"
        fixture.responses[0].body = json.dumps(body).encode()
    elif change == "missing_scope_header":
        fixture.responses[1].headers = [("Content-Type", "application/json")]
    else:
        body = json.loads(fixture.responses[1].body)
        body[{"team": "team_id", "user": "user_id", "bot": "bot_id"}[change]] = (
            "B12345678" if change == "bot" else "TOTHER123" if change == "team" else "UOTHER123"
        )
        fixture.responses[1].body = json.dumps(body).encode()
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert fixture.row()["state"] == "held"


@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("hold_failure", [False, True])
def test_transport_failure_cancellation_and_unconfirmed_hold_have_fixed_distinct_signal(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, cancel: bool, hold_failure: bool
) -> None:
    fixture.failure = KeyboardInterrupt(PRIVATE) if cancel else RuntimeError(PRIVATE)
    if hold_failure:

        def failed_hold() -> None:
            raise RuntimeError(PRIVATE)

        monkeypatch.setattr(fixture.operation, "hold", failed_hold)
    kind = (
        (OAuthExchangeCancellationHoldUnconfirmed if cancel else OAuthExchangeHoldUnconfirmed)
        if hold_failure
        else OAuthExchangeCancelled
        if cancel
        else OAuthExchangeError
    )
    with pytest.raises(kind) as raised:
        fixture.execute()
    assert type(raised.value) is kind
    safe(raised.value)
    assert len(fixture.calls) == 1 and fixture.connections[0].closed


def test_restart_consumed_transaction_cannot_redo_code_exchange(fixture: Fixture) -> None:
    fixture.execute()
    with pytest.raises(OAuthTransactionError):
        fixture.transactions.callback(fixture.state, authority=fixture.transactions.reopen())
    assert fixture.loads == 1 and len(fixture.calls) == 3


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Type", "application/json"), ("content-type", "application/json")],
        [("Content-Type", "text/plain")],
        [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
        [("Content-Type", "application/json"), ("Content-Length", "65537")],
        [("Content-Type", "application/json"), ("Content-Length", "-1")],
        [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked")],
        [("Content-Type", "application/json"), ("Location", "https://evil.example/")],
        [("Content-Type", "application/json"), ("X-Private", "invented\r\nHeader")],
    ],
)
def test_exchange_strict_header_envelope_no_redirect_or_compression(
    fixture: Fixture, headers: list[tuple[str, str]]
) -> None:
    fixture.responses[0].headers = headers
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert len(fixture.calls) == 1 and fixture.row()["state"] == "held"


@pytest.mark.parametrize("stage", [1, 2])
def test_reused_identity_read_transport_rejects_duplicate_security_headers(
    fixture: Fixture, stage: int
) -> None:
    fixture.responses[stage].headers.append(("content-type", "application/json"))
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert len(fixture.calls) == stage + 1 and fixture.row()["state"] == "held"


@pytest.mark.parametrize("cancel", [False, True])
def test_private_client_secret_loader_failure_never_reaches_socket(
    fixture: Fixture, cancel: bool
) -> None:
    def rejected(configuration: Any) -> SecretStr:
        raise (
            KeyboardInterrupt(CLIENT_SECRET + PRIVATE)
            if cancel
            else RuntimeError(CLIENT_SECRET + PRIVATE)
        )

    with pytest.raises(OAuthExchangeCancelled if cancel else OAuthExchangeError) as raised:
        fixture.execute(client_secret_loader=rejected)
    safe(raised.value)
    assert not fixture.calls and fixture.row()["state"] == "held"


@pytest.mark.parametrize(
    "secret", ["invented-plain-secret", SecretStr(""), SecretStr("invented\r\nsecret")]
)
def test_secret_loader_must_return_bounded_secretstr(fixture: Fixture, secret: Any) -> None:
    with pytest.raises(OAuthExchangeError):
        fixture.execute(client_secret_loader=lambda configuration: secret)
    assert not fixture.calls and fixture.row()["state"] == "held"


@pytest.mark.parametrize("provider", ["gmail", "slack"])
def test_discovery_without_subject_pin_never_claims_subject_pin_authority(
    tmp_path: Path, provider: str
) -> None:
    fixture = Fixture(tmp_path, provider)
    result = fixture.execute(expected_subject=None)
    assert result.candidate.subject_id == fixture.expected
    assert result.candidate.subject_pin_verified is False
    assert result.installed is False and result.processing_authorized is False


def test_no_default_socket_until_explicit_exchange_and_tls_ignores_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from zacai.connectors import oauth_exchange as module

    opened = []

    class Context:
        def set_alpn_protocols(self, protocols: Any) -> None:
            assert protocols == ["http/1.1"]

    def fake_connection(host: str, **options: Any) -> Any:
        opened.append((host, options))
        return object()

    monkeypatch.setenv("HTTPS_PROXY", "https://invented-proxy.example")
    monkeypatch.setenv("ALL_PROXY", "https://invented-proxy.example")
    monkeypatch.setattr(module.ssl, "create_default_context", Context)
    monkeypatch.setattr(module.http.client, "HTTPSConnection", fake_connection)
    OAuthExchangeTransport()
    assert not opened
    module._direct_tls("oauth2.googleapis.com")
    assert opened[0][0] == "oauth2.googleapis.com"
    assert opened[0][1]["port"] == 443 and opened[0][1]["timeout"] == 20
    with pytest.raises(ValueError):
        module._direct_tls("invented-proxy.example")
    assert len(opened) == 1


@pytest.mark.parametrize("expired_material", ["access", "refresh"])
def test_final_current_attestation_expiry_advance_prevents_candidate_disclosure(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    expired_material: str,
) -> None:
    start = fixture.transactions.sessions.now
    token = json.loads(fixture.responses[0].body)
    if expired_material == "access":
        token["expires_in"] = 60
        info = json.loads(fixture.responses[1].body)
        info["expires_in"] = "60"
        info["exp"] = str(int(start.timestamp()) + 60)
        fixture.responses[1].body = json.dumps(info).encode()
    else:
        token["refresh_token_expires_in"] = 60
    fixture.responses[0].body = json.dumps(token).encode()
    original = fixture.transactions.registration.attest
    post_profile_attestations = 0

    def current_then_clock_advance(configuration: Any, rotation: Any) -> None:
        nonlocal post_profile_attestations
        original(configuration, rotation)
        if len(fixture.calls) == 3:
            post_profile_attestations += 1
            # Post-profile current checks before/after persistence; the third
            # attestation starts the final current, after the old expiry guard.
            if post_profile_attestations == 3:
                fixture.transactions.sessions.now += timedelta(seconds=90)

    monkeypatch.setattr(fixture.transactions.registration, "attest", current_then_clock_advance)
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert post_profile_attestations >= 3
    assert fixture.transactions.sessions.now == start + timedelta(seconds=90)
    assert len(fixture.calls) == 3 and fixture.loads == 1
    assert fixture.row()["state"] == "held"


def test_slack_exchange_network_latency_never_extends_short_access_lifetime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(tmp_path, "slack")
    token = json.loads(fixture.responses[0].body)
    token["authed_user"]["expires_in"] = 60
    fixture.responses[0].body = json.dumps(token).encode()
    original = Connection.getresponse

    def delayed(self: Connection) -> Response:
        if len(self.fixture.calls) == 1:
            self.fixture.transactions.sessions.now += timedelta(seconds=90)
        return original(self)

    monkeypatch.setattr(Connection, "getresponse", delayed)
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert fixture.row()["state"] == "held" and len(fixture.calls) <= 2


def test_failed_original_hold_sets_local_authority_latch_before_other_account_can_begin(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture.failure = RuntimeError(PRIVATE)
    original_lock = fixture.transactions.authority._locked
    original_hold = fixture.operation.hold

    def unreadable_hold() -> None:
        def unreadable() -> Any:
            raise OSError(PRIVATE)

        with monkeypatch.context() as context:
            context.setattr(fixture.transactions.authority, "_locked", unreadable)
            original_hold()

    monkeypatch.setattr(fixture.operation, "hold", unreadable_hold)
    with pytest.raises(OAuthExchangeHoldUnconfirmed) as raised:
        fixture.execute()
    safe(raised.value)
    monkeypatch.setattr(fixture.transactions.authority, "_locked", original_lock)
    fixture.transactions.configuration = slack()
    fixture.transactions.rotation = SlackRotation.ROTATING
    from zacai.connectors.oauth_transactions import OAuthTransactionUnconfirmed

    with pytest.raises(OAuthTransactionUnconfirmed):
        fixture.transactions.begin()


def test_final_observation_enforces_durable_future_watermark_without_process_clock_rollback(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = fixture.operation.current
    post_profile = 0

    def current_then_restart_watermark() -> None:
        nonlocal post_profile
        original()
        if len(fixture.calls) == 3:
            post_profile += 1
            if post_profile == 2:
                with fixture.transactions.authority._locked():
                    value = fixture.transactions.authority._read()
                    value["watermark"] = (
                        fixture.transactions.sessions.now + timedelta(seconds=1)
                    ).isoformat()
                    fixture.transactions.authority._write(value)

    monkeypatch.setattr(fixture.operation, "current", current_then_restart_watermark)
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert post_profile == 2 and fixture.row()["state"] == "held"


def test_pre_request_observation_final_clock_expiry_prevents_any_provider_io(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_snapshot = fixture.operation.observed_at
    original_now = fixture.transactions.authority._now
    observations = 0

    def expires_at_final_clock(value: Any) -> Any:
        nonlocal observations
        observations += 1
        if observations == 4:
            fixture.transactions.sessions.now += timedelta(minutes=6)
        return original_now(value)

    def pre_request_snapshot() -> Any:
        with monkeypatch.context() as context:
            context.setattr(fixture.transactions.authority, "_now", expires_at_final_clock)
            return original_snapshot()

    monkeypatch.setattr(fixture.operation, "observed_at", pre_request_snapshot)
    with pytest.raises(OAuthExchangeError) as raised:
        fixture.execute()
    safe(raised.value)
    assert observations >= 4
    assert not fixture.calls and not fixture.connections
    assert fixture.row()["state"] == "held"


def test_gmail_profile_accepts_its_official_readonly_scope_uri_header(tmp_path):
    f = Fixture(tmp_path)
    f.responses[2].headers.append(
        ("X-OAuth-Scopes", "https://www.googleapis.com/auth/gmail.readonly")
    )
    result = f.execute()
    assert result.installed is False
    assert len(f.calls) == 3 and all(connection.closed for connection in f.connections)
