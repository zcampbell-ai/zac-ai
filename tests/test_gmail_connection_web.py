"""Invented ASGI Gmail assembly, disposable encrypted stores, no native/provider IO."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from tests.test_oauth_configuration import gmail
from tests.test_private_host import CONFIG, NOW, ORIGIN, InventedIdentity, enroll, sign_in
from zacai.connectors.oauth_exchange import OAuthExchangeTransport
from zacai.connectors.oauth_transactions import (
    OAuthTransactionAuthority,
    OAuthTransactionUnconfirmed,
)
from zacai.interfaces.gmail_connection_web import GmailConnectionWeb
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_host import PrivateHostError, prepare_owner_host
from zacai.interfaces.private_web import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

ACCESS = "invented-gmail-access"
REFRESH = "invented-gmail-refresh"
SECRET = "invented-client-secret"
CODE = "invented-authorization-code"
SUBJECT = "invented-gmail-stable-subject"
SCOPE = BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))


class Registration:
    def __init__(self):
        self.calls = 0
        self.action = None

    def attest(self, configuration, rotation):
        self.calls += 1
        if self.action:
            self.action()

    def generation(self, configuration, rotation):
        return "invented-reviewed-generation"


class Guard:
    def __init__(self):
        self.halts = 0

    def ready(self):
        if self.halts:
            raise RuntimeError(SECRET)

    def halt_unconfirmed(self):
        self.halts += 1


class Response:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def getheader(self, name):
        return "application/json" if name.lower() == "content-type" else None

    def read(self, amount):
        return self.body[:amount]


class Connection:
    def __init__(self, fixture, host, response):
        self.fixture, self.host, self.response = fixture, host, response
        self.closed = False

    def request(self, method, path, body, headers):
        self.fixture.requests.append((self.host, method, path))
        if self.fixture.provider_action:
            self.fixture.provider_action()

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class Fixture:
    def __init__(self, directory: Path, *, scopes=(SCOPE,), binding="correct"):
        self.directory = directory / "private"
        self.clock = HostObservedClock(lambda: NOW)
        enroll(self.directory, self.clock, scopes=scopes)
        self.registration, self.guard = Registration(), Guard()
        self.configuration = gmail(private_origin=ORIGIN)
        self.loads = 0
        self.stop_calls = 0
        self.requests, self.connections, self.staged = [], [], []
        self.loader_action = self.provider_action = self.stage_action = None
        self.inputs = self.controller = self.authority = None
        self.binding = binding
        self.transport = OAuthExchangeTransport(connection_factory=self.connect)

        async def view(principal):
            return "<main>Invented protected page</main>"

        self.prepared = prepare_owner_host(
            configuration=CONFIG,
            directory=self.directory,
            view=view,
            identities=InventedIdentity(self.clock),
            clock=self.clock,
            gmail_factory=self.factory,
        )

    def factory(self, inputs):
        self.inputs = inputs
        clock = HostObservedClock(lambda: NOW) if self.binding == "clock" else inputs.clock
        owner = (lambda: inputs.owner()) if self.binding == "owner" else inputs.owner
        continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=owner,
            clock=clock,
            key=b"Y" * 32 if self.binding == "continuity_key" else inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        self.authority = OAuthTransactionAuthority(
            inputs.directory / "gmail-oauth",
            continuity=continuity,
            key=b"Y" * 32 if self.binding == "ledger_key" else inputs.session_key,
            registration_backend=self.registration,
        )
        self.authority.initialize()
        self.controller = GmailConnectionWeb(
            configuration=self.configuration,
            authority=self.authority,
            client_secret_loader=self.load,
            transport=self.transport,
            stage_checked=self.stage,
            host_guard=self.guard,
            stop_host=self.stop,
        )
        return self.controller

    def stop(self):
        self.stop_calls += 1

    def load(self, configuration):
        assert configuration == self.configuration
        self.loads += 1
        if self.loader_action:
            self.loader_action()
        return SecretStr(SECRET)

    def stage(self, result, operation):
        operation.current()
        self.staged.append(result)
        if self.stage_action:
            self.stage_action()

    def connect(self, host):
        scope = " ".join(sorted(self.configuration.scopes))
        responses = [
            {
                "access_token": ACCESS,
                "refresh_token": REFRESH,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": scope,
            },
            {
                "azp": self.configuration.client_id,
                "aud": self.configuration.client_id,
                "sub": SUBJECT,
                "scope": scope,
                "exp": str(int(NOW.timestamp()) + 3600),
                "expires_in": "3600",
                "access_type": "offline",
            },
            {
                "emailAddress": self.configuration.gmail_mailbox,
                "messagesTotal": 0,
                "threadsTotal": 0,
                "historyId": "123",
            },
        ]
        connection = Connection(self, host, Response(responses[len(self.connections)]))
        self.connections.append(connection)
        return connection

    def browser(self):
        return TestClient(self.prepared.app, base_url=ORIGIN, follow_redirects=False)

    def fields(self, browser):
        response = browser.get("/connections/gmail")
        assert response.status_code == 200
        assert response.headers["referrer-policy"] == "same-origin"
        assert (
            "form-action 'self' https://accounts.google.com;"
            in response.headers["content-security-policy"]
        )
        fields = dict(re.findall(r'name="([^"]+)" value="([^"]+)"', response.text))
        assert set(fields) == {"csrf", "reviewed_configuration_digest"}
        return fields

    def begin(self, browser):
        response = browser.post(
            "/connections/gmail/begin", data=self.fields(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code in {303, 307}
        return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]

    def callback(self, browser, state):
        return browser.get(
            "/connections/gmail/callback?" + urlencode({"state": state, "code": CODE})
        )

    def row(self):
        with self.authority._locked():
            return next(iter(self.authority._read()["rows"].values()))


def safe(response):
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert all(private not in response.text for private in (ACCESS, REFRESH, SECRET, CODE, SUBJECT))


def test_actual_owner_cookie_form_exchange_is_held_and_uninstalled(tmp_path):
    f = Fixture(tmp_path)
    assert f.authority._continuity._clock is f.clock
    assert f.authority._continuity._sessions is f.prepared.sessions
    with f.browser() as browser:
        sign_in(browser)
        state = f.begin(browser)
        response = f.callback(browser, state)
        assert response.status_code == 303
        assert response.headers["location"] == "/connections/gmail/status"
        safe(response)
        status = browser.get(response.headers["location"])
        assert status.status_code == 200
        safe(status)
        assert f.loads == 1 and len(f.requests) == 3 and len(f.staged) == 1
        assert f.stop_calls == 0
        result = f.staged[0]
        assert result.installed is False and result.processing_authorized is False
        assert result.candidate.subject_pin_verified is False
        assert result.candidate.subject_id == SUBJECT
        assert f.row()["state"] == "held"
        assert f.row()["verifier"] is None
        assert all(connection.closed for connection in f.connections)
        replay = f.callback(browser, state)
        assert replay.status_code == 303
        assert replay.headers["location"] == "/connections/gmail/status"
        safe(replay)
        assert f.loads == 1 and len(f.requests) == 3
        assert browser.post("/connections/gmail/install").status_code == 404


@pytest.mark.parametrize("binding", ["clock", "owner", "continuity_key", "ledger_key"])
def test_actual_host_rejects_foreign_binding(tmp_path, binding):
    with pytest.raises(PrivateHostError, match="private owner host unavailable"):
        Fixture(tmp_path, binding=binding)


@pytest.mark.parametrize(
    "scopes",
    [
        (),
        (BoundaryScope(B.PERSONAL, SCOPE.classifications),),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    ],
)
def test_logged_out_or_insufficient_owner_scope_before_registration(tmp_path, scopes):
    # Empty scope case uses an enrolled owner but does not sign in.
    f = Fixture(tmp_path, scopes=scopes or (SCOPE,))
    with f.browser() as browser:
        if scopes:
            sign_in(browser)
        response = browser.get("/connections/gmail")
        assert response.status_code >= 400
        safe(response)
        assert f.registration.calls == f.loads == 0 and not f.requests


@pytest.mark.parametrize(
    "body",
    [
        b"csrf=bad&reviewed_configuration_digest=bad",
        b"csrf=x&csrf=y&reviewed_configuration_digest=z",
        b"csrf=%ZZ&reviewed_configuration_digest=z",
        b"x=" + b"a" * 1024,
    ],
)
def test_malformed_form_rejected_before_registration_or_secret(tmp_path, body):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        response = browser.post(
            "/connections/gmail/begin",
            content=body,
            headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code >= 400
        safe(response)
        assert f.registration.calls == f.loads == 0 and not f.requests


def test_cross_origin_valid_form_is_denied_before_registration(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        response = browser.post(
            "/connections/gmail/begin",
            data=f.fields(browser),
            headers={"origin": "https://evil.example"},
        )
        assert response.status_code >= 400
        assert f.registration.calls == f.loads == 0


@pytest.mark.parametrize("seam", ["loader", "provider", "stage"])
def test_session_revocation_during_blocking_seam_preserves_hold(tmp_path, seam):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)
        state = f.begin(browser)
        setattr(f, seam + "_action", lambda: f.prepared.sessions.revoke(cookie))
        response = f.callback(browser, state)
        assert response.status_code == 303
        assert response.headers["location"] == "/connections/gmail/status"
        safe(response)
        assert f.row()["state"] == "held"
        assert len(f.requests) == {"loader": 0, "provider": 1, "stage": 3}[seam]


def test_owner_revocation_before_callback_reads_no_secret(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        state = f.begin(browser)
        f.prepared.revoke_owner()
        response = f.callback(browser, state)
        assert response.status_code == 303
        assert response.headers["location"] == "/connections/gmail/status"
        safe(response)
        assert f.loads == 0 and not f.requests


def test_hold_uncertainty_calls_host_halt_and_stops_further_admission(tmp_path, monkeypatch):
    from zacai.connectors.oauth_transactions import OAuthExchangeOperation

    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        state = f.begin(browser)

        def uncertain(operation):
            raise OAuthTransactionUnconfirmed(SECRET)

        monkeypatch.setattr(OAuthExchangeOperation, "hold", uncertain)
        response = f.callback(browser, state)
        assert response.status_code == 303
        assert response.headers["location"] == "/connections/gmail/status"
        safe(response)
        assert f.guard.halts >= 1
        calls = f.registration.calls
        response = browser.get("/connections/gmail")
        assert response.status_code >= 400
        assert f.registration.calls == calls


@pytest.mark.parametrize("field", ["csrf", "reviewed_configuration_digest"])
def test_valid_owner_form_tampering_cannot_attest_registration(tmp_path, field):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        fields = f.fields(browser)
        fields[field] = "x" * len(fields[field])
        response = browser.post("/connections/gmail/begin", data=fields, headers={"origin": ORIGIN})
        assert response.status_code >= 400
        safe(response)
        assert f.registration.calls == f.loads == 0 and not f.requests


def test_callback_is_bound_to_original_browser_not_any_enrolled_owner(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as first, f.browser() as second:
        first_cookie = sign_in(first)
        second_cookie = sign_in(second)
        assert first_cookie != second_cookie
        state = f.begin(first)
        denied = f.callback(second, state)
        assert denied.status_code == 303
        assert denied.headers["location"] == "/connections/gmail/status"
        safe(denied)
        assert f.loads == 0 and not f.requests
        assert f.row()["state"] == "pending"
        accepted = f.callback(first, state)
        assert accepted.status_code == 303
        assert f.loads == 1 and f.row()["state"] == "held"


def test_provider_denial_terminates_without_secret_or_exchange(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        state = f.begin(browser)
        response = browser.get(
            "/connections/gmail/callback?"
            + urlencode({"state": state, "error": "access_denied", "error_description": SECRET})
        )
        assert response.status_code == 303
        safe(response)
        assert f.loads == 0 and not f.requests and not f.staged
        assert f.row()["state"] == "denied"


@pytest.mark.parametrize("stop_raises", [False, True])
def test_unconfirmed_durable_halt_stops_host_and_propagates_fatal(
    tmp_path, monkeypatch, stop_raises
):
    from zacai.connectors.oauth_transactions import OAuthExchangeOperation
    from zacai.interfaces.gmail_connection_web import GmailConnectionFatal

    f = Fixture(tmp_path)
    browser = f.browser()
    try:
        sign_in(browser)
        state = f.begin(browser)

        def uncertain(operation):
            raise OAuthTransactionUnconfirmed(SECRET)

        def unavailable_halt():
            raise RuntimeError(REFRESH)

        def stop_host():
            f.stop_calls += 1
            if stop_raises:
                raise RuntimeError(ACCESS)

        monkeypatch.setattr(OAuthExchangeOperation, "hold", uncertain)
        monkeypatch.setattr(f.guard, "halt_unconfirmed", unavailable_halt)
        monkeypatch.setattr(f.controller, "_stop_host", stop_host)
        with pytest.raises(BaseExceptionGroup) as raised:
            f.callback(browser, state)
        assert f.stop_calls == 1
        assert all(private not in str(raised.value) for private in (ACCESS, REFRESH, SECRET, CODE))
        leaves = []
        pending = [raised.value]
        while pending:
            error = pending.pop()
            if isinstance(error, BaseExceptionGroup):
                pending.extend(error.exceptions)
            else:
                leaves.append(error)
        fatal = [error for error in leaves if type(error) is GmailConnectionFatal]
        assert len(fatal) == 1
        assert all(
            type(error) is GmailConnectionFatal
            or (type(error) is RuntimeError and str(error) == "No response returned.")
            for error in leaves
        )
        assert fatal[0].__context__ is None and fatal[0].__cause__ is None
        calls = (f.loads, len(f.requests), f.registration.calls)
        response = browser.get("/connections/gmail")
        assert response.status_code >= 400
        assert (f.loads, len(f.requests), f.registration.calls) == calls
        assert f.stop_calls == 1
    finally:
        browser.close()


def test_staging_generation_is_stable_per_original_transaction_and_not_a_token(tmp_path):
    from tests.test_oauth_transactions import Fixture as Transactions
    from zacai.connectors.oauth_transactions import OAuthTransactionError

    values = []
    for name in ("first", "second"):
        directory = tmp_path / name
        directory.mkdir()
        transaction = Transactions(directory)
        state = transaction.state()
        operation = transaction.callback(state)
        generation = operation.staging_generation()
        assert re.fullmatch("[0-9a-f]{32}", generation)
        assert generation == operation.staging_generation()
        assert generation not in {state, CODE, ACCESS, REFRESH}
        values.append(generation)
        operation.hold()
        with pytest.raises(OAuthTransactionError):
            operation.staging_generation()
    assert values[0] != values[1]


@pytest.mark.parametrize("change", ["revoked", "expired", "slack"])
def test_staging_generation_requires_current_original_gmail_transaction(tmp_path, change):
    from datetime import timedelta

    from tests.test_oauth_configuration import slack
    from tests.test_oauth_transactions import Fixture as Transactions
    from zacai.connectors.oauth_transactions import OAuthTransactionError
    from zacai.connectors.provider_oauth_evidence import SlackRotation

    transaction = Transactions(tmp_path)
    if change == "slack":
        transaction.configuration = slack(private_origin="https://caz.example")
        transaction.rotation = SlackRotation.ROTATING
    operation = transaction.callback(transaction.state())
    if change == "revoked":
        transaction.sessions.sessions.revoke(transaction.sessions.cookie)
    elif change == "expired":
        transaction.sessions.now += timedelta(minutes=5)
    with pytest.raises(OAuthTransactionError):
        operation.staging_generation()


def test_unconfirmed_ready_guard_stops_before_registration_or_provider_io(tmp_path, monkeypatch):
    from starlette.requests import Request

    from zacai.connectors.oauth_host_guard import OAuthHostHaltUnconfirmed
    from zacai.interfaces.gmail_connection_web import GmailConnectionError, GmailConnectionFatal

    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/connections/gmail",
            "query_string": b"",
            "headers": [
                (b"host", urlsplit(ORIGIN).netloc.encode()),
                (b"cookie", ("__Host-zac-session=" + cookie).encode()),
            ],
            "server": (urlsplit(ORIGIN).hostname, 443),
            "client": ("127.0.0.1", 1),
        }
    )

    def uncertain():
        raise OAuthHostHaltUnconfirmed(SECRET)

    monkeypatch.setattr(f.guard, "ready", uncertain)
    with pytest.raises(GmailConnectionFatal) as raised:
        f.controller.page(request)
    assert f.stop_calls == 1
    assert f.registration.calls == f.loads == 0 and not f.requests
    assert SECRET not in str(raised.value)
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    with pytest.raises(GmailConnectionError):
        f.controller.page(request)
    assert f.stop_calls == 1 and f.registration.calls == f.loads == 0


STATUS_COUNTS = ("pending", "exchange_pending", "exchange_started", "denied", "held", "loaded")
STATUS_FLAGS = (
    "installed",
    "original_actor_verified",
    "source_subject_verified",
    "native_material_verified",
    "live_access_proven",
    "credential_authority",
    "processing_authorized",
    "execution_authorized",
)


def status_request(cookie, **changes):
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": "/connections/gmail/status",
        "query_string": b"",
        "headers": [
            (b"host", urlsplit(ORIGIN).netloc.encode()),
            (b"cookie", ("__Host-zac-session=" + cookie).encode()),
        ],
        "server": (urlsplit(ORIGIN).hostname, 443),
        "client": ("127.0.0.1", 1),
    }
    scope.update(changes)
    return Request(scope)


def status_json(response, expected):
    assert response.status_code == 200
    safe(response)
    value = response.json()
    assert set(value) == set(STATUS_COUNTS + STATUS_FLAGS + ("total", "message"))
    assert tuple(value[name] for name in STATUS_COUNTS) == expected
    assert all(type(value[name]) is int for name in STATUS_COUNTS + ("total",))
    assert value["total"] == sum(expected[:5])
    assert all(value[name] is False for name in STATUS_FLAGS)
    assert type(value["message"]) is str
    return value


def test_status_zero_then_pending_before_any_google_exchange(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        status_json(browser.get("/connections/gmail/status"), (0, 0, 0, 0, 0, 0))
        f.begin(browser)
        status_json(browser.get("/connections/gmail/status"), (1, 0, 0, 0, 0, 0))
        assert f.loads == 0 and not f.requests and not f.staged


def test_status_completed_exchange_reports_held_loaded_without_authority(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        assert f.callback(browser, f.begin(browser)).status_code == 303
        before = (f.loads, len(f.requests), len(f.staged), f.registration.calls)
        status_json(browser.get("/connections/gmail/status"), (0, 0, 0, 0, 1, 1))
        assert (f.loads, len(f.requests), len(f.staged), f.registration.calls) == before


def test_unknown_callback_does_not_turn_status_into_credential_saved_claim(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        assert f.callback(browser, "invented-unknown-state").status_code == 303
        status_json(browser.get("/connections/gmail/status"), (0, 0, 0, 0, 0, 0))
        assert f.loads == 0 and not f.requests


def test_provider_denied_status_counts_denial_without_secret_read(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        state = f.begin(browser)
        assert (
            browser.get(
                "/connections/gmail/callback?"
                + urlencode({"state": state, "error": "access_denied"})
            ).status_code
            == 303
        )
        status_json(browser.get("/connections/gmail/status"), (0, 0, 0, 1, 0, 0))
        assert f.loads == 0 and not f.requests


def test_status_inspection_cannot_write_renew_or_call_registration(tmp_path, monkeypatch):
    from datetime import timedelta

    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        f.begin(browser)
        before = {p: p.read_bytes() for p in f.directory.rglob("*") if p.is_file()}
        monkeypatch.setattr(f.clock, "_read", lambda: NOW + timedelta(minutes=1))

        def forbidden(*args, **kwargs):
            raise AssertionError("Read-only status cannot mutate or access a provider")

        for name in ("_now", "_write", "_persist", "initialize", "begin", "consume_callback"):
            monkeypatch.setattr(OAuthTransactionAuthority, name, forbidden)
        monkeypatch.setattr(f.registration, "attest", forbidden)
        monkeypatch.setattr(f.registration, "generation", forbidden)
        monkeypatch.setattr(f.controller, "_loader", forbidden)
        status_json(browser.get("/connections/gmail/status"), (1, 0, 0, 0, 0, 0))
        assert {p: p.read_bytes() for p in before} == before
        assert f.loads == 0 and not f.requests and not f.staged


@pytest.mark.parametrize("change", ["logged_out", "cookie", "revoked", "owner", "expired"])
def test_status_requires_current_saved_owner_without_reading_ledger(tmp_path, monkeypatch, change):
    from datetime import timedelta

    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)
        if change == "logged_out":
            browser.cookies.clear()
        elif change == "cookie":
            browser.cookies.clear()
            browser.cookies.set("__Host-zac-session", "x" * 43)
        elif change == "revoked":
            f.prepared.sessions.revoke(cookie)
        elif change == "owner":
            f.prepared.revoke_owner()
        else:
            monkeypatch.setattr(f.clock, "_read", lambda: NOW + timedelta(days=1))
        reads = []
        original = f.authority._read
        monkeypatch.setattr(f.authority, "_read", lambda: (reads.append(True), original())[1])
        response = browser.get("/connections/gmail/status")
        assert response.status_code >= 400
        safe(response)
        assert not reads and f.loads == 0 and not f.requests


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "POST"},
        {"scheme": "http"},
        {"path": "/connections/gmail"},
        {"query_string": b"state=private"},
        {"headers": [(b"host", b"evil.example")]},
        {"headers": [(b"host", urlsplit(ORIGIN).netloc.encode())] * 2},
    ],
)
def test_status_rejects_malformed_direct_request_before_ledger(tmp_path, monkeypatch, changes):
    from zacai.interfaces.gmail_connection_web import GmailConnectionError

    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)
    reads = []
    monkeypatch.setattr(f.authority, "_read", lambda: reads.append(True))
    with pytest.raises(GmailConnectionError):
        f.controller.status(status_request(cookie, **changes))
    assert not reads and f.loads == 0 and not f.requests


def test_status_halted_guard_cannot_disclose_local_counts(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        f.begin(browser)
        f.guard.halts = 1
        reads = []
        monkeypatch.setattr(f.authority, "_read", lambda: reads.append(True))
        response = browser.get("/connections/gmail/status")
        assert response.status_code >= 400
        safe(response)
        assert not reads


@pytest.mark.parametrize("field", ["_authority", "_configuration", "_guard", "_status_inspector"])
def test_status_original_dependency_replacement_denies_before_callbacks(
    tmp_path, monkeypatch, field
):
    from zacai.interfaces.gmail_connection_web import GmailConnectionError

    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)
    called = []
    monkeypatch.setattr(f.guard, "ready", lambda: called.append("guard"))
    monkeypatch.setattr(f.authority, "_read", lambda: called.append("ledger"))
    monkeypatch.setattr(f.controller, field, object())
    with pytest.raises(GmailConnectionError):
        f.controller.status(status_request(cookie))
    assert not called


@pytest.mark.parametrize("exception", [RuntimeError, KeyboardInterrupt])
def test_status_private_ledger_errors_and_cancellation_are_sanitized(
    tmp_path, monkeypatch, exception
):
    from zacai.interfaces.gmail_connection_web import GmailConnectionCancelled, GmailConnectionError

    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)

    def fail():
        raise exception(SECRET + REFRESH + cookie)

    monkeypatch.setattr(f.authority, "_read", fail)
    expected = GmailConnectionError if exception is RuntimeError else GmailConnectionCancelled
    with pytest.raises(expected) as raised:
        f.controller.status(status_request(cookie))
    assert all(p not in str(raised.value) + repr(raised.value) for p in (SECRET, REFRESH, cookie))
    assert raised.value.__cause__ is None and raised.value.__context__ is None


@pytest.mark.parametrize("change", ["revoke", "ledger", "dependency"])
def test_status_final_readiness_callback_cannot_publish_stale_counts(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        cookie = sign_in(browser)
        f.begin(browser)
        calls = []

        def ready():
            calls.append(True)
            if len(calls) == 2:
                if change == "revoke":
                    f.prepared.sessions.revoke(cookie)
                elif change == "ledger":
                    with f.authority._locked():
                        value = f.authority._read()
                        value["rows"].clear()
                        f.authority._write(value)
                else:
                    f.controller._authority = object()

        monkeypatch.setattr(f.guard, "ready", ready)
        response = browser.get("/connections/gmail/status")
        assert response.status_code >= 400
        safe(response)
        assert len(calls) == 2
        assert f.loads == 0 and not f.requests


@pytest.mark.parametrize(
    "scopes",
    [
        (BoundaryScope(B.PERSONAL, SCOPE.classifications),),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    ],
)
def test_status_current_owner_needs_brainstorm_highly_restricted_scope(tmp_path, scopes):
    f = Fixture(tmp_path, scopes=scopes)
    with f.browser() as browser:
        sign_in(browser)
        response = browser.get("/connections/gmail/status")
        assert response.status_code >= 400
        safe(response)
        assert f.registration.calls == f.loads == 0 and not f.requests
