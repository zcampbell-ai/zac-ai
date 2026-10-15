"""Actual original foreground context and ASGI HTTPS, not live TLS termination."""

import fcntl
import os
import threading
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.responses import RedirectResponse, Response

from toy_owner_fixture import Connection
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import OAuthTransactionError
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_host import PrivateHostError, prepare_owner_host
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.private_web import _HEADERS, _SecurityHeaders, create_private_web
from zacai.interfaces.session_store import Identity
from zacai.interfaces.slack_connect_host import open_slack_connect_host

ORIGIN = "https://invented.example"
STATE = "a" * 32
OWNER = Identity(GOOGLE_ISSUER, "invented-owner")


class Inputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.values = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        value = dict(attrs)
        if tag == "input" and "name" in value:
            self.values[value["name"]] = value.get("value", "")


class ToyIdentity:
    async def begin(self, request, redirect_uri):
        request.session["zac_nonce"] = "n" * 32
        request.session["_state_google_" + STATE] = {
            "exp": datetime(2026, 10, 13, tzinfo=UTC).timestamp() + 300,
            "data": {"nonce": "n" * 32, "code_verifier": "v" * 43, "redirect_uri": redirect_uri},
        }
        return RedirectResponse("https://accounts.google.com/invented")

    async def finish(self, request):
        assert request.session["zac_nonce"] == "n" * 32
        assert request.query_params["state"] == STATE
        return OWNER


class RamSlack:
    def __init__(self, config):
        self.net = self.delay = 0.0
        self.failure = self.close_failure = self.revoke_after = None
        self.close_at = 0
        self.chunk_mode = None
        self.paths = []
        self.connections = []
        self.header_scope = ",".join(sorted(config.scopes))
        self.exchange = {
            "ok": True,
            "app_id": config.registration_id,
            "team": {"id": config.slack_team_id},
            "authed_user": {
                "id": "U123456789",
                "scope": self.header_scope,
                "token_type": "user",
                "access_token": "invented-access",
                "refresh_token": "invented-refresh",
                "expires_in": 43200,
            },
            "enterprise": None,
            "is_enterprise_install": False,
        }
        self.identity = {
            "ok": True,
            "team_id": config.slack_team_id,
            "user_id": "U123456789",
            "url": "https://invented.slack.com/",
            "team": "invented",
            "user": "invented",
        }

    def connect(self, host):
        assert host == "slack.com"
        connection = Connection(self, len(self.connections))
        self.connections.append(connection)
        return connection


def inputs(tmp_path):
    now = datetime(2026, 10, 13, tzinfo=UTC)
    clock = HostObservedClock(lambda: now)
    config = OwnerStartupConfiguration(
        "123-invented.apps.googleusercontent.com", ORIGIN, "invented-secret", os.urandom(32)
    )
    slack = OAuthConfiguration(
        provider="slack",
        registration_id="A123456789",
        client_id="123456789.987654321",
        private_origin=ORIGIN,
        slack_team_id="T123456789",
    )
    directory = tmp_path / "operator"
    values = {
        "client_id": config.client_id,
        "origin": ORIGIN,
        "directory": directory,
        "escrow_confirmed_by_operator": True,
        "clock": clock,
        "startup_loader": lambda **_: config,
        "identities": ToyIdentity(),
    }
    return now, config, slack, values


def enroll(values):
    with open_private_operator(
        mode=PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:

        def browser(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.post("/enroll", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/enroll/callback?code=toy&state=" + STATE).status_code == 200

        window.serve(server=browser)
        pending = window.pending_owner()
        grant = window.confirm_owner(
            pairing_code=pending.pairing_code,
            expected_identity=OWNER,
            confirmation="CONFIRM BRAINSTORM / HIGHLY_RESTRICTED",
        )
        assert grant.identity == OWNER


@pytest.mark.parametrize("failure", [False, True])
def test_actual_foreground_slack_owner_flow(tmp_path, monkeypatch, failure):
    now, _config, slack, values = inputs(tmp_path)
    enroll(values)
    ram = RamSlack(slack)
    if failure:
        ram.identity["user_id"] = "U999999999"
    with open_slack_connect_host(
        **values,
        initialize_new_guard=True,
        configuration=slack,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=lambda _: SecretStr("invented-slack-secret"),
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    ) as host:

        def browser(app):
            fd = os.open(values["directory"] / "private-mode.lock", os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.get("/connections/slack").status_code == 403
                assert client.post("/login", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303
                page = client.get("/connections/slack")
                assert page.status_code == 200
                assert (
                    "form-action 'self' https://slack.com;"
                    in page.headers["content-security-policy"]
                )
                assert page.headers["referrer-policy"] == "same-origin"
                form = Inputs(page.text).values
                bad = dict(form, csrf="wrong")
                assert (
                    client.post(
                        "/connections/slack/begin", data=bad, headers={"Origin": ORIGIN}
                    ).status_code
                    == 403
                )
                assert ram.paths == []
                response = client.post(
                    "/connections/slack/begin", data=form, headers={"Origin": ORIGIN}
                )
                assert response.status_code == 303
                assert response.headers["referrer-policy"] == "no-referrer"
                assert (
                    response.headers["content-security-policy"]
                    == _HEADERS["Content-Security-Policy"]
                )
                assert (
                    client.post(
                        "/connections/slack/begin",
                        data=form,
                        headers={"Origin": "https://foreign.example"},
                    ).status_code
                    == 403
                )
                assert (
                    client.post(
                        "/connections/slack/begin", data=form, headers={"Origin": ORIGIN}
                    ).status_code
                    == 409
                )
                state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
                response = client.get(
                    "/connections/slack/callback?" + urlencode({"state": state, "code": "toy"})
                )
                assert response.status_code == (403 if failure else 200)
                assert response.headers["referrer-policy"] == "no-referrer"
                assert (
                    response.headers["content-security-policy"]
                    == _HEADERS["Content-Security-Policy"]
                )
                assert "invented-access" not in response.text
                assert ram.paths == ["/api/oauth.v2.access", "/api/auth.test"]
                if not failure:
                    assert "not saved or installed" in response.text

        if failure:
            import uvicorn

            # Actual Server/Config and stop handle; replace only listener execution.
            monkeypatch.setattr(uvicorn.Server, "run", lambda actual: browser(actual.config.app))
            host.serve()
            assert type(host._server) is uvicorn.Server and host._server.should_exit
            assert host._server.config.proxy_headers is False
            assert host._server.config.forwarded_allow_ips == ""
        else:
            host.serve(server=browser)
        assert set(threading.enumerate()) == {threading.main_thread()}
        operation = host._controller._admission._operation
        with operation._authority._locked():
            assert operation._authority._read()["rows"][operation._state_hash]["state"] == "held"
        with pytest.raises(OAuthTransactionError):
            operation.current()
        assert all(c.closed for c in ram.connections)


@pytest.mark.parametrize(
    "enabled,method,path,status,allowed",
    [
        (True, "GET", "/connections/slack", 200, True),
        (False, "GET", "/connections/slack", 200, False),
        (True, "POST", "/connections/slack", 200, False),
        (True, "GET", "/connections/slack?x=1", 200, False),
        (True, "GET", "/connections/slack", 403, False),
        (True, "GET", "/connections/slack/begin", 200, False),
        (True, "GET", "/connections/slack/callback?code=toy", 200, False),
        (True, "GET", "/protected", 200, False),
    ],
)
def test_security_headers_exact_boundary(enabled, method, path, status, allowed):
    app = FastAPI()
    app.add_middleware(_SecurityHeaders, slack_consent_enabled=enabled)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    def respond(path):
        return Response(
            "toy",
            status_code=status,
            headers={"Content-Security-Policy": "unsafe", "Referrer-Policy": "unsafe"},
        )

    with TestClient(app, base_url=ORIGIN) as client:
        response = client.request(method, path)
    expected = _HEADERS["Content-Security-Policy"]
    if allowed:
        expected = expected.replace("form-action 'self';", "form-action 'self' https://slack.com;")
    assert response.headers["content-security-policy"] == expected
    assert response.headers["referrer-policy"] == (
        "same-origin"
        if allowed or not enabled or not path.startswith("/connections/slack")
        else "no-referrer"
    )


@pytest.mark.parametrize("flag", [1, None, "yes"])
def test_operator_flag_denial_before_loader(tmp_path, flag):
    _, _, _, values = inputs(tmp_path)

    def denied(**kwargs):
        pytest.fail("startup reached")

    values["startup_loader"] = denied
    with (
        pytest.raises(PrivateOperatorError),
        open_private_operator(
            mode=PrivateOperatorMode.OWNER,
            view=lambda _: None,
            slack_consent_enabled=flag,
            **values,
        ),
    ):
        pytest.fail("window exposed")
    assert not values["directory"].exists()


def test_http_scheme_denies_original_owner_action(tmp_path):
    now, _, slack, values = inputs(tmp_path)
    enroll(values)
    ram = RamSlack(slack)
    with open_slack_connect_host(
        **values,
        initialize_new_guard=True,
        configuration=slack,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=lambda _: SecretStr("toy"),
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    ) as host:

        def browser(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.post("/login", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303
                cookie = client.cookies.get("__Host-zac-session")
            with TestClient(app, base_url="http://invented.example") as client:
                response = client.get(
                    "/connections/slack", headers={"Cookie": "__Host-zac-session=" + cookie}
                )
                assert response.status_code == 403
            assert not host._controller._spent and ram.paths == []

        host.serve(server=browser)


@pytest.mark.parametrize("family", ["gmail", "recovery", "email", "named"])
@pytest.mark.parametrize("port", ["operator", "host", "web"])
def test_mixed_family_denies_before_owner_or_startup(tmp_path, monkeypatch, family, port):
    _, config, _, values = inputs(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("owner/startup/session effect reached")

    kwargs = {"slack_consent_enabled": True}
    if port == "web":
        key = {
            "gmail": "gmail_connections",
            "email": "email_workflow",
            "named": "named_questions",
            "recovery": "gmail_recovery_consent_enabled",
        }[family]
        kwargs[key] = True if family == "recovery" else object()
        with pytest.raises(ValueError, match="exclusive Slack"):
            create_private_web(
                origin=ORIGIN,
                identities=ToyIdentity(),
                sessions=object(),
                owner=forbidden,
                view=forbidden,
                clock=values["clock"],
                **kwargs,
            )
    else:
        key = {
            "gmail": "gmail_factory",
            "email": "email_factory",
            "named": "named_factory",
            "recovery": "gmail_recovery_consent_enabled",
        }[family]
        kwargs[key] = True if family == "recovery" else forbidden
        if port == "operator":
            values["startup_loader"] = forbidden
            with (
                pytest.raises(PrivateOperatorError),
                open_private_operator(
                    mode=PrivateOperatorMode.OWNER, view=forbidden, **values, **kwargs
                ),
            ):
                pytest.fail("window exposed")
        else:
            from zacai.interfaces.owner_store import OwnerGrantStore

            monkeypatch.setattr(OwnerGrantStore, "load", forbidden)
            with pytest.raises(PrivateHostError):
                prepare_owner_host(
                    configuration=config,
                    directory=values["directory"],
                    view=forbidden,
                    clock=values["clock"],
                    **kwargs,
                )
    assert not values["directory"].exists()


def test_default_genuine_owner_slack_routes_disabled(tmp_path):
    _, _, _, values = inputs(tmp_path)
    enroll(values)

    async def view(principal):
        return "toy protected view"

    with open_private_operator(mode=PrivateOperatorMode.OWNER, view=view, **values) as window:

        def browser(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.post("/login", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303
                for path in ["/connections/slack", "/connections/slack/callback"]:
                    response = client.get(path)
                    assert response.status_code == 404
                    assert (
                        response.headers["content-security-policy"]
                        == _HEADERS["Content-Security-Policy"]
                    )
                assert (
                    client.post("/connections/slack/begin", headers={"Origin": ORIGIN}).status_code
                    == 404
                )

        window.serve(server=browser)
