from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress
from zacai.interfaces.private_server_lifecycle import _make_server

ORIGIN = "https://private.example.test"


def application() -> tuple[TrustedLoopbackHttpsIngress, list[object]]:
    app = FastAPI()
    calls: list[object] = []

    @app.get("/check")
    async def check(request: Request) -> dict[str, object]:
        calls.append(object())
        return {
            "scheme": request.url.scheme,
            "host": request.headers.get("host"),
            "forwarded": request.headers.get("x-forwarded-proto"),
            "claimed_host": request.headers.get("x-forwarded-host"),
            "peer": request.client.host,
        }

    return TrustedLoopbackHttpsIngress(app, origin=ORIGIN), calls


def test_verified_loopback_proxy_normalizes_https_and_discards_hints() -> None:
    app, calls = application()
    with TestClient(
        app, base_url="http://private.example.test", client=("127.0.0.1", 1234)
    ) as client:
        result = client.get(
            "/check",
            headers={
                "x-forwarded-proto": "https",
                "x-forwarded-host": "untrusted.example.test",
                "x-forwarded-for": "untrusted-peer",
            },
        )
    assert result.status_code == 200
    assert result.json() == {
        "scheme": "https",
        "host": "private.example.test",
        "forwarded": None,
        "claimed_host": None,
        "peer": "127.0.0.1",
    }
    assert len(calls) == 1


@pytest.mark.parametrize(
    "variant",
    [
        "missing_proto",
        "wrong_proto",
        "duplicate_proto",
        "foreign_host",
        "duplicate_host",
        "foreign_peer",
        "already_https",
        "proto_list",
    ],
)
def test_wrong_ingress_denies_before_owner_app(variant: str) -> None:
    app, calls = application()
    headers = [("x-forwarded-proto", "https")]
    base = "http://private.example.test"
    peer = ("127.0.0.1", 1234)
    if variant == "missing_proto":
        headers = []
    elif variant == "wrong_proto":
        headers = [("x-forwarded-proto", "http")]
    elif variant == "duplicate_proto":
        headers.append(("x-forwarded-proto", "https"))
    elif variant == "foreign_host":
        headers.append(("host", "foreign.example.test"))
    elif variant == "duplicate_host":
        headers.extend([("host", "private.example.test"), ("Host", "private.example.test")])
    elif variant == "foreign_peer":
        peer = ("100.64.1.1", 1234)
    elif variant == "already_https":
        base = ORIGIN
    else:
        headers = [("x-forwarded-proto", "https,http")]
    with TestClient(app, base_url=base, client=peer) as client:
        result = client.get("/check", headers=headers)
    assert result.status_code == 403
    assert calls == []
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["referrer-policy"] == "no-referrer"


@pytest.mark.parametrize(
    "origin",
    [
        "http://private.example.test",
        "https://private.example.test:443",
        "https://private.example.test/path",
        "https://Private.example.test",
        "https://private.example.test?query",
        "https://private.example.test#fragment",
    ],
)
def test_invalid_origin_denied(origin: str) -> None:
    with pytest.raises(ValueError, match="private HTTPS ingress unavailable"):
        TrustedLoopbackHttpsIngress(FastAPI(), origin=origin)


def test_actual_listener_wraps_only_explicit_verified_origin() -> None:
    app = FastAPI()
    direct = _make_server(app)
    selected = _make_server(app, verified_private_origin=ORIGIN)
    assert direct.config.app is app
    assert type(selected.config.app) is TrustedLoopbackHttpsIngress
    assert selected.config.app._app is app
    assert selected.config.app._host == b"private.example.test"
    assert selected.config.proxy_headers is False
    assert selected.config.forwarded_allow_ips == ""
    assert not selected.started


def test_actual_owner_gmail_flow_over_verified_local_http_proxy(tmp_path) -> None:
    from tests.test_gmail_connection_web import ORIGIN, Fixture

    fixture = Fixture(tmp_path)
    token = fixture.prepared.sessions.start_user(
        fixture.prepared.owners.load().identity, fixture.clock()
    )
    app = TrustedLoopbackHttpsIngress(fixture.prepared.app, origin=ORIGIN)
    local_origin = ORIGIN.replace("https://", "http://", 1)
    headers = {"x-forwarded-proto": "https", "cookie": "__Host-zac-session=" + token}
    with TestClient(
        app,
        base_url=local_origin,
        client=("127.0.0.1", 1234),
        headers=headers,
        follow_redirects=False,
    ) as browser:
        state = fixture.begin(browser)
        reply = fixture.callback(browser, state)
    assert reply.status_code == 303
    assert reply.headers["location"] == "/connections/gmail/status"
    assert fixture.loads == 1 and len(fixture.requests) == 3
    assert len(fixture.staged) == 1 and fixture.row()["state"] == "held"


def test_http_owner_gmail_without_selected_ingress_denies(tmp_path) -> None:
    from tests.test_gmail_connection_web import ORIGIN, Fixture

    fixture = Fixture(tmp_path)
    token = fixture.prepared.sessions.start_user(
        fixture.prepared.owners.load().identity, fixture.clock()
    )
    headers = {"x-forwarded-proto": "https", "cookie": "__Host-zac-session=" + token}
    with TestClient(
        fixture.prepared.app,
        base_url=ORIGIN.replace("https://", "http://", 1),
        client=("127.0.0.1", 1234),
        headers=headers,
    ) as browser:
        reply = browser.get("/connections/gmail")
    assert reply.status_code == 403
    assert fixture.loads == 0 and fixture.requests == []
