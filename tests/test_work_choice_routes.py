"""ASGI and invented canonical recovery only: no listener/provider/SQL/live capture."""
# ruff: noqa: F401, F811 - imported pytest fixtures registered by module globals

import re
import threading
from urllib.parse import urlencode

import pytest
from starlette.testclient import TestClient

from tests.test_private_web import ORIGIN, InventedProvider, sign_in, web
from tests.test_work_choice_capture import fixture as capture_fixture
from tests.test_work_choice_web import prepared as controller_fixture
from zacai.interfaces.private_web import OwnerGrant, create_private_web
from zacai.interfaces.session_store import Identity, InMemorySessionStore


@pytest.fixture
def choice_http(controller_fixture):
    state, controller, _principal = controller_fixture
    sessions = InMemorySessionStore()

    async def view(found):
        return "<html><main>Invented review</main></html>"

    app = create_private_web(
        origin=ORIGIN,
        identities=InventedProvider(state.owner.identity),
        sessions=sessions,
        owner=lambda: state.owner,
        view=view,
        clock=lambda: state.now,
        work_choices=controller,
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        yield state, controller, sessions, client


def form(client):
    response = client.get("/work-choice")
    assert response.status_code == 200
    assert "<title>Caz AI · Work preference</title>" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "form-action 'self';" in response.headers["content-security-policy"]
    assert "accounts.google.com" not in response.headers["content-security-policy"]
    return {
        "handle": re.search(r'name="handle" value="([^"]+)"', response.text)[1],
        "csrf": re.search(r'name="csrf" value="([^"]+)"', response.text)[1],
        "choice": "Approve as proposed",
        "changes": "",
    }


def post(client, fields, **kwargs):
    return client.post(
        "/work-choice",
        content=urlencode(fields),
        headers={
            "origin": ORIGIN,
            "content-type": "application/x-www-form-urlencoded",
        },
        **kwargs,
    )


def test_disabled_default_has_no_preference_routes_or_home_link(web):
    client = web[0]
    sign_in(client)
    assert client.get("/work-choice").status_code == 404
    assert client.post("/work-choice").status_code == 404
    assert "/work-choice" not in client.get("/").text


def test_authenticated_exact_selection_form_and_real_capture_ack(choice_http):
    state, _controller, _, client = choice_http
    assert client.get("/work-choice").headers["location"] == "/login"
    assert post(client, {}).status_code == 401
    sign_in(client)
    assert '<a href="/work-choice">' in client.get("/").text
    selected = form(client)
    assert state.proposal.outcome in client.get("/work-choice").text
    response = post(client, selected)
    assert response.status_code == 200 and "Preference saved" in response.text
    assert "No work was executed" in response.text
    assert state.puts == 1 and state.rechecks == 1
    assert response.headers["cache-control"] == "no-store"
    again = post(client, selected)
    assert again.status_code == 200 and state.puts == 1
    # Distinct page visits remain the exact same canonical choice identity.
    assert post(client, form(client)).status_code == 200 and state.puts == 1


@pytest.mark.parametrize(
    "fault",
    [
        "origin",
        "null_origin",
        "duplicate_origin",
        "host",
        "cookie",
        "duplicate_cookie",
        "csrf",
        "unknown",
        "duplicate",
        "duplicate_type",
        "bad_type",
        "body",
        "utf8",
        "percent_utf8",
        "percent_escape",
        "query",
    ],
)
def test_bad_requests_never_capture_or_claim_saved(choice_http, fault):
    state, _, _, client = choice_http
    sign_in(client)
    selected = form(client)
    headers = [("origin", ORIGIN), ("content-type", "application/x-www-form-urlencoded")]
    body = urlencode(selected).encode()
    path = "/work-choice"
    if fault == "origin":
        headers[0] = ("origin", "https://wrong.example.test")
    elif fault == "null_origin":
        headers[0] = ("origin", "null")
    elif fault == "duplicate_origin":
        headers.append(("origin", ORIGIN))
    elif fault == "host":
        headers.append(("host", "wrong.example.test"))
    elif fault == "cookie":
        client.cookies.clear()
    elif fault == "duplicate_cookie":
        token = client.cookies.get("__Host-zac-session")
        headers.append(("cookie", f"__Host-zac-session={token}; __Host-zac-session={token}"))
    elif fault == "csrf":
        body = urlencode({**selected, "csrf": "wrong"}).encode()
    elif fault == "unknown":
        body += b"&receipt=untrusted"
    elif fault == "duplicate":
        body += b"&choice=Approve+as+proposed"
    elif fault == "duplicate_type":
        headers.append(("content-type", "application/x-www-form-urlencoded"))
    elif fault == "bad_type":
        headers[1] = ("content-type", "text/plain")
    elif fault == "body":
        body = b"x" * 8193
    elif fault == "utf8":
        body = b"\xff"
    elif fault == "percent_utf8":
        body += b"&changes=%FF"
    elif fault == "percent_escape":
        body += b"&changes=%GG"
    else:
        path += "?receipt=untrusted"
    response = client.post(path, content=body, headers=headers)
    expected = 401 if fault in ("cookie", "duplicate_cookie") else 413 if fault == "body" else 403
    assert response.status_code == expected
    assert "saved" not in response.text.lower() and not state.sources


def test_invalid_owner_and_session_changes_after_capture_withhold_ack(choice_http):
    state, controller, sessions, client = choice_http
    sign_in(client)
    selected = form(client)
    token = client.cookies.get("__Host-zac-session")
    original = controller.submit

    def completed(**kwargs):
        result = original(**kwargs)
        sessions.revoke(token)
        return result

    controller.submit = completed
    response = post(client, selected)
    assert response.status_code == 403 and "saved" not in response.text.lower()
    assert state.puts == 1  # Canonical row exists, but stale caller gets no acknowledgement.


def test_owner_change_before_submit_denies_capture(choice_http):
    state, _, _, client = choice_http
    sign_in(client)
    selected = form(client)
    state.owner = OwnerGrant(
        Identity(state.owner.identity.issuer, "different-owner"), state.owner.scopes
    )
    assert post(client, selected).status_code == 401
    assert not state.sources


def test_unprotected_capture_failure_never_acknowledges_saved(choice_http):
    state, _, _, client = choice_http
    sign_in(client)
    selected = form(client)
    state.fail_protect = True
    response = post(client, selected)
    assert response.status_code == 503 and "saved" not in response.text.lower()
    assert len(state.sources) == 1
    state.fail_protect = False
    assert post(client, selected).status_code == 200 and state.puts == 1


def test_blocking_capture_runs_off_event_loop_without_moving_sql_sessions(choice_http, monkeypatch):
    state, _controller, _, client = choice_http
    sign_in(client)
    selected = form(client)
    from zacai.interfaces import private_web

    seen = []
    original_runner = private_web.run_in_threadpool
    original_capture = state.client.capture

    async def runner(function, *args, **kwargs):
        seen.append(("loop", threading.get_ident()))
        return await original_runner(function, *args, **kwargs)

    def capture(**kwargs):
        seen.append(("capture", threading.get_ident()))
        return original_capture(**kwargs)

    monkeypatch.setattr(private_web, "run_in_threadpool", runner)
    monkeypatch.setattr(state.client, "capture", capture)
    assert post(client, selected).status_code == 200
    assert len(seen) == 2 and seen[0][1] != seen[1][1]


def test_trusted_host_passes_optional_controller_without_source_inference(
    controller_fixture, tmp_path, monkeypatch
):
    from tests.test_private_host import CONFIG, NOW, InventedIdentity, enroll
    from zacai.interfaces import private_host
    from zacai.interfaces.private_host import prepare_owner_host

    state, controller, _ = controller_fixture
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)
    received = []
    real = private_host.create_private_web

    def checked(**kwargs):
        received.append(kwargs["work_choices"])
        return real(**kwargs)

    monkeypatch.setattr(private_host, "create_private_web", checked)

    async def view(principal):
        return "<main>Invented host review</main>"

    host = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(lambda: NOW),
        clock=lambda: NOW,
        work_choices=controller,
    )
    assert received == [controller]
    assert any(route.path == "/work-choice" for route in host.app.routes)
    assert not state.sources


def test_factory_rejects_duck_controller_before_host_owner_callback():
    calls = []

    async def view(principal):
        return "<main>invented</main>"

    def owner():
        calls.append(True)
        raise AssertionError("must reject controller first")

    with pytest.raises(ValueError, match="private work choice configuration unavailable"):
        create_private_web(
            origin=ORIGIN,
            identities=InventedProvider(),
            sessions=InMemorySessionStore(),
            owner=owner,
            view=view,
            work_choices=object(),
        )
    assert not calls


def test_conflicting_choice_has_safe_reconciliation_message_without_state_disclosure(choice_http):
    state, _, _, client = choice_http
    sign_in(client)
    first = form(client)
    assert post(client, first).status_code == 200
    response = post(client, {**form(client), "choice": "I'll do it myself"})
    assert response.status_code == 503
    assert response.text == "Preference not acknowledged. Retry or request a review."
    assert "saved" not in response.text.lower()
    assert state.puts == 1 and len(state.sources) == 1


def test_129_authenticated_page_refreshes_reuse_unexpired_exact_form(choice_http):
    state, controller, _, client = choice_http
    sign_in(client)
    handles = {form(client)["handle"] for _ in range(129)}
    assert len(handles) == 1 and len(controller._handles) == 1
    assert not state.sources


def test_choice_route_query_fields_are_rejected_before_form_or_capture(choice_http):
    state, controller, _, client = choice_http
    sign_in(client)
    assert client.get("/work-choice?handle=untrusted").status_code == 400
    assert not controller._handles
    assert (
        client.post(
            "/work-choice?plan=untrusted", content="", headers={"origin": ORIGIN}
        ).status_code
        == 403
    )
    assert not state.sources
