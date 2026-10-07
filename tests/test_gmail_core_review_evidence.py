"""Actual ASGI/SQLite/lifecycle; invented grants and mocked canonical proofs.

No listener, real Google, Keychain, SQL, model or permission readiness evidence.
"""

import pytest
from fastapi.testclient import TestClient

from tests import test_named_owner_host as named_tests
from tests.test_gmail_connection_web import SCOPE, Fixture
from tests.test_named_owner_host import setup as setup  # noqa: PLC0414 - pytest fixture.
from tests.test_private_host import CONFIG, ORIGIN, InventedIdentity, enroll
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_connection_web import GmailConnectionWeb
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_host import prepare_owner_host
from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress


def combined_factory(f, calls):
    def factory(inputs):
        calls.append(inputs)
        continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        authority = OAuthTransactionAuthority(
            inputs.directory / "combined-gmail",
            key=inputs.session_key,
            continuity=continuity,
            registration_backend=f.registration,
        )
        authority.initialize()
        return GmailConnectionWeb(
            configuration=f.configuration,
            authority=authority,
            client_secret_loader=f.load,
            transport=f.transport,
            stage_checked=f.stage,
            host_guard=f.guard,
            stop_host=f.stop,
        )

    return factory


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "wrong", "foreign_peer", "duplicate_host"]
)
def test_ingress_rejects_before_actual_gmail_request_scope(tmp_path, fault):
    f = Fixture(tmp_path)
    token = f.prepared.sessions.start_user(f.prepared.owners.load().identity, f.clock())
    headers = [("cookie", "__Host-zac-session=" + token), ("x-forwarded-proto", "https")]
    peer = ("127.0.0.1", 1234)
    if fault == "missing":
        headers.pop()
    elif fault == "duplicate":
        headers.append(("x-forwarded-proto", "https"))
    elif fault == "wrong":
        headers[-1] = ("x-forwarded-proto", "http")
    elif fault == "foreign_peer":
        peer = ("100.64.1.1", 1234)
    else:
        headers.extend([("host", "caz.example.test"), ("Host", "caz.example.test")])
    scoped = []
    original = f.authority._scope

    def observed(*args, **kwargs):
        scoped.append(True)
        return original(*args, **kwargs)

    f.authority._scope = observed
    app = TrustedLoopbackHttpsIngress(f.prepared.app, origin=ORIGIN)
    with TestClient(app, base_url=ORIGIN.replace("https:", "http:"), client=peer) as browser:
        response = browser.get("/connections/gmail", headers=headers)
    assert response.status_code == 403
    assert response.headers["referrer-policy"] == "no-referrer"
    assert scoped == [] and f.registration.calls == f.loads == 0 and not f.requests


def test_gmail_and_named_share_graph_and_leave_other_response_headers_unchanged(setup, tmp_path):
    args, named_factory, named_calls = setup
    (tmp_path / "gmail-seed").mkdir(mode=0o700)
    f = Fixture(tmp_path / "gmail-seed")
    # Synthetic CONF+HR owner, not the current enrollment command's grant.
    directory = tmp_path / "combined-owner"
    enroll(directory, args["clock"], scopes=(SCOPE,))
    args = {**args, "directory": directory}
    gmail_calls = []
    host = prepare_owner_host(
        **args,
        named_factory=named_factory,
        gmail_factory=combined_factory(f, gmail_calls),
    )
    ni, gi = named_calls[-1], gmail_calls[-1]
    assert ni.directory == gi.directory == directory
    assert ni.owner is gi.owner and ni.owners is gi.owners is host.owners
    assert ni.sessions is gi.sessions is host.sessions
    assert ni.clock is gi.clock is args["clock"]
    assert ni.session_key == gi.session_key == CONFIG.session_key
    token = host.sessions.start_user(host.owners.load().identity, args["clock"]())
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        browser.cookies.set("__Host-zac-session", token)
        for path, status in [("/", 200), ("/ask-caz-locally", 200), ("/work-choice", 404)]:
            reply = browser.get(path)
            assert reply.status_code == status
            assert reply.headers["referrer-policy"] == "same-origin"
            assert reply.headers["cache-control"] == "no-store"
            assert "form-action 'self';" in reply.headers["content-security-policy"]
            assert "https://accounts.google.com" not in reply.headers["content-security-policy"]
        consent = browser.get("/connections/gmail")
        assert consent.status_code == 200
        assert (
            "form-action 'self' https://accounts.google.com;"
            in consent.headers["content-security-policy"]
        )
        assert not host.named.workers._closed
    assert host.named.workers._closed
    assert f.loads == 0 and not f.requests and not f.staged


@pytest.mark.parametrize("drive_lifespan", [True, False])
def test_gmail_mount_preserves_actual_named_thread_drain(
    setup, tmp_path, monkeypatch, drive_lifespan
):
    (tmp_path / "gmail-seed").mkdir(mode=0o700)
    f = Fixture(tmp_path / "gmail-seed")
    calls = []
    actual = named_tests.open_private_operator

    def with_gmail(**kwargs):
        return actual(**kwargs, gmail_factory=combined_factory(f, calls))

    monkeypatch.setattr(named_tests, "open_private_operator", with_gmail)
    named_tests.test_actual_worker_drain_keeps_logging_and_foreground_lease_until_done(
        setup,
        drive_lifespan,
    )
    assert len(calls) == 1
    assert f.loads == 0 and not f.requests and not f.staged


def test_mounted_work_choice_headers_do_not_inherit_gmail_consent_policy(tmp_path, monkeypatch):
    from zacai.interfaces.private_web import create_private_web
    from zacai.interfaces.work_choice_web import WorkChoiceWeb

    f = Fixture(tmp_path)
    # Header-only controller shape, deliberately not a canonical capture proof.
    choice = object.__new__(WorkChoiceWeb)
    monkeypatch.setattr(choice, "issue", lambda principal: "invented-header-only-handle")
    monkeypatch.setattr(choice, "render", lambda **kwargs: "<p>Invented header-only preference</p>")

    async def view(principal):
        return "<main>Invented owner view</main>"

    app = create_private_web(
        origin=ORIGIN,
        identities=InventedIdentity(f.clock),
        sessions=f.inputs.sessions,
        owner=f.inputs.owner,
        clock=f.clock,
        view=view,
        work_choices=choice,
        gmail_connections=f.controller,
    )
    token = f.inputs.sessions.start_user(f.inputs.owner().identity, f.clock())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
        browser.cookies.set("__Host-zac-session", token)
        response = browser.get("/work-choice")
        assert response.status_code == 200
        assert response.headers["referrer-policy"] == "same-origin"
        assert "form-action 'self';" in response.headers["content-security-policy"]
        assert "https://accounts.google.com" not in response.headers["content-security-policy"]
        assert browser.get("/connections/gmail").status_code == 200
    assert f.loads == 0 and not f.requests and not f.staged
