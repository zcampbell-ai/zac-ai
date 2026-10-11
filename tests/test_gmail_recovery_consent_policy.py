"""Invented mounted ASGI headers; no live browser/provider/native account access."""

from datetime import UTC, datetime
from urllib.parse import urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import HTMLResponse

from tests.test_private_web import ORIGIN, OWNER, SCOPE, InventedProvider
from zacai.interfaces.private_web import (
    OwnerGrant,
    _SecurityHeaders,
    create_private_web,
)
from zacai.interfaces.session_store import InMemorySessionStore

PATH = "/connections/gmail/recover"
GOOGLE = "https://accounts.google.com"


def target_allowed(policy, target):
    """Closed self/Google policy projection, not a browser execution claim."""
    sources = next(part.split()[1:] for part in policy.split(";") if part.strip().startswith("form-action "))
    return ("'self'" in sources and (urlsplit(target).scheme, urlsplit(target).netloc) == (urlsplit(ORIGIN).scheme, urlsplit(ORIGIN).netloc)) or GOOGLE in sources and target.startswith(GOOGLE + "/")


def mounted_app(enabled=False):
    async def view(principal):
        return "invented owner view"

    app = create_private_web(
        origin=ORIGIN,
        identities=InventedProvider(),
        sessions=InMemorySessionStore(),
        owner=lambda: OwnerGrant(OWNER, (SCOPE,)),
        view=view,
        clock=lambda: datetime(2026, 10, 11, tzinfo=UTC),
        gmail_recovery_consent_enabled=enabled,
    )

    async def response(request: Request):
        # Hostile route-supplied headers cannot expand the effective middleware policy.
        return HTMLResponse(
            "invented form",
            status_code=int(request.headers.get("x-invented-status", "200")),
            headers={"content-security-policy": "form-action *", "referrer-policy": "unsafe-url"},
        )

    for path in (PATH, PATH + "/begin", "/connections/gmail/callback", "/connections/gmail/status", "/unrelated"):
        app.add_api_route(path, response, methods=["GET", "POST"])
    return app


def test_disabled_default_recovery_document_rejects_google_target():
    with TestClient(mounted_app(), base_url=ORIGIN) as browser:
        reply = browser.get(PATH)
    assert reply.status_code == 200
    assert target_allowed(reply.headers["content-security-policy"], ORIGIN + PATH + "/begin")
    assert not target_allowed(reply.headers["content-security-policy"], GOOGLE + "/o/oauth2/v2/auth")


def test_enabled_exact_recovery_document_allows_only_fixed_google_and_same_origin():
    with TestClient(mounted_app(True), base_url=ORIGIN) as browser:
        reply = browser.get(PATH)
    assert target_allowed(reply.headers["content-security-policy"], GOOGLE + "/o/oauth2/v2/auth")
    assert not target_allowed(reply.headers["content-security-policy"], "https://foreign.invalid/authorize")
    assert reply.headers["referrer-policy"] == "same-origin"
    assert reply.headers["cache-control"] == "no-store"
    for directive in ("default-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"):
        assert directive in reply.headers["content-security-policy"]


@pytest.mark.parametrize("path,method,status", [
    (PATH, "POST", 200), (PATH, "GET", 403), (PATH, "GET", 303),
    (PATH + "?untrusted=1", "GET", 200), (PATH + "/begin", "GET", 200),
    ("/connections/gmail/callback", "GET", 200),
    ("/connections/gmail/status", "GET", 200), ("/unrelated", "GET", 200),
])
def test_other_effective_responses_cannot_inherit_google_form_permission(path, method, status):
    with TestClient(mounted_app(True), base_url=ORIGIN, follow_redirects=False) as browser:
        reply = browser.request(method, path, headers={"x-invented-status": str(status)})
    assert reply.status_code == status
    assert not target_allowed(reply.headers["content-security-policy"], GOOGLE + "/o/oauth2/v2/auth")
    assert reply.headers["referrer-policy"] == ("same-origin" if path == "/unrelated" else "no-referrer")


@pytest.mark.parametrize("ordinary", [False, True])
def test_both_middleware_compositions_keep_recovery_document_real_origin(ordinary):
    app = FastAPI()
    app.add_middleware(_SecurityHeaders, gmail_consent_enabled=ordinary, gmail_recovery_consent_enabled=True)

    @app.get(PATH)
    async def page():
        return HTMLResponse("invented form")

    with TestClient(app, base_url=ORIGIN) as browser:
        reply = browser.get(PATH)
    assert reply.headers["referrer-policy"] == "same-origin"
    assert target_allowed(reply.headers["content-security-policy"], GOOGLE + "/o/oauth2/v2/auth")


@pytest.mark.parametrize("invalid", [0, 1, None, "true"])
def test_factory_rejects_bool_like_policy(invalid):
    with pytest.raises(ValueError, match="closed recovery consent"):
        mounted_app(invalid)


def test_actual_captured_hr_recovery_listener_has_effective_google_policy(tmp_path, monkeypatch):
    from tests.test_gmail_recovery_host import Fixture
    from tests.test_private_host import sign_in

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    observed = []

    def browse(browser):
        sign_in(browser)
        page = browser.get(PATH)
        assert page.status_code == 200
        assert target_allowed(page.headers["content-security-policy"], GOOGLE + "/o/oauth2/v2/auth")
        assert page.headers["referrer-policy"] == "same-origin"
        assert plan._windows.hr._serving and not plan._windows.original._serving
        observed.append(True)

    f.browser_action = browse
    plan.run()
    assert observed == [True]
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


@pytest.mark.parametrize("invalid", [0, 1, None, "true"])
def test_operator_and_owner_factory_deny_bool_like_before_startup(tmp_path, invalid):
    from tests.test_private_host import CONFIG
    from zacai.interfaces.private_host import PrivateHostError, prepare_owner_host
    from zacai.interfaces.private_operator import (
        PrivateOperatorError,
        PrivateOperatorMode,
        open_private_operator,
    )

    calls = []

    async def view(principal):
        return "invented view"

    def forbidden_loader(**kwargs):
        calls.append(kwargs)
        raise AssertionError("startup must remain uncalled")

    with pytest.raises(PrivateHostError):
        prepare_owner_host(configuration=CONFIG, directory=tmp_path / "owner", view=view,
                           gmail_recovery_consent_enabled=invalid)
    with pytest.raises(PrivateOperatorError), open_private_operator(mode=PrivateOperatorMode.OWNER, client_id=CONFIG.client_id,
                                   origin=CONFIG.origin, directory=tmp_path / "owner",
                                   escrow_confirmed_by_operator=True, view=view,
                                   startup_loader=forbidden_loader,
                                   gmail_recovery_consent_enabled=invalid):
        pytest.fail("invalid policy produced owner context")
    assert calls == [] and not (tmp_path / "owner").exists()


def test_recovery_policy_never_enables_enrollment_startup(tmp_path):
    from tests.test_private_host import CONFIG
    from zacai.interfaces.private_operator import (
        PrivateOperatorError,
        PrivateOperatorMode,
        open_private_operator,
    )

    calls = []

    def forbidden_loader(**kwargs):
        calls.append(kwargs)
        raise AssertionError("startup must remain uncalled")

    with pytest.raises(PrivateOperatorError), open_private_operator(mode=PrivateOperatorMode.ENROLLMENT,
                                   client_id=CONFIG.client_id, origin=CONFIG.origin,
                                   directory=tmp_path / "enrollment",
                                   escrow_confirmed_by_operator=True,
                                   startup_loader=forbidden_loader,
                                   gmail_recovery_consent_enabled=True):
        pytest.fail("recovery policy enabled enrollment")
    assert calls == [] and not (tmp_path / "enrollment").exists()
