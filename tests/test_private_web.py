"""Unmounted app and invented identities only; no real OAuth/source access."""

import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant, create_private_web
from zacai.interfaces.session_store import Identity, InMemorySessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

ORIGIN = "https://zac.example.test"
OWNER = Identity(GOOGLE_ISSUER, "invented-owner")
SCOPE = BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL}))


class InventedProvider:
    # Shape fixture only; real cryptographic OIDC validation is separately tested.
    def __init__(self, identity=OWNER):
        self.identity = identity
        self.finishes = 0

    async def begin(self, request, redirect_uri):
        request.session["invented_transaction"] = "fixed-state"
        assert redirect_uri == ORIGIN + "/auth/callback"
        return RedirectResponse("https://accounts.google.com/invented")

    async def finish(self, request):
        self.finishes += 1
        assert request.query_params["state"] == request.session["invented_transaction"]
        return self.identity


@pytest.fixture
def web():
    provider = InventedProvider()
    sessions = InMemorySessionStore()
    clock = [datetime(2026, 10, 5, tzinfo=UTC)]
    grants = [OwnerGrant(OWNER, (SCOPE,))]
    seen = []

    async def view(principal):
        seen.append(principal)
        return "<html><main>Invented selected review</main></html>"

    app = create_private_web(
        origin=ORIGIN,
        identities=provider,
        sessions=sessions,
        owner=lambda: grants[0],
        view=view,
        clock=lambda: clock[0],
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        yield client, provider, sessions, clock, grants, seen


def sign_in(client):
    begin = client.post("/login", headers={"origin": ORIGIN})
    assert begin.status_code == 307
    assert "Secure" in begin.headers["set-cookie"] and "HttpOnly" in begin.headers["set-cookie"]
    pending = client.cookies.get("__Host-zac-login")
    response = client.get("/auth/callback?code=invented-code&state=fixed-state")
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert client.cookies.get("__Host-zac-session") != pending
    return response


def test_authenticated_read_has_exact_host_scopes_and_private_headers(web):
    client, _, _, _, _, seen = web
    assert client.get("/").headers["location"] == "/login"
    sign_in(client)
    response = client.get("/")
    assert response.status_code == 200 and "Invented selected review" in response.text
    assert seen[0].identity == OWNER and seen[0].scopes == (SCOPE,)
    assert all(s.boundary != B.PERSONAL for s in seen[0].scopes)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "same-origin"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.post("/approve").status_code == 404


@pytest.mark.parametrize(
    "header", ["tailscale-user-login", "authorization", "x-user", "x-boundary"]
)
def test_claimed_headers_never_authenticate(web, header):
    client = web[0]
    response = client.get("/", headers={header: "invented-owner"})
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert not web[-1]


def test_callback_cookie_is_browser_bound_and_consumed_once(web):
    client, provider, _, _, _, _ = web
    assert client.get("/auth/callback?code=x&state=fixed-state").status_code == 401
    assert provider.finishes == 0
    sign_in(client)
    assert client.get("/auth/callback?code=x&state=fixed-state").status_code == 401
    assert provider.finishes == 1


def test_duplicate_state_consumes_transaction_without_provider_exchange(web):
    client, provider = web[:2]
    client.post("/login", headers={"origin": ORIGIN})
    assert (
        client.get("/auth/callback?code=x&state=fixed-state&state=fixed-state").status_code == 401
    )
    assert client.get("/auth/callback?code=x&state=fixed-state").status_code == 401
    assert provider.finishes == 0


def test_other_authenticated_account_cannot_self_enroll(web):
    client, provider = web[:2]
    provider.identity = Identity(GOOGLE_ISSUER, "other-workspace-admin")
    client.post("/login", headers={"origin": ORIGIN})
    assert client.get("/auth/callback?code=x&state=fixed-state").status_code == 401
    assert not client.cookies.get("__Host-zac-session")
    assert not web[-1]


def test_scope_changes_are_refreshed_and_revocation_invalidates_session(web):
    client, _, sessions, _, grants, seen = web
    sign_in(client)
    grants[0] = OwnerGrant(OWNER, (BoundaryScope(B.PERSONAL, frozenset({C.INTERNAL})),))
    client.get("/")
    assert seen[-1].scopes == grants[0].scopes
    sessions.revoke_identity(OWNER)
    assert client.get("/").headers["location"] == "/login"


def test_owner_change_invalidates_previous_session(web):
    client, _, _, _, grants, _ = web
    sign_in(client)
    grants[0] = OwnerGrant(Identity(GOOGLE_ISSUER, "replacement-owner"), (SCOPE,))
    assert client.get("/").headers["location"] == "/login"


def test_idle_and_absolute_expiry_and_regressed_clock(web):
    client, _, _, clock, _, _ = web
    sign_in(client)
    clock[0] += timedelta(minutes=30)
    assert client.get("/").headers["location"] == "/login"
    sign_in(client)
    clock[0] -= timedelta(seconds=1)
    assert client.get("/").headers["location"] == "/login"


@pytest.mark.parametrize("kind", ["origin", "token", "duplicate", "type", "oversize"])
def test_logout_requires_exact_origin_and_csrf_and_keeps_session_on_rejection(web, kind):
    client = web[0]
    sign_in(client)
    html = client.get("/").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    body = "csrf=" + csrf
    headers = {"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"}
    if kind == "origin":
        headers["origin"] = "https://evil.example.test"
    elif kind == "token":
        body = "csrf=forged"
    elif kind == "duplicate":
        body += "&csrf=" + csrf
    elif kind == "type":
        headers["content-type"] = "text/plain"
    else:
        body = "csrf=" + "x" * 300
    assert client.post("/logout", content=body, headers=headers).status_code == 403
    assert client.get("/").status_code == 200


def test_successful_logout_revokes_cookie_and_session(web):
    client = web[0]
    sign_in(client)
    csrf = re.search(r'name="csrf" value="([^"]+)"', client.get("/").text).group(1)
    response = client.post(
        "/logout",
        content="csrf=" + csrf,
        headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 303
    assert not client.cookies.get("__Host-zac-session")
    assert client.get("/").headers["location"] == "/login"


def test_host_and_login_origin_are_fail_closed(web):
    client = web[0]
    assert client.get("/login", headers={"host": "evil.example.test"}).status_code == 400
    assert client.post("/login").status_code == 403
    assert client.post("/login", headers={"origin": "https://evil.example.test"}).status_code == 403


def test_duplicate_cookie_does_not_pick_auth_identity(web):
    client = web[0]
    sign_in(client)
    token = client.cookies.get("__Host-zac-session")
    client.cookies.clear()
    result = client.get(
        "/", headers={"cookie": f"__Host-zac-session={token}; __Host-zac-session={token}"}
    )
    assert result.headers["location"] == "/login"


def test_pending_expiration_and_hashed_storage():
    now = datetime(2026, 10, 5, tzinfo=UTC)
    store = InMemorySessionStore(capacity=1)
    token = store.start_login({"nonce": "invented"}, now)
    assert token not in store._login
    assert store.consume_login(token, now + timedelta(minutes=5)) is None
    assert store.consume_login(token, now) is None
    token = store.start_user(OWNER, now)
    assert token not in store._users
    assert store.user(token, now + timedelta(hours=8)) is None


def test_session_capacity_and_atomic_transaction_consumption():
    from concurrent.futures import ThreadPoolExecutor

    now = datetime(2026, 10, 5, tzinfo=UTC)
    store = InMemorySessionStore(capacity=1)
    token = store.start_login({"nonce": "invented"}, now)
    user_token = store.start_user(OWNER, now)
    with pytest.raises(ValueError, match="session capacity unavailable"):
        store.start_user(OWNER, now)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: store.consume_login(token, now), range(2)))
    assert results.count(None) == 1 and results.count({"nonce": "invented"}) == 1
    store.revoke(user_token)
    assert store.user(user_token, now) is None


def test_absolute_expiry_is_not_extended_by_activity():
    now = datetime(2026, 10, 5, tzinfo=UTC)
    store = InMemorySessionStore(idle=timedelta(minutes=30), lifetime=timedelta(hours=1))
    token = store.start_user(OWNER, now)
    for minute in (20, 40, 59):
        assert store.user(token, now + timedelta(minutes=minute)) is not None
    assert store.user(token, now + timedelta(hours=1)) is None


def test_bad_origin_or_empty_owner_does_not_create_private_app():
    provider = InventedProvider()
    store = InMemorySessionStore()
    grant = OwnerGrant(OWNER, (SCOPE,))

    async def view(principal):
        return "invented"

    for origin in (
        "http://zac.example.test",
        "https://zac.example.test/path",
        "https://zac.example.test?query",
        "https://user:password@zac.example.test",
        "https://zac.example.test:443",
    ):
        with pytest.raises(ValueError, match="private origin unavailable"):
            create_private_web(
                origin=origin, identities=provider, sessions=store, owner=lambda: grant, view=view
            )
    with pytest.raises(ValueError, match="owner enrollment unavailable"):
        OwnerGrant(OWNER, ())


def test_pending_login_flood_preserves_owner_capacity_and_evicts_only_oldest():
    now = datetime(2026, 10, 5, tzinfo=UTC)
    store = InMemorySessionStore(capacity=2)
    first = store.start_login({"nonce": "oldest"}, now)
    second = store.start_login({"nonce": "second"}, now + timedelta(seconds=1))
    owner = store.start_user(OWNER, now + timedelta(seconds=1))
    third = store.start_login({"nonce": "latest"}, now + timedelta(seconds=2))
    assert store.consume_login(first, now + timedelta(seconds=2)) is None
    assert store.consume_login(second, now + timedelta(seconds=2)) == {"nonce": "second"}
    assert store.consume_login(third, now + timedelta(seconds=2)) == {"nonce": "latest"}
    assert store.user(owner, now + timedelta(seconds=2)).identity == OWNER


def test_same_origin_referrer_policy_keeps_exact_origin_csrf_guard(web):
    client = web[0]
    page = client.get("/login")
    assert page.headers["referrer-policy"] == "same-origin"
    assert client.post("/login", headers={"Origin": "null"}).status_code == 403
    sign_in(client)
    html = client.get("/").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    assert (
        client.post(
            "/logout",
            content="csrf=" + csrf,
            headers={"Origin": "null", "content-type": "application/x-www-form-urlencoded"},
        ).status_code
        == 403
    )
    assert client.get("/").status_code == 200


def test_google_form_navigation_allowed_only_on_fixed_start_document(web):
    client = web[0]
    start = client.get("/login")
    assert (
        "form-action 'self' https://accounts.google.com;"
        in start.headers["content-security-policy"]
    )
    failed = client.get("/login", headers={"Host": "wrong.example.test"})
    assert failed.status_code == 400
    assert "https://accounts.google.com" not in failed.headers["content-security-policy"]
    redirect = client.post("/login", headers={"Origin": ORIGIN})
    assert "https://accounts.google.com" not in redirect.headers["content-security-policy"]
    callback = client.get("/auth/callback?code=invented&state=fixed-state")
    assert "https://accounts.google.com" not in callback.headers["content-security-policy"]
    protected = client.get("/")
    assert "form-action 'self';" in protected.headers["content-security-policy"]
    assert "https://accounts.google.com" not in protected.headers["content-security-policy"]


def test_security_header_mode_has_no_arbitrary_csp_override():
    from zacai.interfaces.private_web import _SecurityHeaders

    with pytest.raises(ValueError):
        _SecurityHeaders(object(), google_start_path="/")
