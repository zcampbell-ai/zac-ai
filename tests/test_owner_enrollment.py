"""Invented owner candidates only; no Google/network/credentials or source data."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from starlette.responses import RedirectResponse
from starlette.testclient import TestClient

from zacai.interfaces.owner_enrollment import OwnerEnrollment, create_owner_enrollment
from zacai.interfaces.private_web import BoundaryScope
from zacai.interfaces.session_store import Identity, InMemorySessionStore
from zacai.policy import DataClassification, TrustBoundary

NOW = datetime(2026, 10, 5, tzinfo=UTC)
ORIGIN = "https://zac.example.test"
IDENTITY = Identity("https://accounts.google.com", "invented-owner")
SCOPE = BoundaryScope(TrustBoundary.BRAINSTORM, frozenset({DataClassification.CONFIDENTIAL}))


class Provider:
    calls = 0
    identity = IDENTITY
    fail = False

    async def begin(self, request, redirect_uri):
        request.session["invented-state"] = "invented-nonce"
        assert redirect_uri == ORIGIN + "/enroll/callback"
        return RedirectResponse("https://accounts.google.com/invented")

    async def finish(self, request):
        self.calls += 1
        assert request.session == {"invented-state": "invented-nonce"}
        if self.fail:
            raise ValueError("private-provider-diagnostic")
        return self.identity


class Sessions(InMemorySessionStore):
    def start_user(self, *args, **kwargs):
        raise AssertionError("enrollment must never create user sessions")


@pytest.fixture
def setup():
    now = [NOW]
    registry, provider, sessions = OwnerEnrollment(opened_at=NOW), Provider(), Sessions()
    app = create_owner_enrollment(
        origin=ORIGIN,
        identities=provider,
        sessions=sessions,
        enrollment=registry,
        clock=lambda: now[0],
    )
    return TestClient(app, base_url=ORIGIN, follow_redirects=False), registry, provider, now


def login(client):
    return client.post("/enroll", headers={"Origin": ORIGIN})


def callback(client, query="code=invented&state=invented"):
    return client.get("/enroll/callback?" + query)


def test_browser_completion_is_pending_only_and_local_confirmation_is_explicit(setup):
    client, registry, _, _ = setup
    assert login(client).status_code == 307
    assert callback(client).status_code == 200
    pending = registry.pending(NOW)
    assert pending.identity == IDENTITY
    assert pending.candidate_id not in repr(pending)
    assert "__Host-zac-session" not in client.cookies
    assert not any(r.path in ("/", "/logout", "/approve", "/confirm") for r in client.app.routes)
    assert client.post("/confirm").status_code == 404
    assert callback(client).status_code == 401
    for wrong in (
        {"candidate_id": "wrong", "identity": IDENTITY},
        {"candidate_id": pending.candidate_id, "identity": Identity(IDENTITY.issuer, "wrong")},
    ):
        with pytest.raises(ValueError, match="enrollment unavailable"):
            registry.confirm(
                **wrong, pairing_code=pending.pairing_code, origin=ORIGIN, scopes=(SCOPE,), now=NOW
            )
    with pytest.raises(ValueError, match="owner enrollment unavailable"):
        registry.confirm(
            candidate_id=pending.candidate_id,
            pairing_code=pending.pairing_code,
            origin=ORIGIN,
            identity=IDENTITY,
            scopes=(),
            now=NOW,
        )
    personal = BoundaryScope(TrustBoundary.PERSONAL, frozenset({DataClassification.CONFIDENTIAL}))
    grant = registry.confirm(
        candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code,
        origin=ORIGIN,
        identity=IDENTITY,
        scopes=(SCOPE, personal),
        now=NOW,
    )
    assert grant.scopes == (SCOPE, personal)
    assert registry.pending(NOW) is None
    with pytest.raises(ValueError):
        registry.confirm(
            candidate_id=pending.candidate_id,
            pairing_code=pending.pairing_code,
            origin=ORIGIN,
            identity=IDENTITY,
            scopes=(SCOPE,),
            now=NOW,
        )


@pytest.mark.parametrize(
    "defect",
    ["wrong_origin", "wrong_host", "missing_origin", "duplicate_origin", "expired", "cancelled"],
)
def test_login_rejects_untrusted_or_closed_window(setup, defect):
    client, registry, _, now = setup
    headers = {"Origin": ORIGIN}
    if defect == "wrong_origin":
        headers["Origin"] = "https://attacker.example.test"
    elif defect == "missing_origin":
        headers = {}
    elif defect == "wrong_host":
        headers["Host"] = "attacker.example.test"
    elif defect == "duplicate_origin":
        headers = [("Origin", ORIGIN), ("Origin", ORIGIN)]
    elif defect == "expired":
        now[0] += timedelta(minutes=5)
    else:
        registry.cancel()
    assert client.post("/enroll", headers=headers).status_code == 403
    assert registry.pending(now[0]) is None


@pytest.mark.parametrize(
    "defect",
    [
        "provider",
        "issuer",
        "empty_subject",
        "expired",
        "duplicate_code",
        "oversized",
        "duplicate_cookie",
    ],
)
def test_failed_callback_has_no_candidate_and_no_private_diagnostics(setup, defect):
    client, registry, provider, now = setup
    login(client)
    query = "code=invented&state=invented"
    headers = {}
    if defect == "provider":
        provider.fail = True
    elif defect == "issuer":
        provider.identity = Identity("https://attacker.example.test", "owner")
    elif defect == "empty_subject":
        provider.identity = Identity(IDENTITY.issuer, "")
    elif defect == "expired":
        now[0] += timedelta(minutes=5)
    elif defect == "duplicate_code":
        query += "&code=duplicate"
    elif defect == "oversized":
        query += "&extra=" + "X" * 4096
    else:
        token = client.cookies.get("__Host-zac-enrollment")
        headers["Cookie"] = f"__Host-zac-enrollment={token}; __Host-zac-enrollment={token}"
    response = client.get("/enroll/callback?" + query, headers=headers)
    assert response.status_code in (400, 401)
    assert registry.pending(now[0]) is None
    assert "private-provider-diagnostic" not in response.text
    assert "invented-owner" not in response.text


def test_headers_and_cookie_protection_without_identity_disclosure(setup):
    client, _, _, _ = setup
    response = login(client)
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert "Domain=" not in cookie and "Path=/" in cookie
    page = client.get("/enroll/complete")
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "same-origin"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "invented-owner" not in page.text


def test_candidate_is_bounded_expires_and_atomic():
    registry = OwnerEnrollment(opened_at=NOW)

    def capture(_):
        try:
            registry.capture(IDENTITY, NOW, origin=ORIGIN)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(2) as executor:
        assert sum(executor.map(capture, range(2))) == 1
    assert registry.pending(NOW + timedelta(minutes=5)) is None
    assert not registry.available(NOW)


@pytest.mark.parametrize(
    "origin",
    ["http://zac.example.test", ORIGIN + "/path", ORIGIN + ":443", "https://user@zac.example.test"],
)
def test_invalid_origins_never_build_app(origin):
    with pytest.raises(ValueError):
        create_owner_enrollment(
            origin=origin,
            identities=Provider(),
            sessions=Sessions(),
            enrollment=OwnerEnrollment(opened_at=NOW),
        )


@pytest.mark.asyncio
async def test_actual_provider_and_sqlite_enrollment_without_network(tmp_path, monkeypatch):
    import secrets
    import time
    from urllib.parse import parse_qs, urlsplit

    import httpx
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    from zacai.interfaces.oidc_identity import AuthlibGoogleIdentity
    from zacai.interfaces.sqlite_sessions import SqliteSessionStore

    async def denied(*args, **kwargs):
        raise AssertionError("enrollment tests must not access network")

    monkeypatch.setattr(httpx.AsyncClient, "request", denied)
    registry = OwnerEnrollment(opened_at=NOW)
    provider = AuthlibGoogleIdentity(client_id="invented-client", client_secret="invented-secret")
    store = SqliteSessionStore(tmp_path / "enrollment", key=secrets.token_bytes(32))
    app = create_owner_enrollment(
        origin=ORIGIN, identities=provider, sessions=store, enrollment=registry, clock=lambda: NOW
    )
    signing_key = RSAKey.generate_key(2048)
    provider._client.server_metadata["jwks"] = {"keys": [signing_key.as_dict(private=False)]}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN, follow_redirects=False
    ) as client:
        # Network denial patches request globally; ASGI send still stays in-process.
        response = await client.send(
            client.build_request("POST", "/enroll", headers={"Origin": ORIGIN})
        )
        assert response.status_code == 302
        args = parse_qs(urlsplit(response.headers["location"]).query)
        assert args["redirect_uri"] == [ORIGIN + "/enroll/callback"]
        signed = jwt.encode(
            {"alg": "RS256"},
            {
                "iss": IDENTITY.issuer,
                "sub": IDENTITY.subject,
                "aud": "invented-client",
                "iat": int(time.time()),
                "exp": int(time.time()) + 120,
                "nonce": args["nonce"][0],
            },
            signing_key,
        )

        async def exchange(**kwargs):
            assert kwargs["redirect_uri"] == ORIGIN + "/enroll/callback"
            assert len(kwargs["code_verifier"]) >= 43
            return {"access_token": "invented-token", "token_type": "Bearer", "id_token": signed}

        monkeypatch.setattr(provider._client, "fetch_access_token", exchange)
        callback_request = client.build_request(
            "GET", "/enroll/callback", params={"code": "invented", "state": args["state"][0]}
        )
        response = await client.send(callback_request)
        assert response.status_code == 200
        assert "__Host-zac-session" not in client.cookies
        assert registry.pending(NOW).identity == IDENTITY


def test_regressed_clock_closes_pending_enrollment():
    registry = OwnerEnrollment(opened_at=NOW)
    registry.capture(IDENTITY, NOW + timedelta(seconds=2), origin=ORIGIN)
    assert registry.pending(NOW + timedelta(seconds=1)) is None
    assert not registry.available(NOW + timedelta(seconds=3))


def test_browser_pairing_code_is_ephemeral_and_not_a_bearer_credential(setup):
    import re

    client, registry, _, _ = setup
    login(client)
    response = callback(client)
    pending = registry.pending(NOW)
    assert re.fullmatch(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}", pending.pairing_code)
    assert pending.pairing_code in response.text
    assert pending.pairing_code not in repr(pending)
    assert pending.candidate_id not in response.text and IDENTITY.subject not in response.text
    assert "location" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/enroll/complete").text.find(pending.pairing_code) == -1
    for code, origin in (
        ("AAAA-AAAA-AAAA-AAAA", ORIGIN),
        (pending.pairing_code, "https://other.example.test"),
        ("é", ORIGIN),
    ):
        with pytest.raises(ValueError, match="enrollment unavailable"):
            registry.confirm(
                candidate_id=pending.candidate_id,
                pairing_code=code,
                origin=origin,
                identity=IDENTITY,
                scopes=(SCOPE,),
                now=NOW,
            )
    assert client.post("/confirm", json={"pairing_code": pending.pairing_code}).status_code == 404
    assert (
        client.get("/", headers={"Authorization": "Bearer " + pending.pairing_code}).status_code
        == 404
    )
    assert "__Host-zac-session" not in client.cookies
    assert registry.pending(NOW + timedelta(minutes=5)) is None
    with pytest.raises(ValueError):
        registry.confirm(
            candidate_id=pending.candidate_id,
            pairing_code=pending.pairing_code,
            origin=ORIGIN,
            identity=IDENTITY,
            scopes=(SCOPE,),
            now=NOW + timedelta(minutes=5),
        )


def test_pairing_codes_have_independent_randomness_and_bind_exact_candidates():
    first, second = OwnerEnrollment(opened_at=NOW), OwnerEnrollment(opened_at=NOW)
    one = first.capture(IDENTITY, NOW, origin=ORIGIN)
    two = second.capture(IDENTITY, NOW, origin=ORIGIN)
    assert one.pairing_code != two.pairing_code and one.candidate_id != two.candidate_id
    with pytest.raises(ValueError):
        second.confirm(
            candidate_id=two.candidate_id,
            pairing_code=one.pairing_code,
            origin=ORIGIN,
            identity=IDENTITY,
            scopes=(SCOPE,),
            now=NOW,
        )
    grant = second.confirm(
        candidate_id=two.candidate_id,
        pairing_code=two.pairing_code,
        origin=ORIGIN,
        identity=IDENTITY,
        scopes=(SCOPE,),
        now=NOW,
    )
    assert grant.scopes == (SCOPE,)
    with pytest.raises(ValueError):
        second.confirm(
            candidate_id=two.candidate_id,
            pairing_code=two.pairing_code,
            origin=ORIGIN,
            identity=IDENTITY,
            scopes=(SCOPE,),
            now=NOW,
        )


def test_only_enrollment_start_document_allows_google_form_navigation(setup):
    client = setup[0]
    start = client.get("/enroll")
    assert (
        "form-action 'self' https://accounts.google.com;"
        in start.headers["content-security-policy"]
    )
    for response in (
        login(client),
        callback(client),
        client.get("/enroll/complete"),
        client.get("/missing"),
    ):
        assert "https://accounts.google.com" not in response.headers["content-security-policy"]
        assert "form-action 'self';" in response.headers["content-security-policy"]
