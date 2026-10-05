"""Composed ASGI flow with actual disposable encrypted stores, invented OIDC only.

No listener, TLS, real Google exchange, Keychain, source data or deployment. These
prove assembly/request/restart behavior, not mobile readiness or source recovery.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_host import (
    PrivateHostError,
    prepare_enrollment_host,
    prepare_owner_host,
)
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.private_web import BoundaryScope
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

ORIGIN = "https://caz.example.test"
NOW = datetime(2026, 10, 5, tzinfo=UTC)
OWNER = Identity(GOOGLE_ISSUER, "invented-stable-owner")
SCOPE = BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL}))
CONFIG = OwnerStartupConfiguration(
    "123456-invented.apps.googleusercontent.com", ORIGIN, "invented-not-a-secret", b"X" * 32
)
STATE = "a" * 32
NONCE = "n" * 32


class InventedIdentity:
    def __init__(self, clock):
        self.clock = clock
        self.finished = 0
        self.redirects = []

    async def begin(self, request, redirect_uri):
        self.redirects.append(redirect_uri)
        request.session["zac_nonce"] = NONCE
        request.session["_state_google_" + STATE] = {
            "exp": self.clock().timestamp() + 300,
            "data": {
                "nonce": NONCE,
                "code_verifier": "v" * 43,
                "redirect_uri": redirect_uri,
            },
        }
        return RedirectResponse("https://accounts.google.com/invented")

    async def finish(self, request):
        assert request.session["zac_nonce"] == NONCE
        assert request.query_params["state"] == STATE
        self.finished += 1
        return OWNER


def enroll(directory, clock, scopes=(SCOPE,)):
    had_record = (directory / "owner" / "owner.json").exists()
    identities = InventedIdentity(clock)
    prepared = prepare_enrollment_host(
        configuration=CONFIG, directory=directory, identities=identities, clock=clock
    )
    with TestClient(prepared.app, base_url=ORIGIN, follow_redirects=False) as browser:
        assert browser.get("/").status_code == 404
        assert browser.get("/enroll").status_code == 200
        assert browser.post("/enroll", headers={"origin": ORIGIN}).status_code == 307
        response = browser.get("/enroll/callback?code=invented&state=" + STATE)
        assert response.status_code == 200
        assert not browser.cookies.get("__Host-zac-session")
        pending = prepared.enrollment.pending(clock())
        assert pending is not None
        assert pending.pairing_code in response.text

        # Browser completion still cannot prepare the owner app or issue data access.
        async def forbidden(principal):
            raise AssertionError("no protected view before local confirmation")

        if not had_record:
            with pytest.raises(PrivateHostError):
                prepare_owner_host(
                    configuration=CONFIG,
                    directory=directory,
                    view=forbidden,
                    clock=clock,
                    identities=identities,
                )
        grant = prepared.owners.confirm_and_save(
            enrollment=prepared.enrollment,
            candidate_id=pending.candidate_id,
            pairing_code=pending.pairing_code,
            origin=ORIGIN,
            identity=OWNER,
            scopes=scopes,
            now=clock(),
        )
        assert grant.identity == OWNER
        assert identities.redirects == [ORIGIN + "/enroll/callback"]
    return prepared


def sign_in(browser):
    assert browser.post("/login", headers={"origin": ORIGIN}).status_code == 307
    assert browser.get("/auth/callback?code=invented&state=" + STATE).status_code == 303
    token = browser.cookies.get("__Host-zac-session")
    assert token
    return token


def test_real_store_assembly_enrollment_signin_restart_and_revocation(tmp_path):
    clock = lambda: NOW
    directory = tmp_path / "private-host"
    enrollment = enroll(directory, clock)
    seen = []

    async def view(principal):
        seen.append(principal)
        return "<html><main>Invented protected view</main></html>"

    first = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(clock),
        clock=clock,
    )
    assert first.owners.load() == enrollment.owners.load()
    with TestClient(first.app, base_url=ORIGIN, follow_redirects=False) as browser:
        assert browser.get("/enroll").status_code == 404
        assert browser.post("/approve").status_code == 404
        token = sign_in(browser)
        assert browser.get("/").status_code == 200
        assert seen[-1].identity == OWNER and seen[-1].scopes == (SCOPE,)
    # A new host and encrypted session store use the persisted owner and cookie.
    restarted = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(clock),
        clock=clock,
    )
    with TestClient(restarted.app, base_url=ORIGIN, follow_redirects=False) as browser:
        browser.cookies.set("__Host-zac-session", token, domain="caz.example.test", path="/")
        response = browser.get("/")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        calls = len(seen)
        restarted.revoke_owner()
        assert browser.get("/").status_code == 503
        assert len(seen) == calls
    with pytest.raises(PrivateHostError):
        prepare_owner_host(configuration=CONFIG, directory=directory, view=view)


def test_missing_owner_never_constructs_provider_sessions_or_enrollment(tmp_path, monkeypatch):
    import zacai.interfaces.private_host as host

    calls = []
    monkeypatch.setattr(host, "AuthlibGoogleIdentity", lambda **kwargs: calls.append(kwargs))
    directory = tmp_path / "new-owner"

    async def view(principal):
        raise AssertionError

    with pytest.raises(PrivateHostError, match="private owner host unavailable") as exc:
        prepare_owner_host(configuration=CONFIG, directory=directory, view=view)
    assert not calls
    assert not (directory / "sessions").exists()
    assert exc.value.__context__ is None and exc.value.__cause__ is None


def test_corrupted_enrollment_denies_existing_session_and_restart(tmp_path):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)
    seen = []

    async def view(principal):
        seen.append(principal)
        return "<main>invented</main>"

    prepared = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(lambda: NOW),
        clock=lambda: NOW,
    )
    with TestClient(prepared.app, base_url=ORIGIN, follow_redirects=False) as browser:
        sign_in(browser)
        (directory / "owner" / "owner.json").write_bytes(b'{"tampered":true}')
        assert browser.get("/").status_code == 503
        assert not seen
    with pytest.raises(PrivateHostError):
        prepare_owner_host(configuration=CONFIG, directory=directory, view=view)


def test_wrong_key_cannot_recover_owner_or_initialize_new_sessions(tmp_path):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)
    session_bytes = (directory / "sessions" / "sessions.sqlite").read_bytes()

    async def view(principal):
        raise AssertionError

    wrong = OwnerStartupConfiguration(CONFIG.client_id, ORIGIN, CONFIG.client_secret, b"Y" * 32)
    with pytest.raises(PrivateHostError):
        prepare_owner_host(configuration=wrong, directory=directory, view=view)
    assert (directory / "sessions" / "sessions.sqlite").read_bytes() == session_bytes


def test_enrollment_restart_invalidates_volatile_candidate(tmp_path):
    directory = tmp_path / "host"
    clock = lambda: NOW
    first = prepare_enrollment_host(
        configuration=CONFIG, directory=directory, identities=InventedIdentity(clock), clock=clock
    )
    pending = first.enrollment.capture(OWNER, NOW, origin=ORIGIN)
    next_setup = prepare_enrollment_host(
        configuration=CONFIG, directory=directory, identities=InventedIdentity(clock), clock=clock
    )
    assert next_setup.enrollment.pending(NOW) is None
    with pytest.raises(ValueError):
        next_setup.owners.confirm_and_save(
            enrollment=next_setup.enrollment,
            candidate_id=pending.candidate_id,
            pairing_code=pending.pairing_code,
            origin=ORIGIN,
            identity=OWNER,
            scopes=(SCOPE,),
            now=NOW,
        )


@pytest.mark.parametrize("fault", ["origin", "client", "secret", "key", "relative", "mode", "link"])
def test_bad_configuration_and_paths_fail_before_identity_construction(
    tmp_path, monkeypatch, fault
):
    import zacai.interfaces.private_host as host

    calls = []
    monkeypatch.setattr(host, "AuthlibGoogleIdentity", lambda **kwargs: calls.append(kwargs))
    config = CONFIG
    directory = tmp_path / "host"
    if fault == "origin":
        config = OwnerStartupConfiguration(
            CONFIG.client_id,
            "https://caz.example.test/path",
            CONFIG.client_secret,
            CONFIG.session_key,
        )
    elif fault == "client":
        config = OwnerStartupConfiguration(
            "malformed-client", ORIGIN, CONFIG.client_secret, CONFIG.session_key
        )
    elif fault == "secret":
        config = OwnerStartupConfiguration(
            CONFIG.client_id, ORIGIN, "private\nsecret", CONFIG.session_key
        )
    elif fault == "key":
        config = OwnerStartupConfiguration(CONFIG.client_id, ORIGIN, CONFIG.client_secret, b"short")
    elif fault == "relative":
        directory = Path("relative-host")
    elif fault == "mode":
        directory.mkdir(mode=0o755)
    else:
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        directory.symlink_to(target, target_is_directory=True)
    with pytest.raises(PrivateHostError) as exc:
        prepare_enrollment_host(configuration=config, directory=directory)
    assert not calls
    assert exc.value.__context__ is None
    assert "private" not in str(exc.value).replace("private enrollment host unavailable", "")


def test_explicit_scope_tuple_preserved_without_personal_union(tmp_path):
    scopes = (
        BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),
        SCOPE,
    )
    setup = enroll(tmp_path / "host", lambda: NOW, scopes)
    assert setup.owners.load().scopes == scopes
    assert setup.owners.load().scopes[1].classifications == frozenset({C.CONFIDENTIAL})


def test_enrollment_only_window_expires_and_does_not_grant_access(tmp_path):
    now = [NOW]
    prepared = prepare_enrollment_host(
        configuration=CONFIG,
        directory=tmp_path / "host",
        identities=InventedIdentity(lambda: now[0]),
        clock=lambda: now[0],
    )
    now[0] += timedelta(minutes=5)
    with TestClient(prepared.app, base_url=ORIGIN) as browser:
        assert browser.get("/enroll").status_code == 403
        assert browser.get("/").status_code == 404
    with pytest.raises(ValueError):
        prepared.owners.load()
    assert CONFIG.client_secret not in repr(prepared)
    assert str(CONFIG.session_key) not in repr(prepared)


@pytest.mark.parametrize("revoke_first", [True, False])
@pytest.mark.parametrize("intervening_request", [True, False])
@pytest.mark.parametrize("changed_scope", [True, False])
def test_reenrollment_never_revives_old_cookie(
    tmp_path, revoke_first, intervening_request, changed_scope
):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)
    seen = []

    async def view(principal):
        seen.append(principal)
        return "<main>invented</main>"

    first = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(lambda: NOW),
        clock=lambda: NOW,
    )
    with TestClient(first.app, base_url=ORIGIN, follow_redirects=False) as browser:
        token = sign_in(browser)
        if revoke_first:
            first.revoke_owner()
        if intervening_request:
            response = browser.get("/")
            assert response.status_code == (503 if revoke_first else 200)
    scopes = (
        (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),)
        if changed_scope
        else (SCOPE,)
    )
    enroll(directory, lambda: NOW, scopes)
    restarted = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(lambda: NOW),
        clock=lambda: NOW,
    )
    count = len(seen)
    with TestClient(restarted.app, base_url=ORIGIN, follow_redirects=False) as browser:
        browser.cookies.set("__Host-zac-session", token, domain="caz.example.test", path="/")
        assert browser.get("/").headers["location"] == "/login"
        assert len(seen) == count
        sign_in(browser)
        assert browser.get("/").status_code == 200
        assert seen[-1].scopes == scopes


def test_revoked_owner_does_not_refresh_cookie_idle_time(tmp_path):
    import sqlite3

    directory = tmp_path / "host"
    now = [NOW]
    enroll(directory, lambda: now[0])

    async def view(principal):
        raise AssertionError("revoked view must not run")

    host = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(lambda: now[0]),
        clock=lambda: now[0],
    )
    path = directory / "sessions" / "sessions.sqlite"
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        sign_in(browser)
        with sqlite3.connect(path) as connection:
            before = connection.execute(
                "SELECT seen,sealed FROM sessions WHERE kind='user'"
            ).fetchone()
        # Direct storage tombstone is not the composed revoke entrypoint, but
        # denied owner requests still must not extend the old session's idle time.
        host.owners.revoke()
        now[0] += timedelta(minutes=20)
        assert browser.get("/").status_code == 503
        with sqlite3.connect(path) as connection:
            after = connection.execute(
                "SELECT seen,sealed FROM sessions WHERE kind='user'"
            ).fetchone()
        assert before == after


@pytest.mark.parametrize("failing", ["owner", "sessions"])
def test_composed_revocation_failure_never_acknowledges_and_still_attempts_both(
    tmp_path, monkeypatch, failing
):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)

    async def view(principal):
        return "<main>invented</main>"

    host = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=InventedIdentity(lambda: NOW),
        clock=lambda: NOW,
    )
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        token = sign_in(browser)
    calls = []
    owner_revoke, session_revoke = host.owners.revoke, host.sessions.revoke_all

    def revoke_owner():
        calls.append("owner")
        if failing == "owner":
            raise RuntimeError("invented-private-diagnostic")
        owner_revoke()

    def revoke_sessions():
        calls.append("sessions")
        if failing == "sessions":
            raise RuntimeError("invented-private-diagnostic")
        session_revoke()

    monkeypatch.setattr(host.owners, "revoke", revoke_owner)
    monkeypatch.setattr(host.sessions, "revoke_all", revoke_sessions)
    with pytest.raises(PrivateHostError) as exc:
        host.revoke_owner()
    assert calls == ["owner", "sessions"]
    assert "invented-private" not in str(exc.value)
    assert exc.value.__context__ is None and exc.value.__cause__ is None
    if failing == "owner":
        assert host.sessions.user(token, NOW) is None
    else:
        with pytest.raises(ValueError):
            host.owners.load()


def test_enrollment_invalidates_old_pending_owner_oidc_transactions(tmp_path):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)

    async def view(principal):
        return "<main>invented</main>"

    identity = InventedIdentity(lambda: NOW)
    host = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        identities=identity,
        clock=lambda: NOW,
    )
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        assert browser.post("/login", headers={"origin": ORIGIN}).status_code == 307
        prepare_enrollment_host(
            configuration=CONFIG,
            directory=directory,
            identities=InventedIdentity(lambda: NOW),
            clock=lambda: NOW,
        )
        assert browser.get("/auth/callback?code=invented&state=" + STATE).status_code == 401
        assert identity.finished == 0


@pytest.mark.parametrize("changed", ["origin", "client"])
def test_host_configuration_change_requires_fresh_enrollment(tmp_path, changed):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)
    config = OwnerStartupConfiguration(
        CONFIG.client_id if changed == "origin" else "999-other.apps.googleusercontent.com",
        "https://other.example.test" if changed == "origin" else ORIGIN,
        CONFIG.client_secret,
        CONFIG.session_key,
    )

    async def view(principal):
        raise AssertionError

    with pytest.raises(PrivateHostError):
        prepare_owner_host(configuration=config, directory=directory, view=view)



def test_key_rotation_requires_explicit_new_enrollment_and_old_key_stays_denied(tmp_path):
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)
    rotated = OwnerStartupConfiguration(CONFIG.client_id, ORIGIN, CONFIG.client_secret, b"Y" * 32)
    setup = prepare_enrollment_host(
        configuration=rotated, directory=directory,
        identities=InventedIdentity(lambda: NOW), clock=lambda: NOW,
    )
    with pytest.raises(ValueError):
        setup.owners.load()
    pending = setup.enrollment.capture(OWNER, NOW, origin=ORIGIN)
    setup.owners.confirm_and_save(
        enrollment=setup.enrollment, candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code, origin=ORIGIN,
        identity=OWNER, scopes=(SCOPE,), now=NOW,
    )

    async def view(principal):
        return "<main>invented rotated-key host</main>"

    host = prepare_owner_host(
        configuration=rotated, directory=directory, view=view,
        identities=InventedIdentity(lambda: NOW), clock=lambda: NOW,
    )
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        sign_in(browser)
        assert browser.get("/").status_code == 200
    with pytest.raises(PrivateHostError):
        prepare_owner_host(configuration=CONFIG, directory=directory, view=view)


def test_callback_after_direct_owner_tombstone_creates_no_user_session(tmp_path):
    import sqlite3
    directory = tmp_path / "host"
    enroll(directory, lambda: NOW)

    async def view(principal):
        raise AssertionError

    identities = InventedIdentity(lambda: NOW)
    host = prepare_owner_host(
        configuration=CONFIG, directory=directory, view=view,
        identities=identities, clock=lambda: NOW,
    )
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        assert browser.post("/login", headers={"origin": ORIGIN}).status_code == 307
        host.owners.revoke()
        assert browser.get("/auth/callback?code=invented&state=" + STATE).status_code == 401
        assert not browser.cookies.get("__Host-zac-session")
    with sqlite3.connect(directory / "sessions" / "sessions.sqlite") as connection:
        assert connection.execute("SELECT count(*) FROM sessions WHERE kind='user'").fetchone()[0] == 0
