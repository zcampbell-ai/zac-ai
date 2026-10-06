"""Actual encrypted session API with invented keys/cookies/owner/temp files."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from zacai.interfaces import named_session_binding as m
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def fixture(tmp_path):
    identity = Identity("https://accounts.google.com", "invented-owner")
    s = SimpleNamespace(
        now=datetime(2026, 10, 5, 12, tzinfo=UTC),
        key=b"x" * 32,
        path=tmp_path / "sessions",
        owner=OwnerGrant(identity, (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)),
    )
    s.clock = HostObservedClock(lambda: s.now)
    s.sessions = SqliteSessionStore(s.path, key=s.key)
    s.cookie = s.sessions.start_user(identity, s.now)
    s.args = {
        "sessions": s.sessions,
        "owner": lambda: s.owner,
        "clock": s.clock,
        "key": s.key,
        "origin": "https://caz.example",
        "client_id": "invented-client",
    }
    s.helper = m.NamedSessionContinuity(**s.args)
    return s


def test_actual_session_binding_idempotent_after_idle_refresh_and_reopen(fixture):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    s.now += timedelta(minutes=1)
    assert operation.recheck(original.binding_digest) == original
    s.sessions = SqliteSessionStore(s.path, key=s.key)
    s.helper = m.NamedSessionContinuity(**{**s.args, "sessions": s.sessions})
    assert s.helper.for_cookie(s.cookie).recheck(original.binding_digest) == original
    assert original.principal.identity == s.owner.identity
    assert not original.processing_authorized and not original.execution_authorized
    assert s.cookie not in repr(operation) and s.cookie not in repr(original)
    assert s.owner.identity.subject not in repr(original)


def test_same_owner_new_cookie_cannot_resume_original_admission(fixture):
    s = fixture
    original = s.helper.for_cookie(s.cookie).establish()
    new_cookie = s.sessions.start_user(s.owner.identity, s.now)
    replacement = s.helper.for_cookie(new_cookie)
    assert replacement.establish().binding_digest != original.binding_digest
    with pytest.raises(m.NamedSessionBindingError):
        replacement.recheck(original.binding_digest)
    recovered = replacement.receipt_only(original.principal)
    assert recovered.principal == original.principal and not recovered.processing_authorized


@pytest.mark.parametrize("revocation", ["one", "all"])
def test_actual_revoked_cookie_denied_even_with_original_digest(fixture, revocation):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    s.sessions.revoke(s.cookie) if revocation == "one" else s.sessions.revoke_all()
    with pytest.raises(m.NamedSessionBindingError) as error:
        operation.recheck(original.binding_digest)
    assert error.value.__context__ is None


@pytest.mark.parametrize("expiry", ["idle", "absolute"])
def test_actual_idle_and_absolute_expiry_equal_denied(fixture, expiry):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    s.now += timedelta(minutes=30) if expiry == "idle" else timedelta(hours=8)
    with pytest.raises(m.NamedSessionBindingError):
        operation.recheck(original.binding_digest)


@pytest.mark.parametrize("kind", ["identity", "scopes"])
def test_current_enrolled_owner_or_grant_change_denies(fixture, kind):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    if kind == "identity":
        s.owner = OwnerGrant(Identity("https://accounts.google.com", "other-owner"), s.owner.scopes)
    else:
        s.owner = OwnerGrant(
            s.owner.identity, (BoundaryScope(B.BRAINSTORM, frozenset({C.INTERNAL})),)
        )
    with pytest.raises(m.NamedSessionBindingError):
        operation.recheck(original.binding_digest)
    with pytest.raises(m.NamedSessionBindingError):
        operation.receipt_only(original.principal)


def test_unavailable_owner_checked_before_cookie_idle_refresh(fixture, monkeypatch):
    s = fixture
    calls = 0
    original = s.sessions.peek_user

    def counted(token, now):
        nonlocal calls
        calls += 1
        return original(token, now)

    monkeypatch.setattr(s.sessions, "peek_user", counted)

    def denied():
        raise RuntimeError("PRIVATE owner failure")

    helper = m.NamedSessionContinuity(**{**s.args, "owner": denied})
    with pytest.raises(m.NamedSessionBindingError):
        helper.for_cookie(s.cookie).establish()
    assert calls == 0


def test_revocation_during_post_call_owner_check_denies(fixture):
    s = fixture
    calls = 0

    def owner():
        nonlocal calls
        calls += 1
        if calls == 2:
            s.sessions.revoke(s.cookie)
        return s.owner

    helper = m.NamedSessionContinuity(**{**s.args, "owner": owner})
    with pytest.raises(m.NamedSessionBindingError):
        helper.for_cookie(s.cookie).establish()


def test_clock_expiry_advanced_by_final_owner_callback_denies(fixture):
    s = fixture
    calls = 0

    def owner():
        nonlocal calls
        calls += 1
        if calls == 2:
            s.now += timedelta(hours=8)
        return s.owner

    helper = m.NamedSessionContinuity(**{**s.args, "owner": owner})
    with pytest.raises(m.NamedSessionBindingError):
        helper.for_cookie(s.cookie).establish()


@pytest.mark.parametrize("digest", [None, True, "", "G" * 64, "0" * 64, b"0" * 64])
def test_forged_or_malformed_correlation_digest_grants_nothing(fixture, digest):
    s = fixture
    with pytest.raises(m.NamedSessionBindingError):
        s.helper.for_cookie(s.cookie).recheck(digest)


@pytest.mark.parametrize("cookie", [None, True, "", "x" * 42, "x" * 44, "a b", "é" * 43])
def test_invalid_cookie_shapes_denied(fixture, cookie):
    with pytest.raises(m.NamedSessionBindingError):
        fixture.helper.for_cookie(cookie)


def test_unknown_but_wellformed_cookie_denied_without_identity_lookup(fixture):
    with pytest.raises(m.NamedSessionBindingError):
        fixture.helper.for_cookie("x" * 43).establish()


@pytest.mark.parametrize(
    "field,value",
    [("origin", "https://other.example"), ("client_id", "other-client"), ("key", b"y" * 32)],
)
def test_binding_is_key_and_host_config_separated(fixture, field, value):
    s = fixture
    original = s.helper.for_cookie(s.cookie).establish()
    helper = m.NamedSessionContinuity(**{**s.args, field: value})
    with pytest.raises(m.NamedSessionBindingError):
        helper.for_cookie(s.cookie).recheck(original.binding_digest)


def test_clock_rollback_rechecks_actual_host_watermark(fixture):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    s.now -= timedelta(seconds=1)
    with pytest.raises(m.NamedSessionBindingError):
        operation.recheck(original.binding_digest)


def _sealed_session_rows(state):
    import sqlite3

    with sqlite3.connect(state.path / "sessions.sqlite") as connection:
        return connection.execute("SELECT kind,issued,seen,expires,sealed FROM sessions").fetchall()


def test_internal_checks_never_refresh_or_reseal_browser_activity(fixture):
    s = fixture
    original_rows = _sealed_session_rows(s)
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    for minutes in (5, 10, 20, 29):
        s.now = original.issued_at + timedelta(minutes=minutes)
        assert operation.recheck(original.binding_digest) == original
        assert operation.receipt_only(original.principal) == original
        assert _sealed_session_rows(s) == original_rows
    s.now = original.issued_at + timedelta(minutes=30)
    with pytest.raises(m.NamedSessionBindingError):
        operation.recheck(original.binding_digest)
    assert _sealed_session_rows(s) == original_rows


def test_internal_activity_cannot_hold_session_past_idle_deadline(fixture):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    s.now += timedelta(minutes=29)
    operation.recheck(original.binding_digest)
    s.now += timedelta(minutes=1)
    with pytest.raises(m.NamedSessionBindingError):
        operation.establish()


def test_real_browser_activity_refreshes_idle_but_internal_checks_do_not(fixture):
    s = fixture
    operation = s.helper.for_cookie(s.cookie)
    original = operation.establish()
    s.now += timedelta(minutes=20)
    browser = s.sessions.user(s.cookie, s.now)
    assert browser.last_seen_at == s.now
    after_browser = _sealed_session_rows(s)
    s.now = original.issued_at + timedelta(minutes=49)
    assert operation.recheck(original.binding_digest) == original
    assert _sealed_session_rows(s) == after_browser
    s.now += timedelta(minutes=1)
    with pytest.raises(m.NamedSessionBindingError):
        operation.establish()


def test_idle_deadline_crossed_by_last_clock_read_cannot_be_acknowledged(fixture):
    s = fixture
    observed = 0

    def reader():
        nonlocal observed
        observed += 1
        if observed == 3:
            s.now += timedelta(minutes=30)
        return s.now

    helper = m.NamedSessionContinuity(**{**s.args, "clock": HostObservedClock(reader)})
    original_rows = _sealed_session_rows(s)
    with pytest.raises(m.NamedSessionBindingError):
        helper.for_cookie(s.cookie).establish()
    assert observed == 3
    assert _sealed_session_rows(s) == original_rows
