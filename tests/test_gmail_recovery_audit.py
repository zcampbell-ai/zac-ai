"""Actual disposable nested owner contexts; no live providers or native calls."""

from datetime import timedelta

import pytest

from tests.test_gmail_recovery_host import Fixture, form
from tests.test_private_host import ORIGIN, sign_in
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError, GmailRecoveryHostFatal
from zacai.policy import DataClassification as C


def run_checked(f, plan, check, *, allow_terminal=True):
    failures = []
    completed = []

    def browse(browser):
        try:
            check(browser)
            completed.append(True)
        except BaseException as error:
            failures.append(error)
            raise

    f.browser_action = browse
    terminal = None
    try:
        plan.run()
    except (GmailRecoveryHostError, GmailRecoveryHostFatal) as error:
        terminal = error
    if failures:
        raise failures[0]
    assert completed == [True]
    if terminal is not None and not allow_terminal:
        raise terminal
    return terminal


def pair(browser):
    sign_in(browser)
    response = browser.post(
        "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
    )
    assert response.status_code == 303


def test_private_paired_action_reports_bounded_deadline_without_original_grant_upgrade(
    tmp_path, monkeypatch
):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    old_owner = (f.directory / "owner/owner.json").read_bytes()

    def check(browser):
        pair(browser)
        f.both_leases()
        action = plan._join._action
        assert action.current() == action._expires > f.now
        assert action._scope() == action._expires
        original_grant = plan._original_continuity._grant()
        assert all(
            C.HIGHLY_RESTRICTED not in scope.classifications for scope in original_grant.scopes
        )
        assert action.original_actor_verified is action.installed is False
        assert (f.directory / "owner/owner.json").read_bytes() == old_owner

    run_checked(f, plan, check, allow_terminal=False)
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


@pytest.mark.parametrize("change", ["original_revoke", "hr_revoke", "expire"])
def test_private_action_rechecks_actual_both_sessions_and_expiry(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    def check(browser):
        pair(browser)
        action = plan._join._action
        action.current()
        if change == "original_revoke":
            plan._original_continuity._sessions.revoke(action._original_cookie)
        elif change == "hr_revoke":
            plan._hr_continuity._sessions.revoke(action._hr_cookie)
        else:
            f.now = action._expires + timedelta(microseconds=1)
        with pytest.raises(ValueError):
            action.current()
        f.both_leases()
        assert not plan._consumer._spent
        assert not f.secret_reads and not f.provider_calls and not f.native_factories

    run_checked(f, plan, check)
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    assert rows == {f.old_state: f.old_row}


@pytest.mark.parametrize("change", ["origin", "csrf", "extra_identity", "duplicate_csrf"])
def test_pairing_rejects_browser_authority_before_private_session_issue(
    tmp_path, monkeypatch, change
):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    def check(browser):
        sign_in(browser)
        fields = form(browser)
        origin = ORIGIN
        if change == "origin":
            origin = "https://foreign.example.invalid"
        elif change == "csrf":
            fields["csrf"] = "invented-foreign-csrf"
        elif change == "extra_identity":
            fields["subject"] = "invented-stable-owner"
        from urllib.parse import urlencode

        body = urlencode(fields)
        if change == "duplicate_csrf":
            body += "&csrf=" + fields["csrf"]
        response = browser.post(
            "/connections/gmail/recover/pair",
            content=body,
            headers={"origin": origin, "content-type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 403
        assert plan._join._action is None and not plan._join._pairing_spent
        assert plan._consumer is None
        f.both_leases()

    run_checked(f, plan, check)
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_durable_recovery_spend_precedes_fresh_state_and_failure_never_refunds(
    tmp_path, monkeypatch
):
    from zacai.connectors.gmail_recovery_consumer import SPEND_NAME
    from zacai.connectors.oauth_transactions import OAuthTransactionAuthority

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    observed = []
    saved_spend = []

    def refuse_fresh(authority, *args, **kwargs):
        f.both_leases()
        spend = authority._directory / SPEND_NAME
        assert spend.is_file() and spend.stat().st_mode & 0o777 == 0o600
        saved_spend.append(spend.read_bytes())
        with authority._locked():
            assert authority._read()["rows"] == {f.old_state: f.old_row}
        observed.append(True)
        raise ValueError("invented fresh preparation failure")

    monkeypatch.setattr(OAuthTransactionAuthority, "begin_recovery", refuse_fresh)

    def check(browser):
        pair(browser)
        response = browser.post(
            "/connections/gmail/quarantine", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 303
        fields = form(browser)
        response = browser.post(
            "/connections/gmail/recover/begin", data=fields, headers={"origin": ORIGIN}
        )
        assert response.status_code == 403
        assert plan._consumer._spent
        assert observed == [True]
        assert (
            browser.post(
                "/connections/gmail/recover/begin", data=fields, headers={"origin": ORIGIN}
            ).status_code
            == 403
        )
        assert observed == [True]
        f.both_leases()

    run_checked(f, plan, check)
    assert (f.directory / "gmail-oauth-transactions" / SPEND_NAME).read_bytes() == saved_spend[0]
    with f.authority._locked():
        assert f.authority._read()["rows"] == {f.old_state: f.old_row}
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_same_issuer_different_saved_subject_cannot_pair_domains(tmp_path, monkeypatch):
    import tests.test_gmail_recovery_host as fixture_module
    import tests.test_private_host as identity_fixture
    from zacai.interfaces.session_store import Identity

    original_enroll = fixture_module.enroll

    def enroll_distinct(directory, clock, scopes):
        if directory.name == "original-owner":
            with monkeypatch.context() as local:
                local.setattr(
                    identity_fixture,
                    "OWNER",
                    Identity(identity_fixture.OWNER.issuer, "invented-other-stable-subject"),
                )
                return original_enroll(directory, clock, scopes=scopes)
        return original_enroll(directory, clock, scopes=scopes)

    monkeypatch.setattr(fixture_module, "enroll", enroll_distinct)
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    with pytest.raises(GmailRecoveryHostError):
        plan.run()
    assert not f.server_runs
    assert plan._consumer is None
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_saved_original_owner_revocation_after_pair_session_write_denies_action(
    tmp_path, monkeypatch
):
    from zacai.interfaces.sqlite_sessions import SqliteSessionStore

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    original_start = SqliteSessionStore.start_user
    revoked = []

    def start_and_revoke(store, identity, now):
        cookie = original_start(store, identity, now)
        if plan._active and store is plan._original_continuity._sessions:
            f.both_leases()
            plan._windows.original._prepared.revoke_owner()
            revoked.append(True)
        return cookie

    monkeypatch.setattr(SqliteSessionStore, "start_user", start_and_revoke)

    def check(browser):
        sign_in(browser)
        response = browser.post(
            "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 403
        assert revoked == [True]
        assert plan._join._pairing_spent and plan._join._action is None
        assert plan._consumer is None
        assert f.servers[-1].should_exit
        f.both_leases()

    run_checked(f, plan, check)
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_spend_descriptor_reuse_at_owner_clock_never_touches_foreign_file(tmp_path, monkeypatch):
    import os

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    foreign = tmp_path / "invented-foreign-file"
    foreign.write_bytes(b"invented untouched foreign bytes")
    foreign_inode = foreign.stat().st_ino
    read_clock = f.clock._read
    raw_close, raw_open, raw_dup2 = os.close, os.open, os.dup2
    foreign_effects, reused = [], []

    def is_foreign(fd):
        try:
            return os.fstat(fd).st_ino == foreign_inode
        except OSError:
            return False

    for name in ("write", "pread", "read", "fsync", "close"):
        original = getattr(os, name)

        def observe(fd, *args, _name=name, _original=original):
            if is_foreign(fd):
                foreign_effects.append(_name)
            return _original(fd, *args)

        monkeypatch.setattr(os, name, observe)

    def owner_clock():
        result = read_clock()
        consumer = plan._consumer
        if consumer is not None and consumer._spend_fd is not None and not reused:
            target = consumer._spend_fd
            raw_close(target)
            replacement = raw_open(foreign, os.O_RDWR)
            if replacement != target:
                raw_dup2(replacement, target)
                raw_close(replacement)
            reused.append(target)
        return result

    monkeypatch.setattr(f.clock, "_read", owner_clock)

    def check(browser):
        pair(browser)
        assert (
            browser.post(
                "/connections/gmail/quarantine", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        response = browser.post(
            "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 403
        assert len(reused) == 1 and not foreign_effects
        assert plan._consumer._spent
        assert os.fstat(reused[0]).st_ino == foreign_inode
        f.both_leases()

    try:
        run_checked(f, plan, check)
        assert not foreign_effects
        assert foreign.read_bytes() == b"invented untouched foreign bytes"
    finally:
        for fd in reused:
            raw_close(fd)
    with f.authority._locked():
        assert f.authority._read()["rows"] == {f.old_state: f.old_row}
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


@pytest.mark.parametrize("stop_fails", [False, True])
def test_actual_mounted_route_cancel_is_private_safe_and_terminal_under_both_leases(
    tmp_path, monkeypatch, stop_fails
):
    import asyncio

    import anyio
    from starlette.requests import Request

    from tests.test_gmail_setup import Server
    from zacai.interfaces.gmail_recovery_web import GmailRecoveryWeb, GmailRecoveryWebFatal

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    attempts = []
    raw_setattr = Server.__setattr__

    def set_exit(server, name, value):
        raw_setattr(server, name, value)
        if name == "should_exit" and value is True:
            attempts.append(True)
            if stop_fails:
                raise RuntimeError("invented private stop callback failure")

    monkeypatch.setattr(Server, "__setattr__", set_exit)

    def check(browser):
        sign_in(browser)
        app = f.servers[-1].app
        endpoint = next(
            route.endpoint for route in app.routes if route.path == "/connections/gmail/recover"
        )
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/connections/gmail/recover",
                "query_string": b"invented-private-query",
                "headers": [(b"host", b"caz.example.test")],
                "server": ("caz.example.test", 443),
            }
        )

        def cancel(web, incoming):
            raise asyncio.CancelledError("invented-private-cancellation")

        with monkeypatch.context() as local:
            local.setattr(GmailRecoveryWeb, "_page", cancel)
            with pytest.raises(GmailRecoveryWebFatal) as raised:
                anyio.run(endpoint, request)
        error = raised.value
        assert error.__context__ is error.__cause__ is None
        assert "invented-private" not in str(error)
        frame = error.__traceback__
        audited = []
        while frame:
            if frame.tb_frame.f_code.co_filename.endswith("gmail_recovery_web.py"):
                values = frame.tb_frame.f_locals
                assert "request" not in values
                assert (
                    not values.get("body") and not values.get("text") and not values.get("consent")
                )
                audited.append(True)
            frame = frame.tb_next
        assert audited
        assert attempts == [True] and f.servers[-1].should_exit
        assert browser.get("/connections/gmail/recover").status_code == 403
        assert browser.get("/login").status_code == 403
        f.both_leases()

    terminal = run_checked(f, plan, check)
    assert isinstance(terminal, GmailRecoveryHostFatal)
    assert plan._windows is plan._consumer is plan._runtime is None
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


@pytest.mark.parametrize("domain", ["original", "hr"])
def test_terminal_owner_clock_revocation_cannot_return_private_action_deadline(
    tmp_path, monkeypatch, domain
):
    import inspect

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    revoked = []

    def check(browser):
        pair(browser)
        action = plan._join._action
        original_read = f.clock._read

        def late_clock():
            # Target the documented last-clock seam after both session snapshots,
            # without depending on the number of earlier authentication callbacks.
            frame = inspect.currentframe()
            terminal = False
            try:
                while frame:
                    if (
                        frame.f_code.co_name == "_current"
                        and frame.f_globals.get("__name__")
                        == "zacai.connectors.gmail_recovery_authorization"
                        and "hr_before" in frame.f_locals
                    ):
                        terminal = True
                        break
                    frame = frame.f_back
            finally:
                del frame
            if terminal and not revoked:
                continuity = (
                    plan._original_continuity if domain == "original" else plan._hr_continuity
                )
                cookie = action._original_cookie if domain == "original" else action._hr_cookie
                continuity._sessions.revoke(cookie)
                revoked.append(True)
            return original_read()

        with monkeypatch.context() as local:
            local.setattr(f.clock, "_read", late_clock)
            with pytest.raises(ValueError, match="terminal paired owner session changed"):
                action.current()
        assert revoked == [True]
        f.both_leases()

    run_checked(f, plan, check)
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_terminal_saved_owner_callback_clock_jump_cannot_use_stale_observation(
    tmp_path, monkeypatch
):
    import inspect
    import os

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    advanced = []

    def check(browser):
        pair(browser)
        action = plan._join._action
        owner_inode = (f.directory / "owner/owner.json").stat().st_ino
        raw_read = os.read

        def late_owner_read(fd, *args):
            value = raw_read(fd, *args)
            frame = inspect.currentframe()
            terminal = False
            try:
                while frame:
                    if (
                        frame.f_code.co_name == "_grant"
                        and frame.f_back is not None
                        and frame.f_back.f_code.co_name == "_current"
                        and frame.f_back.f_globals.get("__name__")
                        == "zacai.connectors.gmail_recovery_authorization"
                        and "hr_before" in frame.f_back.f_locals
                    ):
                        terminal = True
                        break
                    frame = frame.f_back
            finally:
                del frame
            if terminal and os.fstat(fd).st_ino == owner_inode and not advanced:
                f.now = action._expires + timedelta(microseconds=1)
                advanced.append(True)
            return value

        with monkeypatch.context() as local:
            local.setattr(os, "read", late_owner_read)
            with pytest.raises(ValueError):
                action.current()
        assert advanced == [True]
        f.both_leases()

    run_checked(f, plan, check)
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
