"""Honest foreground install teardown and new actual owner restart composition."""

from __future__ import annotations

from tests.test_gmail_installation import fixture, fresh, install
from tests.test_gmail_recovery_host import form
from tests.test_private_host import ORIGIN, sign_in
from zacai.interfaces.gmail_recovery_host import (
    GmailRecoveryHostError,
    GmailRecoveryHostFatal,
    GmailRecoveryHostPlan,
)


def fixture_restarted(tmp_path, monkeypatch):
    f, original = fixture(tmp_path, monkeypatch)
    failures = []

    def baseline(browser):
        try:
            fresh(browser)
            install(browser)
            assert (
                browser.post(
                    "/connector-review", data=form(browser), headers={"origin": ORIGIN}
                ).status_code
                == 303
            )
            reply = browser.post(
                "/connector-execute", data=form(browser), headers={"origin": ORIGIN}
            )
            assert reply.status_code == 200 and reply.json()["profile_verified"] is True
        except BaseException as error:  # noqa: BLE001 - only invented fixture diagnostics
            failures.append(error)

    f.browser_action = baseline
    original.run()
    if failures:
        raise failures[0]
    assert original._runtime is original._windows is original._consumer is None
    new = GmailRecoveryHostPlan(
        configuration=f.configuration,
        original_directory=f.directory,
        hr_directory=f.hr_directory,
        owner_client_id=original._owner_client_id,
        startup_loader=original._loader,
        clock=f.clock,
        escrow_confirmed_by_operator=True,
        reviewed_registration_generation=original._generation,
        console_observed_at=original._observed,
        review_expires_at=original._expires,
        action_generation="invented-new-reopen-action",
        identities=original._identities,
        load_existing=True,
    )
    new._server._factory = f.server_factory
    return f, new


def test_honest_teardown_new_owner_load_and_new_concrete_gateway_review(tmp_path, monkeypatch):
    f, plan = fixture_restarted(tmp_path, monkeypatch)
    failures = []
    before = len(f.shared_reads), len(f.secret_reads), len(f.provider_calls)

    def browse(browser):
        try:
            sign_in(browser)
            assert browser.get("/connections/gmail/reopen").status_code == 200
            for path in (
                "/connections/gmail/recover/begin",
                "/connections/gmail/install",
                "/connections/gmail/callback",
            ):
                assert browser.get(path).status_code in (404, 405)
            page = browser.get("/connections/gmail/reopen")
            import re

            fields = dict(re.findall('name="([^"]+)" value="([^"]*)"', page.text))
            paired = browser.post(
                "/connections/gmail/recover/pair", data=fields, headers={"origin": ORIGIN}
            )
            assert paired.status_code == 303
            f.both_leases()
            assert plan._loaded._issued is not None and plan._consumer is None
            page = browser.get("/connections/gmail/reopen")
            fields = dict(re.findall('name="([^"]+)" value="([^"]*)"', page.text))
            assert (
                browser.post(
                    "/connector-review", data=fields, headers={"origin": ORIGIN}
                ).status_code
                == 303
            )
            page = browser.get("/connections/gmail/reopen")
            fields = dict(re.findall('name="([^"]+)" value="([^"]*)"', page.text))
            reply = browser.post("/connector-execute", data=fields, headers={"origin": ORIGIN})
            assert reply.status_code == 200 and reply.json()["profile_verified"] is True
            assert reply.json()["original_actor_verified"] is False
        except BaseException as error:  # noqa: BLE001 - surface invented failures after teardown
            failures.append(error)

    f.browser_action = browse
    try:
        plan.run()
    except (GmailRecoveryHostError, GmailRecoveryHostFatal):
        if not failures:
            raise
    if failures:
        raise failures[0]
    assert len(f.shared_reads) == before[0] + 2 and len(f.secret_reads) == before[1]
    assert plan._loaded is plan._runtime is plan._windows is None


def _new_restart_plan(f, prior):
    plan = GmailRecoveryHostPlan(
        configuration=f.configuration,
        original_directory=f.directory,
        hr_directory=f.hr_directory,
        owner_client_id=prior._owner_client_id,
        startup_loader=prior._loader,
        clock=f.clock,
        escrow_confirmed_by_operator=True,
        reviewed_registration_generation=prior._generation,
        console_observed_at=prior._observed,
        review_expires_at=prior._expires,
        action_generation="invented-new-reopen-action",
        identities=prior._identities,
        load_existing=True,
    )
    plan._server._factory = f.server_factory
    return plan


def test_authenticated_restart_denies_corrupt_active_pending_only_and_residue(
    tmp_path, monkeypatch
):
    import os

    import pytest

    from tests.test_gmail_installed_load_audit import reopen_form, run_restarted
    from tests.test_private_host import CONFIG
    from zacai.connectors.connector_authority import _json
    from zacai.connectors.gmail_installation import ACTIVE, QUARANTINED
    from zacai.connectors.gmail_installed_load import _cipher, _record

    f, proposal = fixture_restarted(tmp_path, monkeypatch)
    path = f.authority._directory / ACTIVE
    original = path.read_bytes()
    context = b"zac-fresh-gmail-installation-v1\x00" + f.authority._context
    cipher = _cipher(CONFIG.session_key, b"zac-fresh-gmail-installation-v1", context)
    record = _record(cipher, original, context)
    variants = [original[:-1] + bytes([original[-1] ^ 1])]
    for field, value in (("version", True), ("pair_hash", "f" * 64)):
        altered = dict(record, **{field: value})
        nonce = b"B" * 12
        variants.append(nonce + cipher.encrypt(nonce, _json(altered), context))
    for altered in variants:
        path.write_bytes(altered)
        plan = _new_restart_plan(f, proposal)
        before = len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)

        def browse(browser):
            sign_in(browser)
            denied = browser.post(
                "/connections/gmail/recover/pair",
                data=reopen_form(browser),
                headers={"origin": ORIGIN},
            )
            assert denied.status_code == 403 and f.servers[-1].should_exit
            f.both_leases()

        run_restarted(f, plan, browse)
        assert (len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)) == before
    path.write_bytes(original)
    for residue in (None, QUARANTINED, "unexpected-owned-child"):
        extra = None
        if residue is None:
            path.unlink()
        else:
            extra = f.authority._directory / residue
            extra.write_bytes(b"invented-residue")
            os.chmod(extra, 0o600)
        plan = _new_restart_plan(f, proposal)
        before = (
            len(f.shared_reads), len(f.secret_reads),
            len(f.provider_calls), len(f.reader_bindings),
        )
        with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
            plan.run()
        assert (
            len(f.shared_reads), len(f.secret_reads),
            len(f.provider_calls), len(f.reader_bindings),
        ) == before
        if extra is not None:
            extra.unlink()
        else:
            path.write_bytes(original)
            os.chmod(path, 0o600)


def test_quarantine_denies_same_owned_directory_mode_change_and_closes_fd(
    tmp_path, monkeypatch
):
    import os

    import pytest

    from tests.test_gmail_installed_load_audit import paired_restart, run_restarted
    from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAuthorizationError

    f, plan = fixture_restarted(tmp_path, monkeypatch)
    events = []

    def browse(browser):
        paired_restart(browser)
        loader, cap = plan._loaded, plan._loaded._issued
        original_open, original_write, original_close = os.open, os.write, os.close
        owned_directory = []

        def opened(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if path == loader._directory and flags & os.O_DIRECTORY:
                owned_directory.append(fd)
            return fd

        def written(fd, value):
            result = original_write(fd, value)
            if fd == loader._quarantine_fd:
                os.chmod(loader._directory, 0o750)
                events.append("unsafe-mode")
            return result

        def closed(fd):
            if fd in owned_directory:
                events.append("owned-directory-closed")
            return original_close(fd)

        with monkeypatch.context() as patch:
            patch.setattr(os, "open", opened)
            patch.setattr(os, "write", written)
            patch.setattr(os, "close", closed)
            with pytest.raises(GmailRecoveryAuthorizationError):
                cap.quarantine()
        assert events == ["unsafe-mode", "owned-directory-closed"]
        assert loader._quarantine_fd is None and loader._quarantined is False
        assert owned_directory
        with pytest.raises(OSError):
            os.fstat(owned_directory[0])
        os.chmod(loader._directory, 0o700)
        f.both_leases()

    run_restarted(f, plan, browse)


def test_loaded_web_rejects_exact_class_installation_transplant_before_callbacks(
    tmp_path, monkeypatch
):
    from tests.test_gmail_installed_load_audit import paired_restart, run_restarted
    from zacai.connectors.gmail_installation import GmailInstallation
    from zacai.interfaces.gmail_installed_web import GmailInstalledWeb

    f, plan = fixture_restarted(tmp_path, monkeypatch)
    before = len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)

    def browse(browser):
        paired_restart(browser)
        route = next(
            route for route in browser.app.routes
            if getattr(route, "path", None) == "/connections/gmail/reopen"
        )
        web = next(
            cell.cell_contents for cell in route.endpoint.__closure__
            if type(cell.cell_contents) is GmailInstalledWeb
        )
        original = web._installation
        assert type(original) is GmailInstallation
        clone = object.__new__(GmailInstallation)
        vars(clone).update(vars(original))
        import pytest

        original_clock = f.clock._read
        triggered = []

        def replacing_clock():
            if not triggered:
                triggered.append(True)
                web._installation = clone
            return original_clock()

        with monkeypatch.context() as patch:
            patch.setattr(f.clock, "_read", replacing_clock)
            with pytest.raises(ValueError, match="original reopened installation"):
                web._current()
        assert triggered == [True]
        web._installation = original
        web._current()
        web._installation = clone
        denied = browser.get("/connections/gmail/reopen")
        assert denied.status_code == 403 and f.servers[-1].should_exit
        assert web._original_installation is original
        f.both_leases()

    run_restarted(f, plan, browse)
    assert (len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)) == before
