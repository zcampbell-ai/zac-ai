"""Actual nested disposable OWNER leases, one invented listener/provider only."""

from __future__ import annotations

import fcntl
import os
import re
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_gmail_setup import Fixture as SetupFixture
from tests.test_oauth_transactions import Registration
from tests.test_private_host import CONFIG, ORIGIN, InventedIdentity, enroll, sign_in
from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
from zacai.connectors.oauth_host_guard import OAuthHostGuard
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError, GmailRecoveryHostPlan
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_host import prepare_owner_host
from zacai.interfaces.private_web import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

PATH = "/connections/gmail/recover"


class Fixture(SetupFixture):
    def __init__(self, temporary, monkeypatch):
        super().__init__(temporary, monkeypatch)
        self.hr_directory = temporary / "restricted-owner"
        enroll(
            self.hr_directory,
            self.clock,
            scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.HIGHLY_RESTRICTED})),),
        )
        self.directory = temporary / "original-owner"
        enroll(
            self.directory,
            self.clock,
            scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
        )
        for root in (self.directory, self.hr_directory):
            (root / "private-mode.lock").write_bytes(b"")
            (root / "private-mode.lock").chmod(0o600)

        async def view(principal):
            return "invented original view"

        prepared = prepare_owner_host(
            configuration=CONFIG,
            directory=self.directory,
            view=view,
            clock=self.clock,
            identities=InventedIdentity(self.clock),
        )
        continuity = NamedSessionContinuity(
            sessions=prepared.sessions,
            owner=prepared.owners.load,
            clock=self.clock,
            key=CONFIG.session_key,
            origin=ORIGIN,
            client_id=CONFIG.client_id,
        )
        guard = OAuthHostGuard(
            self.directory / "gmail-oauth-guard",
            key=CONFIG.session_key,
            origin=ORIGIN,
            client_id=CONFIG.client_id,
        )
        (self.directory / "gmail-oauth-guard").mkdir(mode=0o700)
        guard.initialize()
        guard.halt_unconfirmed()
        self.authority = OAuthTransactionAuthority(
            self.directory / "gmail-oauth-transactions",
            key=CONFIG.session_key,
            continuity=continuity,
            registration_backend=Registration(),
        )
        self.authority.initialize()
        with self.authority._locked():
            value = self.authority._read()
            _, account = self.authority._configuration(self.configuration, None)
            self.old_state = "a" * 64
            self.old_row = {
                "configuration": self.configuration.configuration_digest,
                "account": account,
                "binding": "b" * 64,
                "generation": "invented-historical-generation",
                "rotation": None,
                "expires": (self.now + timedelta(minutes=5)).isoformat(),
                "state": "held",
                "verifier": None,
                "execution": "c" * 64,
                "loaded": True,
            }
            value["rows"][self.old_state] = self.old_row
            self.authority._write(value)

    def recovery_plan(self, monkeypatch, **changes):
        fields = {
            "configuration": self.configuration,
            "original_directory": self.directory,
            "hr_directory": self.hr_directory,
            "owner_client_id": CONFIG.client_id,
            "startup_loader": self.startup,
            "clock": self.clock,
            "escrow_confirmed_by_operator": True,
            "reviewed_registration_generation": "invented-current-registration",
            "console_observed_at": self.now,
            "review_expires_at": self.now + timedelta(minutes=30),
            "action_generation": "invented-recovery-v1",
            "identities": InventedIdentity(self.clock),
        }
        fields.update(changes)
        plan = GmailRecoveryHostPlan(**fields)
        monkeypatch.setattr(plan._server, "_factory", self.server_factory)
        return plan

    def both_leases(self):
        for root in (self.directory, self.hr_directory):
            fd = os.open(root / "private-mode.lock", os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)


def form(browser):
    page = browser.get(PATH)
    assert page.status_code == 200
    return dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))


def test_inert_nested_actual_owner_contexts_one_listener_two_startup_reads(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    old_owner = (f.directory / "owner/owner.json").read_bytes()
    hr_owner = (f.hr_directory / "owner/owner.json").read_bytes()
    ready = (f.directory / "gmail-oauth-guard/oauth-host.ready").read_bytes()
    halt = (f.directory / "gmail-oauth-guard/oauth-host.halted").read_bytes()
    plan = f.recovery_plan(monkeypatch)
    assert not f.shared_reads and not f.server_runs

    def browse(browser):
        f.both_leases()
        assert plan._windows.original._serving is False and plan._windows.hr._serving is True
        assert plan._windows.original_inputs.session_key is plan._windows.hr_inputs.session_key
        assert plan._runtime is plan._capture[5]
        assert browser.get("/").status_code == 303
        sign_in(browser)
        assert browser.get(PATH).status_code == 200
        assert browser.get("/connections/gmail/begin").status_code == 404
        assert len([r for r in f.servers[-1].app.routes if r.path == "/auth/callback"]) == 1
        assert (
            len([r for r in f.servers[-1].app.routes if r.path == "/connections/gmail/callback"])
            == 1
        )
        f.both_leases()

    f.browser_action = browse
    plan.run()
    assert (
        f.server_runs == 1
        and len(f.shared_reads) == 2
        and not f.secret_reads
        and not f.provider_calls
        and not f.native_factories
    )
    assert (f.directory / "owner/owner.json").read_bytes() == old_owner
    assert (f.hr_directory / "owner/owner.json").read_bytes() == hr_owner
    assert (f.directory / "gmail-oauth-guard/oauth-host.ready").read_bytes() == ready
    assert (f.directory / "gmail-oauth-guard/oauth-host.halted").read_bytes() == halt
    assert plan._runtime is plan._windows is plan._consumer is None
    with pytest.raises(GmailRecoveryHostError):
        plan.run()
    assert len(f.shared_reads) == 2


def test_pair_journal_fresh_exchange_existing_profile_and_held_native_pair(tmp_path, monkeypatch):
    import zacai.interfaces.gmail_recovery_host as host_module

    f = Fixture(tmp_path, monkeypatch)
    actual_stage = HeldGmailNativeStage
    monkeypatch.setattr(
        host_module,
        "HeldGmailNativeStage",
        lambda **kwargs: actual_stage(**kwargs, bindings_factory=f.native_factory),
    )
    monkeypatch.setattr(host_module, "OAuthExchangeTransport", lambda: f.transport)
    plan = f.recovery_plan(monkeypatch)

    def browse(browser):
        sign_in(browser)
        for target in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
            fields = form(browser)
            response = browser.post(target, data=fields, headers={"origin": ORIGIN})
            assert response.status_code in (200, 303)
            f.both_leases()
        fields = form(browser)
        response = browser.post(
            "/connections/gmail/recover/begin", data=fields, headers={"origin": ORIGIN}
        )
        assert response.status_code == 303
        state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
        callback = browser.get(
            "/connections/gmail/callback", params={"state": state, "code": "invented-fresh-code"}
        )
        assert callback.status_code == 200
        assert callback.json()["profile_verified"] is True
        assert callback.json()["installed"] is callback.json()["credential_authority"] is False
        assert callback.json()["original_actor_verified"] is False
        assert (
            callback.json()["processing_authorized"]
            is callback.json()["execution_authorized"]
            is False
        )
        f.both_leases()
        assert browser.get(PATH).status_code == 200

    f.browser_action = browse
    plan.run()
    with f.authority._locked():
        value = f.authority._read()
    assert len(value["rows"]) == 2 and value["rows"][f.old_state] == f.old_row
    fresh = next(row for key, row in value["rows"].items() if key != f.old_state)
    assert fresh["state"] == "held" and fresh["loaded"] is True
    assert (
        len(f.shared_reads) == 2
        and len(f.secret_reads) == 1
        and len(f.provider_calls) == 3
        and len(f.native_factories) == 1
    )
    assert all(connection.closed for connection in f.connections)
    assert (
        f.directory / "gmail-oauth-guard/oauth-host.halted"
    ).read_bytes() == b"zac-oauth-host-halted-v1\n"


@pytest.mark.parametrize(
    "change", ["missing_halt", "forged_halt", "forged_ready", "expired_review"]
)
def test_original_authenticated_markers_and_review_required_before_listener(
    tmp_path, monkeypatch, change
):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    if change == "expired_review":
        f.now += timedelta(hours=1)
    else:
        path = (
            f.directory
            / "gmail-oauth-guard"
            / ("oauth-host.ready" if change == "forged_ready" else "oauth-host.halted")
        )
        if change == "missing_halt":
            path.unlink()
        else:
            path.write_bytes(b"invented-forged-marker")
    with pytest.raises(GmailRecoveryHostError):
        plan.run()
    assert (
        not f.server_runs and not f.secret_reads and not f.provider_calls and not f.native_factories
    )
    assert plan._runtime is plan._windows is None
    assert len(f.shared_reads) == (0 if change in {"missing_halt", "expired_review"} else 2)


@pytest.mark.parametrize("stream", ["stdin", "stdout", "stderr"])
def test_three_tty_attempt_spent_before_startup(tmp_path, monkeypatch, stream):
    import sys

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)
    monkeypatch.setattr(getattr(sys, stream), "isatty", lambda: False)
    with pytest.raises(GmailRecoveryHostError):
        plan.run()
    monkeypatch.setattr(getattr(sys, stream), "isatty", lambda: True)
    with pytest.raises(GmailRecoveryHostError):
        plan.run()
    assert not f.shared_reads and not f.server_runs


@pytest.mark.parametrize("child", ["marker_path", "continuity_clock", "owner_path"])
def test_original_captured_children_cannot_be_replaced(tmp_path, monkeypatch, child):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    def browse(browser):
        if child == "marker_path":
            obj, field = plan._markers, "_ready_path"
            replacement = f.directory / "invented-other-ready"
        elif child == "continuity_clock":
            obj, field = plan._hr_continuity, "_clock"
            replacement = lambda: f.now
        else:
            obj, field = plan._windows.original_inputs.owners, "_path"
            replacement = f.directory / "invented-other-owner"
        original = getattr(obj, field)
        setattr(obj, field, replacement)
        try:
            with pytest.raises(ValueError):
                plan._recovery_current()
        finally:
            setattr(obj, field, original)
        assert plan._recovery_current() is None
        f.both_leases()

    f.browser_action = browse
    plan.run()
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


@pytest.mark.parametrize("cancelled", [False, True])
def test_actual_physical_thread_drain_retains_both_owner_leases(tmp_path, monkeypatch, cancelled):
    import threading

    f = Fixture(tmp_path, monkeypatch)
    server_done = threading.Event()
    checked = []
    errors = []
    original_factory = f.server_factory

    def factory(app):
        server = original_factory(app)
        actual_run = server.run

        def run():
            actual_run()
            server_done.set()
            if cancelled:
                raise KeyboardInterrupt("invented server cancellation")

        server.run = run
        return server

    f.server_factory = factory
    plan = f.recovery_plan(monkeypatch)

    def browse(browser):
        def worker():
            try:
                assert server_done.wait(3)
                f.both_leases()
                assert plan._windows.original._active and plan._windows.hr._active
                checked.append(True)
            except BaseException as error:  # noqa: BLE001 - surface invented worker failures
                errors.append(type(error))

        threading.Thread(target=worker).start()

    f.browser_action = browse
    if cancelled:
        with pytest.raises(GmailRecoveryHostError):
            plan.run()
    else:
        plan.run()
    assert checked == [True] and not errors
    assert plan._windows is None and plan._runtime is None
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
