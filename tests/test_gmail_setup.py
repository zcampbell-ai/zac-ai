"""Concrete foreground setup with disposable crypto and invented OS/provider seams."""

from __future__ import annotations

import ctypes
import fcntl
import json
import os
import subprocess
import sys
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from tests.test_gmail_connection_web import SCOPE
from tests.test_gmail_native_staging import InventedBindings
from tests.test_oauth_configuration import gmail
from tests.test_private_host import CONFIG, NOW, ORIGIN, InventedIdentity, enroll
from zacai.connectors.oauth_exchange import OAuthExchangeTransport
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_startup import OwnerStartupLoader

ACCESS = "invented-concrete-setup-access"
REFRESH = "invented-concrete-setup-refresh"
SUBJECT = "invented-concrete-setup-subject"
SECRET = b"invented-concrete-gmail-client-secret\n"


class Response:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def getheader(self, name):
        return "application/json" if name.lower() == "content-type" else None

    def read(self, amount):
        return self.body[:amount]


class Connection:
    def __init__(self, fixture, host, response):
        self.fixture, self.host, self.response = fixture, host, response
        self.closed = False

    def request(self, method, path, body, headers):
        self.fixture.provider_calls.append((self.host, method, path))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class Server:
    def __init__(self, fixture, app):
        self.fixture, self.app = fixture, app
        self.should_exit = False

    def run(self):
        self.fixture.server_runs += 1
        with TestClient(self.app, base_url=ORIGIN, follow_redirects=False) as browser:
            if self.fixture.browser_action:
                self.fixture.browser_action(browser)


class Fixture:
    def __init__(self, temporary, monkeypatch):
        self.directory = temporary / "private-owner"
        self.now = NOW
        self.clock = HostObservedClock(lambda: self.now)
        enroll(self.directory, self.clock, scopes=(SCOPE,))
        self.configuration = gmail(private_origin=ORIGIN)
        parent = temporary / "invented-keychains"
        parent.mkdir(mode=0o700)
        self.keychain = parent / "login.keychain-db"
        self.keychain.write_bytes(b"invented metadata only")
        self.keychain.chmod(0o644)
        self.startup = OwnerStartupLoader(
            client_id=CONFIG.client_id,
            origin=ORIGIN,
            keychain_path=self.keychain,
            mode="foreground",
            foreground_timeout_seconds=120,
            keychain_file_policy="reviewed_login",
        )
        self.owner_loads = self.server_runs = 0
        self.secret_reads, self.provider_calls, self.connections, self.native_factories = (
            [],
            [],
            [],
            [],
        )
        self.browser_action = None
        self.bindings = InventedBindings()
        self.transport = OAuthExchangeTransport(connection_factory=self.connect)
        self.servers = []

        self.shared_reads = []
        self.startup_session_key = CONFIG.session_key
        self.read_action = None

        def secret_read(argv, **kwargs):
            assert argv[0:2] == ["/usr/bin/security", "find-generic-password"]
            assert argv[4] == "-s" and argv[6:] == ["-w", str(self.keychain)]
            service = argv[5]
            assert kwargs == {
                "shell": False,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
                "timeout": 120,
                "check": False,
                "env": {},
            }
            self.held_lease()
            if service == "zacai-shared-owner-google-client-secret":
                assert argv[2:4] == ["-a", "zac-owner-sign-in"]
                self.shared_reads.append(service)
                output = CONFIG.client_secret.encode() + b"\n"
            elif service == "zacai-shared-owner-session-key":
                assert argv[2:4] == ["-a", "zac-owner-sign-in"]
                self.shared_reads.append(service)
                self.owner_loads += 1
                output = b"hex:" + self.startup_session_key.hex().encode() + b"\n"
            else:
                assert service == "zacai-brainstorm-gmail-client-secret"
                assert argv[2:4] == ["-a", "zac-owner-source-access"]
                self.secret_reads.append(True)
                output = SECRET
            if self.read_action:
                self.read_action(service)
            return subprocess.CompletedProcess(argv, 0, stdout=output)

        def forbid_native(*args, **kwargs):
            raise AssertionError("Actual native library forbidden in invented concrete setup tests")

        monkeypatch.setattr(subprocess, "run", secret_read)
        monkeypatch.setattr(ctypes, "CDLL", forbid_native)
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            monkeypatch.setattr(stream, "isatty", lambda: True)

    def held_lease(self):
        fd = os.open(self.directory / "private-mode.lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            raise AssertionError("Actual owner operator lease must precede startup")
        finally:
            os.close(fd)

    def native_factory(self):
        self.native_factories.append(True)
        return self.bindings

    def server_factory(self, app):
        server = Server(self, app)
        self.servers.append(server)
        return server

    def connect(self, host):
        assert host in {"oauth2.googleapis.com", "gmail.googleapis.com"}
        scope = " ".join(sorted(self.configuration.scopes))
        responses = [
            {
                "access_token": ACCESS,
                "refresh_token": REFRESH,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": scope,
            },
            {
                "azp": self.configuration.client_id,
                "aud": self.configuration.client_id,
                "sub": SUBJECT,
                "scope": scope,
                "exp": str(int(NOW.timestamp()) + 3600),
                "expires_in": "3600",
                "access_type": "offline",
            },
            {
                "emailAddress": self.configuration.gmail_mailbox,
                "messagesTotal": 0,
                "threadsTotal": 0,
                "historyId": "123",
            },
        ]
        result = Connection(self, host, Response(responses[len(self.connections)]))
        self.connections.append(result)
        return result

    def plan(self, monkeypatch, **changes):
        from zacai.interfaces.gmail_setup import GmailSetupPlan

        fields = {
            "configuration": self.configuration,
            "owner_client_id": CONFIG.client_id,
            "directory": self.directory,
            "startup_loader": self.startup,
            "clock": self.clock,
            "approved_generation": "invented-approved-foreground-review",
            "console_observed_at": NOW,
            "review_expires_at": NOW + timedelta(hours=1),
            "initialize_new_guard": True,
            "initialize_new_transactions": True,
            "escrow_confirmed_by_operator": True,
            "transport": self.transport,
            "bindings_factory": self.native_factory,
            "identities": InventedIdentity(self.clock),
        }
        fields.update(changes)
        plan = GmailSetupPlan(**fields)
        monkeypatch.setattr(plan._server, "_factory", self.server_factory)
        return plan


def test_constructor_inert_and_run_composes_exact_production_hooks(tmp_path, monkeypatch):
    import re
    from urllib.parse import parse_qs, urlsplit

    from tests.test_private_host import sign_in
    from zacai.connectors.gmail_client_secret import GmailClientSecretLoader
    from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
    from zacai.connectors.gmail_registration import ReviewedGmailRegistration
    from zacai.connectors.oauth_host_guard import OAuthHostGuard
    from zacai.interfaces.gmail_setup import GmailSetupError, GmailSetupPlan

    f = Fixture(tmp_path, monkeypatch)
    before = set(f.directory.rglob("*"))
    plan = f.plan(monkeypatch)
    assert set(f.directory.rglob("*")) == before
    assert f.owner_loads == f.server_runs == 0 and not f.secret_reads and not f.native_factories
    assert not f.provider_calls
    composed = []
    original = GmailSetupPlan._verify

    def verify(self, inputs, controller, registration, loader, stage):
        f.held_lease()
        original(self, inputs, controller, registration, loader, stage)
        composed.append((inputs, controller, registration, loader, stage))

    monkeypatch.setattr(GmailSetupPlan, "_verify", verify)

    def browse(browser):
        sign_in(browser)
        root = browser.get("/")
        assert root.status_code == 200
        assert "inactive" in root.text
        page = browser.get("/connections/gmail")
        fields = dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))
        consent = browser.post("/connections/gmail/begin", data=fields, headers={"origin": ORIGIN})
        assert consent.status_code == 303
        state = parse_qs(urlsplit(consent.headers["location"]).query)["state"][0]
        callback = browser.get(
            "/connections/gmail/callback", params={"state": state, "code": "invented-code"}
        )
        assert (
            callback.status_code == 303
            and callback.headers["location"] == "/connections/gmail/status"
        )
        assert ACCESS not in callback.text and REFRESH not in callback.text
        assert browser.post("/approve").status_code == 404
        assert browser.post("/connections/gmail/install").status_code == 404

    f.browser_action = browse
    assert plan.run() is None
    assert f.owner_loads == f.server_runs == 1 and len(f.secret_reads) == 1
    assert f.shared_reads == [
        "zacai-shared-owner-google-client-secret",
        "zacai-shared-owner-session-key",
    ]
    assert len(f.provider_calls) == 3 and f.native_factories == [True]
    assert [event[0] for event in f.bindings.events] == [
        "open",
        "access",
        "add",
        "readback",
        "release",
        "release",
    ]
    assert f.servers[0].should_exit is True and all(
        connection.closed for connection in f.connections
    )
    assert len(composed) == 1
    inputs, controller, registration, loader, stage = composed[0]
    assert type(loader) is GmailClientSecretLoader and type(stage) is HeldGmailNativeStage
    assert type(registration) is ReviewedGmailRegistration and type(plan._guard) is OAuthHostGuard
    assert controller._authority._continuity._sessions is inputs.sessions
    assert controller._authority._continuity._owner is inputs.owner
    assert controller._authority._continuity._clock is registration.clock is f.clock
    assert registration.host_guard is controller._guard is stage._guard is plan._guard
    assert registration.stop_host is controller._stop_host is stage._stop is plan._stop_host
    assert getattr(plan._stop_host, "__self__", None) is plan._server
    assert controller._authority._backend is registration
    assert (
        loader.configuration.configuration_digest
        == stage._configuration.configuration_digest
        == f.configuration.configuration_digest
    )
    with controller._authority._locked():
        row = next(iter(controller._authority._read()["rows"].values()))
    assert row["state"] == "held" and row["loaded"] is True
    assert not hasattr(plan, "install") and not hasattr(plan, "send")
    counts = (f.owner_loads, len(f.secret_reads), len(f.provider_calls), len(f.bindings.events))
    import pytest

    with pytest.raises(GmailSetupError):
        plan.run()
    assert counts == (
        f.owner_loads,
        len(f.secret_reads),
        len(f.provider_calls),
        len(f.bindings.events),
    )


def test_existing_selection_never_initializes_missing_operational_children(tmp_path, monkeypatch):
    import pytest

    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert f.owner_loads == 1 and f.server_runs == 0
    assert not (f.directory / "gmail-oauth-guard").exists()
    assert not (f.directory / "gmail-oauth-transactions").exists()
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_empty_existing_crypto_state_can_reopen_without_reinitialization(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    first = f.plan(monkeypatch)
    first.run()
    guard_lock = f.directory / "gmail-oauth-guard" / "oauth-host.lock"
    ledger_lock = f.directory / "gmail-oauth-transactions" / "provider-oauth-transactions.lock"
    inodes = (guard_lock.stat().st_ino, ledger_lock.stat().st_ino)
    second = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    second.run()
    assert (guard_lock.stat().st_ino, ledger_lock.stat().st_ino) == inodes
    assert f.owner_loads == f.server_runs == 2
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_advancing_clock_existing_pair_reopens_and_exposes_authenticated_status(
    tmp_path, monkeypatch
):
    from itertools import pairwise

    from tests.test_gmail_connection_web import status_json
    from tests.test_private_host import sign_in

    f = Fixture(tmp_path, monkeypatch)
    observations = []

    def advancing_time():
        f.now += timedelta(milliseconds=1)
        observations.append(f.now)
        return f.now

    monkeypatch.setattr(f.clock, "_read", advancing_time)
    first = f.plan(monkeypatch)
    first.run()
    files = (
        f.directory / "gmail-oauth-guard" / "oauth-host.lock",
        f.directory / "gmail-oauth-guard" / "oauth-host.ready",
        f.directory / "gmail-oauth-transactions" / "provider-oauth-transactions.lock",
        f.directory / "gmail-oauth-transactions" / "provider-oauth-transactions.bin",
    )
    before = tuple((p.stat().st_ino, p.read_bytes()) for p in files)
    observations_before_reopen = len(observations)
    f.now += timedelta(minutes=1)
    inspected = []

    def browse(browser):
        sign_in(browser)
        inspected.append(status_json(browser.get("/connections/gmail/status"), (0,) * 6))

    f.browser_action = browse
    second = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    second.run()
    assert len(observations) > observations_before_reopen
    assert all(a < b for a, b in pairwise(observations))
    assert len(inspected) == 1
    assert tuple((p.stat().st_ino, p.read_bytes()) for p in files) == before
    assert not (f.directory / "gmail-oauth-guard" / "oauth-host.halted").exists()
    assert f.owner_loads == f.server_runs == 2
    assert len(f.shared_reads) == 4
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
    assert all(server.should_exit for server in f.servers)


def test_new_operational_initialization_is_one_shot_without_fallback(tmp_path, monkeypatch):
    import pytest

    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    first = f.plan(monkeypatch)
    first.run()
    guard = f.directory / "gmail-oauth-guard"
    before = {path.name: path.read_bytes() for path in guard.iterdir()}
    second = f.plan(monkeypatch)
    with pytest.raises(GmailSetupError):
        second.run()
    assert {path.name: path.read_bytes() for path in guard.iterdir()} == before
    assert f.owner_loads == 2 and f.server_runs == 1
    assert not f.secret_reads and not f.provider_calls


def test_existing_non_denied_transaction_halts_guard_and_never_resumes(tmp_path, monkeypatch):
    import re

    import pytest

    from tests.test_private_host import sign_in
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)

    def pending(browser):
        sign_in(browser)
        page = browser.get("/connections/gmail")
        fields = dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))
        assert (
            browser.post(
                "/connections/gmail/begin", data=fields, headers={"origin": ORIGIN}
            ).status_code
            == 303
        )

    f.browser_action = pending
    first = f.plan(monkeypatch)
    first.run()
    ledger = f.directory / "gmail-oauth-transactions" / "provider-oauth-transactions.bin"
    before = ledger.read_bytes()
    second = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    with pytest.raises(GmailSetupError):
        second.run()
    assert (f.directory / "gmail-oauth-guard" / "oauth-host.halted").exists()
    assert ledger.read_bytes() == before
    assert (
        f.server_runs == 1
        and not f.secret_reads
        and not f.provider_calls
        and not f.native_factories
    )


@pytest.mark.parametrize(
    "change",
    [
        "guard_flag",
        "transaction_flag",
        "escrow",
        "owner_loader",
        "clock",
        "source_config",
        "expiry",
        "owner_client",
        "relative_path",
        "background_loader",
        "pin",
    ],
)
def test_invalid_proposal_is_inert_before_startup_native_or_provider(tmp_path, monkeypatch, change):
    from pathlib import Path

    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    changes = {
        "guard_flag": {"initialize_new_guard": 1},
        "transaction_flag": {"initialize_new_transactions": 1},
        "escrow": {"escrow_confirmed_by_operator": False},
        "owner_loader": {"startup_loader": lambda **kwargs: CONFIG},
        "clock": {"clock": lambda: NOW},
        "source_config": {
            "configuration": gmail(private_origin=ORIGIN, grant_profile="approved_communications")
        },
        "expiry": {"review_expires_at": NOW + timedelta(hours=2, microseconds=1)},
        "owner_client": {"owner_client_id": "456-other.apps.googleusercontent.com"},
        "relative_path": {"directory": Path("relative")},
        "background_loader": {
            "startup_loader": OwnerStartupLoader(
                client_id=CONFIG.client_id,
                origin=ORIGIN,
                keychain_path=f.keychain,
                mode="background",
                keychain_file_policy="reviewed_login",
            )
        },
        "pin": {"expected_subject": "not-a-stable-google-pin"},
    }
    before = set(f.directory.rglob("*"))
    with pytest.raises(GmailSetupError):
        f.plan(monkeypatch, **changes[change])
    assert set(f.directory.rglob("*")) == before
    assert f.owner_loads == f.server_runs == 0
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


@pytest.mark.parametrize("stream", ["stdin", "stdout", "stderr"])
def test_no_interactive_tty_denies_before_owner_startup_or_operational_creation(
    tmp_path, monkeypatch, stream
):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    monkeypatch.setattr(getattr(sys, stream), "isatty", lambda: False)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert f.owner_loads == f.server_runs == 0
    assert not (f.directory / "gmail-oauth-guard").exists()
    assert not (f.directory / "gmail-oauth-transactions").exists()
    assert not f.secret_reads and not f.provider_calls


def test_non_main_thread_cannot_start_foreground_setup(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    with ThreadPoolExecutor(max_workers=1) as workers, pytest.raises(GmailSetupError):
        workers.submit(plan.run).result()
    assert f.owner_loads == f.server_runs == 0 and not f.secret_reads and not f.provider_calls


@pytest.mark.parametrize("now", [NOW - timedelta(microseconds=1), NOW + timedelta(hours=1)])
def test_not_current_or_expired_review_spends_attempt_without_owner_secret_reads(
    tmp_path, monkeypatch, now
):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    f.now = now
    with pytest.raises(GmailSetupError):
        plan.run()
    assert plan._spent is True and plan._running is False
    assert f.owner_loads == f.server_runs == 0 and not f.secret_reads and not f.provider_calls


@pytest.mark.parametrize(
    "field,value",
    [("_new_guard", False), ("_generation", "unapproved"), ("_expected_subject", "123")],
)
def test_changed_original_proposal_denies_before_owner_startup(tmp_path, monkeypatch, field, value):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    setattr(plan, field, value)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert f.owner_loads == f.server_runs == 0 and not f.secret_reads and not f.provider_calls


def test_changed_native_loader_settings_deny_before_owner_startup(tmp_path, monkeypatch):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    object.__setattr__(f.startup, "foreground_timeout_seconds", 1)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert f.owner_loads == f.server_runs == 0 and not f.secret_reads and not f.provider_calls


def test_ambiguous_transaction_initialization_halts_and_stops_without_gmail_secret(
    tmp_path, monkeypatch
):
    from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)

    def failed_write(authority, value):
        raise OSError("invented ambiguous transaction persistence")

    monkeypatch.setattr(OAuthTransactionAuthority, "_write", failed_write)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert plan._spent is True and plan._server._stopped is True
    assert (f.directory / "gmail-oauth-guard" / "oauth-host.halted").exists()
    assert (f.directory / "gmail-oauth-transactions" / "provider-oauth-transactions.lock").exists()
    assert not (
        f.directory / "gmail-oauth-transactions" / "provider-oauth-transactions.bin"
    ).exists()
    assert f.owner_loads == 1 and f.server_runs == 0
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_guard_publication_failure_cannot_fall_back_to_ready_state(tmp_path, monkeypatch):
    from zacai.connectors.oauth_host_guard import OAuthHostGuard, OAuthHostGuardError
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    original = OAuthHostGuard._create

    def acknowledged_then_failed(guard, path, value):
        original(guard, path, value)
        if path.name == "oauth-host.ready":
            raise OSError("invented post-publication acknowledgement failure")

    monkeypatch.setattr(OAuthHostGuard, "_create", acknowledged_then_failed)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert plan._spent is True and plan._server._stopped is True
    assert (f.directory / "gmail-oauth-guard" / "oauth-host.ready").exists()
    assert (f.directory / "gmail-oauth-guard" / "oauth-host.halted").exists()
    with pytest.raises(OAuthHostGuardError):
        plan._guard.ready()
    assert f.owner_loads == 1 and f.server_runs == 0
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_missing_existing_ledger_is_not_recreated_or_moved(tmp_path, monkeypatch):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    first = f.plan(monkeypatch)
    first.run()
    directory = f.directory / "gmail-oauth-transactions"
    ledger = directory / "provider-oauth-transactions.bin"
    lock = directory / "provider-oauth-transactions.lock"
    inode = lock.stat().st_ino
    ledger.unlink()
    second = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    with pytest.raises(GmailSetupError):
        second.run()
    assert not ledger.exists() and lock.stat().st_ino == inode
    assert second._guard is None
    assert not (f.directory / "gmail-oauth-guard" / "oauth-host.halted").exists()
    assert (
        f.server_runs == 1
        and not f.secret_reads
        and not f.provider_calls
        and not f.native_factories
    )


def test_wrong_startup_key_cannot_enroll_or_construct_gmail_factory(tmp_path, monkeypatch):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    original_owner = (f.directory / "owner" / "owner.json").read_bytes()
    plan = f.plan(monkeypatch)

    f.startup_session_key = b"Y" * 32
    with pytest.raises(GmailSetupError):
        plan.run()
    assert (f.directory / "owner" / "owner.json").read_bytes() == original_owner
    assert not (f.directory / "gmail-oauth-guard").exists()
    assert not (f.directory / "gmail-oauth-transactions").exists()
    assert f.owner_loads == 1 and f.server_runs == 0
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_existing_held_native_stage_cannot_start_another_provider_or_native_attempt(
    tmp_path, monkeypatch
):
    import re
    from urllib.parse import parse_qs, urlsplit

    from tests.test_private_host import sign_in
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)

    def complete(browser):
        sign_in(browser)
        page = browser.get("/connections/gmail")
        fields = dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))
        consent = browser.post("/connections/gmail/begin", data=fields, headers={"origin": ORIGIN})
        state = parse_qs(urlsplit(consent.headers["location"]).query)["state"][0]
        assert (
            browser.get(
                "/connections/gmail/callback", params={"state": state, "code": "invented-code"}
            ).status_code
            == 303
        )

    f.browser_action = complete
    first = f.plan(monkeypatch)
    first.run()
    assert len(f.secret_reads) == 1 and len(f.provider_calls) == 3 and f.native_factories == [True]
    counts = (len(f.secret_reads), len(f.provider_calls), len(f.bindings.events), f.server_runs)
    second = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    with pytest.raises(GmailSetupError):
        second.run()
    assert counts == (
        len(f.secret_reads),
        len(f.provider_calls),
        len(f.bindings.events),
        f.server_runs,
    )
    assert (f.directory / "gmail-oauth-guard" / "oauth-host.halted").exists()


@pytest.mark.parametrize("flags", [(True, False), (False, True)])
def test_mixed_initialization_flags_are_inert_before_shared_reads(tmp_path, monkeypatch, flags):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    before = set(f.directory.rglob("*"))
    with pytest.raises(GmailSetupError):
        f.plan(monkeypatch, initialize_new_guard=flags[0], initialize_new_transactions=flags[1])
    assert set(f.directory.rglob("*")) == before
    assert not f.shared_reads and not f.secret_reads and not f.provider_calls
    assert not f.native_factories and f.server_runs == 0


@pytest.mark.parametrize("present", ["gmail-oauth-guard", "gmail-oauth-transactions"])
def test_new_mode_preflights_both_children_before_creating_either(tmp_path, monkeypatch, present):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    existing = f.directory / present
    existing.mkdir(mode=0o700)
    marker = existing / "invented-partial-init"
    marker.write_bytes(b"invented retained partial crash evidence")
    marker.chmod(0o600)
    before = set(f.directory.rglob("*"))
    plan = f.plan(monkeypatch)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert set(f.directory.rglob("*")) == before | {f.directory / "private-mode.lock"}
    assert marker.read_bytes() == b"invented retained partial crash evidence"
    assert plan._guard is None and plan._spent and plan._server._stopped
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
    assert f.server_runs == 0


@pytest.mark.parametrize("missing", ["gmail-oauth-guard", "gmail-oauth-transactions"])
def test_existing_mode_missing_whole_child_never_recreates_or_reads_guard(
    tmp_path, monkeypatch, missing
):
    import shutil

    from zacai.connectors.oauth_host_guard import OAuthHostGuard
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    f.plan(monkeypatch).run()
    shutil.rmtree(f.directory / missing)
    before = {p: p.read_bytes() for p in f.directory.rglob("*") if p.is_file()}
    ready_calls = []
    original = OAuthHostGuard.ready

    def ready(guard):
        ready_calls.append(True)
        return original(guard)

    monkeypatch.setattr(OAuthHostGuard, "ready", ready)
    plan = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert not (f.directory / missing).exists()
    assert {p: p.read_bytes() for p in f.directory.rglob("*") if p.is_file()} == before
    assert not ready_calls and plan._guard is None
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
    assert f.server_runs == 1


def test_crashed_partial_initialization_cannot_reset_with_new_or_mixed_selection(
    tmp_path, monkeypatch
):
    from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)

    def failed_write(authority, value):
        raise OSError("invented crash before ledger acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(OAuthTransactionAuthority, "_write", failed_write)
        with pytest.raises(GmailSetupError):
            f.plan(patch).run()
    before = {p: p.read_bytes() for p in f.directory.rglob("*") if p.is_file()}
    for flags in [(True, True), (False, False), (True, False), (False, True)]:
        with pytest.raises(GmailSetupError):
            f.plan(
                monkeypatch, initialize_new_guard=flags[0], initialize_new_transactions=flags[1]
            ).run()
        assert {p: p.read_bytes() for p in f.directory.rglob("*") if p.is_file()} == before
    assert f.server_runs == 0 and not f.secret_reads and not f.provider_calls
    assert not f.native_factories


def test_review_expiring_during_real_owner_loader_denies_before_gmail_io(tmp_path, monkeypatch):
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)

    def expire(service):
        if service == "zacai-shared-owner-session-key":
            f.now = NOW + timedelta(hours=1)

    f.read_action = expire
    with pytest.raises(GmailSetupError):
        plan.run()
    assert f.owner_loads == 1 and len(f.shared_reads) == 2
    assert not (f.directory / "gmail-oauth-guard").exists()
    assert not (f.directory / "gmail-oauth-transactions").exists()
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
    assert plan._spent and plan._server._stopped and f.server_runs == 0


def test_unconfirmed_guard_halt_stops_actual_lifecycle_and_spends_attempt(tmp_path, monkeypatch):
    from zacai.connectors.oauth_host_guard import OAuthHostGuard
    from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
    from zacai.interfaces.gmail_setup import GmailSetupError, GmailSetupFatal

    f = Fixture(tmp_path, monkeypatch)
    plan = f.plan(monkeypatch)
    halt_calls = []

    def failed_write(authority, value):
        raise OSError("invented initialization acknowledgement uncertainty")

    def failed_halt(guard):
        halt_calls.append(True)
        raise OSError("invented durable halt uncertainty")

    monkeypatch.setattr(OAuthTransactionAuthority, "_write", failed_write)
    monkeypatch.setattr(OAuthHostGuard, "halt_unconfirmed", failed_halt)
    with pytest.raises((GmailSetupError, GmailSetupFatal)):
        plan.run()
    assert halt_calls and plan._server._stopped and plan._spent and not plan._running
    counts = (len(f.shared_reads), len(halt_calls))
    with pytest.raises((GmailSetupError, GmailSetupFatal)):
        plan.run()
    assert counts == (len(f.shared_reads), len(halt_calls))
    assert not f.secret_reads and not f.provider_calls and not f.native_factories
    assert f.server_runs == 0


@pytest.mark.parametrize(
    "relative",
    [
        "gmail-oauth-guard/oauth-host.lock",
        "gmail-oauth-guard/oauth-host.ready",
        "gmail-oauth-transactions/provider-oauth-transactions.lock",
        "gmail-oauth-transactions/provider-oauth-transactions.bin",
    ],
)
def test_existing_pair_requires_all_protected_files_before_guard_ready(
    tmp_path, monkeypatch, relative
):
    from zacai.connectors.oauth_host_guard import OAuthHostGuard
    from zacai.interfaces.gmail_setup import GmailSetupError

    f = Fixture(tmp_path, monkeypatch)
    f.plan(monkeypatch).run()
    (f.directory / relative).chmod(0o644)
    operational = [f.directory / "gmail-oauth-guard", f.directory / "gmail-oauth-transactions"]
    before = {p: (p.read_bytes(), p.stat().st_mode) for d in operational for p in d.iterdir()}
    ready_calls = []
    monkeypatch.setattr(OAuthHostGuard, "ready", lambda guard: ready_calls.append(True))
    plan = f.plan(monkeypatch, initialize_new_guard=False, initialize_new_transactions=False)
    with pytest.raises(GmailSetupError):
        plan.run()
    assert not ready_calls and plan._guard is None and plan._server._stopped
    assert {
        p: (p.read_bytes(), p.stat().st_mode) for d in operational for p in d.iterdir()
    } == before
    assert f.server_runs == 1 and not f.secret_reads and not f.provider_calls
    assert not f.native_factories
