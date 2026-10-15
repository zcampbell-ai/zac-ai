"""Dormant operator configuration and actual owner composition; invented I/O only."""

import json
import sys
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from test_slack_mounted_host import ORIGIN, STATE, Inputs, RamSlack, enroll, inputs
from test_slack_saved_preflight import Native
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle
from zacai.interfaces.private_startup import OwnerStartupLoader
from zacai.interfaces.slack_setup import (
    SlackSetupConfiguration,
    SlackSetupError,
    SlackSetupPlan,
    parse_configuration,
)

_BROWSER_FAILURES = []


@pytest.fixture(autouse=True)
def propagate_invented_browser_failures():
    """Setup sanitization must not turn a test failure into expected held."""
    _BROWSER_FAILURES.clear()
    yield
    assert not _BROWSER_FAILURES, _BROWSER_FAILURES


def configuration(tmp_path, **changes):
    now, owner, slack, values = inputs(tmp_path)
    fields = {
        "mode": "initial_identity",
        "owner_client_id": owner.client_id,
        "configuration": slack,
        "expected_user_id": "U123456789",
        "rotation": SlackRotation.ROTATING,
        "approved_generation": "invented-reviewed",
        "console_observed_at": now,
        "review_expires_at": now + timedelta(hours=1),
        "directory": values["directory"],
        "owner_startup_keychain_path": tmp_path / "owner-invented.keychain-db",
        "client_secret_keychain_path": tmp_path / "client-invented.keychain-db",
        "native_keychain_path": tmp_path / "native-invented.keychain-db",
        "escrow_confirmed_by_operator": True,
    }
    fields.update(changes)
    return SlackSetupConfiguration(**fields)


class Fixture:
    def __init__(self, tmp_path, monkeypatch):
        self.now, self.owner, self.slack, self.values = inputs(tmp_path)
        enroll(self.values)
        self.config = configuration(tmp_path)
        for path in (
            self.config.owner_startup_keychain_path,
            self.config.client_secret_keychain_path,
            self.config.native_keychain_path,
        ):
            path.write_bytes(b"invented native path witness")
            path.chmod(0o600)
        self.loads, self.servers = [], []
        self.ram = RamSlack(self.slack)
        self.secret = Native(self.config.client_secret_keychain_path, "success")
        self.secret.service, self.secret.account, self.secret.payload = (
            "zacai-brainstorm-slack-client-secret",
            "zac-owner-source-access",
            b"deadbeef0123456789",
        )
        self.native = Native(self.config.native_keychain_path, "success")
        self.action = lambda browser, plan: None
        self.plan = None
        self.startup = OwnerStartupLoader(
            client_id=self.owner.client_id,
            origin=ORIGIN,
            keychain_path=self.config.owner_startup_keychain_path,
            mode="foreground",
        )

        def load(loader, *, client_id, origin):
            assert loader is self.startup
            assert (client_id, origin) == (self.owner.client_id, ORIGIN)
            self.loads.append(True)
            return self.owner

        monkeypatch.setattr(OwnerStartupLoader, "__call__", load)
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            monkeypatch.setattr(stream, "isatty", lambda: True)

    def server_factory(self, app):
        fixture = self

        class Server:
            should_exit = False

            def run(self):
                with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
                    try:
                        fixture.action(browser, fixture.plan)
                    except Exception as error:
                        _BROWSER_FAILURES.append(error)
                        raise

        server = Server()
        self.servers.append(server)
        return server

    def build(self, config=None):
        lifecycle = PrivateServerLifecycle(server_factory=self.server_factory)
        self.plan = SlackSetupPlan(
            configuration=config or self.config,
            clock=self.values["clock"],
            startup_loader=self.startup,
            lifecycle=lifecycle,
            identities=self.values["identities"],
            client_secret_bindings_factory=lambda: self.secret,
            native_bindings_factory=lambda: self.native,
            connection_factory=self.ram.connect,
            network_clock=lambda: self.ram.net,
        )
        return self.plan


def login(browser):
    assert browser.post("/login", headers={"Origin": ORIGIN}).status_code == 307
    assert browser.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303


def install(browser, plan):
    fixture = plan
    host = fixture._host
    login(browser)
    before = browser.get("/connections/slack/install")
    assert before.status_code == 200 and "Review Slack registration" in before.text
    form = Inputs(browser.get("/connections/slack").text).values
    response = browser.post("/connections/slack/begin", data=form, headers={"Origin": ORIGIN})
    assert response.status_code == 303
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    assert (
        browser.get(
            "/connections/slack/callback", params={"state": state, "code": "toy"}
        ).status_code
        == 200
    )
    assert host._saved_backend is None
    return host


def review_execute(browser, page):
    form = Inputs(browser.get(page).text).values
    response = browser.post("/connector-review", data=form, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    execute = Inputs(response.text).values
    result = browser.post("/connector-execute", data=execute, headers={"Origin": ORIGIN})
    assert result.status_code == 200
    assert (
        browser.post("/connector-execute", data=execute, headers={"Origin": ORIGIN}).status_code
        == 403
    )


def test_configuration_and_constructor_inert_without_paths_or_clock(tmp_path):
    config = configuration(tmp_path)
    assert not config.directory.exists() and not config.native_keychain_path.exists()
    calls = []
    from zacai.host_clock import HostObservedClock

    clock = HostObservedClock(lambda: calls.append(True))
    plan = SlackSetupPlan(configuration=config, clock=clock)
    assert not calls and not config.directory.exists() and not plan._spent
    assert parse_configuration(config.model_dump_json().encode()) == config


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "automatic"},
        {"version": True},
        {"escrow_confirmed_by_operator": 1},
        {"foreground_timeout_seconds": True},
        {"foreground_timeout_seconds": "60"},
        {"foreground_timeout_seconds": 121},
        {"expected_user_id": "U999"},
        {"client_secret": "invented-accidental-secret"},
        {"directory": "relative"},
        {"mode": "saved_identity"},
        {"client_secret_keychain_path": None},
    ],
)
def test_invalid_configuration_never_creates_namespace(tmp_path, change):
    with pytest.raises((ValueError, SlackSetupError)):
        configuration(tmp_path, **change)
    assert not (tmp_path / "operator").exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"x" * 16385,
        b'{"mode":"initial_identity","mode":"saved_identity"}',
        b'{"client_secret":"invented-pasted-secret"}',
        b"[]",
    ],
)
def test_parser_denies_bounded_duplicate_unknown_and_sanitizes(raw):
    with pytest.raises(SlackSetupError) as error:
        parse_configuration(raw)
    assert "invented-pasted-secret" not in str(error.value)
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_actual_initial_then_new_saved_operator_uses_same_persistence(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    before = set(f.config.directory.rglob("*"))
    assert not f.loads and not f.secret.calls and not f.native.calls and not f.servers
    assert set(f.config.directory.rglob("*")) == before
    captured = {}

    def first(browser, current):
        host = install(browser, current)
        assert f.secret.calls.count("data") == 1 and not f.native.calls
        review_execute(browser, "/connections/slack/install")
        assert host._saved_backend._active
        captured["warm"] = host._saved_backend
        assert host._paired_lifecycle is current._server

    f.action = first
    plan.run()
    assert len(f.loads) == 1 and f.servers[-1].should_exit
    assert plan._host._closed and not plan._running
    assert f.native.calls.count("add") == f.native.calls.count("data") == 1
    warm_native, warm_calls = f.native, list(f.native.calls)
    secret_calls, paths = list(f.secret.calls), list(f.ram.paths)
    f.native = Native(f.config.native_keychain_path, "success")
    f.native.payload, f.native.service, f.native.account = (
        warm_native.payload,
        warm_native.service,
        warm_native.account,
    )
    saved = f.config.model_copy(
        update={"mode": "saved_identity", "client_secret_keychain_path": None}
    )
    cold = f.build(saved)

    def second(browser, current):
        login(browser)
        review_execute(browser, "/connections/slack/saved")
        assert current._host._saved_backend._completed

    f.action = second
    cold.run()
    assert len(f.loads) == 2 and f.servers[-1].should_exit
    assert f.secret.calls == secret_calls and warm_native.calls == warm_calls
    assert f.native.calls.count("data") == 1 and "add" not in f.native.calls
    assert len(f.ram.paths) == len(paths) + 1
    assert all(connection.closed for connection in f.ram.connections)
    assert sorted(f.native.owned) == sorted(f.native.released)
    assert cold._host._saved_backend._is_closed and cold._host._saved_backend._saved is None


@pytest.mark.parametrize("namespace", ["slack-connect", "slack-installation", "slack-oauth-guard"])
def test_initial_unknown_namespace_preserved_before_startup(tmp_path, monkeypatch, namespace):
    f = Fixture(tmp_path, monkeypatch)
    path = f.config.directory / namespace
    path.mkdir(mode=0o700)
    marker = path / "unknown.bin"
    marker.write_bytes(b"invented-unknown-history")
    plan = f.build()
    with pytest.raises(SlackSetupError):
        plan.run()
    assert marker.read_bytes() == b"invented-unknown-history"
    assert not f.loads and not f.servers and not f.secret.calls and not f.native.calls
    assert plan._server._stopped


def test_paired_stop_reaches_actual_same_server_and_prevents_restart(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()

    def action(browser, current):
        current._host._stop()
        assert f.servers[-1].should_exit and current._server._stopped

    f.action = action
    with pytest.raises(SlackSetupError):
        plan.run()
    assert f.servers[-1].should_exit
    with pytest.raises(SlackSetupError):
        plan.run()
    assert len(f.loads) == len(f.servers) == 1


def test_initial_mounted_boundaries_deny_before_namespace_or_native(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()

    def action(browser, current):
        host = install(browser, current)
        page = browser.get("/connections/slack/install")
        form = Inputs(page.text).values
        for path, content, headers in [
            ("/connector-review", form, {"Origin": "https://foreign.invalid"}),
            ("/connector-review?x=1", form, {"Origin": ORIGIN}),
            ("/connector-review", {**form, "csrf": "wrong"}, {"Origin": ORIGIN}),
            ("/connector-review", {**form, "reviewed_scope_digest": "f" * 64}, {"Origin": ORIGIN}),
        ]:
            assert browser.post(path, data=content, headers=headers).status_code == 403
        assert not f.native.calls and host._saved_backend is None
        assert not (f.config.directory / "slack-installation").exists()

    f.action = action
    with pytest.raises(SlackSetupError):
        plan.run()
    assert not f.native.calls and f.secret.calls.count("data") == 1


def test_setup_real_native_worker_logout_and_paired_physical_drain(tmp_path, monkeypatch):
    import threading

    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    entered, release, logged_out = threading.Event(), threading.Event(), threading.Event()
    primitive_threads, outcomes, errors = [], {}, []

    def blocked():
        primitive_threads.append(threading.current_thread())
        entered.set()
        assert release.wait(12), "invented native primitive release timed out"

    f.native.on_read = blocked

    def action(browser, current):
        host = install(browser, current)
        form = Inputs(browser.get("/connections/slack/install").text).values
        review = browser.post("/connector-review", data=form, headers={"Origin": ORIGIN})
        assert review.status_code == 200
        execute_form = Inputs(review.text).values
        logout_form = {"csrf": Inputs(browser.get("/").text).values["csrf"]}
        portal = browser.portal

        def request(name, path, data, done=None):
            try:
                assert browser.portal is portal
                response = browser.post(path, data=data, headers={"Origin": ORIGIN})
                outcomes[name] = response.status_code
                response.close()
                assert response.is_closed
            except BaseException as error:  # noqa: BLE001 - transfer invented helper-thread errors
                errors.append(error)
            finally:
                if done:
                    done.set()

        execution = threading.Thread(
            target=request, args=("execute", "/connector-execute", execute_form)
        )
        logout = threading.Thread(
            target=request, args=("logout", "/logout", logout_form, logged_out)
        )
        started = []
        try:
            execution.start()
            started.append(execution)
            assert entered.wait(5) and execution.is_alive()
            assert primitive_threads[0] is not threading.main_thread()
            logout.start()
            started.append(logout)
            assert logged_out.wait(3) and outcomes.get("logout") == 303
            assert not release.is_set() and execution.is_alive()
        finally:
            release.set()
            for thread in started:
                thread.join(10)
        assert not errors, errors
        assert all(not thread.is_alive() for thread in started)
        assert outcomes == {"logout": 303, "execute": 403}
        assert host._saved_backend._failed and host._saved_backend._saved is None
        assert len(f.ram.paths) == 2  # Exchange plus original identity; no saved identity dispatch.

    f.action = action
    with pytest.raises(SlackSetupError):
        plan.run()
    assert f.servers[-1].should_exit and plan._server._stopped and plan._host._closed
    assert sorted(f.native.owned) == sorted(f.native.released)
    assert f.native.calls.count("add") == f.native.calls.count("data") == 1
    assert not primitive_threads[0].is_alive()


@pytest.mark.parametrize("changed", ["configuration", "startup", "factory"])
def test_original_plan_dependencies_rebound_deny_before_effects(tmp_path, monkeypatch, changed):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    if changed == "configuration":
        object.__setattr__(
            plan._configuration, "approved_generation", "different-invented-generation"
        )
    elif changed == "startup":
        object.__setattr__(f.startup, "keychain_path", tmp_path / "other.keychain-db")
    else:
        plan._server._factory = lambda app: pytest.fail("rebound factory invoked")
    with pytest.raises(SlackSetupError):
        plan.run()
    assert not f.loads and not f.servers and not f.secret.calls and not f.native.calls


def test_saved_missing_namespace_no_birth_fallback_or_secret(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    saved = f.config.model_copy(
        update={"mode": "saved_identity", "client_secret_keychain_path": None}
    )
    before = {
        str(p.relative_to(f.config.directory)): p.read_bytes()
        for p in f.config.directory.rglob("*")
        if p.is_file()
    }
    plan = f.build(saved)
    with pytest.raises(SlackSetupError):
        plan.run()
    after = {
        str(p.relative_to(f.config.directory)): p.read_bytes()
        for p in f.config.directory.rglob("*")
        if p.is_file()
    }
    assert before == after
    assert not f.loads and not f.servers and not f.secret.calls and not f.native.calls


def test_failed_paired_stop_sticky_halts_actual_guard(tmp_path, monkeypatch):
    from zacai.connectors.oauth_host_guard import OAuthHostHaltUnconfirmed
    from zacai.interfaces.slack_setup import SlackSetupCancelled

    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()

    def action(browser, current):
        server = f.servers[-1]

        def rejected(server, value):
            raise OSError("invented private listener stop failure")

        monkeypatch.setattr(type(server), "should_exit", property(lambda server: False, rejected))
        with pytest.raises(OAuthHostHaltUnconfirmed):
            current._host._stop()
        assert current._host._halt_failed and current._host._halted
        from zacai.connectors.oauth_host_guard import OAuthHostGuardError

        with pytest.raises(OAuthHostGuardError):
            current._host._guard.ready()

    f.action = action
    with pytest.raises((SlackSetupError, SlackSetupCancelled)):
        plan.run()
    assert plan._host._halt_failed and plan._host._closed


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 1.0),
        ("escrow_confirmed_by_operator", 1),
        ("escrow_confirmed_by_operator", "true"),
        ("console_observed_at", 1791849600),
        ("review_expires_at", True),
        ("console_observed_at", "2026-10-13"),
        ("review_expires_at", "2026-10-13T01:00:00+01:00"),
    ],
)
def test_json_literal_datetime_types_are_exact(tmp_path, field, value):
    raw = json.loads(configuration(tmp_path).model_dump_json())
    raw[field] = value
    with pytest.raises(SlackSetupError):
        parse_configuration(json.dumps(raw).encode())


def test_no_owner_action_never_reports_success(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    with pytest.raises(SlackSetupError):
        plan.run()
    assert plan._host._closed and plan._server._stopped
    assert not f.secret.calls and not f.native.calls and not f.ram.paths


@pytest.mark.parametrize("change", ["owner_revoke", "logout", "canonical_held"])
def test_terminal_published_history_is_not_current_owner_acceptance(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()

    def action(browser, current):
        host = install(browser, current)
        review_execute(browser, "/connections/slack/install")
        assert host._saved_backend._active
        if change == "owner_revoke":
            host._prepared.owners.revoke()
        elif change == "logout":
            form = {"csrf": Inputs(browser.get("/").text).values["csrf"]}
            assert browser.post("/logout", data=form, headers={"Origin": ORIGIN}).status_code == 303
        else:
            sdk = host._identity_sdk
            with sdk._locked():
                value = sdk._read()
                row = value["rows"][str(host._saved_backend._plan.attempt_id)]
                assert row["state"] == "completed" and row["loaded"]
                row["state"] = "held"
                sdk._write(value)
                assert (
                    sdk._read()["rows"][str(host._saved_backend._plan.attempt_id)]["state"]
                    == "held"
                )

    f.action = action
    with pytest.raises(SlackSetupError):
        plan.run()
    assert plan._host._closed and f.servers[-1].should_exit


def setup_mode(f, mode):
    if mode == "initial_identity":
        return f.build(), "/connections/slack/install"

    def warm(browser, current):
        install(browser, current)
        review_execute(browser, "/connections/slack/install")

    f.action = warm
    f.build().run()
    old = f.native
    f.native = Native(f.config.native_keychain_path, "success")
    f.native.payload, f.native.service, f.native.account = old.payload, old.service, old.account
    saved = f.config.model_copy(
        update={"mode": "saved_identity", "client_secret_keychain_path": None}
    )
    return f.build(saved), "/connections/slack/saved"


def enter_mode(browser, current, mode):
    if mode == "initial_identity":
        return install(browser, current)
    login(browser)
    return current._host


@pytest.mark.parametrize("fault", ["read", "write"])
@pytest.mark.parametrize("mode", ["initial_identity", "saved_identity"])
def test_failed_real_canonical_review_never_enters_backend_execute(
    tmp_path, monkeypatch, fault, mode
):
    from zacai.connectors.connector_authority import ConnectorAuthority
    from zacai.connectors.slack_native_installation import (
        SlackPendingInstallation,
        SlackSavedInstallation,
    )

    f = Fixture(tmp_path, monkeypatch)
    plan, page = setup_mode(f, mode)
    real_approve = ConnectorAuthority.approve_review
    real_read, real_write = ConnectorAuthority._read, ConnectorAuthority._write
    backend_type = (
        SlackPendingInstallation if mode == "initial_identity" else SlackSavedInstallation
    )
    real_execute = backend_type.execute
    entered, faults, injecting = [], [], []

    def read(sdk):
        if injecting and fault == "read":
            faults.append(True)
            raise OSError("invented canonical read failure during approval")
        return real_read(sdk)

    def write(sdk, value):
        if (
            injecting
            and fault == "write"
            and any(row["state"] == "approved" for row in value["rows"].values())
        ):
            faults.append(True)
            raise OSError("invented canonical approval persistence failure")
        return real_write(sdk, value)

    def approve(sdk, *args, **kwargs):
        injecting.append(True)
        try:
            return real_approve(sdk, *args, **kwargs)
        finally:
            injecting.clear()

    def execute(backend, **kwargs):
        entered.append(True)
        return real_execute(backend, **kwargs)

    monkeypatch.setattr(ConnectorAuthority, "_read", read)
    monkeypatch.setattr(ConnectorAuthority, "_write", write)
    monkeypatch.setattr(ConnectorAuthority, "approve_review", approve)
    monkeypatch.setattr(backend_type, "execute", execute)

    def action(browser, current):
        host = enter_mode(browser, current, mode)
        form = Inputs(browser.get(page).text).values
        review = browser.post("/connector-review", data=form, headers={"Origin": ORIGIN})
        assert review.status_code == 403 and faults
        assert host._saved_backend is not None and not f.native.calls
        result = browser.post("/connector-execute", data=form, headers={"Origin": ORIGIN})
        assert result.status_code == 403
        assert not entered, "backend execute entered without successful canonical approval"
        if fault == "write":
            with host._identity_sdk._locked():
                rows = host._identity_sdk._read()["rows"]
            row = rows.get(str(host._saved_backend._plan.attempt_id))
            assert row is None or row["state"] == "held"

    f.action = action
    with pytest.raises(SlackSetupError):
        plan.run()
    assert faults and not entered and not f.native.calls


@pytest.mark.parametrize("mode", ["initial_identity", "saved_identity"])
@pytest.mark.parametrize("phase", ["review", "execute"])
def test_unauthenticated_and_wrong_csrf_cannot_spend_owner_action(
    tmp_path, monkeypatch, mode, phase
):
    f = Fixture(tmp_path, monkeypatch)
    plan, page = setup_mode(f, mode)
    observed = {}

    def action(browser, current):
        host = enter_mode(browser, current, mode)
        form = Inputs(browser.get(page).text).values
        if phase == "execute":
            review = browser.post("/connector-review", data=form, headers={"Origin": ORIGIN})
            assert review.status_code == 200
            form = Inputs(review.text).values
        path = "/connector-" + phase
        native_before = list(f.native.calls)
        wrong = {**form, "csrf": "invented-stale-or-wrong-csrf"}
        assert browser.post(path, data=wrong, headers={"Origin": ORIGIN}).status_code == 403
        cookies = list(browser.cookies.jar)
        browser.cookies.clear()
        try:
            assert browser.get(page).status_code == 403
            assert browser.post(path, data=form, headers={"Origin": ORIGIN}).status_code == 403
        finally:
            for cookie in cookies:
                browser.cookies.jar.set_cookie(cookie)
        assert f.native.calls == native_before
        observed.update(review_spent=host._saved_spent, execute_spent=host._saved_execute_spent)
        if phase == "review":
            review = browser.post(path, data=form, headers={"Origin": ORIGIN})
            assert review.status_code == 200
            form = Inputs(review.text).values
        assert (
            browser.post("/connector-execute", data=form, headers={"Origin": ORIGIN}).status_code
            == 200
        )

    f.action = action
    failure = None
    try:
        plan.run()
    except SlackSetupError as error:
        failure = error
    assert observed and not observed["execute_spent"], observed
    if phase == "review":
        assert not observed["review_spent"], observed
    assert failure is None, failure


def test_completion_reads_and_terminal_checks_use_actual_owned_worker(tmp_path, monkeypatch):
    import threading

    from zacai.interfaces.named_session_binding import NamedSessionOperation

    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    reads, checks = [], []
    real_recheck = NamedSessionOperation.recheck

    def action(browser, current):
        host = install(browser, current)
        form = Inputs(browser.get("/connections/slack/install").text).values
        review = browser.post("/connector-review", data=form, headers={"Origin": ORIGIN})
        assert review.status_code == 200
        form = Inputs(review.text).values
        sdk = host._identity_sdk
        real_read = sdk._read

        def witness():
            return threading.current_thread().name, host._controller._worker_lock._is_owned()

        def read():
            reads.append(witness())
            return real_read()

        def recheck(operation, *args, **kwargs):
            checks.append(witness())
            return real_recheck(operation, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(sdk, "_read", read)
            patch.setattr(NamedSessionOperation, "recheck", recheck)
            assert (
                browser.post(
                    "/connector-execute", data=form, headers={"Origin": ORIGIN}
                ).status_code
                == 200
            )

    f.action = action
    failure = None
    try:
        plan.run()
    except SlackSetupError as error:
        failure = error
    assert reads and checks
    assert all(owned for _, owned in reads), [item for item in reads if not item[1]]
    assert all(owned for _, owned in checks), [item for item in checks if not item[1]]
    assert all("portal" not in name for name, _ in reads + checks)
    assert failure is None, failure


def test_successful_paired_stop_does_not_duplicate_actual_server_setter(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    writes = []

    def action(browser, current):
        install(browser, current)
        review_execute(browser, "/connections/slack/install")
        server = f.servers[-1]
        state = {"value": False}

        def accept(server, value):
            writes.append(value)
            state["value"] = value

        monkeypatch.setattr(
            type(server), "should_exit", property(lambda server: state["value"], accept)
        )

    f.action = action
    plan.run()
    assert writes == [True], writes


def test_stopped_flag_after_failed_setter_never_acknowledges_stop(tmp_path, monkeypatch):
    from zacai.connectors.oauth_host_guard import OAuthHostHaltUnconfirmed
    from zacai.interfaces.slack_setup import SlackSetupCancelled

    f = Fixture(tmp_path, monkeypatch)
    plan = f.build()
    writes = []

    def action(browser, current):
        server = f.servers[-1]

        def reject(server, value):
            writes.append(value)
            raise OSError("invented physical stop uncertainty")

        monkeypatch.setattr(type(server), "should_exit", property(lambda server: False, reject))
        for _ in range(2):
            with pytest.raises(OAuthHostHaltUnconfirmed):
                current._host._stop()
            assert current._server._stopped is True
            assert current._host._halt_failed and current._host._halted
        assert len(writes) >= 2, "attempted flag cannot replace physical confirmation"
        raise KeyboardInterrupt("invented original cancellation")

    f.action = action
    with pytest.raises(SlackSetupCancelled):
        plan.run()
    assert plan._host._halt_failed and plan._host._closed
    assert len(writes) >= 2
