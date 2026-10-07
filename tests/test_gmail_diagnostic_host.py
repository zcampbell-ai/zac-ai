"""Invented foreground diagnostic composition; no real listener/native/provider."""

from __future__ import annotations

import fcntl
import os
import sys
import threading
from urllib.parse import urlsplit

import pytest

from tests.gmail_preservation_fixture import Fixture as PreservationFixture
from tests.test_private_host import CONFIG, ORIGIN
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostError


class Fixture(PreservationFixture):
    def diagnostic_plan(self, monkeypatch, **changes):
        from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostPlan

        fields = {
            "configuration": self.configuration,
            "owner_client_id": CONFIG.client_id,
            "directory": self.directory,
            "startup_loader": self.startup,
            "clock": self.clock,
            "escrow_confirmed_by_operator": True,
        }
        fields.update(changes)
        plan = GmailDiagnosticHostPlan(**fields)
        monkeypatch.setattr(plan._server, "_factory", self.server_factory)
        return plan


def test_actual_operator_two_shared_reads_held_counts_and_no_oauth_routes(tmp_path, monkeypatch):
    from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    before = f.operational_snapshot()
    plan = f.diagnostic_plan(monkeypatch)
    assert type(plan._server) is PrivateServerLifecycle
    assert getattr(plan._stop_host, "__self__", None) is plan._server
    assert not f.shared_reads and not f.server_runs and f.operational_snapshot() == before

    def forbidden(*args, **kwargs):
        raise AssertionError("Diagnostic OAuth writes forbidden")

    for name in ("_write", "_persist", "_now", "initialize", "begin", "consume_callback"):
        monkeypatch.setattr(OAuthTransactionAuthority, name, forbidden)

    def browse(browser):
        f.held_lease()
        browser.cookies.set("__Host-zac-session", f.cookie)
        response = browser.get("/connections/gmail/diagnostic")
        assert response.status_code == 200
        body = response.json()
        assert body["held"] == body["loaded"] == body["total"] == 1
        assert (
            body["pending"]
            == body["exchange_pending"]
            == body["exchange_started"]
            == body["denied"]
            == 0
        )
        assert all(
            value is False
            for name, value in body.items()
            if name
            not in {
                "pending",
                "exchange_pending",
                "exchange_started",
                "denied",
                "held",
                "loaded",
                "total",
            }
        )
        assert response.headers["cache-control"] == "no-store"
        assert all(
            private not in response.text
            for private in (
                f.cookie,
                str(f.directory),
                f.configuration.gmail_mailbox,
                CONFIG.client_id,
            )
        )
        for method, path in (
            ("get", "/connections/gmail"),
            ("post", "/connections/gmail/begin"),
            ("get", "/connections/gmail/callback"),
            ("post", "/connections/gmail/install"),
            ("get", "/enroll"),
        ):
            assert getattr(browser, method)(path).status_code == 404
        assert browser.get("/connections/gmail/diagnostic?generation=invented").status_code >= 400
        f.no_gmail_io()

    f.browser_action = browse
    plan.run()
    assert f.owner_loads == f.server_runs == 1
    assert f.shared_reads == [
        "zacai-shared-owner-google-client-secret",
        "zacai-shared-owner-session-key",
    ]
    assert f.servers[0].should_exit is True
    assert f.operational_snapshot() == before
    f.no_gmail_io()
    with pytest.raises(GmailDiagnosticHostError):
        plan.run()
    assert f.owner_loads == 1
    # Physical operator close released its original lease after serving ended.
    fd = os.open(f.directory / "private-mode.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "path",
    [
        "private-mode.lock",
        "owner/owner.json",
        "sessions/sessions.sqlite",
        "gmail-oauth-guard/oauth-host.lock",
        "gmail-oauth-guard/oauth-host.ready",
        "gmail-oauth-transactions/provider-oauth-transactions.lock",
        "gmail-oauth-transactions/provider-oauth-transactions.bin",
    ],
)
@pytest.mark.parametrize("change", ["missing", "unsafe"])
def test_existing_state_preflight_precedes_shared_reads_or_recreation(
    tmp_path, monkeypatch, path, change
):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    selected = f.directory / path
    if change == "missing":
        selected.unlink()
    else:
        selected.chmod(0o644)
    plan = f.diagnostic_plan(monkeypatch)
    with pytest.raises(GmailDiagnosticHostError):
        plan.run()
    assert not f.shared_reads and f.owner_loads == f.server_runs == 0
    if change == "missing":
        assert not selected.exists()
    f.no_gmail_io()


@pytest.mark.parametrize("tty", [0, 1, 2])
def test_tty_denial_spends_attempt_before_shared_reads(tmp_path, monkeypatch, tty):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    stream = (sys.stdin, sys.stdout, sys.stderr)[tty]
    monkeypatch.setattr(stream, "isatty", lambda: False)
    with pytest.raises(GmailDiagnosticHostError):
        plan.run()
    monkeypatch.setattr(stream, "isatty", lambda: True)
    with pytest.raises(GmailDiagnosticHostError):
        plan.run()
    assert not f.shared_reads and not f.server_runs
    f.no_gmail_io()


def test_worker_cannot_start_foreground_host(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    errors = []

    def run():
        try:
            plan.run()
        except GmailDiagnosticHostError as error:
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    assert len(errors) == 1 and not f.shared_reads and not f.server_runs
    f.no_gmail_io()


@pytest.mark.parametrize("cookie", ["missing", "wrong", "expired"])
def test_count_route_requires_actual_current_owner_cookie(tmp_path, monkeypatch, cookie):
    from datetime import timedelta

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    if cookie == "expired":
        f.now += timedelta(days=1)

    def browse(browser):
        if cookie != "missing":
            browser.cookies.set("__Host-zac-session", f.cookie if cookie == "expired" else "x" * 43)
        response = browser.get("/connections/gmail/diagnostic")
        assert response.status_code >= 400
        assert "loaded" not in response.text

    f.browser_action = browse
    plan.run()
    f.no_gmail_io()


@pytest.mark.parametrize("change", ["configuration", "loader", "clock", "escrow"])
def test_invalid_proposal_constructor_has_no_startup_or_operational_effect(
    tmp_path, monkeypatch, change
):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    before = f.operational_snapshot()
    alterations = {
        "configuration": {
            "configuration": f.configuration.model_copy(update={"provider": "slack"})
        },
        "loader": {"startup_loader": lambda **kwargs: CONFIG},
        "clock": {"clock": lambda: f.now},
        "escrow": {"escrow_confirmed_by_operator": False},
    }
    with pytest.raises(GmailDiagnosticHostError):
        f.diagnostic_plan(monkeypatch, **alterations[change])
    assert not f.shared_reads and not f.server_runs and f.operational_snapshot() == before
    f.no_gmail_io()


def test_unsafe_or_partial_namespace_never_calls_authority_constructor(tmp_path, monkeypatch):
    import shutil

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    shutil.rmtree(f.directory / "gmail-oauth-transactions")
    plan = f.diagnostic_plan(monkeypatch)
    calls = []
    monkeypatch.setattr(
        OAuthTransactionAuthority, "__init__", lambda *args, **kwargs: calls.append(True)
    )
    with pytest.raises(GmailDiagnosticHostError):
        plan.run()
    assert not calls and not f.shared_reads
    assert not (f.directory / "gmail-oauth-transactions").exists()
    f.no_gmail_io()


def test_original_startup_configuration_return_retained_during_actual_operator(
    tmp_path, monkeypatch
):
    from zacai.interfaces.private_startup import OwnerStartupLoader

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    returned = []
    original = OwnerStartupLoader.__call__

    def load(loader, **kwargs):
        result = original(loader, **kwargs)
        returned.append(result)
        return result

    monkeypatch.setattr(OwnerStartupLoader, "__call__", load)

    def browse(browser):
        assert len(returned) == 1 and plan._captured is returned[0]
        assert plan._diagnostic._reconciliation._authority._continuity._clock is f.clock
        f.held_lease()

    f.browser_action = browse
    plan.run()
    assert plan._captured is None
    f.no_gmail_io()


@pytest.mark.parametrize(
    "change", ["key", "loader", "configuration", "owner_inode", "ledger_inode"]
)
def test_original_context_mutations_during_startup_deny_before_listener(
    tmp_path, monkeypatch, change
):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    if change == "key":
        f.startup_session_key = b"Z" * 32
    else:

        def mutate(service):
            if service != "zacai-shared-owner-session-key":
                return
            if change == "loader":
                f.startup.foreground_timeout_seconds = 119
            elif change == "configuration":
                object.__setattr__(plan._configuration, "client_id", "invented-altered-client")
            else:
                target = f.directory / (
                    "owner/owner.json"
                    if change == "owner_inode"
                    else "gmail-oauth-transactions/provider-oauth-transactions.bin"
                )
                replacement = target.with_name("invented-replacement")
                replacement.write_bytes(target.read_bytes())
                replacement.chmod(0o600)
                replacement.replace(target)

        f.read_action = mutate
    with pytest.raises(GmailDiagnosticHostError) as raised:
        plan.run()
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert all(
        private not in repr(raised.value) + str(raised.value)
        for private in (str(f.directory), CONFIG.client_secret, f.cookie)
    )
    tb = raised.value.__traceback__
    while tb:
        if tb.tb_frame.f_globals.get("__name__") == "zacai.interfaces.gmail_diagnostic_host":
            assert tb.tb_frame.f_code.co_name == "call"
            assert "args" not in tb.tb_frame.f_locals and "kwargs" not in tb.tb_frame.f_locals
        tb = tb.tb_next
    assert not f.server_runs and plan._server._stopped
    f.no_gmail_io()


def test_actual_operator_physically_drains_new_worker_before_releasing_lease(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    events = []
    errors = []

    class Server:
        should_exit = False

        def run(self):
            def worker():
                try:
                    threading.Event().wait(0.1)
                    assert events == ["server returned"]
                    f.held_lease()
                    events.append("worker drained with lease")
                except BaseException as error:  # noqa: BLE001 - propagate worker test assertion
                    errors.append(error)

            threading.Thread(target=worker).start()
            events.append("server returned")

    server = Server()
    monkeypatch.setattr(plan._server, "_factory", lambda app: server)
    plan.run()
    assert not errors and events == ["server returned", "worker drained with lease"]
    assert server.should_exit is True
    f.no_gmail_io()


@pytest.mark.parametrize("seam", ["inspection", "after_receipt"])
@pytest.mark.parametrize("stop_fails", [False, True])
def test_actual_diagnostic_endpoint_cancellation_drops_context_and_request_frames(
    tmp_path, monkeypatch, seam, stop_fails
):
    import anyio
    from starlette.requests import Request

    from zacai.connectors.gmail_held_diagnostic import HeldGmailDiagnostic
    from zacai.interfaces.gmail_diagnostic_host import (
        GmailDiagnosticHostFatal,
        GmailDiagnosticHostPlan,
    )
    from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    stops = []
    original_stop = PrivateServerLifecycle.stop_host

    def stop(server):
        stops.append(server)
        if stop_fails:
            raise RuntimeError("invented-private-stop-" + f.cookie)
        original_stop(server)

    monkeypatch.setattr(PrivateServerLifecycle, "stop_host", stop)
    plan = f.diagnostic_plan(monkeypatch)
    original_inspect = HeldGmailDiagnostic.inspect
    original_check = GmailDiagnosticHostPlan._check
    returned = []
    leaves = []
    inspection_calls = []
    drained = []
    worker_errors = []

    def inspect(diagnostic, **kwargs):
        inspection_calls.append(True)
        if seam == "inspection":
            raise KeyboardInterrupt("invented-private-cookie-" + kwargs["cookie"])
        result = original_inspect(diagnostic, **kwargs)
        returned.append(result)
        return result

    def check(host):
        original_check(host)
        if returned:
            raise KeyboardInterrupt("invented-private-post-receipt-" + f.cookie)

    monkeypatch.setattr(HeldGmailDiagnostic, "inspect", inspect)
    monkeypatch.setattr(GmailDiagnosticHostPlan, "_check", check)

    def browse(browser):
        # Execute the actual mounted route coroutine with its actual Request
        # through AnyIO's worker seam, retaining its exception before outer
        # lifecycle sanitizers can hide a route-frame leak. No socket is opened.
        endpoint = next(
            route.endpoint
            for route in f.servers[-1].app.routes
            if route.path == "/connections/gmail/diagnostic"
        )
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/connections/gmail/diagnostic",
                "raw_path": b"/connections/gmail/diagnostic",
                "query_string": b"",
                "headers": [
                    (b"host", urlsplit(ORIGIN).netloc.encode()),
                    (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                ],
                "server": (urlsplit(ORIGIN).netloc, 443),
                "client": ("127.0.0.1", 1),
            }
        )
        before_stops = len(stops)
        with pytest.raises(GmailDiagnosticHostFatal) as raised:
            anyio.run(endpoint, request)
        error = raised.value
        leaves.append(error)
        assert len(stops) == before_stops + 1 and stops[-1] is plan._server
        assert f.servers[-1].should_exit is (not stop_fails)
        assert error.__cause__ is None and error.__context__ is None
        assert f.cookie not in str(error) + repr(error)
        tb = error.__traceback__
        route_frames = []
        while tb:
            if (
                tb.tb_frame.f_globals.get("__name__") == "zacai.interfaces.gmail_diagnostic_host"
                and tb.tb_frame.f_code.co_name == "counts"
            ):
                route_frames.append(tb.tb_frame)
                assert not {"request", "receipt", "cookie"} & tb.tb_frame.f_locals.keys()
            tb = tb.tb_next
        assert len(route_frames) == 1
        f.held_lease()
        returned.clear()
        before_calls = len(inspection_calls)
        denied = anyio.run(endpoint, Request(request.scope.copy()))
        assert denied.status_code >= 400
        assert len(inspection_calls) == before_calls
        assert browser.get("/login").status_code >= 400

        def worker():
            try:
                threading.Event().wait(0.1)
                f.held_lease()
                drained.append(True)
            except BaseException as error:  # noqa: BLE001 - propagate invented worker assertions
                worker_errors.append(error)

        threading.Thread(target=worker).start()

    f.browser_action = browse
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    assert len(leaves) == 1 and drained == [True] and not worker_errors
    assert plan._diagnostic is plan._captured is None
    f.no_gmail_io()


def test_real_anyio_cancel_scope_latches_failure_and_denies_later_requests(tmp_path, monkeypatch):
    import anyio
    from starlette.requests import Request

    from zacai.connectors.gmail_held_diagnostic import HeldGmailDiagnostic
    from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostFatal

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    completed = []
    calls = []
    original = HeldGmailDiagnostic.inspect

    def inspect(diagnostic, **kwargs):
        calls.append(True)
        return original(diagnostic, **kwargs)

    monkeypatch.setattr(HeldGmailDiagnostic, "inspect", inspect)
    endpoints = []

    def request():
        return Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/connections/gmail/diagnostic",
                "query_string": b"",
                "headers": [
                    (b"host", urlsplit(ORIGIN).netloc.encode()),
                    (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                ],
            }
        )

    def browse(browser):
        endpoint = next(
            route.endpoint
            for route in f.servers[-1].app.routes
            if route.path == "/connections/gmail/diagnostic"
        )
        endpoints.append(endpoint)

        async def cancelled():
            with anyio.CancelScope() as scope:
                scope.cancel()
                await endpoint(request())

        with pytest.raises(GmailDiagnosticHostFatal) as raised:
            anyio.run(cancelled)
        assert raised.value.__cause__ is raised.value.__context__ is None
        tb = raised.value.__traceback__
        frames = []
        while tb:
            if (
                tb.tb_frame.f_globals.get("__name__") == "zacai.interfaces.gmail_diagnostic_host"
                and tb.tb_frame.f_code.co_name == "counts"
            ):
                frames.append(tb.tb_frame)
                assert not {"request", "receipt", "cookie"} & tb.tb_frame.f_locals.keys()
            tb = tb.tb_next
        assert len(frames) == 1
        before = len(calls)
        denied = anyio.run(endpoint, request())
        assert denied.status_code >= 400 and len(calls) == before
        assert f.servers[-1].should_exit is True
        f.held_lease()
        completed.append(True)

    f.browser_action = browse
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    assert completed == [True]
    assert plan._diagnostic is plan._captured is None
    before = len(calls)
    assert anyio.run(endpoints[0], request()).status_code >= 400
    assert len(calls) == before
    f.no_gmail_io()


@pytest.mark.parametrize("target", ["ledger", "guard", "owner", "halt"])
def test_final_preservation_audit_inside_lease_after_serve_reports_failure(
    tmp_path, monkeypatch, target
):
    from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostFatal

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    audited = []
    original = type(plan)._check
    served = []

    def check(host):
        if served:
            f.held_lease()
            audited.append(True)
        return original(host)

    monkeypatch.setattr(type(plan), "_check", check)

    def browse(browser):
        served.append(True)
        if target == "halt":
            path = f.directory / "gmail-oauth-guard/oauth-host.halted"
            path.write_bytes(b"invented-sticky-halt")
            path.chmod(0o600)
        else:
            paths = {
                "ledger": "gmail-oauth-transactions/provider-oauth-transactions.bin",
                "guard": "gmail-oauth-guard/oauth-host.ready",
                "owner": "owner/owner.json",
            }
            path = f.directory / paths[target]
            path.chmod(0o644)

    f.browser_action = browse
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    assert audited and plan._diagnostic is plan._captured is None
    assert f.servers[-1].should_exit is True
    f.no_gmail_io()


def test_midserve_preservation_failure_latched_even_when_audit_later_appears_clean(
    tmp_path, monkeypatch
):
    from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostFatal

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    completed = []
    failed = []
    original = type(plan)._files

    def files(host):
        result = original(host)
        if failed == ["transient"]:
            failed.append("observed")
            return ()  # An observed witness failure cannot be repaired by retry.
        return result

    monkeypatch.setattr(type(plan), "_files", files)

    def browse(browser):
        import anyio
        from starlette.requests import Request

        endpoint = next(
            route.endpoint
            for route in f.servers[-1].app.routes
            if route.path == "/connections/gmail/diagnostic"
        )

        def request():
            return Request(
                {
                    "type": "http",
                    "method": "GET",
                    "scheme": "https",
                    "path": "/connections/gmail/diagnostic",
                    "query_string": b"",
                    "headers": [
                        (b"host", urlsplit(ORIGIN).netloc.encode()),
                        (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                    ],
                }
            )

        failed.append("transient")
        with pytest.raises(GmailDiagnosticHostFatal):
            anyio.run(endpoint, request())
        assert failed == ["transient", "observed"]
        assert anyio.run(endpoint, request()).status_code >= 400
        f.held_lease()
        completed.append(True)

    f.browser_action = browse
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    assert completed == [True]
    assert plan._diagnostic is plan._captured is None
    f.no_gmail_io()


def test_completed_host_retires_inspector_and_extracted_route_without_cookie_read(
    tmp_path, monkeypatch
):
    import anyio
    from starlette.requests import Request

    import zacai.interfaces.gmail_diagnostic_host as source
    from zacai.connectors.gmail_held_diagnostic import HeldGmailDiagnostic

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    endpoints = []

    def browse(browser):
        endpoints.append(
            next(
                route.endpoint
                for route in f.servers[-1].app.routes
                if route.path == "/connections/gmail/diagnostic"
            )
        )

    f.browser_action = browse
    plan.run()
    assert plan._diagnostic is plan._captured is None
    calls = []
    monkeypatch.setattr(
        HeldGmailDiagnostic, "inspect", lambda *args, **kwargs: calls.append("inspect")
    )
    monkeypatch.setattr(source, "_cookie", lambda *args, **kwargs: calls.append("cookie"))
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/connections/gmail/diagnostic",
            "query_string": b"",
            "headers": [
                (b"host", urlsplit(ORIGIN).netloc.encode()),
                (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
            ],
        }
    )
    response = anyio.run(endpoints[0], request)
    assert response.status_code >= 400 and not calls
    f.no_gmail_io()


def test_ordinary_inspection_failure_still_audits_storage_and_stops_host(tmp_path, monkeypatch):
    import anyio
    from starlette.requests import Request

    from zacai.connectors.gmail_held_diagnostic import GmailHeldDiagnosticError, HeldGmailDiagnostic
    from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostFatal

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    calls = []
    completed = []

    def inspect(diagnostic, **kwargs):
        calls.append(True)
        target = f.directory / "gmail-oauth-transactions/provider-oauth-transactions.bin"
        replacement = target.with_name("invented-replacement")
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(target)
        raise GmailHeldDiagnosticError("invented-private-error-" + kwargs["cookie"])

    monkeypatch.setattr(HeldGmailDiagnostic, "inspect", inspect)

    def browse(browser):
        endpoint = next(
            route.endpoint
            for route in f.servers[-1].app.routes
            if route.path == "/connections/gmail/diagnostic"
        )
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/connections/gmail/diagnostic",
                "query_string": b"",
                "headers": [
                    (b"host", urlsplit(ORIGIN).netloc.encode()),
                    (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                ],
            }
        )
        with pytest.raises(GmailDiagnosticHostFatal) as raised:
            anyio.run(endpoint, request)
        assert raised.value.__context__ is raised.value.__cause__ is None
        assert f.cookie not in repr(raised.value)
        assert f.servers[-1].should_exit is True and len(calls) == 1
        denied = anyio.run(endpoint, Request(request.scope.copy()))
        assert denied.status_code >= 400 and len(calls) == 1
        assert browser.get("/login").status_code >= 400
        f.held_lease()
        completed.append(True)

    f.browser_action = browse
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    assert completed == [True]
    assert plan._captured is plan._diagnostic is None
    f.no_gmail_io()


def test_changed_stop_alias_is_denied_using_retained_actual_listener_callback(
    tmp_path, monkeypatch
):
    import anyio
    from starlette.requests import Request

    from zacai.connectors.gmail_held_diagnostic import HeldGmailDiagnostic
    from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostFatal

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    before = f.operational_snapshot()
    targeted = []
    completed = []
    original_inspect = HeldGmailDiagnostic.inspect

    def replacement():
        targeted.append(True)
        raise RuntimeError("invented-private-replaced-stop")

    def inspect(diagnostic, **kwargs):
        receipt = original_inspect(diagnostic, **kwargs)
        plan._original_stop = replacement
        return receipt

    monkeypatch.setattr(HeldGmailDiagnostic, "inspect", inspect)

    def browse(browser):
        endpoint = next(
            route.endpoint
            for route in f.servers[-1].app.routes
            if route.path == "/connections/gmail/diagnostic"
        )
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/connections/gmail/diagnostic",
                "query_string": b"",
                "headers": [
                    (b"host", urlsplit(ORIGIN).netloc.encode()),
                    (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                ],
            }
        )
        with pytest.raises(GmailDiagnosticHostFatal) as raised:
            anyio.run(endpoint, request)
        assert raised.value.__cause__ is raised.value.__context__ is None
        assert not targeted and f.servers[-1].should_exit is True
        assert anyio.run(endpoint, Request(request.scope.copy())).status_code >= 400
        assert browser.get("/login").status_code >= 400
        f.held_lease()
        completed.append(True)

    f.browser_action = browse
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    assert completed == [True] and not targeted
    assert f.servers[-1].should_exit is True
    assert plan._diagnostic is plan._captured is None
    assert f.operational_snapshot() == before
    f.no_gmail_io()


def test_non_count_route_failure_latches_whole_host_and_drains_before_failure(
    tmp_path, monkeypatch
):
    from fastapi.testclient import TestClient

    from zacai.connectors.gmail_held_diagnostic import HeldGmailDiagnostic
    from zacai.interfaces.gmail_diagnostic_host import GmailDiagnosticHostFatal

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.diagnostic_plan(monkeypatch)
    inspection_calls = []
    monkeypatch.setattr(
        HeldGmailDiagnostic, "inspect", lambda *args, **kwargs: inspection_calls.append(True)
    )
    completed = []
    drained = []
    worker_errors = []

    def browse(browser):
        app = f.servers[-1].app

        @app.get("/invented-non-count-failure")
        async def failure():
            raise RuntimeError("invented-private-route-" + f.cookie)

        with pytest.raises((GmailDiagnosticHostFatal, BaseExceptionGroup)) as raised:
            browser.get("/invented-non-count-failure")

        def leaves(error):
            if isinstance(error, BaseExceptionGroup):
                return [leaf for child in error.exceptions for leaf in leaves(child)]
            return [error]

        assert all(isinstance(error, GmailDiagnosticHostFatal) for error in leaves(raised.value))
        assert f.servers[-1].should_exit is True
        # A BaseException ends TestClient's first AnyIO portal. A fresh
        # invented client exercises subsequent requests to the same ASGI app.
        with TestClient(app, base_url=ORIGIN, follow_redirects=False) as later:
            later.cookies.set("__Host-zac-session", f.cookie)
            assert later.get("/login").status_code == 403
            assert later.get("/connections/gmail/diagnostic").status_code == 403
        assert not inspection_calls
        f.held_lease()
        completed.append(True)

        def worker():
            try:
                threading.Event().wait(0.1)
                f.held_lease()
                drained.append(True)
            except BaseException as error:  # noqa: BLE001 - forward invented worker assertions
                worker_errors.append(error)

        threading.Thread(target=worker).start()

    callback_errors = []

    def guarded(browser):
        try:
            browse(browser)
        except BaseException as error:
            callback_errors.append(error)
            raise

    f.browser_action = guarded
    with pytest.raises(GmailDiagnosticHostFatal):
        plan.run()
    if callback_errors:
        raise callback_errors[0]
    assert completed == drained == [True] and not worker_errors
    assert plan._diagnostic is plan._captured is None
    assert not inspection_calls
    f.no_gmail_io()
