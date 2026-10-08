"""Pure isolated diagnostics: no owner/SQLite/native/provider/socket or real signals."""

import ast
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from tests.test_oauth_configuration import gmail
from zacai.interfaces.gmail_recovery_host import (
    GmailRecoveryHostError,
    GmailRecoveryHostFatal,
    GmailRecoveryHostPlan,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_operator import PrivateOperatorWindow
from zacai.interfaces.private_server_lifecycle import (
    PrivateServerLifecycle,
    PrivateServerLifecycleError,
)
from zacai.interfaces.private_startup import OwnerStartupLoader

NOW = datetime(2026, 10, 8, tzinfo=UTC)


def plan(**changes):
    fields = dict(  # noqa: C408 - typed keyword readability
        configuration=gmail(),
        original_directory=Path("/private/tmp/invented-original"),
        hr_directory=Path("/private/tmp/invented-hr"),
        owner_client_id="123456-invented.apps.googleusercontent.com",
        startup_loader=OwnerStartupLoader(
            client_id="123456-invented.apps.googleusercontent.com",
            origin="https://invented.example",
            keychain_path=Path("/private/tmp/invented/login.keychain-db"),
            mode="foreground",
            keychain_file_policy="reviewed_login",
        ),
        clock=HostObservedClock(lambda: NOW),
        escrow_confirmed_by_operator=True,
        reviewed_registration_generation="invented-registration",
        console_observed_at=NOW,
        review_expires_at=NOW + timedelta(hours=1),
        action_generation="invented-serving",
        diagnostic_serving=True,
    )
    fields.update(changes)
    return GmailRecoveryHostPlan(**fields)


@pytest.mark.parametrize("value", [0, 1, None, [], "true"])
def test_exact_bool_mode_required(value):
    with pytest.raises(GmailRecoveryHostError):
        plan(diagnostic_serving=value)


@pytest.mark.parametrize("change", [{"load_existing": True}, {"startup_only": True}])
def test_diagnostic_mode_cannot_load_tokens_or_skip_serving(change):
    with pytest.raises(GmailRecoveryHostError):
        plan(**change)


@pytest.mark.parametrize("value", [False, 1, "private-value"])
def test_diagnostic_mode_pinned_before_existing_guard(value):
    candidate = plan()
    candidate._diagnostic_serving = value
    with pytest.raises(ValueError):
        candidate._proposal_current()


@pytest.mark.parametrize("failure_at", [None, 1, 2, 3, 4])
def test_health_only_app_async_budget_stop_and_existing_server_cleanup(monkeypatch, failure_at):
    candidate = plan()
    checks = []

    def current():
        checks.append("protected-current")
        if len(checks) == failure_at or candidate._fatal:
            raise ValueError("invented current refusal")

    candidate._recovery_current = current
    candidate._active = True
    original_sleep = asyncio.sleep

    async def budget(seconds):
        assert seconds == 10
        await original_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", budget)
    observed = []

    class Server:
        should_exit = False
        started = False

        def __init__(self, app):
            self.app = app

        def run(self):
            async def exercise():
                async with self.app.router.lifespan_context(self.app):
                    self.started = True
                    assert {route.path for route in self.app.routes} == {"/health"}
                    async with httpx.AsyncClient(
                        transport=httpx.ASGITransport(app=self.app),
                        base_url="https://invented.example",
                    ) as client:
                        for path in [
                            "/login",
                            "/connections/gmail/recover",
                            "/connections/gmail/begin",
                            "/connections/gmail/callback",
                        ]:
                            assert (await client.get(path)).status_code == 404
                        reply = await client.get("/health")
                        assert reply.text == (
                            "Startup diagnostic unavailable."
                            if failure_at == 2
                            else "Startup diagnostic only; Gmail inactive."
                        )
                    await original_sleep(0)
                    await original_sleep(0)
                    assert self.should_exit is True

            asyncio.run(exercise())

    def factory(app):
        server = Server(app)
        observed.append(server)
        return server

    candidate._server._factory = factory
    owner_app = FastAPI()
    window = SimpleNamespace(
        foreground_stage="server_returned",
        foreground_cleanup_stage="restored",
        foreground_cleanup_failure_stage="not_started",
        serve=lambda *, server: server(owner_app),
    )
    if failure_at is not None:
        with pytest.raises((ValueError, PrivateServerLifecycleError)):
            candidate._diagnostic_serve(window)
        assert candidate._active is False or failure_at == 4
        if failure_at == 1:
            assert observed == []
        else:
            assert len(observed) == 1 and candidate._server._spent
        return
    candidate._diagnostic_serve(window)
    assert len(observed) == 1 and observed[0].app is not owner_app
    assert candidate._server._spent and candidate._server._stopped
    assert len(checks) == 4 and candidate._active is False
    assert candidate.listener_stage == "started"
    assert candidate.diagnostic_request_stage == "current_returned"
    assert candidate.server_stage == "server_run_returned"


@pytest.mark.parametrize("failure", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_server_failure_retains_fixed_phase_and_cancellation_stop(failure):
    class Server:
        should_exit = False
        started = False

        def run(self):
            raise failure("invented-private-value")

    server = Server()
    lifecycle = PrivateServerLifecycle(server_factory=lambda app: server)
    with pytest.raises(PrivateServerLifecycleError) as error:
        lifecycle(FastAPI())
    assert lifecycle.lifecycle_stage == "server_run_entered"
    assert lifecycle.listener_stage == "not_started"
    assert server.should_exit is True and lifecycle._spent and lifecycle._stopped
    assert "invented-private" not in str(error.value)


def test_foreign_diagnostic_values_never_format_or_compare_private_object():
    class Private:
        def __str__(self):
            raise AssertionError("private formatting")

        __repr__ = __str__

        def __eq__(self, other):
            raise AssertionError("private comparison")

        def __hash__(self):
            raise AssertionError("private hash")

    candidate = plan()
    for field, getter in [
        ("_shutdown_stage", "shutdown_stage"),
        ("_shutdown_failure_stage", "shutdown_failure_stage"),
        ("_protected_stop_stage", "protected_stop_stage"),
        ("_diagnostic_request_stage", "diagnostic_request_stage"),
        ("_foreground_stage", "foreground_stage"),
        ("_foreground_cleanup_stage", "foreground_cleanup_stage"),
    ]:
        setattr(candidate, field, Private())
        assert getattr(candidate, getter) == "unavailable"
    lifecycle = candidate._server
    lifecycle._lifecycle_stage = lifecycle._listener_stage = Private()
    assert lifecycle.lifecycle_stage == lifecycle.listener_stage == "unavailable"
    window = object.__new__(PrivateOperatorWindow)
    window._foreground_stage = window._foreground_cleanup_stage = Private()
    assert window.foreground_stage == window.foreground_cleanup_stage == "unavailable"


def test_source_branch_after_initial_proof_before_join_or_routes_and_no_provider_calls():
    import inspect

    source = ast.parse(inspect.getsource(GmailRecoveryHostPlan))
    cls = source.body[0]
    run = next(node for node in cls.body if getattr(node, "name", "") == "run")
    branch = next(
        node
        for node in ast.walk(run)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Attribute)
        and node.test.attr == "_diagnostic_serving"
    )
    assert len(branch.body) == 2 and isinstance(branch.body[-1], ast.Return)
    assert (
        isinstance(branch.body[0], ast.Expr)
        and branch.body[0].value.func.attr == "_diagnostic_serve"
    )
    diagnostic = next(node for node in cls.body if getattr(node, "name", "") == "_diagnostic_serve")
    text = ast.unparse(diagnostic)
    for forbidden in [
        "GmailRecoveryJoin",
        "GmailRecoveryWeb",
        "begin_once",
        "commit_quarantine",
        "GmailClientSecretLoader",
        "GmailNativeReader",
        "OAuthExchangeTransport",
    ]:
        assert forbidden not in text
    assert branch.lineno < next(
        node.lineno
        for node in ast.walk(run)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "GmailRecoveryJoin"
    )


def test_native_configuration_and_lifespan_hooks_call_real_superclass_without_listener():
    from zacai.interfaces.private_server_lifecycle import _make_server

    stages = []
    server = _make_server(FastAPI(), diagnostic_stage=stages.append)
    server.config.load()
    assert stages == ["configuration_load_entered", "configuration_load_returned"]

    async def exercise():
        lifespan = server.config.lifespan_class(server.config)
        await lifespan.startup()
        assert stages[-2:] == ["lifespan_startup_entered", "bind_pending"]
        await lifespan.shutdown()

    asyncio.run(exercise())


@pytest.mark.parametrize("started", [False, True])
def test_native_startup_shutdown_hook_order_with_superclass_mock_no_socket(monkeypatch, started):
    import uvicorn

    from zacai.interfaces.private_server_lifecycle import _make_server

    stages = []
    super_calls = []

    async def startup(self, sockets=None):
        super_calls.append("startup")
        self.started = started

    async def shutdown(self, sockets=None):
        super_calls.append("shutdown")

    monkeypatch.setattr(uvicorn.Server, "startup", startup)
    monkeypatch.setattr(uvicorn.Server, "shutdown", shutdown)
    server = _make_server(FastAPI(), diagnostic_stage=stages.append)

    async def exercise():
        await server.startup()
        await server.shutdown()

    asyncio.run(exercise())
    assert super_calls == ["startup", "shutdown"]
    assert stages == [
        "startup_entered",
        "listener_started" if started else "startup_returned",
        "shutdown_entered",
        "shutdown_returned",
    ]


def test_native_hook_failure_retains_first_fixed_phase_before_later_cleanup(monkeypatch):
    import uvicorn

    from zacai.interfaces.private_server_lifecycle import _make_server

    lifecycle = PrivateServerLifecycle(diagnostic_stages=True)

    async def startup(self, sockets=None):
        raise KeyboardInterrupt("invented-private")

    async def shutdown(self, sockets=None):
        return None

    monkeypatch.setattr(uvicorn.Server, "startup", startup)
    monkeypatch.setattr(uvicorn.Server, "shutdown", shutdown)
    server = _make_server(
        FastAPI(),
        diagnostic_stage=lifecycle._record_stage,
        diagnostic_failure=lifecycle._record_failure,
    )

    async def exercise():
        with pytest.raises(KeyboardInterrupt):
            await server.startup()
        await server.shutdown()

    asyncio.run(exercise())
    assert lifecycle.failure_stage == "startup_entered"
    assert lifecycle.lifecycle_stage == "shutdown_returned"


def test_health_cancellation_discards_private_exception_context():
    candidate = plan()
    candidate._active = True
    calls = 0
    caught = []

    def current():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise asyncio.CancelledError("invented-private-interruption")

    candidate._recovery_current = current

    def factory(app):
        endpoint = next(route.endpoint for route in app.routes if route.path == "/health")

        class Server:
            started = False
            should_exit = False

            def run(self):
                async def invoke():
                    try:
                        await endpoint()
                    except GmailRecoveryHostFatal as error:
                        caught.append(error)

                asyncio.run(invoke())

        return Server()

    candidate._server._factory = factory
    window = SimpleNamespace(
        serve=lambda *, server: server(FastAPI()),
        foreground_stage="server_returned",
        foreground_cleanup_stage="restored",
        foreground_cleanup_failure_stage="not_started",
    )
    with pytest.raises(GmailRecoveryHostFatal):
        candidate._diagnostic_serve(window)
    assert len(caught) == 1
    assert caught[0].__context__ is None and caught[0].__cause__ is None
    assert str(caught[0]) == "Startup diagnostic interrupted"
    assert candidate.diagnostic_request_stage == "request_refused"
    assert candidate._fatal and not candidate._active
