"""Invented source-derived lifecycle controls. No listener/key/provider or real signals."""

import ast
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from zacai.interfaces.private_server_lifecycle import (
    PrivateServerLifecycle,
)

ROOT = Path(__file__).parents[1] / "src/zacai/interfaces"


def source_operator(*, extra_thread=False, drain_failure=False):
    tree = ast.parse((ROOT / "private_operator.py").read_text())
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PrivateOperatorWindow"
    )
    method = next(
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_run_foreground"
    )
    events = []
    marker = object()

    class OperatorError(RuntimeError):
        pass

    class PreparedOwner:
        pass

    class Signal:
        SIGINT, SIGTERM, SIG_IGN = 2, 15, 0

        def getsignal(self, value):
            return 42

        def signal(self, value, handler):
            events.append("signal_emulated")

    logging = SimpleNamespace(root=SimpleNamespace(manager=SimpleNamespace(disable=0)))
    logging.disable = lambda value: events.append("logging_emulated")
    namespace = {
        "Callable": Callable,
        "FastAPI": FastAPI,
        "threading": SimpleNamespace(
            enumerate=lambda: [marker, object()] if extra_thread else [marker],
            main_thread=lambda: marker,
        ),
        "signal": Signal(),
        "logging": logging,
        "sys": SimpleNamespace(maxsize=2**63 - 1),
        "_drain_threads": lambda baseline: (
            (_ for _ in ()).throw(ValueError("invented-drain-failure"))
            if drain_failure
            else events.append("drain_emulated")
        ),
        "PreparedOwnerHost": PreparedOwner,
        "PrivateOperatorError": OperatorError,
    }
    module = ast.Module(body=[method], type_ignores=[])
    exec(  # noqa: S102 - exact trusted source AST, no private data
        compile(ast.fix_missing_locations(module), "<source-only-operator-method>", "exec"),
        namespace,
    )
    window = SimpleNamespace(
        _active=True,
        _foreground_cleanup_failure_stage="not_started",
        _foreground_cleanup_stage="not_started",
        _served=False,
        _serving=False,
        _require=lambda: None,
        _prepared=SimpleNamespace(app=FastAPI()),
    )
    return namespace["_run_foreground"], window, OperatorError, events


def host_closed():
    tree = ast.parse((ROOT / "gmail_recovery_host.py").read_text())
    nodes = [
        n
        for n in tree.body
        if getattr(n, "name", "") in {"GmailRecoveryHostError", "GmailRecoveryHostFatal", "_closed"}
    ]
    namespace = {"Callable": Callable, "wraps": wraps}
    exec(  # noqa: S102 - exact trusted source AST, no private data
        compile(
            ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
            "<source-only-host-wrapper>",
            "exec",
        ),
        namespace,
    )
    return namespace


@pytest.mark.parametrize("failure", [OSError, RuntimeError, SystemExit, KeyboardInterrupt])
def test_different_failure_categories_collapse_to_same_fixed_host_unavailable(failure):
    def run():
        raise failure("invented nonprivate failure")

    server = SimpleNamespace(should_exit=False, run=run)
    lifecycle = PrivateServerLifecycle(server_factory=lambda app: server)
    method, window, _operator_error, events = source_operator()
    host = host_closed()

    def call():
        method(window, lifecycle)

    with pytest.raises(
        host["GmailRecoveryHostError"], match="Gmail recovery host unavailable"
    ) as result:
        host["_closed"](call)()
    assert not isinstance(result.value, KeyboardInterrupt)
    assert server.should_exit is True and lifecycle._spent and lifecycle._stopped
    assert "drain_emulated" in events and window._active is False


def test_normal_fake_server_return_is_not_listener_or_connection_evidence():
    server = SimpleNamespace(should_exit=False, run=lambda: None)
    lifecycle = PrivateServerLifecycle(server_factory=lambda app: server)
    method, window, _, events = source_operator()
    method(window, lifecycle)
    assert window._active and lifecycle._spent and "drain_emulated" in events
    # No socket or request exists: serving label/normal return cannot prove binding.
    lifecycle.stop_host()
    assert server.should_exit is True


def test_foreground_baseline_denies_before_server_construction():
    method, window, operator_error, _events = source_operator(extra_thread=True)
    called = []
    with pytest.raises(operator_error):
        method(window, lambda app: called.append(True))
    assert called == [] and window._foreground_stage == "thread_baseline"


def test_drain_failure_preserves_server_return_phase_and_restoration():
    method, window, operator_error, _events = source_operator(drain_failure=True)
    with pytest.raises(operator_error):
        method(window, lambda app: None)
    assert window._foreground_stage == "server_returned"
    assert window._foreground_cleanup_stage == "restored" and window._active is False
    assert window._foreground_cleanup_failure_stage == "thread_drain"
