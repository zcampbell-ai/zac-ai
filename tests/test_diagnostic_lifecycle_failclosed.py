"""Real ASGI lifespan engine; signals/delivery/drain simulated, no process or listener."""
import asyncio
import logging
import signal
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from zacai.interfaces import private_operator as operator
from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress
from zacai.interfaces.private_server_lifecycle import _make_server


@pytest.mark.parametrize("forwarded", [False, True])
def test_diagnostic_lifespan_refusal_cannot_be_auto_unsupported(forwarded):
    stages, entered = [], []

    async def unsupported(scope, receive, send):
        assert scope["type"] == "lifespan"
        entered.append("forwarded lifespan")
        raise RuntimeError("invented refused lifecycle")

    server = _make_server(unsupported,
        verified_private_origin="https://invented.example" if forwarded else None,
        diagnostic_stage=stages.append)
    assert isinstance(server.config.app, TrustedLoopbackHttpsIngress) is forwarded
    server.config.load()

    async def exercise():
        lifespan = server.config.lifespan_class(server.config)
        await lifespan.startup()
        assert entered == ["forwarded lifespan"]
        assert lifespan.error_occurred
        assert lifespan.should_exit
        assert stages[-1] == "lifespan_refused"
        await lifespan.shutdown()

    asyncio.run(exercise())
    assert not server.started


def test_normal_listener_keeps_auto_lifespan():
    server = _make_server(FastAPI())
    assert server.config.lifespan == "auto"
    assert not server.started


@pytest.mark.parametrize("first", [signal.SIGINT, signal.SIGTERM])
def test_local_interrupt_disarms_both_before_action_finally_and_drain(monkeypatch, first):
    originals = {signal.SIGINT: object(), signal.SIGTERM: object()}
    handlers = dict(originals)
    events = []
    disabled = logging.root.manager.disable

    def install(sig, handler):
        previous = handlers[sig]
        handlers[sig] = handler
        return previous

    monkeypatch.setattr(operator.signal, "signal", install)
    monkeypatch.setattr(operator.signal, "getsignal", lambda sig: handlers[sig])

    def deliver(sig):
        handler = handlers[sig]
        if handler is signal.SIG_IGN:
            events.append("repeat ignored")
        else:
            handler(sig, None)

    def drain(baseline):
        assert handlers == {sig: signal.SIG_IGN for sig in originals}
        events.append("physical drain boundary")

    monkeypatch.setattr(operator, "_drain_threads", drain)
    window = operator.PrivateOperatorWindow(SimpleNamespace(app=FastAPI()),
        mode=operator.PrivateOperatorMode.OWNER, origin="https://invented.example",
        clock=lambda: None)

    def action():
        events.append("action entered")
        try:
            deliver(first)
        finally:
            # This action cleanup precedes run_local's finally; waiting for that
            # outer finally to suppress the handlers is too late.
            assert handlers == {sig: signal.SIG_IGN for sig in originals}
            deliver(signal.SIGINT)
            deliver(signal.SIGTERM)
            events.append("action cleanup completed")

    with pytest.raises(operator.PrivateOperatorError):
        window.run_local(action=action)
    assert events == ["action entered", "repeat ignored", "repeat ignored",
        "action cleanup completed", "physical drain boundary"]
    assert handlers == originals
    assert logging.root.manager.disable == disabled
    assert window._served and not window._serving and not window._active
    assert window.foreground_cleanup_stage == "restored"
    with pytest.raises(operator.PrivateOperatorError):
        window.run_local(action=lambda: events.append("forbidden replay"))
    assert "forbidden replay" not in events
