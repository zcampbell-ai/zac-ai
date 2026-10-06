"""Isolated real host/registry with no listener, SQL/model or production proofs."""

import logging
import signal
from uuid import uuid4

import pytest

from tests.test_named_owner_host import operator_args
from tests.test_named_owner_host import setup as setup  # noqa: PLC0414 - pytest fixture re-export.
from zacai.interfaces.named_worker_lifecycle import (
    NamedWorkerRequest,
    ThreadBoundNamedAskPipeline,
    _Worker,
)
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)


def test_server_return_cannot_hide_actual_unresolved_worker_shutdown(setup):
    args, factory, _ = setup
    prior = logging.root.manager.disable

    class InventedPipeline:
        def submit(self, **kwargs):
            raise AssertionError("no processing")

        def recheck(self, **kwargs):
            raise AssertionError("no processing")

    def enabled(inputs):
        pair = factory(inputs)
        pair.controller._pipeline = ThreadBoundNamedAskPipeline(
            workers=pair.workers, pipeline=InventedPipeline(), store=pair.controller._store
        )
        return pair

    with open_private_operator(mode=PrivateOperatorMode.OWNER, view=args["view"],
                               named_factory=enabled, **operator_args(args)) as window:
        def server(app):
            pair = window._prepared.named
            request = NamedWorkerRequest(uuid4(), "b" * 64, args["clock"](),
                                         args["clock"]())
            pair.workers._entries[request.request_id] = _Worker(request)
            # Simulate server swallowing lifespan.shutdown.failed, no threads.
        with pytest.raises(PrivateOperatorError, match="stop and reconcile"):
            window.serve(server=server)
        assert not window._active
    assert logging.root.manager.disable == prior


def test_unknown_c_signal_handler_startup_failure_remains_sanitized(setup, monkeypatch):
    args, _, _ = setup
    prior = logging.root.manager.disable
    get, setter = signal.getsignal, signal.signal
    attempts = []

    def getsig(sig):
        return None if sig == signal.SIGINT else get(sig)

    def setsig(sig, handler):
        attempts.append((sig, handler))
        assert handler is not None
        return setter(sig, handler)

    monkeypatch.setattr(signal, "getsignal", getsig)
    monkeypatch.setattr(signal, "signal", setsig)
    values = operator_args(args)
    def failed(**kwargs):
        raise ValueError("PRIVATE invented failure")
    values["startup_loader"] = failed
    with pytest.raises(PrivateOperatorError) as error, open_private_operator(
        mode=PrivateOperatorMode.OWNER, view=args["view"], **values
    ):
        raise AssertionError("not exposed")
    assert error.value.__context__ is None
    assert logging.root.manager.disable == prior
    assert attempts and all(sig == signal.SIGTERM for sig, _ in attempts)
    assert attempts[-1][1] == get(signal.SIGTERM)


def test_startup_signal_suppression_failure_is_sanitized_and_drained(setup, monkeypatch):
    args, _, _=setup
    values=operator_args(args)
    actual=signal.signal
    def signal_failure(sig, handler):
        if handler is signal.SIG_IGN:
            raise RuntimeError('invented private suppression failure')
        return actual(sig,handler)
    monkeypatch.setattr(signal,'signal',signal_failure)
    def failed(**kwargs):
        raise ValueError('invented private startup failure')
    values['startup_loader']=failed
    with pytest.raises(PrivateOperatorError) as error, open_private_operator(
        mode=PrivateOperatorMode.OWNER, view=args['view'], **values
    ):
        raise AssertionError('not exposed')
    assert error.value.__context__ is None


def test_serve_resuppression_failure_cannot_skip_actual_thread_drain(setup, monkeypatch):
    import sys
    from threading import Event, Thread

    from zacai.interfaces import private_operator as module
    args, factory, _=setup
    values=operator_args(args)
    values["named_factory"]=factory
    prior=logging.root.manager.disable
    handlers={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
    actual_signal=signal.signal;actual_drain=module._drain_threads
    fail_seen,drain_entered,release=Event(),Event(),Event()
    calls=0;observed=[];threads=[];error=None
    def signal_failure(sig,handler):
        nonlocal calls
        if handler is signal.SIG_IGN:
            calls+=1
            if calls==3:
                fail_seen.set()
                raise RuntimeError('invented private suppression failure')
        return actual_signal(sig,handler)
    def drain(baseline):
        drain_entered.set()
        return actual_drain(baseline)
    monkeypatch.setattr(signal,'signal',signal_failure)
    monkeypatch.setattr(module,'_drain_threads',drain)
    def worker():
        assert release.wait(5)
    def observer():
        try:
            assert fail_seen.wait(5)
            entered=drain_entered.wait(.1)
            observed.append(entered and logging.root.manager.disable==sys.maxsize)
        finally:
            release.set()
    def server(app):
        for fn in (worker,observer):
            thread=Thread(target=fn);threads.append(thread);thread.start()
    try:
        with open_private_operator(mode=PrivateOperatorMode.OWNER,view=args['view'],**values) as window:
            try:
                window.serve(server=server)
            except PrivateOperatorError as caught:
                error=caught
    finally:
        release.set()
        for thread in threads:thread.join(5)
    assert observed==[True] and error is None
    assert all(not t.is_alive() for t in threads)
    assert logging.root.manager.disable==prior
    assert {sig:signal.getsignal(sig) for sig in handlers}==handlers
