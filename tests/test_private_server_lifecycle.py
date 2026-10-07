from __future__ import annotations

import threading

import pytest
from fastapi import FastAPI

from zacai.interfaces.private_server_lifecycle import (
    PrivateServerLifecycle,
    PrivateServerLifecycleError,
    _make_server,
)


class FakeServer:
    should_exit = False

    def __init__(self) -> None:
        self.calls = 0
        self.started = threading.Event()
        self.stopping = threading.Event()

    def run(self) -> None:
        self.calls += 1
        self.started.set()
        assert self.stopping.wait(2)
        assert self.should_exit is True


def test_inert_then_worker_stops_original_listener() -> None:
    server = FakeServer()
    factories: list[FastAPI] = []

    def factory(app: FastAPI) -> FakeServer:
        factories.append(app)
        return server

    lifecycle = PrivateServerLifecycle(server_factory=factory)
    assert factories == []

    def worker() -> None:
        assert server.started.wait(2)
        lifecycle.stop_host()
        server.stopping.set()

    thread = threading.Thread(target=worker)
    thread.start()
    app = FastAPI()
    lifecycle(app)
    thread.join(2)
    assert not thread.is_alive()
    assert factories == [app]
    assert server.calls == 1
    with pytest.raises(PrivateServerLifecycleError):
        lifecycle(app)
    assert server.calls == 1


def test_stop_before_start_never_calls_factory() -> None:
    calls: list[object] = []
    lifecycle = PrivateServerLifecycle(server_factory=lambda app: calls.append(app))
    lifecycle.stop_host()
    with pytest.raises(PrivateServerLifecycleError):
        lifecycle(FastAPI())
    assert calls == []


@pytest.mark.parametrize("cancelled", [False, True])
def test_failed_factory_is_spent_and_private_safe(cancelled: bool) -> None:
    calls = 0

    def broken(_: FastAPI) -> FakeServer:
        nonlocal calls
        calls += 1
        if cancelled:
            raise KeyboardInterrupt("invented-private-detail")
        raise ValueError("invented-private-detail")

    lifecycle = PrivateServerLifecycle(server_factory=broken)
    for _ in range(2):
        with pytest.raises(PrivateServerLifecycleError) as failure:
            lifecycle(FastAPI())
        assert failure.value.__context__ is None
        assert "invented-private-detail" not in str(failure.value)
    assert calls == 1


def test_worker_cannot_start_listener() -> None:
    calls: list[object] = []
    lifecycle = PrivateServerLifecycle(server_factory=lambda app: calls.append(app))
    failures: list[BaseException] = []

    def worker() -> None:
        try:
            lifecycle(FastAPI())
        except PrivateServerLifecycleError as error:
            failures.append(error)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(2)
    assert len(failures) == 1 and type(failures[0]) is PrivateServerLifecycleError
    assert calls == []


def test_actual_uvicorn_configuration_private_and_no_listener() -> None:
    app = FastAPI()
    server = _make_server(app)
    config = server.config
    assert config.app is app
    assert config.host == "127.0.0.1" and config.port == 8766
    assert config.workers == 1 and not config.reload
    assert not config.access_log and config.log_config is None
    assert not config.proxy_headers and config.forwarded_allow_ips == ""
    assert not config.server_header and config.ws == "none"
    assert config.timeout_graceful_shutdown is None
    assert not server.started


def test_actual_uvicorn_exit_flag_and_listener_close_before_drain() -> None:
    import asyncio

    from uvicorn import Server

    observed: list[str] = []

    class Listener:
        def close(self) -> None:
            observed.append("listener_closed")

    class Lifespan:
        async def shutdown(self) -> None:
            observed.append("lifespan_stopped")

    async def scenario() -> None:
        server = _make_server(FastAPI())
        assert type(server) is Server
        server.should_exit = True
        assert await server.on_tick(1) is True
        server.servers = [Listener()]
        server.lifespan = Lifespan()

        async def drain() -> None:
            assert observed == ["listener_closed"]
            observed.append("tasks_drained")

        server._wait_tasks_to_complete = drain
        await server.shutdown()

    asyncio.run(scenario())
    assert observed == ["listener_closed", "tasks_drained", "lifespan_stopped"]
