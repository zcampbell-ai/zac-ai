"""One-shot private listener with an explicit trusted shutdown callback.

Construction binds no socket and reads no credentials. The callback requests
Uvicorn graceful shutdown, including closing listeners. It is not proof that
workers have finished: use PrivateOperatorWindow.serve's physical thread drain
and retained lease. Native work can block indefinitely; never force-exit/release
the lease while protected work remains. All provider adapters still need the
shared durable stop gate. No restart, public binding, proxy trust or logging.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from typing import Protocol

from fastapi import FastAPI


class PrivateServerLifecycleError(BaseException):
    """Fixed fatal lifecycle diagnostic; operator must stop and reconcile."""


class _Server(Protocol):
    should_exit: bool

    def run(self) -> None: ...


def _make_server(
    app: FastAPI,
    *,
    verified_private_origin: str | None = None,
    diagnostic_stage: Callable[[str], None] | None = None,
    diagnostic_failure: Callable[[], None] | None = None,
) -> _Server:
    import uvicorn

    from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress

    selected = (
        app
        if verified_private_origin is None
        else TrustedLoopbackHttpsIngress(app, origin=verified_private_origin)
    )
    configuration_type = uvicorn.Config
    server_type = uvicorn.Server
    if diagnostic_stage is not None:
        observe: Callable[[str], None] = diagnostic_stage
        failed: Callable[[], None] = (
            diagnostic_failure if diagnostic_failure is not None else lambda: None
        )
        from uvicorn.lifespan.on import LifespanOn

        class ObservedLifespan(LifespanOn):
            async def startup(self) -> None:
                observe("lifespan_startup_entered")
                try:
                    await super().startup()
                except BaseException:
                    failed()
                    raise
                observe("lifespan_refused" if self.should_exit else "bind_pending")

        class ObservedConfiguration(uvicorn.Config):
            def load(self) -> None:
                observe("configuration_load_entered")
                try:
                    super().load()
                except BaseException:
                    failed()
                    raise
                if self.lifespan_class is not LifespanOn:
                    raise ValueError("reviewed diagnostic lifespan required")
                self.lifespan_class = ObservedLifespan
                observe("configuration_load_returned")

        class ObservedServer(uvicorn.Server):
            async def startup(self, sockets: list[socket.socket] | None = None) -> None:
                observe("startup_entered")
                try:
                    await super().startup(sockets=sockets)
                except BaseException:
                    failed()
                    raise
                observe("listener_started" if self.started else "startup_returned")

            async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
                observe("shutdown_entered")
                try:
                    await super().shutdown(sockets=sockets)
                except BaseException:
                    failed()
                    raise
                observe("shutdown_returned")

        configuration_type = ObservedConfiguration
        server_type = ObservedServer

    return server_type(
        configuration_type(
            selected,
            host="127.0.0.1",
            port=8766,
            workers=1,
            reload=False,
            access_log=False,
            log_config=None,
            log_level="critical",
            proxy_headers=False,
            forwarded_allow_ips="",
            server_header=False,
            ws="none",
            timeout_graceful_shutdown=None,
            lifespan="on" if diagnostic_stage is not None else "auto",
        )
    )


class PrivateServerLifecycle:
    """Trusted host uses the same instance for server= and stop_host= inputs.

    Factory injection is test/host controlled, never selected by HTTP. A failed
    run/construction spends this instance. A stop before serving prevents serving.
    stop_host may run in the existing owner request worker; it sends no signals.
    """

    def __init__(
        self,
        *,
        server_factory: Callable[[FastAPI], _Server] = _make_server,
        verified_private_origin: str | None = None,
        diagnostic_stages: bool = False,
    ) -> None:
        if type(diagnostic_stages) is not bool or (
            diagnostic_stages and server_factory is not _make_server
        ):
            raise PrivateServerLifecycleError("closed diagnostic server required")
        if not callable(server_factory):
            raise PrivateServerLifecycleError("private listener unavailable")
        if verified_private_origin is not None and server_factory is not _make_server:
            raise PrivateServerLifecycleError("private ingress selection unavailable")
        if verified_private_origin is not None:
            from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress

            # Constructor-only validation, no listener/provider/credential access.
            TrustedLoopbackHttpsIngress(FastAPI(), origin=verified_private_origin)
        self._factory: Callable[[FastAPI], _Server]
        if diagnostic_stages:
            self._factory = lambda app: _make_server(
                app,
                verified_private_origin=verified_private_origin,
                diagnostic_stage=self._record_stage,
                diagnostic_failure=self._record_failure,
            )
        else:
            self._factory = (
                server_factory
                if verified_private_origin is None
                else lambda app: _make_server(app, verified_private_origin=verified_private_origin)
            )
        self._lock = threading.Lock()
        self._server: _Server | None = None
        self._spent = self._stopped = False
        self._lifecycle_stage = "prepared"
        self._listener_stage = "unconfirmed"
        self._failure_stage = "not_observed"

    def _record_stage(self, value: str) -> None:
        if type(value) is str and value in {
            "configuration_load_entered",
            "configuration_load_returned",
            "startup_entered",
            "lifespan_startup_entered",
            "lifespan_refused",
            "bind_pending",
            "listener_started",
            "startup_returned",
            "shutdown_entered",
            "shutdown_returned",
        }:
            self._lifecycle_stage = value

    def _record_failure(self) -> None:
        if self._failure_stage == "not_observed":
            self._failure_stage = self.lifecycle_stage

    @property
    def failure_stage(self) -> str:
        value = self._failure_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "not_observed",
                "foreground_gate",
                "server_construct",
                "server_run_entered",
                "server_run_returned",
                "configuration_load_entered",
                "configuration_load_returned",
                "startup_entered",
                "lifespan_startup_entered",
                "lifespan_refused",
                "bind_pending",
                "listener_started",
                "startup_returned",
                "shutdown_entered",
                "shutdown_returned",
            }
            else "unavailable"
        )

    @property
    def lifecycle_stage(self) -> str:
        """Fixed operation reached, never readiness or authority."""
        value = self._lifecycle_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "prepared",
                "foreground_gate",
                "server_construct",
                "server_run_entered",
                "server_run_returned",
                "configuration_load_entered",
                "configuration_load_returned",
                "startup_entered",
                "lifespan_startup_entered",
                "lifespan_refused",
                "bind_pending",
                "listener_started",
                "startup_returned",
                "shutdown_entered",
                "shutdown_returned",
            }
            else "unavailable"
        )

    @property
    def listener_stage(self) -> str:
        """Trusted server's bounded started observation, not live access proof."""
        value = self._listener_stage
        return (
            value
            if type(value) is str and value in {"unconfirmed", "not_started", "started"}
            else "unavailable"
        )

    def _observe_started(self) -> None:
        # Diagnostic only; failed/foreign properties never alter cleanup/result.
        value = None
        try:
            if self._server is not None:
                value = getattr(self._server, "started", None)
        except BaseException:  # noqa: BLE001,S110 - nonauthoritative observation only
            pass
        self._listener_stage = (
            "started" if value is True else "not_started" if value is False else "unconfirmed"
        )

    def stop_host(self) -> None:
        okay = False
        try:
            with self._lock:
                self._stopped = True
                if self._server is not None:
                    self._server.should_exit = True
                    if self._server.should_exit is not True:
                        raise ValueError("listener stop not accepted")
                okay = True
        except BaseException:  # noqa: BLE001,S110 - fixed fatal, no server diagnostics
            pass
        if not okay:
            raise PrivateServerLifecycleError("private listener shutdown unconfirmed")

    def __call__(self, app: FastAPI) -> None:
        okay = False
        try:
            self._lifecycle_stage = "foreground_gate"
            if (
                threading.current_thread() is not threading.main_thread()
                or type(app) is not FastAPI
            ):
                raise ValueError("dedicated private foreground serving required")
            with self._lock:
                if self._spent or self._stopped:
                    raise ValueError("private listener already spent")
                self._spent = True
                self._lifecycle_stage = "server_construct"
                server = self._factory(app)
                if server.should_exit is not False or not callable(server.run):
                    raise ValueError("fresh private server required")
                self._server = server
            self._lifecycle_stage = "server_run_entered"
            server.run()
            self._lifecycle_stage = "server_run_returned"
            okay = True
        except BaseException:  # noqa: BLE001 - never expose request/backend frames
            self._record_failure()
        self._observe_started()
        if not okay:
            self.stop_host()
            raise PrivateServerLifecycleError("private listener unavailable; stop and reconcile")
