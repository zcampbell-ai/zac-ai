"""One-shot private listener with an explicit trusted shutdown callback.

Construction binds no socket and reads no credentials. The callback requests
Uvicorn graceful shutdown, including closing listeners. It is not proof that
workers have finished: use PrivateOperatorWindow.serve's physical thread drain
and retained lease. Native work can block indefinitely; never force-exit/release
the lease while protected work remains. All provider adapters still need the
shared durable stop gate. No restart, public binding, proxy trust or logging.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Protocol

from fastapi import FastAPI


class PrivateServerLifecycleError(BaseException):
    """Fixed fatal lifecycle diagnostic; operator must stop and reconcile."""


class _Server(Protocol):
    should_exit: bool

    def run(self) -> None: ...


def _make_server(app: FastAPI, *, verified_private_origin: str | None = None) -> _Server:
    import uvicorn

    from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress

    selected = (
        app
        if verified_private_origin is None
        else TrustedLoopbackHttpsIngress(app, origin=verified_private_origin)
    )
    return uvicorn.Server(
        uvicorn.Config(
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
    ) -> None:
        if not callable(server_factory):
            raise PrivateServerLifecycleError("private listener unavailable")
        if verified_private_origin is not None and server_factory is not _make_server:
            raise PrivateServerLifecycleError("private ingress selection unavailable")
        if verified_private_origin is not None:
            from zacai.interfaces.private_https_ingress import TrustedLoopbackHttpsIngress

            # Constructor-only validation, no listener/provider/credential access.
            TrustedLoopbackHttpsIngress(FastAPI(), origin=verified_private_origin)
        self._factory = (
            server_factory
            if verified_private_origin is None
            else lambda app: _make_server(app, verified_private_origin=verified_private_origin)
        )
        self._lock = threading.Lock()
        self._server: _Server | None = None
        self._spent = self._stopped = False

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
            if (
                threading.current_thread() is not threading.main_thread()
                or type(app) is not FastAPI
            ):
                raise ValueError("dedicated private foreground serving required")
            with self._lock:
                if self._spent or self._stopped:
                    raise ValueError("private listener already spent")
                self._spent = True
                server = self._factory(app)
                if server.should_exit is not False or not callable(server.run):
                    raise ValueError("fresh private server required")
                self._server = server
            server.run()
            okay = True
        except BaseException:  # noqa: BLE001,S110 - never expose request/backend frames
            pass
        if not okay:
            self.stop_host()
            raise PrivateServerLifecycleError("private listener unavailable; stop and reconcile")
