"""Trusted fresh Slack assembly inside the original private operator context.

Construction is inert. The default loopback server does not establish HTTPS
transport; deployment transport review remains required. No credential saving,
gateway, source capture, installed connection or cold reopen is provided here.
"""

from __future__ import annotations

import os
import threading
import time
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import SecretStr

from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import Connection, _direct_tls
from zacai.connectors.oauth_host_guard import OAuthHostGuard, OAuthHostHaltUnconfirmed
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.private_host import PreparedOwnerHost
from zacai.interfaces.private_operator import (
    PrivateOperatorMode,
    PrivateOperatorWindow,
    StartupLoader,
    open_private_operator,
)
from zacai.interfaces.private_startup import OwnerStartupConfiguration, load_owner_startup
from zacai.interfaces.slack_connection_web import SlackConnectionWeb

_HOSTS: weakref.WeakSet[SlackConnectHost] = weakref.WeakSet()


class SlackConnectHostError(ValueError):
    """Fixed trusted assembly failure without startup or request material."""


class SlackConnectHost:
    _window: PrivateOperatorWindow
    _prepared: PreparedOwnerHost
    _clock: HostObservedClock
    _controller: SlackConnectionWeb
    _continuity: NamedSessionContinuity
    _closed: bool
    _stop_requested: bool
    _server: Any
    _guard: OAuthHostGuard
    _guard_pins: tuple[Any, ...]
    _halted: bool
    _halt_failed: bool

    def __init__(self) -> None:
        raise TypeError("actual private operator assembly required")

    def _preserve(self) -> None:
        if (
            type(self) is not SlackConnectHost
            or self not in _HOSTS
            or self._closed
            or self._stop_requested
            or self._halted
            or not self._window._active
            or not self._window._serving
            or self._window._prepared is not self._prepared
            or self._window._clock is not self._clock
            or self._controller._continuity is not self._continuity
            or self._continuity._sessions is not self._prepared.sessions
            or getattr(self._continuity._owner, "__self__", None) is not self._prepared.owners
        ):
            raise ValueError("same live original operator context required")
        self._guard_ready()

    def _guard_ready(self) -> None:
        guard = self._guard
        if type(guard) is not OAuthHostGuard or self._guard_pins != (
            guard,
            guard._directory,
            guard._lock_path,
            guard._ready_path,
            guard._halt_path,
            guard._ready_bytes,
            guard._halt_bytes,
        ):
            raise ValueError("original fixed host stop gate required")
        try:
            guard.ready()
        except Exception:
            raise
        except BaseException:
            self._halt_unconfirmed()
            raise

    def _halt_unconfirmed(self) -> None:
        self._halted = True
        failed = False
        try:
            self._guard.halt_unconfirmed()
        except BaseException:  # noqa: BLE001 - never acknowledge an uncertain durable marker
            failed = True
        try:
            self._stop()
        except BaseException:  # noqa: BLE001 - physical stop also remains mandatory
            failed = True
        if failed:
            # Sticky for this original issued host. A later marker observation
            # cannot erase the earlier uncertainty or authorize reconciliation.
            self._halt_failed = True
            raise OAuthHostHaltUnconfirmed("host halt unconfirmed; stop and reconcile")

    def _stop(self) -> None:
        self._stop_requested = True
        if self._server is not None:
            self._server.should_exit = True

    def serve(self, *, server: Callable[[FastAPI], None] | None = None) -> None:
        """Serve once with original lease, signals, logging and physical drain.

        Injected servers are trusted test composition and must close their app
        clients before return. This is not a browser transport approval receipt.
        """
        if self not in _HOSTS or self._closed or self._stop_requested:
            raise SlackConnectHostError("Slack host unavailable")
        self._guard_ready()
        self._window._require()
        execute: Callable[[FastAPI], None]
        if server is None:
            import uvicorn

            self._server = uvicorn.Server(
                uvicorn.Config(
                    self._prepared.app,
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

            def native_server(app: FastAPI) -> None:
                self._server.run()

            execute = native_server
        else:
            if not callable(server):
                raise SlackConnectHostError("trusted server required")
            execute = server

        def owned(app: FastAPI) -> None:
            try:
                execute(app)
            finally:
                # Latch and hold before the original physical thread drain.
                self._controller.close()

        self._window.serve(server=owned)


@contextmanager
def open_slack_connect_host(
    *,
    client_id: str,
    origin: str,
    directory: Path,
    escrow_confirmed_by_operator: bool,
    clock: HostObservedClock,
    configuration: OAuthConfiguration,
    expected_user_id: str,
    rotation: SlackRotation,
    approved_generation: str,
    console_observed_at: datetime,
    review_expires_at: datetime,
    client_secret_loader: Callable[[OAuthConfiguration], SecretStr],
    startup_loader: StartupLoader = load_owner_startup,
    identities: IdentityProvider | None = None,
    connection_factory: Callable[[str], Connection] = _direct_tls,
    network_clock: Callable[[], float] = time.monotonic,
    initialize_new_guard: bool = False,
) -> Iterator[SlackConnectHost]:
    """Issue only inside the actual original OWNER window; never a public DTO."""
    if (
        threading.current_thread() is not threading.main_thread()
        or type(initialize_new_guard) is not bool
        or type(clock) is not HostObservedClock
        or configuration.private_origin != origin
    ):
        raise SlackConnectHostError("trusted original Slack host inputs required")
    captured: list[OwnerStartupConfiguration] = []

    def startup(*, client_id: str, origin: str) -> OwnerStartupConfiguration:
        actual = startup_loader(client_id=client_id, origin=origin)
        captured.append(actual)
        return actual

    async def view(principal: Any) -> str:
        return '<p>Work Slack setup</p><a href="/connections/slack">Set up Slack</a>'

    with open_private_operator(
        mode=PrivateOperatorMode.OWNER,
        client_id=client_id,
        origin=origin,
        directory=directory,
        escrow_confirmed_by_operator=escrow_confirmed_by_operator,
        view=view,
        clock=clock,
        startup_loader=startup,
        identities=identities,
        slack_consent_enabled=True,
    ) as window:
        if type(window._prepared) is not PreparedOwnerHost or len(captured) != 1:
            raise SlackConnectHostError("actual owner assembly required")
        host = object.__new__(SlackConnectHost)
        host._window = window
        host._prepared = window._prepared
        host._clock = clock
        host._closed = host._stop_requested = False
        host._server = None
        host._halted = False
        host._halt_failed = False
        guard_path = directory / "slack-oauth-guard"
        if initialize_new_guard:
            # An explicit fresh action, never retry/fallback to repair state.
            os.mkdir(guard_path, 0o700)
        host._guard = OAuthHostGuard(
            guard_path, key=captured[0].session_key, origin=origin, client_id=client_id
        )
        if initialize_new_guard:
            host._guard.initialize()
        else:
            host._guard.ready()
        guard = host._guard
        host._guard_pins = (
            guard,
            guard._directory,
            guard._lock_path,
            guard._ready_path,
            guard._halt_path,
            guard._ready_bytes,
            guard._halt_bytes,
        )

        host._continuity = NamedSessionContinuity(
            sessions=host._prepared.sessions,
            owner=host._prepared.owners.load,
            clock=clock,
            key=captured[0].session_key,
            origin=origin,
            client_id=client_id,
        )
        host._controller = SlackConnectionWeb(
            continuity=host._continuity,
            configuration=configuration,
            expected_user_id=expected_user_id,
            rotation=rotation,
            approved_generation=approved_generation,
            console_observed_at=console_observed_at,
            review_expires_at=review_expires_at,
            directory=directory / "slack-connect",
            key=captured[0].session_key,
            client_secret_loader=client_secret_loader,
            preservation_check=host._preserve,
            stop_host=host._stop,
            connection_factory=connection_factory,
            network_clock=network_clock,
        )
        host._controller.mount(host._prepared.app)
        _HOSTS.add(host)
        try:
            yield host
        finally:
            host._closed = True
            try:
                host._controller.close()
            finally:
                _HOSTS.discard(host)
