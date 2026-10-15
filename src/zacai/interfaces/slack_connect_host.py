"""Trusted Slack assembly inside the actual private operator context.

Construction is inert. Fresh consent and explicit saved identity review use
canonical owner/session and external credential authority. Default loopback
serving does not establish approved HTTPS or actual provider installation.
History ingestion and conversational messages remain separate capabilities.
"""

from __future__ import annotations

import hashlib
import html
import os
import threading
import time
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qsl

from fastapi import FastAPI
from pydantic import SecretStr
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

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
from zacai.interfaces.slack_connection_web import SlackConnectionCancelled, SlackConnectionWeb

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
    _serve_started: bool
    _server: Any
    _paired_lifecycle: Any
    _paired_stop: Callable[[], None] | None
    _paired_pins: tuple[Any, ...] | None
    _guard: OAuthHostGuard
    _guard_pins: tuple[Any, ...]
    _halted: bool
    _halt_failed: bool

    def __init__(self) -> None:
        raise TypeError("actual private operator assembly required")

    def bind_server_lifecycle(self, lifecycle: Any) -> None:
        """Bind one trusted one-shot server and its exact shutdown callback.

        Setup is single-threaded and must finish before serve. No config/request
        flag or method-shaped object establishes this pairing.
        """
        from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle

        if (
            self not in _HOSTS
            or self._closed
            or self._stop_requested
            or self._serve_started
            or self._window._serving
            or self._paired_lifecycle is not None
            or type(lifecycle) is not PrivateServerLifecycle
            or lifecycle._spent
            or lifecycle._stopped
        ):
            raise SlackConnectHostError("one fresh trusted server lifecycle required")
        self._paired_lifecycle = lifecycle
        self._paired_stop = lifecycle.stop_host
        self._paired_pins = (lifecycle, lifecycle._factory, self._paired_stop)

    def mount_initial_identity(
        self,
        *,
        plan: Any,
        keychain_path: Path,
        bindings_factory: Callable[[], Any] | None = None,
        keychain_file_policy: str = "owner_only",
    ) -> None:
        """Compose inert warm review and execution routes before serving."""
        self._mount_identity(
            plan=plan,
            keychain_path=keychain_path,
            bindings_factory=bindings_factory,
            keychain_file_policy=keychain_file_policy,
            initial=True,
        )

    def mount_saved_identity(
        self,
        *,
        plan: Any,
        keychain_path: Path,
        bindings_factory: Callable[[], Any] | None = None,
        keychain_file_policy: str = "owner_only",
    ) -> None:
        self._mount_identity(
            plan=plan,
            keychain_path=keychain_path,
            bindings_factory=bindings_factory,
            keychain_file_policy=keychain_file_policy,
            initial=False,
        )

    def _mount_identity(
        self,
        *,
        plan: Any,
        keychain_path: Path,
        bindings_factory: Callable[[], Any] | None = None,
        keychain_file_policy: str = "owner_only",
        initial: bool,
    ) -> None:
        """Mount exact separate canonical owner review and execution requests.

        Mount once before serving begins. A serving attempt permanently closes
        this composition step, including when an injected server returns.
        Owner authentication, displayed account/scope review
        and a later CSRF-bound execution precede any saved credential access.
        """
        from zacai.connectors.account_preflight import PreflightPlan
        from zacai.connectors.connector_authority import (
            ConnectorAuthority,
            _json,
            review_scope_digest,
        )
        from zacai.connectors.connector_authority import _plan as canonical_plan
        from zacai.connectors.slack_native_installation import (
            SlackPendingInstallation,
            SlackSavedInstallation,
        )

        if (
            type(initial) is not bool
            or self not in _HOSTS
            or self._closed
            or self._stop_requested
            or self._serve_started
            or self._window._serving
            or getattr(self, "_saved_action_mounted", False)
            or type(plan) is not PreflightPlan
            or plan.provider.value != "slack"
            or plan.grant_profile != "read"
            or plan.metadata
            or plan.max_pages != 1
            or plan.client_id != self._controller._configuration.client_id
            or plan.subject_id != self._controller._user
            or plan.slack_account is None
            or plan.slack_account.team_id != self._controller._configuration.slack_team_id
            or any(
                getattr(route, "path", None)
                in {
                    "/connections/slack/saved",
                    "/connections/slack/install",
                    "/connector-review",
                    "/connector-execute",
                }
                for route in self._prepared.app.routes
            )
        ):
            raise SlackConnectHostError("one exact saved identity plan required")
        self._saved_action_mounted = True
        self._saved_backend: Any = None
        self._identity_sdk: Any = None
        self._identity_plan = plan
        self._identity_publication: tuple[Any, str, str] | None = None
        self._initial_identity = initial
        self._saved_spent = self._saved_execute_spent = self._saved_reviewed = False
        team_id = plan.slack_account.team_id
        digest = review_scope_digest(plan)
        confirmation = (
            "Save and verify this fresh Slack account"
            if initial
            else "Verify this saved Slack account"
        )
        page_path = "/connections/slack/install" if initial else "/connections/slack/saved"
        origin = self._controller._configuration.private_origin

        def form(csrf: str, path: str, label: str) -> str:
            fields = {"csrf": csrf, "reviewed_scope_digest": digest, "confirmation": confirmation}
            hidden = "".join(
                f'<input type="hidden" name="{key}" value="{html.escape(value, quote=True)}">'
                for key, value in fields.items()
            )
            return f'<form method="post" action="{path}">{hidden}<button type="submit">{label}</button></form>'

        async def body(request: Request) -> dict[str, str]:
            if (
                request.url.scheme != "https"
                or request.url.query
                or request.headers.getlist("host") != [origin.removeprefix("https://")]
                or request.headers.getlist("origin") != [origin]
                or request.headers.get("content-type", "").split(";", 1)[0]
                != "application/x-www-form-urlencoded"
            ):
                raise ValueError("same exact private form boundary required")
            raw = b""
            async for chunk in request.stream():
                if len(raw) + len(chunk) > 4096:
                    raise ValueError("bounded owner form required")
                raw += chunk
            pairs = parse_qsl(raw.decode("ascii"), strict_parsing=True, max_num_fields=3)
            fields = dict(pairs)
            if (
                not raw
                or len(pairs) != len(fields)
                or set(fields) != {"csrf", "reviewed_scope_digest", "confirmation"}
                or fields["reviewed_scope_digest"] != digest
                or fields["confirmation"] != confirmation
            ):
                raise ValueError("same displayed identity review required")
            return fields

        def authenticated(request: Request, csrf: str | None = None) -> Any:
            # _work retires a spent OAuth action on a thrown exception. A bad
            # public request must instead be an inert rejection, not a failed
            # admitted action. Fatal interruption still propagates to drain.
            try:
                self._preserve()
                operation, owner_view = self._controller._view(request)
                if csrf is not None and csrf != owner_view[5]:
                    return None
                return operation, owner_view
            except Exception:  # noqa: BLE001 - deny unavailable actor without spending effects
                return None

        def terminal(operation: Any, binding: str) -> None:
            self._preserve()
            operation.recheck(binding)

        def cancel() -> None:
            try:
                self._controller.close()
            except BaseException:  # noqa: BLE001,S110 - preserve fixed fatal without private frames
                pass
            raise SlackConnectionCancelled("saved Slack owner action cancelled") from None

        @self._prepared.app.get(page_path, response_class=HTMLResponse)
        async def saved_view(request: Request) -> Response:
            if (
                request.url.scheme != "https"
                or request.url.query
                or request.headers.getlist("host") != [origin.removeprefix("https://")]
                or request.headers.getlist("origin") not in ([], [origin])
            ):
                return Response("Saved Slack review unavailable", status_code=403)

            def view() -> str | None:
                actor = authenticated(request)
                if actor is None:
                    return None
                operation, owner_view = actor
                binding = owner_view[1]
                if initial and self._controller._fresh is None:
                    content = (
                        "<h1>Connect work Slack</h1><p>First review this registration and complete fresh consent.</p>"
                        '<a href="/connections/slack">Review Slack registration</a>'
                        "<p>After the callback, return here to review saving and verifying the account.</p>"
                    )
                    terminal(operation, binding)
                    return content
                if initial:
                    fresh_view = self._controller._fresh
                    if fresh_view is None:
                        raise ValueError("original fresh consent required")
                    fresh_view.current()
                content = (
                    (
                        "<h1>Save fresh work Slack account</h1>"
                        if initial
                        else "<h1>Verify saved work Slack account</h1>"
                    )
                    + f"<p>Team: {html.escape(team_id)}; user: {html.escape(plan.subject_id)}; client: {html.escape(plan.client_id)}</p>"
                    f"<p>Permissions: {html.escape(', '.join(sorted(plan.scopes)))}</p>"
                    + (
                        "<p>This action adds the fresh credential once, reads it back once and sends one Slack identity request. It does not read message history.</p>"
                        if initial
                        else "<p>This action reads the saved credential once and sends one Slack identity request. It does not read message history.</p>"
                    )
                ) + form(owner_view[5], "/connector-review", "Review this exact account")
                terminal(operation, binding)
                return content

            try:
                content = await run_in_threadpool(self._controller._work, view)
                return (
                    Response("Saved Slack review unavailable", status_code=403)
                    if content is None
                    else HTMLResponse(content)
                )
            except Exception:  # noqa: BLE001 - fixed owner/storage diagnostic
                return Response("Saved Slack review unavailable", status_code=403)
            except BaseException:  # noqa: BLE001 - original worker close/drain lifecycle
                cancel()
                raise AssertionError("unreachable")

        @self._prepared.app.post("/connector-review", response_class=HTMLResponse)
        async def saved_review(request: Request) -> Response:
            try:
                fields = await body(request)

                def review() -> str | None:
                    actor = authenticated(request, fields["csrf"])
                    if actor is None or self._saved_spent:
                        return None
                    _operation, owner_view = actor
                    self._saved_spent = True
                    kwargs = (
                        {} if bindings_factory is None else {"bindings_factory": bindings_factory}
                    )
                    backend: Any
                    if initial:
                        # Authenticate the exact canonical review request before
                        # any exclusive namespace birth or fresh token access.
                        fresh = self._controller._fresh
                        if fresh is None:
                            raise ValueError("actual completed fresh consent required")
                        fresh.current()
                        if owner_view[1] != fresh._owner._registration._binding:
                            raise ValueError("same consenting owner required")
                        backend = SlackPendingInstallation.prepare(
                            fresh=fresh,
                            host=self,
                            plan=plan,
                            directory=self._guard._directory.parent / "slack-installation",
                            keychain_path=keychain_path,
                            keychain_file_policy=keychain_file_policy,
                            **kwargs,
                        )
                        self._saved_backend = backend
                        sdk = ConnectorAuthority(
                            backend._directory / "sdk",
                            key=self._continuity._key,
                            continuity=self._continuity,
                            backend=backend,
                        )
                        self._identity_sdk = sdk
                        try:
                            sdk.initialize()
                        except BaseException:
                            self._halt_unconfirmed()
                            raise
                    else:
                        backend = SlackSavedInstallation.prepare(
                            host=self,
                            request=request,
                            csrf=fields["csrf"],
                            plan=plan,
                            keychain_path=keychain_path,
                            keychain_file_policy=keychain_file_policy,
                            **kwargs,
                        )
                        sdk = backend._sdk
                        self._identity_sdk = sdk
                    self._saved_backend = backend
                    try:
                        sdk.approve_review(
                            plan,
                            request=request,
                            csrf=fields["csrf"],
                            reviewed_scope_digest=fields["reviewed_scope_digest"],
                            payload_digest=None,
                        )
                    except BaseException:
                        if sdk._issuance_uncertain:
                            self._halt_unconfirmed()
                        raise
                    registration = (
                        backend._fresh._owner._registration if initial else backend._registration
                    )
                    terminal(registration._operation, registration._binding)
                    self._saved_reviewed = True
                    return "<p>Exact account review recorded. Verify its identity once.</p>" + form(
                        fields["csrf"], "/connector-execute", confirmation
                    )

                content = await run_in_threadpool(self._controller._work, review)
                return (
                    Response("Saved Slack review held", status_code=403)
                    if content is None
                    else HTMLResponse(content)
                )
            except Exception:  # noqa: BLE001 - fixed authority/native diagnostic
                return Response("Saved Slack review held", status_code=403)
            except BaseException:  # noqa: BLE001 - original worker close/drain lifecycle
                cancel()
                raise AssertionError("unreachable")

        @self._prepared.app.post("/connector-execute")
        async def saved_execute(request: Request) -> Response:
            try:
                fields = await body(request)

                def action() -> Response | None:
                    actor = authenticated(request, fields["csrf"])
                    if actor is None:
                        return None
                    backend = self._saved_backend
                    if self._saved_execute_spent or not self._saved_reviewed or backend is None:
                        return None
                    # for_request independently authenticates actual canonical
                    # execution path/cookie/CSRF before any effect is consumed.
                    gateway = self._identity_sdk.for_request(request, csrf=fields["csrf"])
                    self._saved_execute_spent = True
                    backend.execute(gateway=gateway)
                    registration = (
                        backend._fresh._owner._registration if initial else backend._registration
                    )
                    operation, binding = registration._operation, registration._binding
                    if initial:
                        if not backend._active:
                            raise ValueError("actual active identity receipt required")
                        backend._held_current()
                        generation = backend._generation
                    else:
                        backend.current()
                        generation = backend._active_record["generation"]
                    terminal(operation, binding)
                    expected_plan, expected_account, expected_payload = canonical_plan(plan)
                    with self._identity_sdk._locked() as lock_current:
                        row = self._identity_sdk._read()["rows"].get(str(plan.attempt_id))
                        if (
                            type(row) is not dict
                            or row["state"] != "completed"
                            or row["loaded"] is not True
                            or row["uncertain"] is not False
                            or row["plan"] != expected_plan
                            or row["account"] != expected_account
                            or row["payload"] != expected_payload
                            or row["binding"] != binding
                            or row["generation"] != generation
                            or self._identity_sdk._issuance_uncertain
                            or type(row["coverage"]) is not dict
                            or row["coverage"]["identity_matched"] is not True
                            or row["coverage"]["requests"] != 1
                        ):
                            raise ValueError("actual exact completed SDK witness required")
                        completed_digest = hashlib.sha256(_json(row)).hexdigest()
                        terminal(operation, binding)
                        lock_current()
                    self._identity_publication = operation, binding, completed_digest
                    return Response(
                        "Slack account saved and identity verified"
                        if initial
                        else "Saved Slack account identity verified"
                    )

                result = await run_in_threadpool(self._controller._work, action)
                return (
                    Response("Saved Slack verification held", status_code=403)
                    if result is None
                    else result
                )
            except Exception:  # noqa: BLE001 - fixed authority/native diagnostic
                return Response("Saved Slack verification held", status_code=403)
            except BaseException:  # noqa: BLE001 - original worker close/drain lifecycle
                cancel()
                raise AssertionError("unreachable")

    def identity_receipt_current(self) -> None:
        """Validate actual terminal publication and durable row after draining.

        This is a read-only outcome check, never a new execution capability or
        proof of browser delivery. Preserve the original current owner even
        though the serving window has ended; never revive its `_preserve` gate.
        """
        from zacai.connectors.connector_authority import ConnectorAuthority, _json
        from zacai.connectors.connector_authority import _plan as canonical_plan
        from zacai.interfaces.named_session_binding import NamedSessionOperation

        publication = getattr(self, "_identity_publication", None)
        sdk = getattr(self, "_identity_sdk", None)
        backend = getattr(self, "_saved_backend", None)
        if (
            self not in _HOSTS
            or self._closed
            or self._window._serving
            or not self._window._active
            or self._halted
            or self._halt_failed
            or publication is None
            or type(sdk) is not ConnectorAuthority
            or sdk._backend is not backend
            or sdk._issuance_uncertain
            or not self._saved_execute_spent
            or not self._saved_reviewed
        ):
            raise SlackConnectHostError("actual published identity result required")
        operation, binding, digest = publication
        if type(operation) is not NamedSessionOperation:
            raise SlackConnectHostError("actual original terminal owner required")
        self._guard_ready()
        operation.recheck(binding)
        plan = self._identity_plan
        expected_plan, expected_account, expected_payload = canonical_plan(plan)
        with sdk._locked() as lock_current:
            row = sdk._read()["rows"].get(str(plan.attempt_id))
            if (
                type(row) is not dict
                or row["state"] != "completed"
                or row["loaded"] is not True
                or row["uncertain"] is not False
                or row["plan"] != expected_plan
                or row["account"] != expected_account
                or row["payload"] != expected_payload
                or row["binding"] != binding
                or type(row["coverage"]) is not dict
                or row["coverage"]["identity_matched"] is not True
                or row["coverage"]["requests"] != 1
                or hashlib.sha256(_json(row)).hexdigest() != digest
            ):
                raise SlackConnectHostError("same exact completed identity row required")
            operation.recheck(binding)
            lock_current()

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
        if (
            self._paired_lifecycle is not None
            and (self._paired_lifecycle, self._paired_lifecycle._factory, self._paired_stop)
            != self._paired_pins
        ):
            raise ValueError("original paired lifecycle changed")
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
        if self._paired_lifecycle is not None:
            from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle

            paired = cast(PrivateServerLifecycle, self._paired_lifecycle)
            stop = self._paired_stop
            try:
                if (
                    type(paired) is not PrivateServerLifecycle
                    or getattr(stop, "__self__", None) is not paired
                    or (paired, paired._factory, stop) != self._paired_pins
                    or not callable(stop)
                    or getattr(stop, "__func__", None) is not PrivateServerLifecycle.stop_host
                ):
                    raise ValueError("original paired shutdown required")
                retained_server = paired._server
                # `_stopped` is set before the listener setter runs.
                # Skip a duplicate only with the retained server's real ack.
                if not (
                    paired._stopped is True
                    and (retained_server is None or retained_server.should_exit is True)
                ):
                    stop()
                if paired._stopped is not True or (
                    paired._server is not None and paired._server.should_exit is not True
                ):
                    raise ValueError("paired stop unconfirmed")
            except BaseException:  # noqa: BLE001 - shutdown uncertainty permanently holds host
                self._halt_failed = self._halted = True
                self._guard.halt_unconfirmed()
                raise OAuthHostHaltUnconfirmed("paired listener stop unconfirmed") from None
        if self._server is not None:
            self._server.should_exit = True
            if self._server.should_exit is not True:
                self._halt_failed = self._halted = True
                self._guard.halt_unconfirmed()
                raise OAuthHostHaltUnconfirmed("listener stop unconfirmed")

    def serve(self, *, server: Callable[[FastAPI], None] | None = None) -> None:
        """Serve once with original lease, signals, logging and physical drain.

        Injected servers are trusted test composition and must close their app
        clients before return. This is not a browser transport approval receipt.
        The unpaired default is review-only plain loopback HTTP; it cannot
        satisfy HTTPS identity admission. Attended setup uses the reviewed
        paired lifecycle and separately approved HTTPS ingress.
        """
        if self not in _HOSTS or self._closed or self._stop_requested:
            raise SlackConnectHostError("Slack host unavailable")
        if self._paired_lifecycle is not None and server is not self._paired_lifecycle:
            raise SlackConnectHostError("original paired server required")
        self._serve_started = True
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
                backend = getattr(self, "_saved_backend", None)
                if backend is not None:
                    if getattr(self, "_initial_identity", False):
                        backend._failed = True
                        backend._saved = None
                        backend._payload = b""
                        backend._fresh._owner._saved_identity_current = None
                    else:
                        backend.close()
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
        host._closed = host._stop_requested = host._serve_started = False
        host._server = None
        host._paired_lifecycle = host._paired_stop = host._paired_pins = None
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
