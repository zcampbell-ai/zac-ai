"""Separately approved foreground preservation host; construction is inert.

run() loads only the two fixed SHARED startup items and serves current enrolled
owner authentication plus aggregate diagnostic metadata. It never mounts Gmail
consent/callback, reads Gmail credentials or native items, or resumes transactions.
The actual operator lease remains held through listener shutdown and thread drain.
Existing owner/session storage supports ordinary login writes; OAuth ledger and
paired guard files are preserved. Metadata counts grant no source/install access.
On exit the plan clears its diagnostic/startup attributes and closes HTTP
admission and the extracted counts endpoint. Private route closures and the
server graph still retain host objects, including credential-bearing authority
and session objects. Other directly extracted Python endpoints bypass the HTTP
middleware. In-process private objects remain subject to the trusted external
operator-lease prerequisite; this is not all-Python revocation or zeroization.
An uncaught application failure or browser disconnect can end this one attempt;
stop and review rather than retrying automatically.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from functools import wraps
from pathlib import Path

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from zacai.connectors.connector_authority import _guard
from zacai.connectors.gmail_client_secret import _configuration
from zacai.connectors.gmail_held_diagnostic import HeldGmailDiagnostic
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.private_host import NamedOwnerHostInputs, PreparedOwnerHost
from zacai.interfaces.private_operator import PrivateOperatorMode, open_private_operator
from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle
from zacai.interfaces.private_startup import OwnerStartupConfiguration, OwnerStartupLoader, _path
from zacai.interfaces.private_startup import _configuration as _owner_configuration
from zacai.interfaces.private_web import InterfacePrincipal, _cookie


class GmailDiagnosticHostError(RuntimeError):
    """Fixed private-safe host denial."""


class GmailDiagnosticHostFatal(BaseException):
    """Fixed private-safe interruption; stop and review before another attempt."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard private startup/session/ledger frames
            failure = GmailDiagnosticHostError
        except BaseException:  # noqa: BLE001 - no interrupted private frame disclosure
            failure = GmailDiagnosticHostFatal
        del args, kwargs
        raise failure("Gmail diagnostic host unavailable; stop and review")

    return call


class _ClosedRegistration:
    def attest(self, *args: object) -> None:
        raise ValueError("registration execution unavailable")

    def generation(self, *args: object) -> str:
        raise ValueError("registration execution unavailable")


class GmailDiagnosticHostPlan:
    """One human foreground attempt, with no initialization or retry mode."""

    @_closed
    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        owner_client_id: str,
        directory: Path,
        startup_loader: OwnerStartupLoader,
        clock: HostObservedClock,
        escrow_confirmed_by_operator: bool,
        identities: IdentityProvider | None = None,
    ) -> None:
        configuration = _configuration(configuration)
        _owner_configuration(owner_client_id, configuration.private_origin)
        directory = _path(directory)
        if (
            type(startup_loader) is not OwnerStartupLoader
            or startup_loader.client_id != owner_client_id
            or startup_loader.origin != configuration.private_origin
            or startup_loader.mode != "foreground"
            or startup_loader.keychain_file_policy != "reviewed_login"
            or startup_loader.keychain_path.name != "login.keychain-db"
            or type(clock) is not HostObservedClock
            or type(escrow_confirmed_by_operator) is not bool
            or not escrow_confirmed_by_operator
        ):
            raise ValueError("explicit reviewed foreground inputs required")
        self._configuration, self._owner_client_id, self._directory = (
            configuration,
            owner_client_id,
            directory,
        )
        self._loader, self._clock, self._escrow, self._identities = (
            startup_loader,
            clock,
            escrow_confirmed_by_operator,
            identities,
        )
        self._server = PrivateServerLifecycle(verified_private_origin=configuration.private_origin)
        self._stop_host = self._server.stop_host
        self._original_stop = self._stop_host
        self._admission_lock = threading.Lock()
        self._active = self._fatal = False
        self._original = (
            configuration,
            owner_client_id,
            directory,
            startup_loader,
            clock,
            escrow_confirmed_by_operator,
            identities,
            self._server,
            self._stop_host,
            self._admission_lock,
            self._original_stop,
        )
        self._digest, self._loader_settings = (
            configuration.configuration_digest,
            startup_loader._settings,
        )
        self._spent = False
        self._captured: OwnerStartupConfiguration | None = None
        self._diagnostic: HeldGmailDiagnostic | None = None
        self._witness: tuple[tuple[int, ...], ...] | None = None

    def __repr__(self) -> str:
        return "GmailDiagnosticHostPlan()"

    def _current(self) -> None:
        current = (
            self._configuration,
            self._owner_client_id,
            self._directory,
            self._loader,
            self._clock,
            self._escrow,
            self._identities,
            self._server,
            self._stop_host,
            self._admission_lock,
            self._original_stop,
        )
        if any(a is not b for a, b in zip(current, self._original, strict=True)):
            raise ValueError("original foreground composition required")
        if (
            _configuration(self._configuration).configuration_digest != self._digest
            or self._loader._settings != self._loader_settings
            or (
                self._loader.client_id,
                self._loader.origin,
                str(self._loader.keychain_path),
                self._loader.mode,
                self._loader.foreground_timeout_seconds,
                self._loader.keychain_file_policy,
            )
            != self._loader_settings
            or getattr(self._stop_host, "__self__", None) is not self._server
            or getattr(self._stop_host, "__func__", None) is not PrivateServerLifecycle.stop_host
        ):
            raise ValueError("original public configuration required")

    def _files(self) -> tuple[tuple[int, ...], ...]:
        root = self._directory
        paths = (
            (root, True, False),
            (root / "private-mode.lock", False, False),
            (root / "owner", True, False),
            (root / "owner" / "owner.json", False, True),
            (root / "sessions", True, False),
            (root / "sessions" / "sessions.sqlite", False, False),
            (root / "gmail-oauth-guard", True, False),
            (root / "gmail-oauth-guard" / "oauth-host.lock", False, True),
            (root / "gmail-oauth-guard" / "oauth-host.ready", False, True),
            (root / "gmail-oauth-transactions", True, False),
            (root / "gmail-oauth-transactions" / "provider-oauth-transactions.lock", False, True),
            (root / "gmail-oauth-transactions" / "provider-oauth-transactions.bin", False, True),
        )
        result = []
        for path, directory, full in paths:
            if path.resolve(strict=True) != path:
                raise ValueError("canonical existing storage required")
            info = _guard(path, directory=directory)
            base = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)
            result.append(
                base + ((info.st_size, info.st_mtime_ns, info.st_ctime_ns) if full else ())
            )
        halt = root / "gmail-oauth-guard" / "oauth-host.halted"
        try:
            info = _guard(halt)
        except FileNotFoundError:
            result.append(())
        else:
            result.append(
                (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_uid,
                    info.st_nlink,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
            )
        return tuple(result)

    def _check(self) -> None:
        self._current()
        if self._witness is None or self._files() != self._witness:
            raise ValueError("existing preservation storage changed")

    def _admitted(self) -> bool:
        with self._admission_lock:
            return self._active and not self._fatal

    def _latch(self) -> None:
        # Set denial before requesting graceful stop, including a failed stop.
        with self._admission_lock:
            first = not self._fatal
            self._fatal = True
            self._active = False
        if not first:
            return
        try:
            self._original[8]()
        except BaseException:  # noqa: BLE001,S110 - sticky failure survives stop diagnostics
            pass

    def _preservation_check(self) -> None:
        try:
            self._check()
            return
        except BaseException:  # noqa: BLE001,S110 - no private preservation error frames
            pass
        self._latch()
        raise GmailDiagnosticHostFatal("Gmail diagnostic preservation failed")

    def _load(self, *, client_id: str, origin: str) -> OwnerStartupConfiguration:
        self._check()
        configuration = self._loader(client_id=client_id, origin=origin)
        self._check()
        if (
            type(configuration) is not OwnerStartupConfiguration
            or configuration.client_id != self._owner_client_id
            or configuration.origin != self._configuration.private_origin
            or self._captured is not None
        ):
            raise ValueError("original startup configuration required")
        self._captured = configuration
        return configuration

    @_closed
    def run(self) -> None:
        if self._spent:
            raise ValueError("one dedicated foreground attempt required")
        self._spent = True
        if threading.current_thread() is not threading.main_thread() or not all(
            s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr)
        ):
            raise ValueError("one dedicated foreground attempt required")
        try:
            self._current()
            self._witness = self._files()  # all existing paths before lease mkdir/O_CREAT

            async def view(principal: InterfacePrincipal) -> str:
                del principal
                return (
                    "<h1>Gmail preservation review</h1><p>No Gmail authorization is retried.</p>"
                    '<p><a href="/connections/gmail/diagnostic">Inspect diagnostic counts</a></p>'
                )

            with open_private_operator(
                mode=PrivateOperatorMode.OWNER,
                client_id=self._owner_client_id,
                origin=self._configuration.private_origin,
                directory=self._directory,
                escrow_confirmed_by_operator=self._escrow,
                view=view,
                clock=self._clock,
                startup_loader=self._load,
                identities=self._identities,
            ) as window:
                self._check()
                prepared, configuration = window._prepared, self._captured
                if (
                    type(prepared) is not PreparedOwnerHost
                    or type(configuration) is not OwnerStartupConfiguration
                ):
                    raise ValueError("actual owner host required")
                inputs = NamedOwnerHostInputs(
                    configuration.origin,
                    configuration.client_id,
                    configuration.session_key,
                    self._directory,
                    prepared.owners,
                    prepared.owners.load,
                    prepared.sessions,
                    self._clock,
                )
                continuity = NamedSessionContinuity(
                    sessions=inputs.sessions,
                    owner=inputs.owner,
                    clock=inputs.clock,
                    key=inputs.session_key,
                    origin=inputs.origin,
                    client_id=inputs.client_id,
                )
                self._check()
                authority = OAuthTransactionAuthority(
                    self._directory / "gmail-oauth-transactions",
                    key=inputs.session_key,
                    continuity=continuity,
                    registration_backend=_ClosedRegistration(),
                )
                self._check()
                diagnostic = HeldGmailDiagnostic(
                    reconciliation=HeldGmailReconciliation(
                        authority=authority, configuration=self._configuration
                    )
                )
                self._diagnostic = diagnostic
                with self._admission_lock:
                    self._active = True

                @prepared.app.middleware("http")
                async def lifetime(
                    request: Request, call_next: RequestResponseEndpoint
                ) -> Response:
                    if not self._admitted():
                        return Response("Gmail diagnostic unavailable", status_code=403)
                    try:
                        return await call_next(request)
                    except BaseException:  # noqa: BLE001,S110 - no private middleware frames
                        pass
                    del request, call_next
                    self._latch()
                    raise GmailDiagnosticHostFatal("Gmail diagnostic host interrupted")

                @prepared.app.get("/connections/gmail/diagnostic")
                async def counts(request: Request) -> Response:
                    receipt = None
                    if not self._admitted():
                        return Response("Gmail diagnostic unavailable", status_code=403)
                    try:
                        self._preservation_check()
                        if (
                            request.url.scheme != "https"
                            or request.headers.getlist("host") != [authority._host]
                            or request.scope.get("query_string", b"")
                        ):
                            raise ValueError("actual private owner request required")
                        receipt = await run_in_threadpool(
                            diagnostic.inspect, cookie=_cookie(request, "__Host-zac-session")
                        )
                        self._preservation_check()
                        if not self._admitted():
                            raise GmailDiagnosticHostFatal("Gmail diagnostic admission closed")
                        return JSONResponse(
                            {
                                name: getattr(receipt, name)
                                for name in (
                                    "pending",
                                    "exchange_pending",
                                    "exchange_started",
                                    "denied",
                                    "held",
                                    "loaded",
                                    "total",
                                    "installed",
                                    "original_actor_verified",
                                    "source_subject_verified",
                                    "native_material_verified",
                                    "live_access_proven",
                                    "credential_authority",
                                    "processing_authorized",
                                    "execution_authorized",
                                )
                            }
                        )
                    except Exception:  # noqa: BLE001 - no private request/backend diagnostics
                        denied = True
                    except BaseException:  # noqa: BLE001 - discard interrupted request diagnostics
                        denied = False
                    if denied:
                        # Failed authentication stays an ordinary denial only
                        # after a pure host preservation audit outside its handler.
                        try:
                            self._preservation_check()
                        except BaseException:  # noqa: BLE001,S110 - fixed fatal below
                            pass
                        else:
                            return Response("Gmail diagnostic unavailable", status_code=403)
                    # Raise after leaving the handler so no original exception
                    # context or request/cookie frame is retained by this fatal.
                    del request, receipt
                    self._latch()
                    raise GmailDiagnosticHostFatal("Gmail diagnostic host interrupted")

                self._preservation_check()
                try:
                    window.serve(server=self._server)
                finally:
                    # serve() physically drains protected workers first. Audit
                    # preservation before this actual operator lease can exit.
                    with self._admission_lock:
                        self._active = False
                    self._preservation_check()
                    if self._fatal:
                        raise GmailDiagnosticHostFatal("Gmail diagnostic host requires review")
        finally:
            with self._admission_lock:
                self._active = False
            self._diagnostic = None
            self._captured = None
            try:
                self._original[8]()
            except BaseException:  # noqa: BLE001 - fixed fatal after original stop attempt
                self._fatal = True
            if self._fatal:
                raise GmailDiagnosticHostFatal("Gmail diagnostic host requires review")
