"""One foreground, one listener, two retained actual owner domains.

Inert engineering composition. Actual run requires separate explicit approval;
only two fixed SHARED startup reads occur, reused privately for both OWNER
windows. The original grant, ready/halt markers and held history remain intact.
Fresh installation requires its own bounded review; original holds remain intact.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from zacai.connectors.connector_authority import _guard
from zacai.connectors.gmail_client_secret import GmailClientSecretLoader, _configuration
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
from zacai.connectors.gmail_installation import GmailInstallation
from zacai.connectors.gmail_native_reader import GmailNativeReader
from zacai.connectors.gmail_registration import ReviewedGmailRegistration
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import OAuthExchangeTransport
from zacai.connectors.oauth_host_guard import OAuthHostGuard
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_diagnostic_host import _ClosedRegistration
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.private_host import NamedOwnerHostInputs, PreparedOwnerHost
from zacai.interfaces.private_operator import (
    PrivateOperatorMode,
    PrivateOperatorWindow,
    open_private_operator,
)
from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle
from zacai.interfaces.private_startup import OwnerStartupConfiguration, OwnerStartupLoader, _path
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class GmailRecoveryHostError(RuntimeError):
    """Fixed foreground rejection; no private configuration or startup frames."""


class GmailRecoveryHostFatal(BaseException):
    """Fixed interrupted or unconfirmed host; no automatic restart."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard private foreground frames
            failure = GmailRecoveryHostError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failure = GmailRecoveryHostFatal
        del args, kwargs
        raise failure("Gmail recovery host unavailable; stop and review")

    return call


@dataclass(frozen=True, init=False, repr=False)
class _OwnerWindows:
    """Issued inside both retained operator contexts; never caller attestation."""

    _issuer: GmailRecoveryHostPlan
    original: PrivateOperatorWindow
    hr: PrivateOperatorWindow
    original_inputs: NamedOwnerHostInputs
    hr_inputs: NamedOwnerHostInputs

    def __init__(self) -> None:
        raise TypeError("actual retained foreground windows required")


class _RecoveryGuard:
    def __init__(self, host: GmailRecoveryHostPlan) -> None:
        self._host = host

    def ready(self) -> None:
        self._host._recovery_current()

    def halt_unconfirmed(self) -> None:
        self._host._latch()
        raise GmailRecoveryHostFatal("Gmail recovery host requires review")


class GmailRecoveryHostPlan:
    """Closed one-run actual host; startup and live operations are not automatic."""

    _original_grant_profile: str
    _startup_stage: str
    _startup_only: bool

    @_closed
    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        original_directory: Path,
        hr_directory: Path,
        owner_client_id: str,
        startup_loader: OwnerStartupLoader,
        clock: HostObservedClock,
        escrow_confirmed_by_operator: bool,
        reviewed_registration_generation: str,
        console_observed_at: datetime,
        review_expires_at: datetime,
        action_generation: str,
        identities: IdentityProvider | None = None,
        load_existing: bool = False,
        original_grant_profile: str = "confidential",
        startup_only: bool = False,
        diagnostic_serving: bool = False,
    ) -> None:
        config = _configuration(configuration)
        original, hr = _path(original_directory), _path(hr_directory)
        if (
            type(diagnostic_serving) is not bool
            or (diagnostic_serving and (startup_only or load_existing))
            or type(startup_only) is not bool
            or type(original_grant_profile) is not str
            or original_grant_profile
            not in {"confidential", "legacy_confidential_highly_restricted"}
            or type(load_existing) is not bool
            or original == hr
            or type(startup_loader) is not OwnerStartupLoader
            or startup_loader.client_id != owner_client_id
            or startup_loader.origin != config.private_origin
            or startup_loader.mode != "foreground"
            or startup_loader.keychain_file_policy != "reviewed_login"
            or startup_loader.keychain_path.name != "login.keychain-db"
            or type(clock) is not HostObservedClock
            or escrow_confirmed_by_operator is not True
            or any(
                type(v) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", v) is None
                for v in (reviewed_registration_generation, action_generation)
            )
            or type(console_observed_at) is not datetime
            or console_observed_at.utcoffset() is None
            or type(review_expires_at) is not datetime
            or review_expires_at.utcoffset() is None
            or not timedelta(0) < review_expires_at - console_observed_at <= timedelta(hours=2)
        ):
            raise ValueError("explicit original and HR foreground proposal required")
        self._configuration, self._original_directory, self._hr_directory = config, original, hr
        self._startup_only = startup_only
        self._diagnostic_serving = diagnostic_serving
        self._shutdown_stage = "not_started"
        self._shutdown_failure_stage = "not_started"
        self._protected_stop_stage = "not_requested"
        self._diagnostic_request_stage = "not_observed"
        self._foreground_stage = self._foreground_cleanup_stage = "not_started"
        self._foreground_cleanup_failure_stage = "not_started"
        self._original_grant_profile = original_grant_profile
        self._startup_stage = "prepared"
        self._callback_diagnostic = OAuthCallbackDiagnostic()
        self._load_existing = load_existing
        self._loaded: Any = None
        self._original_loaded: Any = None
        self._owner_client_id, self._loader, self._clock = owner_client_id, startup_loader, clock
        self._escrow, self._generation, self._action_generation = (
            True,
            reviewed_registration_generation,
            action_generation,
        )
        self._observed, self._expires, self._identities = (
            console_observed_at,
            review_expires_at,
            identities,
        )
        self._server = PrivateServerLifecycle(
            verified_private_origin=config.private_origin, diagnostic_stages=diagnostic_serving
        )
        self._stop = self._server.stop_host
        self._settings = (
            config.configuration_digest,
            original,
            hr,
            owner_client_id,
            self._generation,
            action_generation,
            console_observed_at,
            review_expires_at,
            load_existing,
            original_grant_profile,
            startup_only,
            diagnostic_serving,
        )
        self._loader_settings = startup_loader._settings
        self._dependencies = (startup_loader, clock, identities, self._server, self._stop)
        self._spent = self._active = self._fatal = self._stop_attempted = False
        self._runtime: OwnerStartupConfiguration | None = None
        self._windows: _OwnerWindows | None = None
        self._original_continuity: NamedSessionContinuity | None = None
        self._hr_continuity: NamedSessionContinuity | None = None
        self._authority: OAuthTransactionAuthority | None = None
        self._consumer: Any = None
        self._original_consumer: Any = None
        self._join: Any = None
        self._witness: Any = None
        self._capture: tuple[object, ...] | None = None
        self._markers: OAuthHostGuard | None = None
        self._guard: _RecoveryGuard | None = None
        self._original_graph: tuple[object, ...] | None = None

    def __repr__(self) -> str:
        return "GmailRecoveryHostPlan()"

    @property
    def callback_stage(self) -> str:
        """Fixed operation reached; never authority or a proven failure cause."""
        diagnostic = self._callback_diagnostic
        return diagnostic.phase if type(diagnostic) is OAuthCallbackDiagnostic else "unavailable"

    @property
    def startup_stage(self) -> str:
        """Fixed nonauthoritative phase label; never evidence of credential access."""
        value = self._startup_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "prepared",
                "precredential_storage",
                "credentials",
                "authenticated_owners",
                "markers",
                "markers_lock",
                "marker_ready",
                "marker_halt",
                "marker_post_time",
                "marker_post_proposal",
                "marker_post_graph",
                "marker_post_files",
                "recovery_join",
                "routes",
                "serving",
            }
            else "unavailable"
        )

    @property
    def shutdown_stage(self) -> str:
        value = self._shutdown_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "not_started",
                "serve_entered",
                "serve_returned",
                "consumer_hold",
                "postserve_current",
                "context_close",
                "stop_cleanup",
                "closed",
            }
            else "unavailable"
        )

    @property
    def shutdown_failure_stage(self) -> str:
        value = self._shutdown_failure_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "not_started",
                "serve_entered",
                "serve_returned",
                "consumer_hold",
                "postserve_current",
                "context_close",
                "stop_cleanup",
            }
            else "unavailable"
        )

    @property
    def protected_stop_stage(self) -> str:
        value = self._protected_stop_stage
        return (
            value
            if type(value) is str and value in {"not_requested", "protected_stop_requested"}
            else "unavailable"
        )

    @property
    def diagnostic_request_stage(self) -> str:
        value = self._diagnostic_request_stage
        return (
            value
            if type(value) is str
            and value in {"not_observed", "request_entered", "current_returned", "request_refused"}
            else "unavailable"
        )

    @property
    def foreground_stage(self) -> str:
        value = self._foreground_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "not_started",
                "prepared",
                "require",
                "thread_baseline",
                "signal_snapshot",
                "signal_install",
                "server_call",
                "server_returned",
            }
            else "unavailable"
        )

    @property
    def foreground_cleanup_stage(self) -> str:
        value = self._foreground_cleanup_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "not_started",
                "signal_suppression",
                "thread_drain",
                "paired_worker_drain",
                "logging_restore",
                "signal_restore",
                "restored",
            }
            else "unavailable"
        )

    @property
    def foreground_cleanup_failure_stage(self) -> str:
        value = self._foreground_cleanup_failure_stage
        return (
            value
            if type(value) is str
            and value
            in {
                "not_started",
                "signal_suppression",
                "thread_drain",
                "paired_worker_drain",
                "logging_restore",
                "signal_restore",
            }
            else "unavailable"
        )

    @property
    def server_stage(self) -> str:
        return self._server.lifecycle_stage

    @property
    def server_failure_stage(self) -> str:
        return self._server.failure_stage

    @property
    def listener_stage(self) -> str:
        return self._server.listener_stage

    def _diagnostic_serve(self, hr: PrivateOperatorWindow) -> None:
        """One health-only bounded listener inside retained protected OWNER contexts.

        No ownerlogin/Gmail routes, join, consumer, provider or token operation.
        Ten-second eventloop stop requests graceful shutdown; never force exits
        or skips the existing physical drain. Health is not connection evidence.
        """
        import asyncio
        from collections.abc import AsyncIterator
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def lifetime(app: FastAPI) -> AsyncIterator[None]:
            del app

            async def stop_after_budget() -> None:
                try:
                    await asyncio.sleep(10)
                    self._recovery_current()
                    self._stop()
                except asyncio.CancelledError:
                    raise
                except BaseException:  # noqa: BLE001 - fixed fatal, no task traceback
                    self._latch()

            task = asyncio.create_task(stop_after_budget())
            try:
                yield
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        app = FastAPI(lifespan=lifetime, docs_url=None, redoc_url=None, openapi_url=None)

        @app.get("/health")
        async def health() -> Response:
            self._diagnostic_request_stage = "request_entered"
            interrupted = False
            try:
                self._recovery_current()
                self._diagnostic_request_stage = "current_returned"
            except Exception:  # noqa: BLE001 - fixed public refusal only
                self._diagnostic_request_stage = "request_refused"
                self._latch()
                return Response("Startup diagnostic unavailable.", status_code=403)
            except BaseException:  # noqa: BLE001 - preserve fatal category, sanitize context
                self._diagnostic_request_stage = "request_refused"
                self._latch()
                interrupted = True
            if interrupted:
                raise GmailRecoveryHostFatal("Startup diagnostic interrupted")
            return Response(
                "Startup diagnostic only; Gmail inactive.",
                media_type="text/plain",
                headers={"cache-control": "no-store"},
            )

        def server(owner_app: FastAPI) -> None:
            del owner_app
            self._recovery_current()
            self._server(app)

        self._startup_stage = "serving"
        self._shutdown_stage = "serve_entered"
        try:
            hr.serve(server=server)
            self._shutdown_stage = "serve_returned"
        except BaseException:
            self._shutdown_failure_stage = self._shutdown_stage
            raise
        finally:
            self._foreground_stage = hr.foreground_stage
            self._foreground_cleanup_stage = hr.foreground_cleanup_stage
            self._foreground_cleanup_failure_stage = hr.foreground_cleanup_failure_stage
            self._shutdown_stage = "postserve_current"
            self._recovery_current()
            self._active = False
            if self._fatal:
                raise GmailRecoveryHostFatal("Gmail recovery requires review")

    def _proposal_current(self) -> None:
        current = (
            self._configuration.configuration_digest,
            self._original_directory,
            self._hr_directory,
            self._owner_client_id,
            self._generation,
            self._action_generation,
            self._observed,
            self._expires,
            self._load_existing,
            self._original_grant_profile,
            self._startup_only,
            self._diagnostic_serving,
        )
        dependencies = (self._loader, self._clock, self._identities, self._server, self._stop)
        if (
            type(self._diagnostic_serving) is not bool
            or (self._diagnostic_serving and (self._startup_only or self._load_existing))
            or type(self._startup_only) is not bool
            or type(self._original_grant_profile) is not str
            or self._original_grant_profile
            not in {"confidential", "legacy_confidential_highly_restricted"}
            or current != self._settings
            or any(a is not b for a, b in zip(dependencies, self._dependencies, strict=True))
            or self._loader._settings != self._loader_settings
        ):
            raise ValueError("original foreground proposal required")
        loader_current = (
            self._loader.client_id,
            self._loader.origin,
            str(self._loader.keychain_path),
            self._loader.mode,
            self._loader.foreground_timeout_seconds,
            self._loader.keychain_file_policy,
        )
        if loader_current != self._loader_settings:
            raise ValueError("original fixed startup loader required")

    def _time(self) -> None:
        if not self._observed <= self._clock() < self._expires:
            raise ValueError("current independently reviewed console required")
        self._proposal_current()

    @staticmethod
    def _stat(info: os.stat_result, *, full: bool = True) -> tuple[int, ...]:
        base = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)
        return base + (info.st_size, info.st_mtime_ns, info.st_ctime_ns) if full else base

    def _file(self, path: Path, *, contents: bool) -> tuple[object, ...]:
        before = _guard(path)
        if not contents:
            return self._stat(before, full=False)
        if before.st_size > 512_000:
            raise ValueError("bounded protected original file required")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if self._stat(os.fstat(fd)) != self._stat(before):
                raise ValueError("original protected inode required")
            data = os.read(fd, 512_001)
            if self._stat(os.fstat(fd)) != self._stat(before):
                raise ValueError("protected original file changed")
        finally:
            os.close(fd)
        if self._stat(_guard(path)) != self._stat(before):
            raise ValueError("protected original name changed")
        return self._stat(before) + (hashlib.sha256(data).digest(),)

    def _existing_connector(self, root: Path) -> tuple[Any, ...]:
        from zacai.connectors.gmail_installation import CONNECTOR

        if not self._load_existing or root.name != CONNECTOR:
            raise ValueError("fixed existing connector directory required")
        _guard(root, directory=True)
        if {p.name for p in root.iterdir()} != {
            "connector-authority.lock",
            "connector-authority.bin",
        }:
            raise ValueError("complete existing connector required")
        _guard(root / "connector-authority.bin")
        return (
            self._stat(_guard(root, directory=True), full=False),
            self._file(root / "connector-authority.lock", contents=True),
        )

    def _files(self) -> tuple[Any, ...]:
        roots = []
        for root in (self._original_directory, self._hr_directory):
            roots.append(
                (
                    self._stat(_guard(root, directory=True), full=False),
                    frozenset(p.name for p in root.iterdir()),
                    self._stat(_guard(root / "owner", directory=True), full=False),
                    self._file(root / "owner" / "owner.json", contents=True),
                    self._file(root / "private-mode.lock", contents=True),
                    self._file(root / "sessions" / "sessions.sqlite", contents=False),
                )
            )
        guard = self._original_directory / "gmail-oauth-guard"
        markers = (
            self._stat(_guard(guard, directory=True), full=False),
            frozenset(p.name for p in guard.iterdir()),
            *(
                self._file(guard / name, contents=True)
                for name in ("oauth-host.lock", "oauth-host.ready", "oauth-host.halted")
            ),
        )
        ledger = self._original_directory / "gmail-oauth-transactions"
        identity = self._stat(_guard(ledger, directory=True), full=False)
        if self._load_existing and self._loaded is None:
            from zacai.connectors.gmail_installation import CONNECTOR
            from zacai.connectors.gmail_installed_load import _FILES

            if {p.name for p in ledger.iterdir()} != _FILES | {CONNECTOR}:
                raise ValueError("complete residue-free installed namespace required")
        namespace: tuple[Any, ...]
        if self._loaded is not None:
            if (
                self._loaded is not self._original_loaded
                or self._loaded.namespace_current() is not None
            ):
                raise ValueError("original authenticated load namespace required")
            namespace = (identity[:4],)
        elif self._consumer is None:
            namespace = (
                identity,
                frozenset(p.name for p in ledger.iterdir()),
                tuple(
                    (
                        p.name,
                        self._existing_connector(p) if p.is_dir() else self._file(p, contents=True),
                    )
                    for p in sorted(ledger.iterdir())
                ),
            )
        else:
            check: Callable[[], object] = self._consumer.namespace_current
            if check() is not None:
                raise ValueError("original owned recovery namespace required")
            # Consumer validates exact original/owned names and APFS directory links.
            namespace = (identity[:4],)
        return tuple(roots), markers, namespace

    def _marker_current(self) -> None:
        guard = self._markers
        if type(guard) is not OAuthHostGuard:
            raise ValueError("original authenticated ready and halt required")
        if self._startup_stage != "serving":
            self._startup_stage = "markers_lock"
        with guard._locked():
            for path, expected in (
                (guard._ready_path, guard._ready_bytes),
                (guard._halt_path, guard._halt_bytes),
            ):
                if self._startup_stage != "serving":
                    self._startup_stage = (
                        "marker_ready" if path is guard._ready_path else "marker_halt"
                    )
                before = _guard(path)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    if self._stat(os.fstat(fd)) != self._stat(before) or before.st_size != len(
                        expected
                    ):
                        raise ValueError("exact original marker required")
                    data = os.read(fd, len(expected) + 1)
                    if self._stat(os.fstat(fd)) != self._stat(before) or not hmac.compare_digest(
                        data, expected
                    ):
                        raise ValueError("authenticated original marker required")
                finally:
                    os.close(fd)
                if self._stat(_guard(path)) != self._stat(before):
                    raise ValueError("original marker changed")

    def _graph(self) -> tuple[object, ...]:
        authority, markers, guard = self._authority, self._markers, self._guard
        if authority is None or markers is None or guard is None:
            raise ValueError("original captured children required")
        values: list[object] = []
        cap = self._windows
        if cap is None:
            raise ValueError("actual captured windows required")
        for continuity, inputs in zip(
            (self._original_continuity, self._hr_continuity),
            (cap.original_inputs, cap.hr_inputs),
            strict=True,
        ):
            if continuity is None:
                raise ValueError("both actual continuity domains required")
            owners = inputs.owners
            values.extend(
                (
                    continuity._sessions,
                    continuity._owner,
                    continuity._clock,
                    continuity._context,
                    continuity._key,
                    continuity._sessions._directory,
                    continuity._sessions._path,
                    continuity._sessions._cipher,
                    owners._directory,
                    owners._path,
                    owners._origin,
                    owners._client_id,
                    owners._key,
                )
            )
        values.extend(
            (
                authority._directory,
                authority._path,
                authority._lock_path,
                authority._context,
                authority._cipher,
                authority._continuity,
                authority._backend,
                markers._directory,
                markers._lock_path,
                markers._ready_path,
                markers._halt_path,
                markers._ready_bytes,
                markers._halt_bytes,
                guard._host,
            )
        )
        return tuple(values)

    def _recovery_current(self) -> None:
        self._proposal_current()
        self._time()
        if self._consumer is not self._original_consumer:
            raise ValueError("original private consumer required")
        cap = self._windows
        if (
            not self._active
            or self._fatal
            or type(cap) is not _OwnerWindows
            or cap._issuer is not self
        ):
            raise ValueError("both actual retained OWNER contexts required")
        captured = (
            cap,
            cap.original,
            cap.hr,
            cap.original_inputs,
            cap.hr_inputs,
            self._runtime,
            self._original_continuity,
            self._hr_continuity,
            self._authority,
            self._markers,
            self._guard,
        )
        if self._capture is None or any(
            a is not b for a, b in zip(captured, self._capture, strict=True)
        ):
            raise ValueError("original actual host capture required")
        for window, inputs in ((cap.original, cap.original_inputs), (cap.hr, cap.hr_inputs)):
            if (
                not window._active
                or window._mode is not PrivateOperatorMode.OWNER
                or window._origin != inputs.origin
                or window._clock is not self._clock
                or type(window._prepared) is not PreparedOwnerHost
                or window._prepared.sessions is not inputs.sessions
                or window._prepared.owners is not inputs.owners
            ):
                raise ValueError("actual original owner window required")
        if cap.original._serving:
            raise ValueError("one HR listener only")
        if self._graph() != self._original_graph:
            raise ValueError("original captured child graph required")
        if self._startup_stage != "serving":
            self._startup_stage = "authenticated_owners"
        original = cap.original_inputs.owner()
        hr = cap.hr_inputs.owner()
        if (
            original.scopes
            != (
                BoundaryScope(
                    B.BRAINSTORM,
                    frozenset({C.CONFIDENTIAL})
                    if self._original_grant_profile == "confidential"
                    else frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
                ),
            )
            or hr.scopes != (BoundaryScope(B.BRAINSTORM, frozenset({C.HIGHLY_RESTRICTED})),)
            or original.identity.issuer != hr.identity.issuer
            or original.identity.subject != hr.identity.subject
        ):
            raise ValueError("same verified owner and distinct unchanged scopes required")
        observed = self._files()
        if self._witness is None or observed[:2] != self._witness[:2]:
            raise ValueError("original protected owner and marker files changed")
        if self._consumer is None and self._loaded is None:
            if observed[2] != self._witness[2]:
                raise ValueError("original pre-consumer namespace required")
        elif observed[2][0] != self._witness[2][0][:4]:
            raise ValueError("original ledger directory identity required")
        if self._startup_stage != "serving":
            self._startup_stage = "markers"
        self._marker_current()
        if self._startup_stage != "serving":
            self._startup_stage = "marker_post_time"
        self._time()
        if self._startup_stage != "serving":
            self._startup_stage = "marker_post_proposal"
        self._proposal_current()
        if self._startup_stage != "serving":
            self._startup_stage = "marker_post_graph"
        if self._graph() != self._original_graph:
            raise ValueError("captured child changed during trusted checks")
        if self._startup_stage != "serving":
            self._startup_stage = "marker_post_files"
        if self._files()[:2] != self._witness[:2]:
            raise ValueError("protected files changed during marker authentication")

    def _latch(self) -> None:
        self._protected_stop_stage = "protected_stop_requested"
        self._active = False
        self._fatal = True
        if not self._stop_attempted:
            self._stop_attempted = True
            try:
                self._dependencies[4]()
            except BaseException:  # noqa: BLE001,S110 - fixed fatal regardless stop
                pass

    def _stop_recovery(self) -> None:
        self._latch()

    def _make_recovery_consumer(self, action: Any) -> Any:
        from zacai.connectors.gmail_recovery_consumer import GmailRecoveryConsumer

        self._recovery_current()
        if (
            self._load_existing
            or self._consumer is not None
            or self._runtime is None
            or self._authority is None
            or self._hr_continuity is None
            or self._guard is None
        ):
            raise ValueError("one original captured recovery consumer required")
        registration = ReviewedGmailRegistration(
            configuration=self._configuration,
            approved_generation=self._generation,
            console_observed_at=self._observed,
            review_expires_at=self._expires,
            clock=self._clock,
            host_guard=self._guard,
            stop_host=self._stop,
        )
        loader = GmailClientSecretLoader(
            configuration=self._configuration,
            keychain_path=self._loader.keychain_path,
            mode="foreground",
            foreground_timeout_seconds=self._loader.foreground_timeout_seconds,
            keychain_file_policy="reviewed_login",
        )
        stage = HeldGmailNativeStage(
            configuration=self._configuration,
            authority=self._authority,
            keychain_path=self._loader.keychain_path,
            keychain_file_policy="reviewed_login",
            host_guard=self._guard,
            stop_host=self._stop,
        )
        consumer = GmailRecoveryConsumer(
            host=self,
            action=action,
            key=self._runtime.session_key,
            registration=registration,
            loader=loader,
            transport=OAuthExchangeTransport(),
            stage=stage,
        )
        self._consumer = self._original_consumer = consumer
        return consumer

    @_closed
    def _make_gmail_installation(self, consumer: Any) -> GmailInstallation:
        from zacai.connectors.gmail_recovery_consumer import GmailRecoveryConsumer

        self._recovery_current()
        if (
            type(consumer) is not GmailRecoveryConsumer
            or consumer is not self._consumer
            or consumer is not self._original_consumer
            or consumer._host is not self
            or consumer._authority is not self._authority
            or consumer._installer is not None
            or consumer._original_installer is not None
            or consumer._checked_fresh is None
            or consumer._fresh_observation is None
            or consumer._admission is None
            or not consumer._admission._fresh_published
        ):
            raise ValueError("actual completed fresh recovery required")
        reader = GmailNativeReader(
            configuration=self._configuration,
            reconciliation=consumer._reconciliation,
            keychain_path=self._loader.keychain_path,
            preservation_check=self._recovery_current,
            keychain_file_policy=self._loader.keychain_file_policy,
        )
        installation = GmailInstallation(consumer=consumer, reader=reader)
        consumer._installer = consumer._original_installer = installation
        self._recovery_current()
        return installation

    @_closed
    def _load_gmail_installation(self, action: Any) -> Any:
        from zacai.connectors.gmail_installed_load import GmailInstallationLoader

        self._recovery_current()
        if (
            not self._load_existing
            or self._loaded is not None
            or self._runtime is None
            or self._authority is None
        ):
            raise ValueError("one explicit installation load required")
        loader = GmailInstallationLoader(
            host=self,
            action=action,
            authority=self._authority,
            configuration=self._configuration,
            key=self._runtime.session_key,
        )
        self._loaded = self._original_loaded = loader
        capability = loader.load_existing()
        reader = GmailNativeReader(
            configuration=self._configuration,
            reconciliation=HeldGmailReconciliation(
                authority=self._authority, configuration=self._configuration
            ),
            keychain_path=self._loader.keychain_path,
            preservation_check=self._recovery_current,
            keychain_file_policy=self._loader.keychain_file_policy,
        )
        installation = GmailInstallation.reopen(
            capability=capability, reader=reader, transport=OAuthExchangeTransport()
        )
        self._recovery_current()
        return installation

    @_closed
    def run(self) -> None:
        from zacai.connectors.gmail_recovery_authorization import GmailRecoveryJoin
        from zacai.interfaces.gmail_recovery_web import GmailRecoveryWeb

        if self._spent:
            raise ValueError("one foreground attempt required")
        self._spent = True
        if threading.current_thread() is not threading.main_thread() or not all(
            s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr)
        ):
            raise ValueError("actual foreground three-TTY process required")
        self._proposal_current()
        self._time()
        self._startup_stage = "precredential_storage"
        self._witness = self._files()  # both existing domains/ready/halt before any startup
        if self._witness[0][0][0][:2] == self._witness[0][1][0][:2]:
            raise ValueError("distinct actual original and HR roots required")
        try:

            async def view(principal: InterfacePrincipal) -> str:
                del principal
                return '<h1>Review one Gmail recovery</h1><p>Gmail remains uninstalled.</p><a href="/connections/gmail/recover">Review recovery</a>'

            loaded_runtime: OwnerStartupConfiguration | None = None

            def load(*, client_id: str, origin: str) -> OwnerStartupConfiguration:
                nonlocal loaded_runtime
                self._proposal_current()
                self._time()
                if (
                    client_id != self._owner_client_id
                    or origin != self._configuration.private_origin
                ):
                    raise ValueError("exact original startup context required")
                if loaded_runtime is None:
                    loaded_runtime = self._loader(client_id=client_id, origin=origin)
                    self._runtime = loaded_runtime
                if self._runtime is not loaded_runtime:
                    raise ValueError("original actual startup identity required")
                self._time()
                self._proposal_current()
                if (
                    type(self._runtime) is not OwnerStartupConfiguration
                    or self._runtime.client_id != client_id
                    or self._runtime.origin != origin
                ):
                    raise ValueError("same actual original startup required")
                return self._runtime

            self._startup_stage = "credentials"
            with open_private_operator(  # noqa: SIM117 - retain both actual OWNER contexts
                mode=PrivateOperatorMode.OWNER,
                client_id=self._owner_client_id,
                origin=self._configuration.private_origin,
                directory=self._original_directory,
                escrow_confirmed_by_operator=True,
                view=view,
                clock=self._clock,
                startup_loader=load,
                identities=self._identities,
            ) as original:
                with open_private_operator(
                    mode=PrivateOperatorMode.OWNER,
                    client_id=self._owner_client_id,
                    origin=self._configuration.private_origin,
                    directory=self._hr_directory,
                    escrow_confirmed_by_operator=True,
                    view=view,
                    clock=self._clock,
                    startup_loader=load,
                    identities=self._identities,
                ) as hr:
                    if self._runtime is None:
                        raise ValueError("actual approved startup required")
                    inputs = []
                    for window, directory in (
                        (original, self._original_directory),
                        (hr, self._hr_directory),
                    ):
                        prepared = window._prepared
                        if type(prepared) is not PreparedOwnerHost:
                            raise ValueError("actual OWNER context required")
                        inputs.append(
                            NamedOwnerHostInputs(
                                self._runtime.origin,
                                self._runtime.client_id,
                                self._runtime.session_key,
                                directory,
                                prepared.owners,
                                prepared.owners.load,
                                prepared.sessions,
                                self._clock,
                            )
                        )
                    cap = object.__new__(_OwnerWindows)
                    for name, value in zip(
                        ("_issuer", "original", "hr", "original_inputs", "hr_inputs"),
                        (self, original, hr, *inputs),
                        strict=True,
                    ):
                        object.__setattr__(cap, name, value)
                    self._windows = cap

                    def continuity(input: NamedOwnerHostInputs) -> NamedSessionContinuity:
                        return NamedSessionContinuity(
                            sessions=input.sessions,
                            owner=input.owner,
                            clock=input.clock,
                            key=input.session_key,
                            origin=input.origin,
                            client_id=input.client_id,
                        )

                    self._original_continuity, self._hr_continuity = map(continuity, inputs)
                    self._authority = OAuthTransactionAuthority(
                        self._original_directory / "gmail-oauth-transactions",
                        key=self._runtime.session_key,
                        continuity=self._original_continuity,
                        registration_backend=_ClosedRegistration(),
                    )
                    self._markers = OAuthHostGuard(
                        self._original_directory / "gmail-oauth-guard",
                        key=self._runtime.session_key,
                        origin=self._runtime.origin,
                        client_id=self._runtime.client_id,
                    )
                    self._guard = _RecoveryGuard(self)
                    self._capture = (
                        cap,
                        original,
                        hr,
                        *inputs,
                        self._runtime,
                        self._original_continuity,
                        self._hr_continuity,
                        self._authority,
                        self._markers,
                        self._guard,
                    )
                    self._original_graph = self._graph()
                    self._active = True
                    self._recovery_current()
                    if self._startup_only:
                        return
                    if self._diagnostic_serving:
                        self._diagnostic_serve(hr)
                        return
                    self._startup_stage = "recovery_join"
                    self._join = GmailRecoveryJoin(
                        host=self,
                        authority=self._authority,
                        hr_continuity=self._hr_continuity,
                        configuration=self._configuration,
                        action_generation=self._action_generation,
                    )
                    self._startup_stage = "routes"
                    if self._load_existing:
                        from zacai.interfaces.gmail_installed_web import GmailInstalledWeb

                        GmailInstalledWeb(host=self, join=self._join).mount(hr._prepared.app)
                    else:
                        GmailRecoveryWeb(host=self, join=self._join).mount(hr._prepared.app)

                    @hr._prepared.app.middleware("http")
                    async def lifetime(
                        request: Request, call_next: RequestResponseEndpoint
                    ) -> Response:
                        if not self._active or self._fatal:
                            return Response("Gmail recovery unavailable", status_code=403)
                        try:
                            return await call_next(request)
                        except BaseException:  # noqa: BLE001,S110 - original worker drain retains both contexts
                            pass
                        del request, call_next
                        self._latch()
                        raise GmailRecoveryHostFatal("Gmail recovery host interrupted")

                    try:
                        self._startup_stage = "serving"
                        self._shutdown_stage = "serve_entered"
                        hr.serve(server=self._server)
                        self._shutdown_stage = "serve_returned"
                    except BaseException:
                        self._shutdown_failure_stage = self._shutdown_stage
                        raise
                    finally:
                        self._foreground_stage = hr.foreground_stage
                        self._foreground_cleanup_stage = hr.foreground_cleanup_stage
                        self._foreground_cleanup_failure_stage = hr.foreground_cleanup_failure_stage
                        self._shutdown_stage = "consumer_hold"
                        if self._consumer is not None:
                            self._consumer.hold_pending()
                        self._shutdown_stage = "postserve_current"
                        self._recovery_current()
                        self._active = False
                        if self._fatal:
                            raise GmailRecoveryHostFatal("Gmail recovery requires review")
        except BaseException:
            if self._shutdown_failure_stage == "not_started":
                self._shutdown_failure_stage = self._shutdown_stage
            raise
        finally:
            self._shutdown_stage = "context_close"
            self._active = False
            self._windows = None
            self._runtime = None
            self._consumer = self._original_consumer = self._join = None
            self._loaded = self._original_loaded = None
            self._authority = self._original_continuity = self._hr_continuity = None
            self._capture = self._markers = self._guard = None
            self._original_graph = None
            try:
                self._shutdown_stage = "stop_cleanup"
                self._dependencies[4]()
            except BaseException:  # noqa: BLE001 - fixed fatal after actual stop
                self._fatal = True
            if self._fatal:
                raise GmailRecoveryHostFatal("Gmail recovery requires review")
