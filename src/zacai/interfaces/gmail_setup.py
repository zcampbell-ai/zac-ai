"""Explicit one-shot foreground composition for held work Gmail setup.

Constructor is inert: no clock, owner record, Keychain, filesystem or listener.
run() is a separately authorized local action, not an agent tool. It reads two
fixed SHARED startup items, then permits one original Gmail callback to load the
fixed BRAINSTORM client secret and stage held native tokens. Native prompts have
no hard timeout. No capture, model work, sending, installation or recovery claim.
Actual item ACL review, escrow, signed reader and reconciliation remain gates.

Two explicit initialization flags select NEW operational children or existing
reviewed state. Existing non-denied transactions prevent restart; nothing is
resumed, deleted, reset or moved to an alternate directory. Both flags must agree;
new mode preflights both paths absent, existing mode requires both state domains.
All live components
share actual owner/session/key/clock, concrete durable guard and one captured
listener stop callback. Browser/request fields cannot construct this assembly.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from zacai.connectors.connector_authority import _guard, _json
from zacai.connectors.gmail_client_secret import GmailClientSecretLoader, _configuration
from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
from zacai.connectors.gmail_native_staging import _AppleBindings, _Bindings
from zacai.connectors.gmail_registration import ReviewedGmailRegistration
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import OAuthExchangeTransport
from zacai.connectors.oauth_host_guard import OAuthHostGuard
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_connection_web import GmailConnectionWeb
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_operator import PrivateOperatorMode, open_private_operator
from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle
from zacai.interfaces.private_startup import (
    OwnerStartupConfiguration,
    OwnerStartupLoader,
    _path,
)
from zacai.interfaces.private_startup import (
    _configuration as _owner_configuration,
)
from zacai.interfaces.private_web import InterfacePrincipal


class GmailSetupError(RuntimeError):
    """Fixed local setup failure, never paths, credentials or private identity."""


class GmailSetupFatal(BaseException):
    """Fixed fatal setup diagnostic: stop actual host and reconcile."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard private host callback frames
            failure = GmailSetupError
        except BaseException:  # noqa: BLE001 - no interrupted private diagnostics
            failure = GmailSetupFatal
        del args, kwargs
        raise failure("Gmail setup unavailable; stop and review before another attempt")

    return call


class GmailSetupPlan:
    """Operator-reviewed one foreground proposal; no permissive defaults.

    Optional identity/transport/native test adapters are TRUSTED host injections,
    never evidence of live access and never selected through a browser or CLI.
    Production omits them. Configuration/review facts do not grant installation.
    """

    @_closed
    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        owner_client_id: str,
        directory: Path,
        startup_loader: OwnerStartupLoader,
        clock: HostObservedClock,
        approved_generation: str,
        console_observed_at: datetime,
        review_expires_at: datetime,
        initialize_new_guard: bool,
        initialize_new_transactions: bool,
        escrow_confirmed_by_operator: bool,
        expected_subject: str | None = None,
        transport: OAuthExchangeTransport | None = None,
        bindings_factory: Callable[[], _Bindings] = _AppleBindings,
        identities: IdentityProvider | None = None,
    ) -> None:
        config = _configuration(configuration)
        _owner_configuration(owner_client_id, config.private_origin)
        path = _path(directory)
        if (
            type(startup_loader) is not OwnerStartupLoader
            or startup_loader.client_id != owner_client_id
            or startup_loader.origin != config.private_origin
            or startup_loader.mode != "foreground"
            or startup_loader.keychain_file_policy != "reviewed_login"
            or startup_loader.keychain_path.name != "login.keychain-db"
            or type(clock) is not HostObservedClock
            or type(approved_generation) is not str
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", approved_generation) is None
            or type(console_observed_at) is not datetime
            or console_observed_at.utcoffset() is None
            or type(review_expires_at) is not datetime
            or review_expires_at.utcoffset() is None
            or not timedelta(0) < review_expires_at - console_observed_at <= timedelta(hours=2)
            or type(initialize_new_guard) is not bool
            or type(initialize_new_transactions) is not bool
            or initialize_new_guard is not initialize_new_transactions
            or type(escrow_confirmed_by_operator) is not bool
            or not escrow_confirmed_by_operator
            or (transport is not None and type(transport) is not OAuthExchangeTransport)
            or not callable(bindings_factory)
            or (
                expected_subject is not None
                and (
                    type(expected_subject) is not str
                    or re.fullmatch(r"[0-9]{1,64}", expected_subject) is None
                )
            )
        ):
            raise ValueError("explicit reviewed foreground inputs required")
        self._configuration, self._owner_client_id, self._directory = config, owner_client_id, path
        self._loader, self._clock = startup_loader, clock
        self._generation, self._observed, self._expires = (
            approved_generation,
            console_observed_at,
            review_expires_at,
        )
        self._new_guard, self._new_transactions = initialize_new_guard, initialize_new_transactions
        self._escrow, self._expected_subject = escrow_confirmed_by_operator, expected_subject
        self._transport = transport if transport is not None else OAuthExchangeTransport()
        self._bindings_factory, self._identities = bindings_factory, identities
        self._server = PrivateServerLifecycle(verified_private_origin=config.private_origin)
        self._stop_host = self._server.stop_host  # Capture the SAME bound-method object once.
        self._spent = self._running = False
        self._guard: OAuthHostGuard | None = None
        self._settings = self._public_settings()
        self._loader_settings = startup_loader._settings
        self._dependencies = (
            self._loader,
            self._clock,
            self._transport,
            self._bindings_factory,
            self._identities,
            self._server,
            self._stop_host,
        )
        self._current()

    def __repr__(self) -> str:
        return "GmailSetupPlan()"

    def _public_settings(self) -> tuple[object, ...]:
        return (
            self._configuration.configuration_digest,
            self._owner_client_id,
            str(self._directory),
            self._generation,
            self._observed,
            self._expires,
            self._new_guard,
            self._new_transactions,
            self._escrow,
            self._expected_subject,
        )

    def _current(self) -> None:
        loader_settings = (
            self._loader.client_id,
            self._loader.origin,
            str(self._loader.keychain_path),
            self._loader.mode,
            self._loader.foreground_timeout_seconds,
            self._loader.keychain_file_policy,
        )
        dependencies = (
            self._loader,
            self._clock,
            self._transport,
            self._bindings_factory,
            self._identities,
            self._server,
            self._stop_host,
        )
        if (
            self._public_settings() != self._settings
            or loader_settings != self._loader_settings
            or self._loader._settings != self._loader_settings
            or any(a is not b for a, b in zip(dependencies, self._dependencies, strict=True))
        ):
            raise ValueError("original foreground proposal changed")

    def _time(self) -> None:
        if not self._observed <= self._clock() < self._expires:
            raise ValueError("console review expired or not yet observed")

    def _load(self, *, client_id: str, origin: str) -> OwnerStartupConfiguration:
        self._current()
        self._time()
        self._current()
        self._directory_current()
        config = self._loader(client_id=client_id, origin=origin)
        self._time()
        self._current()
        return config

    def _halt(self) -> None:
        # Never acknowledge ambiguous initialization or release while it is in
        # use. Actual operator finally drains threads and retains its mode lease.
        failed = False
        if self._guard is not None:
            try:
                self._guard.halt_unconfirmed()
            except BaseException:  # noqa: BLE001 - must still stop actual listener
                failed = True
        try:
            self._stop_host()
        except BaseException:  # noqa: BLE001 - fixed fatal if shutdown unconfirmed
            failed = True
        if failed:
            raise GmailSetupFatal("Gmail setup halt unconfirmed; reconcile before restart")

    def _directory_current(self) -> None:
        _guard(self._directory, directory=True)
        if self._directory.resolve(strict=True) != self._directory:
            raise ValueError("original canonical private host directory required")

    def _operational_preflight(self) -> None:
        """Treat guard plus ledger as ONE state domain, never mixed recovery."""
        guard_path = self._directory / "gmail-oauth-guard"
        ledger_path = self._directory / "gmail-oauth-transactions"
        if self._new_guard:
            # Both names must be absent BEFORE creating either child. A retained
            # guard, a lost ledger or any half-published prior attempt refuses.
            for path in (guard_path, ledger_path):
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                raise ValueError("existing or partially published OAuth state")
        else:
            # Require the entire existing state domain before any readiness read
            # or the transaction constructor's O_CREAT can recreate a lock.
            for path in (guard_path, ledger_path):
                _guard(path, directory=True)
                if path.resolve(strict=True) != path:
                    raise ValueError("exact protected operational children required")
            for path in (
                guard_path / "oauth-host.lock",
                guard_path / "oauth-host.ready",
                ledger_path / "provider-oauth-transactions.lock",
                ledger_path / "provider-oauth-transactions.bin",
            ):
                _guard(path)

    def _child(self, name: str, *, new: bool) -> Path:
        child = self._directory / name
        if new:
            child.mkdir(mode=0o700, exist_ok=False)
        _guard(child, directory=True)
        if child.resolve(strict=True) != child:
            raise ValueError("original private operational child required")
        return child

    def _factory(self, inputs: NamedOwnerHostInputs) -> GmailConnectionWeb:
        if (
            not self._running
            or type(inputs) is not NamedOwnerHostInputs
            or inputs.directory != self._directory
            or inputs.clock is not self._clock
            or inputs.client_id != self._owner_client_id
            or inputs.origin != self._configuration.private_origin
        ):
            raise ValueError("actual owner host inputs required")
        try:
            self._current()
            self._time()
            self._current()
            self._directory_current()
            self._operational_preflight()
            guard_path = self._child("gmail-oauth-guard", new=self._new_guard)
            guard = OAuthHostGuard(
                guard_path,
                key=inputs.session_key,
                origin=inputs.origin,
                client_id=inputs.client_id,
            )
            self._guard = guard
            if self._new_guard:
                guard.initialize()
            else:
                guard.ready()
            continuity = NamedSessionContinuity(
                sessions=inputs.sessions,
                owner=inputs.owner,
                clock=inputs.clock,
                key=inputs.session_key,
                origin=inputs.origin,
                client_id=inputs.client_id,
            )
            registration = ReviewedGmailRegistration(
                configuration=self._configuration,
                approved_generation=self._generation,
                console_observed_at=self._observed,
                review_expires_at=self._expires,
                clock=inputs.clock,
                host_guard=guard,
                stop_host=self._stop_host,
            )
            ledger_path = self._child("gmail-oauth-transactions", new=self._new_transactions)
            if not self._new_transactions:
                # Existing selection must not create a missing lock/file merely
                # because OAuthTransactionAuthority's constructor uses O_CREAT.
                _guard(ledger_path / "provider-oauth-transactions.lock")
                _guard(ledger_path / "provider-oauth-transactions.bin")
            authority = OAuthTransactionAuthority(
                ledger_path,
                key=inputs.session_key,
                continuity=continuity,
                registration_backend=registration,
            )
            if self._new_transactions:
                authority.initialize()
            else:
                with authority._locked():
                    ledger = authority._read()
                    authority._now(ledger)
                    if any(row["state"] != "denied" for row in ledger["rows"].values()):
                        raise ValueError("existing transaction requires reconciliation")
            loader = GmailClientSecretLoader(
                configuration=self._configuration,
                keychain_path=self._loader.keychain_path,
                keychain_file_policy="reviewed_login",
                mode="foreground",
                foreground_timeout_seconds=self._loader.foreground_timeout_seconds,
            )
            stage = HeldGmailNativeStage(
                configuration=self._configuration,
                authority=authority,
                keychain_path=self._loader.keychain_path,
                keychain_file_policy="reviewed_login",
                host_guard=guard,
                stop_host=self._stop_host,
                bindings_factory=self._bindings_factory,
            )
            controller = GmailConnectionWeb(
                configuration=self._configuration,
                authority=authority,
                client_secret_loader=loader,
                transport=self._transport,
                stage_checked=stage,
                host_guard=guard,
                stop_host=self._stop_host,
                expected_subject=self._expected_subject,
            )
            self._verify(inputs, controller, registration, loader, stage)
            registration.attest(self._configuration, None)
            self._time()
            self._current()
            guard.ready()
            self._current()
            return controller
        except BaseException:
            self._halt()
            raise

    def _verify(
        self,
        inputs: NamedOwnerHostInputs,
        controller: GmailConnectionWeb,
        registration: ReviewedGmailRegistration,
        loader: GmailClientSecretLoader,
        stage: HeldGmailNativeStage,
    ) -> None:
        authority = controller._authority
        continuity = authority._continuity
        expected_guard = hmac.digest(
            inputs.session_key,
            b"zac-oauth-host-ready-v1\x00"
            + _json({"origin": inputs.origin, "client_id": inputs.client_id}),
            hashlib.sha256,
        )
        if self._guard is None:
            raise ValueError("actual concrete guard required")
        if (
            type(controller) is not GmailConnectionWeb
            or type(authority) is not OAuthTransactionAuthority
            or type(continuity) is not NamedSessionContinuity
            or type(registration) is not ReviewedGmailRegistration
            or type(loader) is not GmailClientSecretLoader
            or type(stage) is not HeldGmailNativeStage
            or type(self._guard) is not OAuthHostGuard
            or self._guard._directory != self._directory / "gmail-oauth-guard"
            or self._guard._lock_path != self._guard._directory / "oauth-host.lock"
            or self._guard._ready_path != self._guard._directory / "oauth-host.ready"
            or self._guard._halt_path != self._guard._directory / "oauth-host.halted"
            or not hmac.compare_digest(self._guard._ready_bytes, expected_guard)
            or authority._directory != self._directory / "gmail-oauth-transactions"
            or authority._backend is not registration
            or continuity._owner is not inputs.owner
            or continuity._sessions is not inputs.sessions
            or continuity._clock is not inputs.clock
            or registration.clock is not inputs.clock
            or registration.approved_generation != self._generation
            or registration.console_observed_at != self._observed
            or registration.review_expires_at != self._expires
            or registration.host_guard is not self._guard
            or registration.stop_host is not self._stop_host
            or controller._guard is not self._guard
            or controller._stop_host is not self._stop_host
            or controller._loader is not loader
            or controller._stage is not stage
            or stage._authority is not authority
            or stage._guard is not self._guard
            or stage._stop is not self._stop_host
            or stage._path != self._loader.keychain_path
            or stage._policy != "reviewed_login"
            or stage._factory is not self._bindings_factory
            or controller._expected_subject != self._expected_subject
            or loader.keychain_path != self._loader.keychain_path
            or loader.mode != "foreground"
            or loader.keychain_file_policy != "reviewed_login"
            or loader.foreground_timeout_seconds != self._loader.foreground_timeout_seconds
            or any(
                c.configuration_digest != self._configuration.configuration_digest
                for c in (
                    controller._configuration,
                    registration.configuration,
                    loader.configuration,
                    stage._configuration,
                )
            )
        ):
            raise ValueError("actual concrete foreground composition differs")

    @_closed
    def run(self) -> None:
        if (
            self._spent
            or self._running
            or threading.current_thread() is not threading.main_thread()
            or not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr))
        ):
            raise ValueError("one dedicated local interactive attempt required")
        self._spent, self._running = True, True
        try:
            self._current()
            self._time()
            self._current()

            async def view(principal: InterfacePrincipal) -> str:
                del principal
                return (
                    "<main><h1>Work Gmail setup</h1><p>This setup holds credentials for review. "
                    "Capture and sending remain inactive.</p>"
                    '<p><a href="/connections/gmail">Authorize Gmail read access</a></p></main>'
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
                gmail_factory=self._factory,
            ) as window:
                self._current()
                self._time()
                self._current()
                window.serve(server=self._server)
        finally:
            self._running = False
            self._stop_host()
