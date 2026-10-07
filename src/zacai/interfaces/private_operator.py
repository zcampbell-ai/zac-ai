"""Trusted foreground private-host orchestration; no CLI or automatic runtime.

Opening a window is an explicit LOCAL operator action, never an agent/API call.
Escrow confirmation is an operator attestation, not proof of independently
recovered credentials or readiness. Default startup reads only existing fixed
Keychain entries; tests inject invented configuration. serve() is a separate
explicit action and does not configure Tailscale/TLS or publish an endpoint.

Use a dedicated foreground process. Enrollment and owner mode share a retained
0600 flock file in the same reviewed 0700 directory. Never unlink the lease.
Locks coordinate cooperating operators, not malicious same-UID code, alternate
storage roots, filesystem rollback or a direct factory that bypasses this runner.
Trusted parents/storage and exclusion of agents remain deployment requirements.

Stop foreground enrollment serving before local pairing/identity confirmation;
then close the setup window before opening owner mode. Default enrollment is fixed
BRAINSTORM/CONFIDENTIAL. The closed opt-in
PERSONAL/HIGHLY_RESTRICTED mode requires a newly created, separate host directory
and its own exact local confirmation. No inferred email/domain,
admin, automatic PERSONAL permission, source release, model or execution authority.

Python logging is globally suppressed while this dedicated foreground server
runs, including third-party OAuth/HTTP logs. Canonical audit/state writes remain
separate. External traceback-local capture/telemetry/native proxy logging must
also be disabled before real release; Python suppression cannot control them.
Forced ASGI shutdown can abandon AnyIO worker jobs. The foreground runner keeps
signal/log suppression and the mode lease until every newly created thread exits,
without a timeout; persistent or unjoinable native/dummy threads hold shutdown rather than
releasing early. Pre-existing background threads are rejected. This does not
protect against SIGKILL/process crashes (which terminate the process/threads);
interrupted canonical writes require normal recovery/reconciliation afterward.
No raw diagnostics/credentials are printed, logged or placed in argv/environment.
"""

from __future__ import annotations

import fcntl
import logging
import os
import secrets
import signal
import stat
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from fastapi import FastAPI

from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.owner_enrollment import PendingOwner
from zacai.interfaces.private_host import (
    NamedOwnerHostFactory,
    PreparedEnrollmentHost,
    PreparedOwnerHost,
    prepare_enrollment_host,
    prepare_owner_host,
)
from zacai.interfaces.private_startup import (
    OwnerStartupConfiguration,
    _configuration,
    load_owner_startup,
)
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

if TYPE_CHECKING:
    from zacai.interfaces.work_choice_web import WorkChoiceWeb

_HOST = "127.0.0.1"
_PORT = 8766  # Separate from the D025 health service on 8000.
_CONFIRMATION = "CONFIRM BRAINSTORM / CONFIDENTIAL"
_SCOPE = (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
_PERSONAL_CONFIRMATION = "CONFIRM PERSONAL / HIGHLY_RESTRICTED"
_PERSONAL_SCOPE = (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),)


class PrivateOperatorError(RuntimeError):
    """Closed local diagnostic; never include secret/path/identity/backend values."""


class PrivateOperatorMode(str, Enum):
    ENROLLMENT = "enrollment"
    PERSONAL_ENROLLMENT = "personal-enrollment"
    OWNER = "owner"


class StartupLoader(Protocol):
    def __call__(self, *, client_id: str, origin: str) -> OwnerStartupConfiguration: ...


def _serve(app: FastAPI) -> None:
    import uvicorn

    uvicorn.run(
        app,
        host=_HOST,
        port=_PORT,
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


def _drain_threads(baseline: set[threading.Thread]) -> None:
    """Dedicated process: join all new threads, including abandoned AnyIO work.

    Thread objects avoid reused identifier ambiguity. Loop closure normally queues
    AnyIO stop after the running job; no private AnyIO API/hook is required. A
    persistent unexpected thread holds indefinitely. Signals remain suppressed.
    """

    def pause() -> None:
        try:
            time.sleep(0.1)
        except BaseException:  # noqa: BLE001,S110 - never escape a fail-closed drain.
            pass

    while True:
        try:
            active = [t for t in threading.enumerate() if t not in baseline and t.is_alive()]
            if not active:
                return
            for worker in active:
                try:
                    worker.join(timeout=0.1)
                except BaseException:  # noqa: BLE001 - dummy/native join failures remain holds.
                    pause()
        except BaseException:  # noqa: BLE001 - unavailable inventory is not proof of stopped work.
            pause()


def _lease(directory: Path) -> int:
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
    ):
        raise ValueError("unsafe operator directory")
    path = directory / "private-mode.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        opened, current = os.fstat(fd), path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError("unsafe operator lease")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _fresh_personal_directory(directory: Path) -> tuple[int, int]:
    """Atomic fresh leaf admission, not an owner or filesystem sandbox proof.

    Existing directories are never reusable, including empty or previous failed
    setup directories. The trusted host supplies a separate reviewed location;
    no saved enrollment file is read to infer or expand another grant.
    """
    if directory.parent.resolve(strict=True) != directory.parent:
        raise ValueError("noncanonical personal setup parent")
    directory.mkdir(mode=0o700, exist_ok=False)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
    ):
        raise ValueError("unsafe fresh personal directory")
    return info.st_dev, info.st_ino


def _personal_directory_unchanged(
    directory: Path, pin: tuple[int, int], *, fresh: bool = True
) -> None:
    info = directory.lstat()
    if (
        directory.resolve(strict=True) != directory
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
        or (info.st_dev, info.st_ino) != pin
        or (fresh and {entry.name for entry in directory.iterdir()} != {"private-mode.lock"})
    ):
        raise ValueError("fresh personal setup directory changed")


def _personal_clock(
    directory: Path, pin: tuple[int, int], clock: Callable[[], datetime]
) -> Callable[[], datetime]:
    """Recheck the same admitted directory across every trusted clock call.

    Before the first enrollment clock returns, no owner/session stores may yet
    exist. Later legitimate store creation is allowed, but changing directory
    identity, owner, mode or canonical path always holds. This does not undo any
    filesystem side effect performed by the trusted callback itself.
    """
    first = True

    def guarded() -> datetime:
        nonlocal first
        _personal_directory_unchanged(directory, pin, fresh=first)
        observed = clock()
        _personal_directory_unchanged(directory, pin, fresh=first)
        first = False
        return observed

    return guarded


class PrivateOperatorWindow:
    """Host-only lifecycle handle; retaining it after close grants nothing."""

    def __init__(
        self,
        prepared: PreparedOwnerHost | PreparedEnrollmentHost,
        *,
        mode: PrivateOperatorMode,
        origin: str,
        clock: Callable[[], datetime],
    ) -> None:
        self._prepared, self._mode, self._origin, self._clock = prepared, mode, origin, clock
        self._active, self._serving, self._served = True, False, False

    def __repr__(self) -> str:
        return "PrivateOperatorWindow()"

    @property
    def private_interface_ready(self) -> Literal[False]:
        return False

    @property
    def credential_recovery_verified(self) -> Literal[False]:
        return False

    @property
    def source_access_authorized(self) -> Literal[False]:
        return False

    def _require(self) -> None:
        if (
            threading.current_thread() is not threading.main_thread()
            or not self._active
            or self._serving
        ):
            raise ValueError("operator unavailable")

    def serve(self, *, server: Callable[[FastAPI], None] = _serve) -> None:
        """Explicit foreground action; injected server is trusted test-only glue.

        Server MUST return only after request/background protection work stops.
        Native Uvicorn waits without a graceful-shutdown timeout. No reload or
        worker subprocesses may outlive the mode lease. No auto-restart occurs.
        """
        okay = False
        try:
            self._require()
            if self._served or not callable(server):
                raise ValueError("operator already served")
            baseline = set(threading.enumerate())
            if baseline != {threading.main_thread()}:
                raise ValueError("dedicated foreground process required")
            handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            if any(handler is None for handler in handlers.values()):
                raise ValueError("unknown foreground signal handler")
            self._served, self._serving = True, True
            disabled = logging.root.manager.disable
            try:
                logging.disable(sys.maxsize)
                try:
                    # Native Uvicorn installs its handlers during serving and
                    # restores these ignored handlers on return. Replayed second
                    # interrupts cannot terminate the ensuing private worker drain.
                    for sig in handlers:
                        signal.signal(sig, signal.SIG_IGN)
                    server(self._prepared.app)
                finally:
                    for sig in handlers:
                        try:
                            signal.signal(sig, signal.SIG_IGN)
                        except BaseException:  # noqa: BLE001,S110 - never skip actual drain on suppression failure.
                            pass
                    _drain_threads(baseline)
                    # Uvicorn can report lifespan.shutdown.failed only to its
                    # logger and return normally. Repeat the actual paired
                    # lifecycle gate while lease/log/signal protection is held.
                    if (
                        type(self._prepared) is PreparedOwnerHost
                        and self._prepared.named is not None
                    ):
                        from zacai.interfaces.named_worker_lifecycle import (
                            NamedWorkerRegistry,
                            ThreadBoundNamedAskPipeline,
                        )

                        pair = self._prepared.named
                        if type(pair.workers) is not NamedWorkerRegistry:
                            raise ValueError("actual worker registry required")
                        pipeline = pair.controller._pipeline
                        if pipeline is None:
                            pair.workers.close_and_drain()
                        else:
                            if (
                                type(pipeline) is not ThreadBoundNamedAskPipeline
                                or pipeline._workers is not pair.workers
                                or pipeline._store is not pair.controller._store
                            ):
                                raise ValueError("actual paired worker lifecycle required")
                            pipeline.close_and_retire()
                okay = True
            finally:
                # All private worker jobs are now finished. Restore logging/state
                # before SIGINT last, so an immediate subsequent interrupt cannot
                # skip restoration or release the lease with a worker still active.
                try:
                    logging.disable(disabled)
                finally:
                    self._serving = False
                    for sig in reversed(handlers):
                        handler = handlers[sig]
                        assert handler is not None
                        signal.signal(sig, handler)
        except BaseException:  # noqa: BLE001 - sanitize runtime/interrupt diagnostics after drain.
            okay = False
            self._active = False
        if not okay:
            raise PrivateOperatorError("private operator serving unavailable; stop and reconcile")

    def pending_owner(self) -> PendingOwner:
        """Explicit local inspection only; never serialize/log candidate identity."""
        result: PendingOwner | None = None
        try:
            self._require()
            if type(self._prepared) is not PreparedEnrollmentHost or not self._served:
                raise ValueError("not stopped enrollment")
            result = self._prepared.enrollment.pending(self._clock())
        except Exception:  # noqa: BLE001,S110
            pass
        except BaseException:  # noqa: BLE001 - interrupts terminate the local window.
            self._active = False
        if result is None:
            raise PrivateOperatorError("private operator enrollment unavailable")
        return result

    def confirm_owner(
        self,
        *,
        pairing_code: str,
        expected_identity: Identity,
        confirmation: str,
    ) -> OwnerGrant:
        """Local explicit exact pairing+issuer/sub confirmation, fixed scopes only."""
        result: OwnerGrant | None = None
        try:
            pending = self.pending_owner()
            personal = self._mode == PrivateOperatorMode.PERSONAL_ENROLLMENT
            if (
                type(self._prepared) is not PreparedEnrollmentHost
                or type(expected_identity) is not Identity
                or expected_identity != pending.identity
                or type(pairing_code) is not str
                or not secrets.compare_digest(pairing_code, pending.pairing_code)
                or confirmation != (_PERSONAL_CONFIRMATION if personal else _CONFIRMATION)
            ):
                raise ValueError("local confirmation mismatch")
            self._active = False  # No serving/retry after confirmation or persistence failure.
            result = self._prepared.owners.confirm_and_save(
                enrollment=self._prepared.enrollment,
                candidate_id=pending.candidate_id,
                pairing_code=pairing_code,
                origin=self._origin,
                identity=expected_identity,
                scopes=_PERSONAL_SCOPE if personal else _SCOPE,
                now=self._clock(),
            )
        except BaseException:  # noqa: BLE001 - no pairing/identity/backend or interrupt diagnostic
            self._active = False
        if result is None:
            raise PrivateOperatorError(
                "private operator confirmation unavailable; stop and reconcile"
            )
        return result

    def revoke_owner(self) -> None:
        okay = False
        try:
            self._require()
            if type(self._prepared) is not PreparedOwnerHost:
                raise ValueError("not owner mode")
            self._active = False
            self._prepared.revoke_owner()
            okay = True
        except BaseException:  # noqa: BLE001
            self._active = False
        if not okay:
            raise PrivateOperatorError(
                "private operator revocation unavailable; stop and reconcile"
            )

    def _close(self) -> None:
        self._active = False
        if type(self._prepared) is PreparedEnrollmentHost:
            self._prepared.enrollment.cancel()


@contextmanager
def open_private_operator(
    *,
    mode: PrivateOperatorMode,
    client_id: str,
    origin: str,
    directory: Path,
    escrow_confirmed_by_operator: bool,
    view: Callable[[InterfacePrincipal], Awaitable[str]] | None = None,
    work_choices: WorkChoiceWeb | None = None,
    named_factory: NamedOwnerHostFactory | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    startup_loader: StartupLoader = load_owner_startup,
    identities: IdentityProvider | None = None,
) -> Iterator[PrivateOperatorWindow]:
    """Explicit trusted local window, not a credential/readiness approval receipt.

    Reviewed directory must be shared by all cooperating modes. Validate public
    inputs and acquire the exclusive lease before any startup credential load.
    Test injections are host-controlled, never browser arguments or agent APIs.
    """
    fd: int | None = None
    window: PrivateOperatorWindow | None = None
    prepared: PreparedOwnerHost | PreparedEnrollmentHost | None = None
    personal_pin: tuple[int, int] | None = None
    host_clock = clock
    startup_threads = set(threading.enumerate()) | {threading.current_thread()}
    try:
        _configuration(client_id, origin)
        if (
            threading.current_thread() is not threading.main_thread()
            or type(mode) is not PrivateOperatorMode
            or type(escrow_confirmed_by_operator) is not bool
            or not escrow_confirmed_by_operator
            or not isinstance(directory, Path)
            or not directory.is_absolute()
            or not callable(clock)
            or not callable(startup_loader)
            or (mode == PrivateOperatorMode.OWNER and not callable(view))
            or (
                mode in (PrivateOperatorMode.ENROLLMENT, PrivateOperatorMode.PERSONAL_ENROLLMENT)
                and (view is not None or work_choices is not None or named_factory is not None)
            )
        ):
            raise ValueError("invalid operator inputs")
        if mode == PrivateOperatorMode.PERSONAL_ENROLLMENT:
            personal_pin = _fresh_personal_directory(directory)
        fd = _lease(directory)
        if personal_pin is not None:
            _personal_directory_unchanged(directory, personal_pin)
        configuration = startup_loader(client_id=client_id, origin=origin)
        if (
            type(configuration) is not OwnerStartupConfiguration
            or configuration.client_id != client_id
            or configuration.origin != origin
        ):
            raise ValueError("startup configuration changed")
        if personal_pin is not None:
            _personal_directory_unchanged(directory, personal_pin)
            host_clock = _personal_clock(directory, personal_pin, clock)
        if mode in (PrivateOperatorMode.ENROLLMENT, PrivateOperatorMode.PERSONAL_ENROLLMENT):
            prepared = prepare_enrollment_host(
                configuration=configuration,
                directory=directory,
                clock=host_clock,
                identities=identities,
            )
        else:
            assert view is not None
            prepared = prepare_owner_host(
                configuration=configuration,
                directory=directory,
                view=view,
                clock=clock,
                identities=identities,
                work_choices=work_choices,
                named_factory=named_factory,
            )
        if type(prepared) is PreparedOwnerHost and prepared.named is not None:
            # Actual retained flock is acquired above and not released until
            # final physical thread drain. Reconcile before app exposure only.
            if any(t is not threading.main_thread() for t in threading.enumerate()):
                raise ValueError("dedicated startup process required")
            workers = prepared.named.workers
            with workers._lock:
                if workers._closed or workers._entries or workers._reservations:
                    raise ValueError("fresh unstarted worker registry required")
                prepared.named.controller._store._reconcile_expired_for_owner(
                    prepared.owners.load()
                )
        window = PrivateOperatorWindow(prepared, mode=mode, origin=origin, clock=host_clock)
    except BaseException:  # noqa: BLE001,S110 - close acquired lease on startup interrupts.
        pass
    if window is None:
        try:
            if type(prepared) is PreparedEnrollmentHost:
                prepared.enrollment.cancel()
        except BaseException:  # noqa: BLE001,S110 - sanitize cleanup; always release acquired lease.
            pass
        finally:
            if fd is not None:
                # Even failed construction may have started native private work.
                # Preserve unrelated pre-existing threads, but never release the
                # actual mode lease while a newly created worker is alive.
                disabled = logging.root.manager.disable
                handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
                try:
                    try:
                        logging.disable(sys.maxsize)
                        for sig, handler in handlers.items():
                            if handler is not None:
                                try:
                                    signal.signal(sig, signal.SIG_IGN)
                                except BaseException:  # noqa: BLE001,S110 - finish actual drain before sanitized failure.
                                    pass
                    finally:
                        _drain_threads(startup_threads)
                    os.close(fd)
                    fd = None
                finally:
                    try:
                        logging.disable(disabled)
                    finally:
                        for sig in reversed(handlers):
                            handler = handlers[sig]
                            if handler is not None:
                                try:
                                    signal.signal(sig, handler)
                                except BaseException:  # noqa: BLE001,S110 - restore other known handlers.
                                    pass
        raise PrivateOperatorError("private operator window unavailable")
    try:
        yield window
    finally:
        try:
            window._close()
        finally:
            assert fd is not None
            os.close(fd)  # Releases flock; do not unlink retained lease inode.
