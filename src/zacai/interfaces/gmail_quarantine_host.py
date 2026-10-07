"""Unactivated foreground journal-only quarantine intent for held Gmail.

This host preserves the original owner, ledger and ready/halt markers. Its one
owner POST records an encrypted intent; it neither resolves the hold nor admits
OAuth, reads credentials, contacts providers, installs a connector or reads mail.
Actual startup reads require separate explicit approval. Private route closures
retain trusted objects after physical drain; no memory erasure is attested.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import sys
import threading
from collections.abc import Callable
from html import escape
from pathlib import Path

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import HTMLResponse, JSONResponse, Response

from zacai.connectors.connector_authority import _guard
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.gmail_quarantine_journal import (
    GmailQuarantineIntentReceipt,
    GmailQuarantineJournal,
    GmailQuarantinePreview,
)
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_host_guard import OAuthHostGuard
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_diagnostic_host import (
    GmailDiagnosticHostError,
    GmailDiagnosticHostFatal,
    GmailDiagnosticHostPlan,
    _closed,
    _ClosedRegistration,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.private_host import NamedOwnerHostInputs, PreparedOwnerHost
from zacai.interfaces.private_operator import PrivateOperatorMode, open_private_operator
from zacai.interfaces.private_startup import OwnerStartupConfiguration, OwnerStartupLoader
from zacai.interfaces.private_web import InterfacePrincipal, _cookie

GmailQuarantineHostError = GmailDiagnosticHostError
GmailQuarantineHostFatal = GmailDiagnosticHostFatal
_PATH = "/connections/gmail/quarantine"


class GmailQuarantineHostPlan(GmailDiagnosticHostPlan):
    """Inert fixed proposal; one foreground run and one owner journal POST."""

    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        owner_client_id: str,
        directory: Path,
        startup_loader: OwnerStartupLoader,
        clock: HostObservedClock,
        escrow_confirmed_by_operator: bool,
        action_generation: str,
        identities: IdentityProvider | None = None,
    ) -> None:
        if (
            type(action_generation) is not str
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", action_generation) is None
        ):
            raise GmailQuarantineHostError("fixed public quarantine action required")
        super().__init__(
            configuration=configuration,
            owner_client_id=owner_client_id,
            directory=directory,
            startup_loader=startup_loader,
            clock=clock,
            escrow_confirmed_by_operator=escrow_confirmed_by_operator,
            identities=identities,
        )
        self._action_generation = self._original_action_generation = action_generation
        self._post_lock = self._original_post_lock = threading.Lock()
        self._request_lock = self._original_request_lock = asyncio.Lock()
        self._post_spent = False
        self._journal: GmailQuarantineJournal | None = None
        self._original_journal: GmailQuarantineJournal | None = None
        self._preview: GmailQuarantinePreview | None = None
        self._original_preview: GmailQuarantinePreview | None = None
        self._preview_cookie_digest: bytes | None = None
        self._marker_guard: OAuthHostGuard | None = None
        self._original_marker_guard: OAuthHostGuard | None = None
        self._marker_context: tuple[object, ...] | None = None

    def __repr__(self) -> str:
        return "GmailQuarantineHostPlan()"

    def _current(self) -> None:
        super()._current()
        if (
            self._action_generation != self._original_action_generation
            or self._post_lock is not self._original_post_lock
            or self._request_lock is not self._original_request_lock
            or self._journal is not self._original_journal
            or self._marker_guard is not self._original_marker_guard
            or self._preview is not self._original_preview
        ):
            raise ValueError("original quarantine proposal required")

        guard = self._marker_guard
        if (
            guard is not None
            and (
                guard._directory,
                guard._lock_path,
                guard._ready_path,
                guard._halt_path,
                guard._ready_bytes,
                guard._halt_bytes,
            )
            != self._marker_context
        ):
            raise ValueError("original marker authentication required")

    @staticmethod
    def _marker_witness(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def _markers_current(self) -> None:
        guard = self._marker_guard
        if guard is None:
            raise ValueError("authenticated original ready and halt required")
        self._current()
        with guard._locked():
            for path, expected in (
                (guard._ready_path, guard._ready_bytes),
                (guard._halt_path, guard._halt_bytes),
            ):
                before = _guard(path)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    actual = os.fstat(fd)
                    if self._marker_witness(actual) != self._marker_witness(
                        before
                    ) or actual.st_size != len(expected):
                        raise ValueError("original marker identity required")
                    value = os.read(fd, len(expected) + 1)
                    if self._marker_witness(os.fstat(fd)) != self._marker_witness(
                        actual
                    ) or not hmac.compare_digest(value, expected):
                        raise ValueError("authenticated original marker required")
                finally:
                    os.close(fd)
                if self._marker_witness(_guard(path)) != self._marker_witness(before):
                    raise ValueError("original marker changed")
        self._current()

    @staticmethod
    def _namespace_current(journal: GmailQuarantineJournal) -> None:
        check: Callable[[], object] = journal.namespace_current
        if check() is not None:
            raise ValueError("original owned journal namespace required")

    def _files(self) -> tuple[tuple[int, ...], ...]:
        observed = super()._files()
        journal = self._journal
        if journal is None or self._witness is None:
            return observed
        if journal is not self._original_journal:
            raise ValueError("original owned journal namespace required")
        self._namespace_current(journal)
        # APFS may change a directory's link count for regular child names.
        # Only the pinned writer's exact owned-name transition permits this
        # one field to normalize; all other directories/fields remain original.
        ledger = observed[9]
        original = self._witness[9]
        return observed[:9] + (ledger[:4] + (original[4],),) + observed[10:]

    def _check(self) -> None:
        super()._check()
        if self._marker_guard is not None:
            self._markers_current()
            super()._check()
        if self._journal is not None:
            self._namespace_current(self._journal)

    def _journal_check(self) -> None:
        self._check()
        if not self._admitted():
            raise ValueError("actual active quarantine host required")

    @_closed
    def run(self) -> None:
        if self._spent:
            raise ValueError("one dedicated foreground attempt required")
        self._spent = True
        if threading.current_thread() is not threading.main_thread() or not all(
            stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)
        ):
            raise ValueError("one dedicated foreground attempt required")
        try:
            self._current()
            self._witness = self._files()  # original protected files before any lease/create
            if not self._witness[12]:
                raise ValueError("already-present halt marker required")
            ledger_directory = self._directory / "gmail-oauth-transactions"
            if {entry.name for entry in ledger_directory.iterdir()} != {
                "provider-oauth-transactions.lock",
                "provider-oauth-transactions.bin",
            }:
                raise ValueError("original unused journal namespace required")
            for name in ("gmail-quarantine-intent.bin", ".gmail-quarantine-intent.stage"):
                try:
                    os.lstat(ledger_directory / name)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("existing quarantine intent requires review")

            async def view(principal: InterfacePrincipal) -> str:
                del principal
                return (
                    "<h1>Review Gmail quarantine intent</h1>"
                    "<p>Gmail remains inactive. No authorization is retried.</p>"
                    '<p><a href="' + _PATH + '">Review journal-only intent</a></p>'
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
                prepared, startup = window._prepared, self._captured
                if (
                    type(prepared) is not PreparedOwnerHost
                    or type(startup) is not OwnerStartupConfiguration
                ):
                    raise ValueError("actual owner host required")
                guard = OAuthHostGuard(
                    self._directory / "gmail-oauth-guard",
                    key=startup.session_key,
                    origin=startup.origin,
                    client_id=startup.client_id,
                )
                self._marker_guard = self._original_marker_guard = guard
                self._marker_context = (
                    guard._directory,
                    guard._lock_path,
                    guard._ready_path,
                    guard._halt_path,
                    guard._ready_bytes,
                    guard._halt_bytes,
                )
                self._check()
                inputs = NamedOwnerHostInputs(
                    startup.origin,
                    startup.client_id,
                    startup.session_key,
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
                reconciliation = HeldGmailReconciliation(
                    authority=authority, configuration=self._configuration
                )
                journal = GmailQuarantineJournal(
                    authority=authority,
                    reconciliation=reconciliation,
                    configuration=self._configuration,
                    key=inputs.session_key,
                    preservation_check=self._journal_check,
                    stop=self._original[8],
                    action_generation=self._action_generation,
                )
                self._journal = self._original_journal = journal
                with self._admission_lock:
                    self._active = True

                @prepared.app.middleware("http")
                async def lifetime(
                    request: Request, call_next: RequestResponseEndpoint
                ) -> Response:
                    if not self._admitted():
                        return Response("Gmail quarantine unavailable", status_code=403)
                    try:
                        return await call_next(request)
                    except BaseException:  # noqa: BLE001,S110 - discard private middleware frames
                        pass
                    del request, call_next
                    self._latch()
                    raise GmailQuarantineHostFatal("Gmail quarantine host interrupted")

                def authenticated(request: Request) -> tuple[str, str]:
                    self._journal_check()
                    if (
                        type(request) is not Request
                        or request.url.scheme != "https"
                        or request.url.path != _PATH
                        or request.headers.getlist("host") != [authority._host]
                        or request.scope.get("query_string", b"")
                    ):
                        raise ValueError("actual private owner request required")
                    cookie = _cookie(request, "__Host-zac-session")
                    operation = continuity.for_cookie(cookie)
                    verified = operation.establish()
                    authority._scope(operation, verified.binding_digest)
                    session = inputs.sessions.peek_user(cookie, self._clock())
                    if session is None or session.identity != verified.principal.identity:
                        raise ValueError("actual owner session required")
                    authority._scope(operation, verified.binding_digest)
                    if operation.recheck(verified.binding_digest).principal != verified.principal:
                        raise ValueError("original owner required")
                    self._journal_check()
                    return cookie, session.csrf

                async def preview(request: Request) -> Response:
                    cookie = csrf = selected = cookie_digest = None
                    if not self._admitted():
                        return Response("Gmail quarantine unavailable", status_code=403)
                    try:
                        cookie, csrf = authenticated(request)
                        cookie_digest = hashlib.sha256(cookie.encode("ascii")).digest()
                        if self._preview is None:
                            selected = await run_in_threadpool(journal.preview, cookie=cookie)
                            self._journal_check()
                            if authenticated(request) != (cookie, csrf):
                                raise ValueError("original preview session required")
                            if type(selected) is not GmailQuarantinePreview:
                                raise ValueError("actual private preview required")
                            with self._post_lock:
                                if self._preview is not None or self._post_spent:
                                    raise ValueError("one original preview required")
                                self._preview = self._original_preview = selected
                                self._preview_cookie_digest = cookie_digest
                        elif cookie_digest != self._preview_cookie_digest:
                            raise ValueError("original preview session required")
                        self._journal_check()
                        if authenticated(request) != (cookie, csrf):
                            raise ValueError("original preview session required")
                        return HTMLResponse(
                            "<h1>Record Gmail quarantine intent</h1>"
                            "<p>This records one encrypted review intent for the held attempt. "
                            "It does not resolve the hold, retry Google consent, read credentials "
                            "or activate Gmail.</p>"
                            '<form method="post" action="' + _PATH + '">'
                            '<input type="hidden" name="csrf" value="'
                            + escape(csrf, quote=True)
                            + '"><input type="hidden" name="reviewed_configuration_digest" value="'
                            + self._digest
                            + '"><input type="hidden" name="action_generation" value="'
                            + escape(self._action_generation, quote=True)
                            + '"><button>Record quarantine intent once</button></form>'
                        )
                    except Exception:  # noqa: BLE001 - fixed denial after preservation audit
                        denied = True
                    except BaseException:  # noqa: BLE001 - interruption retires actual host
                        denied = False
                    if denied:
                        try:
                            self._preservation_check()
                        except BaseException:  # noqa: BLE001,S110
                            pass
                        else:
                            return Response("Gmail quarantine unavailable", status_code=403)
                    del request, cookie, csrf, selected, cookie_digest
                    self._latch()
                    raise GmailQuarantineHostFatal("Gmail quarantine host interrupted")

                async def record(request: Request) -> Response:
                    started = False
                    body = b""
                    receipt = None
                    cookie = csrf = selected = None
                    if not self._admitted():
                        return Response("Gmail quarantine unavailable", status_code=403)
                    try:
                        cookie, csrf = authenticated(request)
                        if request.headers.getlist("origin") != [
                            inputs.origin
                        ] or request.headers.getlist("content-type") != [
                            "application/x-www-form-urlencoded"
                        ]:
                            raise ValueError("actual owner form required")
                        async for chunk in request.stream():
                            if len(body) + len(chunk) > 512:
                                raise ValueError("bounded owner form required")
                            body += chunk
                        if authenticated(request) != (cookie, csrf):
                            raise ValueError("original owner required")
                        self._journal_check()
                        with self._post_lock:
                            if (
                                self._post_spent
                                or self._preview is None
                                or hashlib.sha256(cookie.encode("ascii")).digest()
                                != self._preview_cookie_digest
                            ):
                                raise ValueError("one original preview POST required")
                            self._post_spent = started = True
                            selected = self._preview
                        receipt = await run_in_threadpool(
                            journal.write_once, request=request, body=body, preview=selected
                        )
                        self._journal_check()
                        if authenticated(request) != (cookie, csrf):
                            raise ValueError("original owner required")
                        if (
                            type(receipt) is not GmailQuarantineIntentReceipt
                            or receipt.status != "quarantine_intent_recorded"
                            or any(
                                getattr(receipt, field) is not False
                                for field in (
                                    "installed",
                                    "quarantine_committed",
                                    "quarantine_authorized",
                                    "recovery_authorized",
                                    "original_actor_verified",
                                    "current_reviewer_verified",
                                    "source_subject_verified",
                                    "native_material_verified",
                                    "live_access_proven",
                                    "remote_grant_verified",
                                    "credential_authority",
                                    "processing_authorized",
                                    "execution_authorized",
                                )
                            )
                        ):
                            raise ValueError("actual journal-only receipt required")
                        response = JSONResponse(
                            {
                                "status": "quarantine_intent_recorded",
                                "recorded_only": True,
                                "quarantine_committed": False,
                                "quarantine_authorized": False,
                                "recovery_authorized": False,
                                "original_actor_verified": False,
                                "current_reviewer_verified": False,
                                "source_subject_verified": False,
                                "native_material_verified": False,
                                "live_access_proven": False,
                                "remote_grant_verified": False,
                                "installed": False,
                                "credential_authority": False,
                                "processing_authorized": False,
                                "execution_authorized": False,
                                "message": "Quarantine intent recorded. Gmail remains inactive; no new consent is authorized.",
                            }
                        )
                        with self._admission_lock:
                            self._active = False
                        self._original[8]()
                        return response
                    except Exception:  # noqa: BLE001 - no private request/journal frames
                        denied = not started
                    except BaseException:  # noqa: BLE001 - worker drains before lease release
                        denied = False
                    if denied:
                        try:
                            self._preservation_check()
                        except BaseException:  # noqa: BLE001,S110
                            pass
                        else:
                            return Response("Gmail quarantine unavailable", status_code=403)
                    del request, body, receipt, cookie, csrf, selected
                    self._latch()
                    raise GmailQuarantineHostFatal("Gmail quarantine host interrupted")

                @prepared.app.get(_PATH)
                async def serialized_preview(request: Request) -> Response:
                    try:
                        async with self._original_request_lock:
                            return await preview(request)
                    except BaseException:  # noqa: BLE001,S110 - retire before queued admission
                        pass
                    del request
                    self._latch()
                    raise GmailQuarantineHostFatal("Gmail quarantine host interrupted")

                @prepared.app.post(_PATH)
                async def serialized_record(request: Request) -> Response:
                    try:
                        async with self._original_request_lock:
                            return await record(request)
                    except BaseException:  # noqa: BLE001,S110 - retire before queued admission
                        pass
                    del request
                    self._latch()
                    raise GmailQuarantineHostFatal("Gmail quarantine host interrupted")

                self._preservation_check()
                try:
                    window.serve(server=self._server)
                finally:
                    with self._admission_lock:
                        self._active = False
                    self._preservation_check()
                    if self._fatal:
                        raise GmailQuarantineHostFatal("Gmail quarantine host requires review")
        finally:
            with self._admission_lock:
                self._active = False
            self._journal = self._original_journal = None
            self._preview = self._original_preview = None
            self._preview_cookie_digest = None
            self._marker_guard = self._original_marker_guard = None
            self._marker_context = None
            self._diagnostic = None
            self._captured = None
            try:
                self._original[8]()
            except BaseException:  # noqa: BLE001 - fixed fatal after original stop attempt
                self._fatal = True
            if self._fatal:
                raise GmailQuarantineHostFatal("Gmail quarantine host requires review")
