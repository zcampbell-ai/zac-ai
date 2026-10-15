"""Owned Slack routes only; default foreground/middleware composition is pending.

Construction/mounting is inert. Trusted assembly supplies real owner continuity
and preservation/stop callbacks. No retained operator proof, native storage,
gateway, cold load, source capture or shared CSP exception is supplied here.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import anyio
from fastapi import FastAPI
from pydantic import SecretStr
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import Connection, _direct_tls
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.connectors.slack_owner_admission import SlackFreshAdmission, SlackOwnerAdmission
from zacai.connectors.slack_registration import _config, _issue_reviewed_slack_registration
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.private_web import _cookie
from zacai.policy import DataClassification, TrustBoundary

_CONFIRMATION = "AUTHORIZE FRESH WORK SLACK IDENTITY ONLY"


class SlackConnectionError(ValueError):
    """Fixed stopped owned route; no diagnostic callback prose."""


class SlackConnectionCancelled(BaseException):
    """Fixed cancelled owned route; no private callback frames."""


@dataclass(frozen=True, repr=False)
class _Preview:
    operation: NamedSessionOperation
    view: tuple[Any, ...]
    deadline: datetime
    action: str


class SlackConnectionWeb:
    def __init__(
        self,
        *,
        continuity: NamedSessionContinuity,
        configuration: OAuthConfiguration,
        expected_user_id: str,
        rotation: SlackRotation,
        approved_generation: str,
        console_observed_at: datetime,
        review_expires_at: datetime,
        directory: Path,
        key: bytes,
        client_secret_loader: Callable[[OAuthConfiguration], SecretStr],
        preservation_check: Callable[[], None],
        stop_host: Callable[[], None],
        connection_factory: Callable[[str], Connection] = _direct_tls,
        network_clock: Callable[[], float],
    ) -> None:
        _config(configuration)
        if (
            type(continuity) is not NamedSessionContinuity
            or json.loads(continuity._context)["origin"] != configuration.private_origin
            or type(expected_user_id) is not str
            or re.fullmatch(r"[UW][A-Z0-9]{8,20}", expected_user_id) is None
            or type(rotation) is not SlackRotation
            or type(approved_generation) is not str
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", approved_generation) is None
            or type(console_observed_at) is not datetime
            or console_observed_at.tzinfo is not UTC
            or type(review_expires_at) is not datetime
            or review_expires_at.tzinfo is not UTC
            or not timedelta(0) < review_expires_at - console_observed_at <= timedelta(hours=2)
            or not isinstance(directory, Path)
            or not directory.is_absolute()
            or type(key) is not bytes
            or len(key) != 32
            or not all(
                callable(x)
                for x in (
                    client_secret_loader,
                    preservation_check,
                    stop_host,
                    connection_factory,
                    network_clock,
                )
            )
        ):
            raise ValueError("exact trusted Slack host inputs required")
        self._continuity, self._configuration = continuity, configuration
        self._user, self._rotation, self._generation = (
            expected_user_id,
            rotation,
            approved_generation,
        )
        self._console, self._review_expires = console_observed_at, review_expires_at
        self._directory, self._key = directory, key
        self._loader, self._preserve, self._stop = (
            client_secret_loader,
            preservation_check,
            stop_host,
        )
        self._factory, self._network_clock = connection_factory, network_clock
        self._pins = self._settings()
        self._preview: _Preview | None = None
        self._authority: OAuthTransactionAuthority | None = None
        self._admission: SlackOwnerAdmission | None = None
        self._fresh: SlackFreshAdmission | None = None
        self._directory_inode: tuple[int, int] | None = None
        self._spent = self._callback_done = self._closing = self._failed = self._mounted = False
        self._phase = "not_started"
        self._last_operation = "not_started"
        self._lock = anyio.Lock()
        self._worker_lock = threading.RLock()

    def _settings(self) -> tuple[Any, ...]:
        c = self._continuity
        return (
            c,
            c._sessions,
            c._owner,
            c._clock,
            c._context,
            c._key,
            self._configuration,
            self._configuration.configuration_digest,
            self._user,
            self._rotation,
            self._generation,
            self._console,
            self._review_expires,
            self._directory,
            self._key,
            self._loader,
            self._preserve,
            self._stop,
            self._factory,
            self._network_clock,
        )

    def _original(self) -> None:
        if self._settings() != self._pins or self._closing or self._failed:
            raise ValueError("original active Slack host required")
        if self._directory_inode is not None:
            info = self._directory.lstat()
            if (info.st_dev, info.st_ino) != self._directory_inode:
                raise ValueError("original owned OAuth directory required")

    def _preserve_action(self) -> None:
        """Local current callback; never acquire the OAuth ledger in reverse."""
        self._original()
        check: Callable[[], object] = self._preserve
        if check() is not None:
            raise ValueError("original host preservation required")
        preview = self._preview
        if preview is None or self._continuity._clock() >= preview.deadline:
            raise ValueError("original displayed action expired")
        self._original()

    def _view(
        self, request: Request, *, callback: bool = False
    ) -> tuple[NamedSessionOperation, tuple[Any, ...]]:
        self._original()
        origin = self._configuration.private_origin
        if (
            request.url.scheme != "https"
            or request.headers.getlist("host") != [urlsplit(origin).netloc]
            or (request.url.query and not callback)
        ):
            raise ValueError("fixed private host and query required")
        cookie = _cookie(request, "__Host-zac-session")
        operation = self._continuity.for_cookie(cookie)
        verified = operation.establish()
        if not any(
            s.boundary is TrustBoundary.BRAINSTORM
            and DataClassification.HIGHLY_RESTRICTED in s.classifications
            for s in verified.principal.scopes
        ):
            raise ValueError("actual restricted owner required")
        session = self._continuity._sessions.peek_user(cookie, self._continuity._clock())
        if session is None:
            raise ValueError("original session required")
        terminal = operation.recheck(verified.binding_digest)
        now = self._continuity._clock()
        deadline = min(terminal.effective_expires_at, self._review_expires)
        if terminal.principal != verified.principal or not self._console <= now < deadline:
            raise ValueError("terminal current owner required")
        self._original()
        view = (
            cookie,
            terminal.binding_digest,
            terminal.principal,
            session.issued_at,
            session.expires_at,
            session.csrf,
            terminal.effective_expires_at,
        )
        return operation, view

    def _same_preview(self, view: tuple[Any, ...]) -> _Preview:
        preview = self._preview
        if preview is None or view != preview.view or self._continuity._clock() >= preview.deadline:
            raise ValueError("original displayed actor and deadline required")
        return preview

    def _page(self, request: Request) -> str:
        operation, view = self._view(request)
        if self._preview is None:
            self._preview = _Preview(
                operation, view, min(view[-1], self._review_expires), secrets.token_urlsafe(24)
            )
            self._phase = "preview"
        preview = self._same_preview(view)
        if self._spent:
            return (
                "<p>Fresh Slack exchange checked. Credentials are not saved or installed.</p>"
                if self._callback_done
                else "<p>Slack consent is pending. This action cannot be repeated.</p>"
            )
        c = self._configuration
        public = (
            f"App: {escape(c.registration_id)}; client: {escape(c.client_id)}; "
            f"workspace: {escape(c.slack_team_id or '')}; user: {escape(self._user)}; "
            f"rotation: {escape(self._rotation.value)}; scopes: {escape(', '.join(sorted(c.scopes)))}"
        )
        fields = {
            "csrf": view[5],
            "reviewed_configuration_digest": c.configuration_digest,
            "action_generation": preview.action,
        }
        hidden = "".join(
            f'<input type="hidden" name="{name}" value="{escape(value)}">'
            for name, value in fields.items()
        )
        return (
            f"<p>{public}</p><p>One fresh consent and identity-only checks. No messages or saving in this stage.</p>"
            f'<form method="post" action="/connections/slack/begin">{hidden}'
            f'<label><input type="checkbox" name="confirmation" value="{_CONFIRMATION}">Authorize this one action</label>'
            '<button type="submit">Continue to Slack</button></form>'
        )

    def _begin(self, request: Request, body: bytes) -> str:
        _, view = self._view(request)
        preview = self._same_preview(view)
        if (
            request.method != "POST"
            or request.url.path != "/connections/slack/begin"
            or request.headers.getlist("origin") != [self._configuration.private_origin]
            or request.headers.get("content-type", "").split(";", 1)[0]
            != "application/x-www-form-urlencoded"
            or type(body) is not bytes
            or not 1 <= len(body) <= 2048
        ):
            raise ValueError("closed owner POST required")
        pairs = parse_qsl(
            body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=4
        )
        fields = dict(pairs)
        if (
            len(fields) != len(pairs)
            or set(fields)
            != {"csrf", "reviewed_configuration_digest", "action_generation", "confirmation"}
            or fields["csrf"] != view[5]
            or fields["reviewed_configuration_digest"] != self._configuration.configuration_digest
            or fields["action_generation"] != preview.action
            or fields["confirmation"] != _CONFIRMATION
        ):
            raise ValueError("same actual owner and reviewed form required")
        if self._spent:
            raise ValueError("one action already spent")
        self._spent = True
        self._phase = "begin_entered"
        self._last_operation = "owner_action"
        self._preserve_action()
        registration = _issue_reviewed_slack_registration(
            configuration=self._configuration,
            expected_user_id=self._user,
            rotation=self._rotation,
            approved_generation=self._generation,
            console_observed_at=self._console,
            review_expires_at=min(self._review_expires, preview.deadline),
            operation=preview.operation,
            preservation_check=self._preserve_action,
        )
        if self._directory.resolve() != self._directory:
            raise ValueError("canonical new OAuth namespace required")
        self._last_operation = "namespace_birth"
        os.mkdir(self._directory, 0o700)  # exclusive birth; no existing namespace/reset fallback
        info = self._directory.lstat()
        self._directory_inode = (info.st_dev, info.st_ino)
        authority = OAuthTransactionAuthority(
            self._directory,
            key=self._key,
            continuity=self._continuity,
            registration_backend=registration,
        )
        self._authority = authority
        authority.initialize()
        admission = SlackOwnerAdmission(
            authority=authority,
            registration=registration,
            connection_factory=self._factory,
            network_clock=self._network_clock,
            stop_host=self._stop,
        )
        self._admission = admission
        self._last_operation = "state_begin"
        consent = admission.begin(
            request=request,
            csrf=fields["csrf"],
            reviewed_configuration_digest=fields["reviewed_configuration_digest"],
        )
        self._phase = "consent_returned"
        return consent.url.get_secret_value()

    def _callback(self, request: Request) -> None:
        _, view = self._view(request, callback=True)
        self._same_preview(view)
        admission = self._admission
        if admission is None or self._callback_done:
            raise ValueError("one original callback required")
        self._phase = "callback_entered"
        self._last_operation = "fresh_exchange_identity"
        fresh = admission.consume_callback(request=request, client_secret_loader=self._loader)
        if type(fresh) is not SlackFreshAdmission:
            raise ValueError("no checked fresh result")
        self._fresh = fresh
        self._callback_done = True
        self._phase = "fresh_exchange_uninstalled"

    @staticmethod
    def _priority(
        first: type[BaseException] | None, later: type[BaseException] | None
    ) -> type[BaseException] | None:
        if first is None or (first is SlackConnectionError and later is SlackConnectionCancelled):
            return later
        return first

    def _stop_safe(self) -> type[BaseException] | None:
        try:
            self._stop()
            return None
        except Exception:  # noqa: BLE001 - fixed lifecycle category only
            return SlackConnectionError
        except BaseException:  # noqa: BLE001 - interruption cannot be downgraded
            return SlackConnectionCancelled

    def _retire(self) -> type[BaseException] | None:
        admission = self._admission
        kind: type[BaseException] | None = None
        if admission is not None and admission._operation is not None:
            try:
                admission._operation.hold()
            except BaseException as error:  # noqa: BLE001 - retain uncertainty; never reset
                admission._operation.halt_unconfirmed()
                self._phase = "cleanup_unconfirmed"
                self._failed = True
                kind = (
                    SlackConnectionError
                    if isinstance(error, Exception)
                    else SlackConnectionCancelled
                )
        self._fresh = None
        return kind

    def close(self) -> None:
        """Latch immediately; active worker alone holds after its physical return."""
        self._closing = True
        kind = self._stop_safe()
        if kind is not None:
            self._failed = True
            self._phase = "cleanup_unconfirmed"
        if self._worker_lock.acquire(blocking=False):
            try:
                kind = self._priority(kind, self._retire())
            finally:
                self._worker_lock.release()
        if kind is not None:
            raise kind("Slack owned route cleanup unavailable")

    def _work(self, method: Callable[[], Any]) -> Any:
        with self._worker_lock:
            primary: BaseException | None = None
            result: Any = None
            try:
                self._original()
                result = method()
            except BaseException as error:  # noqa: BLE001 - spent effects remain held
                primary = error
                if self._spent:
                    self._failed = True
                    self._phase = "held"
            kind: type[BaseException] | None = None
            if self._failed or self._closing:
                kind = self._priority(self._retire(), self._stop_safe())
            if primary is not None:
                if isinstance(primary, Exception) and kind is SlackConnectionCancelled:
                    raise SlackConnectionCancelled("Slack owned worker cleanup cancelled")
                raise primary
            if kind is not None:
                raise kind("Slack owned worker cleanup unavailable")
            return result

    def _denied_response(self, request: Request, *, callback: bool = False) -> Response:
        """Read-only current actor proof for fixed stopped diagnostics, never effects."""
        preview = self._preview
        try:
            if (
                preview is None
                or self._settings() != self._pins
                or request.url.scheme != "https"
                or request.headers.getlist("host")
                != [urlsplit(self._configuration.private_origin).netloc]
                or (request.url.query and not callback)
                or (
                    request.method == "POST"
                    and request.headers.getlist("origin") != [self._configuration.private_origin]
                )
            ):
                raise ValueError("original diagnostic actor required")
            cookie = _cookie(request, "__Host-zac-session")
            verified = self._continuity.for_cookie(cookie).recheck(preview.view[1])
            session = self._continuity._sessions.peek_user(cookie, self._continuity._clock())
            final = self._continuity.for_cookie(cookie).recheck(preview.view[1])
            terminal = self._continuity._clock()
            if (
                session is None
                or (
                    cookie,
                    final.binding_digest,
                    final.principal,
                    session.issued_at,
                    session.expires_at,
                    session.csrf,
                    final.effective_expires_at,
                )
                != preview.view
                or final.principal != verified.principal
                or terminal >= preview.deadline
            ):
                raise ValueError("same current diagnostic actor required")
            label = {
                "not_started": "Checking owner sign-in",
                "owner_action": "Checking owner sign-in",
                "namespace_birth": "Preparing setup storage",
                "state_begin": "Starting Slack consent",
                "fresh_exchange_identity": "Verifying Slack account",
                "publication_current": "Checking final sign-in",
            }.get(self._last_operation, "Checking setup")
            return HTMLResponse(
                f"Slack setup stopped during {label}. Outcome remains unknown; credentials are not saved or installed.",
                status_code=403,
            )
        except Exception:  # noqa: BLE001 - anonymous/revoked actor gets no prior finding
            return HTMLResponse("Slack setup unavailable", status_code=403)
        except BaseException:  # noqa: BLE001, S110 - discard private diagnostic frames
            pass
        try:
            self.close()
        except BaseException:  # noqa: BLE001, S110 - retain fixed primary interruption
            pass
        del request
        raise SlackConnectionCancelled("Slack owned diagnostic cancelled")

    def mount(self, app: FastAPI) -> None:
        if type(app) is not FastAPI or self._mounted:
            raise ValueError("one actual app mount required")
        self._mounted = True

        @app.get("/connections/slack")
        async def page(request: Request) -> Response:
            async with self._lock:
                fatal = False
                try:
                    _, before = self._view(request)
                    html = await run_in_threadpool(self._work, lambda: self._page(request))
                    self._last_operation = "publication_current"
                    _, after = self._view(request)
                    if before != after:
                        raise ValueError("same terminal actor required")
                    self._same_preview(after)
                    return HTMLResponse(html)
                except Exception:  # noqa: BLE001, S110 - fixed output; no exception logging
                    pass
                except BaseException:  # noqa: BLE001 - discard private worker frames
                    fatal = True
                if fatal:
                    try:
                        self.close()
                    except BaseException:  # noqa: BLE001, S110 - fixed primary cancellation retained
                        pass
                    del request
                    raise SlackConnectionCancelled("Slack owned route cancelled")
                return self._denied_response(request)

        @app.post("/connections/slack/begin")
        async def begin(request: Request) -> Response:
            async with self._lock:
                if (
                    request.headers.getlist("origin") != [self._configuration.private_origin]
                    or request.url.query
                ):
                    return HTMLResponse("Slack setup unavailable", status_code=403)
                try:
                    _, before = self._view(request)
                    if self._spent:
                        self._same_preview(before)
                        return Response("Slack action already spent", status_code=409)
                    body = b""
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > 2048:
                            raise ValueError("bounded owner form required")
                        body += chunk
                    _, after_body = self._view(request)
                    if before != after_body:
                        raise ValueError("same actor before spend required")
                    url = await run_in_threadpool(self._work, lambda: self._begin(request, body))
                    self._last_operation = "publication_current"
                    _, after = self._view(request)
                    if before != after:
                        raise ValueError("same terminal actor required")
                    self._same_preview(after)
                    return RedirectResponse(url, status_code=303)
                except Exception:  # noqa: BLE001 - fixed response only
                    fatal = False
                except BaseException:  # noqa: BLE001 - failed effect retained before fixed fatal
                    fatal = True
                if self._spent:
                    try:
                        self.close()
                    except BaseException as cleanup:  # noqa: BLE001 - fixed cleanup category only
                        fatal = fatal or not isinstance(cleanup, Exception)
                if fatal:
                    del request
                    raise SlackConnectionCancelled("Slack owned route cancelled")
                return self._denied_response(request)

        @app.get("/connections/slack/callback")
        async def callback(request: Request) -> Response:
            async with self._lock:
                try:
                    _, before = self._view(request, callback=True)
                    self._same_preview(before)
                    if self._callback_done:
                        return Response("Slack callback already spent", status_code=409)
                    await run_in_threadpool(self._work, lambda: self._callback(request))
                    self._last_operation = "publication_current"
                    _, after = self._view(request, callback=True)
                    if before != after:
                        raise ValueError("same terminal actor required")
                    self._same_preview(after)
                    return HTMLResponse(
                        "Fresh Slack exchange checked. Credentials are not saved or installed."
                    )
                except Exception:  # noqa: BLE001 - never disclose raw provider/credential result
                    fatal = False
                except BaseException:  # noqa: BLE001 - worker drained/held before fixed fatal
                    fatal = True
                if self._spent:
                    try:
                        self.close()
                    except BaseException as cleanup:  # noqa: BLE001 - fixed cleanup category only
                        fatal = fatal or not isinstance(cleanup, Exception)
                if fatal:
                    del request
                    raise SlackConnectionCancelled("Slack owned route cancelled")
                return self._denied_response(request, callback=True)
