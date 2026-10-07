"""One HR listener's explicitly paired original-domain fresh Gmail consumer."""

from __future__ import annotations

import asyncio
import html
from typing import Any
from urllib.parse import parse_qs

import anyio
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from zacai.connectors.account_preflight import preflight
from zacai.connectors.connector_authority import review_scope_digest
from zacai.connectors.gmail_recovery_authorization import GmailRecoveryJoin
from zacai.connectors.gmail_recovery_consumer import GmailRecoveryConsumer
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.interfaces.private_web import _cookie


class GmailRecoveryWebFatal(BaseException):
    """Fixed interruption after the actual host has been latched for drain."""


class GmailRecoveryWeb:
    def __init__(self, *, host: Any, join: GmailRecoveryJoin) -> None:
        from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostPlan

        if (
            type(host) is not GmailRecoveryHostPlan
            or type(join) is not GmailRecoveryJoin
            or join._host is not host
        ):
            raise ValueError("actual dual-leased consumer required")
        self._host, self._join = host, join
        self._action: Any = None
        self._consumer: Any = None
        self._receipt: Any = None
        self._lock = asyncio.Lock()
        self._original_lock = self._lock
        self._failed = False
        self._reviewed = False
        self._coverage: Any = None

    def _current(self) -> None:
        if self._failed or self._lock is not self._original_lock:
            raise ValueError("one current recovery listener required")
        self._join._check()
        if self._action is not None:
            self._action.current()

    def _owner(self, request: Request) -> Any:
        self._current()
        cookie = _cookie(request, "__Host-zac-session")
        operation = self._join._hr.for_cookie(cookie)
        verified = operation.establish()
        self._join._owners(operation, verified.binding_digest)
        self._current()
        return verified

    def _form(self, request: Request, action: str, *, confirmation: str | None = None) -> str:
        verified = self._owner(request)
        cookie = _cookie(request, "__Host-zac-session")
        session = self._join._hr._sessions.peek_user(cookie, self._join._hr._clock())
        self._owner(request)
        if session is None or session.identity != verified.principal.identity:
            raise ValueError("actual current owner form required")
        fields = {
            "csrf": session.csrf,
            "reviewed_configuration_digest": self._join._configuration.configuration_digest,
            "action_generation": self._join._generation,
        }
        if confirmation is not None:
            fields["confirmation"] = confirmation
        hidden = "".join(
            '<input type="hidden" name="' + html.escape(k) + '" value="' + html.escape(v) + '">'
            for k, v in fields.items()
        )
        label = {
            "/connections/gmail/recover/pair": "Pair my original Gmail domain for this recovery",
            "/connections/gmail/quarantine": "Record this original attempt for one recovery",
            "/connections/gmail/recover/begin": "Authorize one fresh Gmail read connection",
            "/connections/gmail/install": "Install this fresh connection and verify my Gmail profile",
        }[action]
        return (
            '<form method="post" action="'
            + action
            + '">'
            + hidden
            + "<button>"
            + label
            + "</button></form>"
        )

    def _page(self, request: Request) -> str:
        self._owner(request)
        title = "Recover Gmail read connection"
        if self._receipt is not None:
            if self._coverage is not None:
                installer = self._consumer._installer
                if installer is None:
                    raise ValueError("actual current installed profile receipt required")
                installer.current_active()
                return "<h1>Gmail connected</h1><p>Your installed foreground Gmail connection passed its profile preflight. No mail content was read. Unattended access and renewal are not enabled.</p>"
            installer = self._consumer._installer
            if installer is None or not installer._active:
                return (
                    "<h1>Install fresh Gmail connection</h1><p>Verify the new native token pair and your mailbox. Approve each foreground Keychain prompt.</p>"
                    + self._form(
                        request,
                        "/connections/gmail/install",
                        confirmation="INSTALL FRESH GMAIL AND VERIFY PROFILE",
                    )
                )
            installer.current_active()
            plan = installer.new_plan()
            cookie = _cookie(request, "__Host-zac-session")
            session = self._join._hr._sessions.peek_user(cookie, self._join._hr._clock())
            self._owner(request)
            if session is None:
                raise ValueError("actual profile preflight owner required")
            target = "/connector-execute" if self._reviewed else "/connector-review"
            fields = {"csrf": session.csrf}
            if not self._reviewed:
                fields["reviewed_scope_digest"] = review_scope_digest(plan)
            hidden = "".join(
                '<input type="hidden" name="' + html.escape(k) + '" value="' + html.escape(v) + '">'
                for k, v in fields.items()
            )
            return (
                '<h1>Verify installed Gmail connection</h1><p>Approve one profile-only native credential preflight. No mail content will be read.</p><form method="post" action="'
                + target
                + '">'
                + hidden
                + "<button>Verify Gmail profile</button></form>"
            )

        if self._action is None:
            form = self._form(
                request,
                "/connections/gmail/recover/pair",
                confirmation="PAIR ORIGINAL GMAIL DOMAIN FOR ONE RECOVERY",
            )
            explanation = "Pair your separately enrolled restricted owner identity with your original Gmail domain. This preserves the original grant and failed attempt."
        elif not self._consumer._committed:
            if self._consumer._preview is None:
                self._consumer.preview_quarantine()
            form = self._form(request, "/connections/gmail/quarantine")
            explanation = "Record the original held attempt before one fresh authorization."
        elif not self._consumer._spent:
            form = self._form(
                request,
                "/connections/gmail/recover/begin",
                confirmation="RECOVER ORIGINAL GMAIL ONCE",
            )
            explanation = "Approve Gmail read access once. Caz will verify the mailbox and securely hold a fresh token pair. Installation remains pending."
        else:
            form = ""
            explanation = "This recovery attempt is consumed. Complete its current Google authorization; do not restart it."
        return "<h1>" + title + "</h1><p>" + explanation + "</p>" + form

    def _pair(self, request: Request, body: bytes) -> None:
        if self._action is not None:
            raise ValueError("pairing already consumed")
        self._owner(request)
        self._action = self._join.pair_once(request, body)
        consumer = self._host._make_recovery_consumer(self._action)
        if type(consumer) is not GmailRecoveryConsumer or consumer._action is not self._action:
            raise ValueError("original concrete consumer required")
        self._consumer = consumer
        consumer.prepare()
        self._current()

    def _install(self, request: Request, body: bytes) -> None:
        self._owner(request)
        if self._receipt is None or self._consumer is None:
            raise ValueError("actual fresh held receipt required")
        installer = self._host._make_gmail_installation(self._consumer)
        installer.install_once(request, body)
        installer.new_plan()
        installer.prepare_connector()
        self._current()

    def _connector(self, request: Request, body: bytes) -> None:
        self._owner(request)
        installer = self._consumer._installer if self._consumer is not None else None
        if (
            installer is None
            or request.url.scheme != "https"
            or request.url.query
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("actual installed owner action required")
        fields = parse_qs(body.decode("ascii"), strict_parsing=True, keep_blank_values=True)
        expected = (
            {"csrf", "reviewed_scope_digest"}
            if request.url.path == "/connector-review"
            else {"csrf"}
        )
        if set(fields) != expected or any(len(value) != 1 for value in fields.values()):
            raise ValueError("exact bounded profile review required")
        authority = installer.prepare_connector()
        plan = installer.new_plan()
        if request.url.path == "/connector-review":
            if self._reviewed:
                raise ValueError("profile review already consumed")
            authority.approve_review(
                plan,
                request=request,
                csrf=fields["csrf"][0],
                reviewed_scope_digest=fields["reviewed_scope_digest"][0],
                payload_digest=None,
            )
            self._current()
            self._reviewed = True
        else:
            if not self._reviewed or self._coverage is not None:
                raise ValueError("one actual reviewed profile preflight required")
            gateway = authority.for_request(request, csrf=fields["csrf"][0])
            self._coverage = preflight(
                plan,
                gateway=gateway,
                gmail=GmailReadTransport(
                    connection_factory=lambda: self._consumer._transport._connection(
                        "gmail.googleapis.com"
                    )
                ),
                slack=SlackReadTransport(),
                clock=self._join._hr._clock,
            )
            installer.current_active()
            self._current()

    async def _body(self, request: Request) -> bytes:
        value = bytearray()
        async for part in request.stream():
            value.extend(part)
            if len(value) > 512:
                raise ValueError("bounded owner form required")
        return bytes(value)

    def _stop(self) -> None:
        self._failed = True
        try:
            self._host._stop_recovery()
        except BaseException:  # noqa: BLE001, S110 - preserve fixed fatal category
            pass  # Actual stop is latched before its reporting callback can fail.

    def mount(self, app: FastAPI) -> None:
        if type(app) is not FastAPI:
            raise ValueError("actual HR owner app required")

        async def page(request: Request) -> Response:
            async with self._lock:
                try:
                    text = await anyio.to_thread.run_sync(self._page, request)
                    return HTMLResponse(
                        text,
                        headers={"cache-control": "no-store", "referrer-policy": "same-origin"},
                    )
                except Exception:  # noqa: BLE001 - fixed denial without private traceback
                    if self._action is not None:
                        self._stop()
                    return HTMLResponse(
                        "Gmail recovery unavailable; stop and review.", status_code=403
                    )
                except BaseException:  # noqa: BLE001 - sanitize fatal cancellation without raw frames
                    self._stop()
            del request
            text = ""
            raise GmailRecoveryWebFatal("Gmail recovery interrupted; stop and review.") from None

        async def post(request: Request) -> Response:
            async with self._lock:
                try:
                    body = await self._body(request)
                    if request.url.path == "/connections/gmail/recover/pair":
                        await anyio.to_thread.run_sync(self._pair, request, body)
                    elif self._consumer is None:
                        raise ValueError("actual private paired consumer required")
                    elif request.url.path == "/connections/gmail/install":
                        await anyio.to_thread.run_sync(self._install, request, body)
                    elif request.url.path == "/connections/gmail/quarantine":
                        await anyio.to_thread.run_sync(
                            self._consumer.commit_quarantine, request, body
                        )
                    else:
                        consent = await anyio.to_thread.run_sync(
                            self._consumer.begin_once, request, body
                        )
                        return RedirectResponse(consent.url.get_secret_value(), status_code=303)
                    return RedirectResponse("/connections/gmail/recover", status_code=303)
                except Exception:  # noqa: BLE001 - no owner/body/state disclosure
                    self._stop()
                    return HTMLResponse(
                        "Gmail recovery unavailable; stop and review.", status_code=403
                    )
                except BaseException:  # noqa: BLE001 - sanitize fatal cancellation without raw frames
                    self._stop()
            del request
            body = b""
            consent = None
            raise GmailRecoveryWebFatal("Gmail recovery interrupted; stop and review.") from None

        async def callback(request: Request) -> Response:
            async with self._lock:
                try:
                    if self._consumer is None:
                        raise ValueError("actual private recovery required")
                    self._receipt = await anyio.to_thread.run_sync(
                        self._consumer.callback_once, request
                    )
                    return JSONResponse(
                        {
                            "fresh_attempt_held": True,
                            "profile_verified": self._receipt.profile_verified,
                            "installed": False,
                            "credential_authority": False,
                            "original_actor_verified": False,
                            "processing_authorized": False,
                            "execution_authorized": False,
                        },
                        headers={"cache-control": "no-store", "referrer-policy": "no-referrer"},
                    )
                except Exception:  # noqa: BLE001 - callback URL/code never included
                    self._stop()
                    return HTMLResponse(
                        "Gmail recovery unavailable; stop and review.", status_code=403
                    )
                except BaseException:  # noqa: BLE001 - sanitize fatal cancellation without raw frames
                    self._stop()
            del request
            raise GmailRecoveryWebFatal("Gmail recovery interrupted; stop and review.") from None

        app.add_api_route("/connections/gmail/recover", page, methods=["GET"])
        for path in (
            "/connections/gmail/recover/pair",
            "/connections/gmail/quarantine",
            "/connections/gmail/recover/begin",
            "/connections/gmail/install",
        ):
            app.add_api_route(path, post, methods=["POST"])
        app.add_api_route("/connections/gmail/callback", callback, methods=["GET"])

        async def connector(request: Request) -> Response:
            async with self._lock:
                try:
                    body = await self._body(request)
                    await anyio.to_thread.run_sync(self._connector, request, body)
                    if self._coverage is not None:
                        return JSONResponse(
                            {
                                "installed": True,
                                "profile_verified": True,
                                "live_access_proven": True,
                                "credential_authority": True,
                                "processing_authorized": False,
                                "execution_authorized": False,
                                "source_capture_authorized": False,
                                "requests": self._coverage.requests,
                            },
                            headers={"cache-control": "no-store", "referrer-policy": "no-referrer"},
                        )
                    return RedirectResponse("/connections/gmail/recover", status_code=303)
                except Exception:  # noqa: BLE001 - no private installed/provider frames
                    self._stop()
                    return HTMLResponse(
                        "Gmail activation unavailable; stop and review.", status_code=403
                    )
                except BaseException:  # noqa: BLE001 - sanitize cancellation after actual drain
                    self._stop()
            del request
            body = b""
            raise GmailRecoveryWebFatal("Gmail activation interrupted; stop and review.") from None

        app.add_api_route("/connector-review", connector, methods=["POST"])
        app.add_api_route("/connector-execute", connector, methods=["POST"])

        @app.middleware("http")
        async def recovery_headers(request: Request, call_next: Any) -> Response:
            try:
                response = await call_next(request)
            except BaseException:  # noqa: BLE001 - sanitize fatal cancellation without raw frames
                self._stop()
            else:
                return self._headers(request, response)
            del request, call_next
            raise GmailRecoveryWebFatal("Gmail recovery interrupted; stop and review.") from None

    def _headers(self, request: Request, response: Response) -> Response:
        if request.url.path.startswith("/connections/gmail/recover"):
            response.headers["referrer-policy"] = "same-origin"
            csp = response.headers.get("content-security-policy", "")
            if "form-action 'self'" in csp:
                response.headers["content-security-policy"] = csp.replace(
                    "form-action 'self'", "form-action 'self' https://accounts.google.com"
                )
        if not isinstance(response, Response):
            raise TypeError("actual HTTP response required")
        return response
