"""Load-only owner listener; no Gmail consent, code callback or installation route."""

from __future__ import annotations

import html
from typing import Any
from urllib.parse import parse_qs

import anyio
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from zacai.connectors.account_preflight import preflight
from zacai.connectors.connector_authority import review_scope_digest
from zacai.connectors.gmail_installation import GmailInstallation
from zacai.connectors.gmail_installed_load import AuthenticatedGmailInstallation
from zacai.connectors.gmail_recovery_authorization import GmailRecoveryJoin
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.interfaces.gmail_recovery_web import GmailRecoveryWeb, GmailRecoveryWebFatal
from zacai.interfaces.private_web import _cookie


class GmailInstalledWeb(GmailRecoveryWeb):
    def __init__(self, *, host: Any, join: GmailRecoveryJoin) -> None:
        super().__init__(host=host, join=join)
        if self._host._load_existing is not True:
            raise ValueError("explicit load-only host required")
        self._installation: Any = None
        self._original_installation: Any = None
        self._original_action: Any = None

    def _installation_pins(self) -> None:
        if self._action is not self._original_action:
            raise ValueError("original paired reopening action required")
        if self._installation is None:
            if self._original_installation is not None:
                raise ValueError("original reopened installation required")
            return
        installation = self._installation
        if (
            type(installation) is not GmailInstallation
            or installation is not self._original_installation
            or type(installation._capability) is not AuthenticatedGmailInstallation
        ):
            raise ValueError("original reopened installation required")
        capability = installation._capability
        loader = capability._loader
        if (
            capability._action is not self._original_action
            or loader is not self._host._loaded
            or loader is not self._host._original_loaded
            or loader._host is not self._host
            or loader._issued is not capability
            or capability._configuration is not loader._configuration
            or capability._configuration.configuration_digest
            != self._join._configuration.configuration_digest
            or capability._authority is not self._join._authority
        ):
            raise ValueError("original authenticated reopening composition required")

    def _current(self) -> None:
        self._installation_pins()
        super()._current()
        self._installation_pins()

    def _page(self, request: Request) -> str:
        self._owner(request)
        if self._installation is None:
            return (
                "<h1>Reopen Gmail connection</h1><p>Pair your current owner sessions to verify the existing installed connection.</p>"
                + self._form(
                    request,
                    "/connections/gmail/recover/pair",
                    confirmation="PAIR ORIGINAL GMAIL DOMAIN FOR ONE RECOVERY",
                ).replace(
                    "Pair my original Gmail domain for this recovery",
                    "Reopen my existing Gmail connection",
                )
            )
        self._installation.current_active()
        if self._coverage is not None:
            return "<h1>Gmail connected</h1><p>The existing foreground connection passed a new profile verification. No mail content was read. Renewal and unattended access remain disabled.</p>"
        plan = self._installation.new_plan()
        self._installation.prepare_connector()
        cookie = _cookie(request, "__Host-zac-session")
        session = self._join._hr._sessions.peek_user(cookie, self._join._hr._clock())
        self._owner(request)
        if session is None:
            raise ValueError("actual current owner form required")
        target = "/connector-execute" if self._reviewed else "/connector-review"
        fields = {"csrf": session.csrf}
        if not self._reviewed:
            fields["reviewed_scope_digest"] = review_scope_digest(plan)
        hidden = "".join(
            '<input type="hidden" name="' + html.escape(k) + '" value="' + html.escape(v) + '">'
            for k, v in fields.items()
        )
        self._installation.current_active()
        return (
            '<h1>Verify existing Gmail profile</h1><form method="post" action="'
            + target
            + '">'
            + hidden
            + "<button>Verify Gmail profile</button></form>"
        )

    def _pair(self, request: Request, body: bytes) -> None:
        if self._action is not None or self._installation is not None:
            raise ValueError("one explicit restart pairing required")
        self._owner(request)
        action = self._join.pair_once(request, body)
        self._action = self._original_action = action
        installation = self._host._load_gmail_installation(action)
        self._installation = self._original_installation = installation
        self._installation_pins()
        self._installation.prepare_connector()
        self._installation.new_plan()
        self._installation.current_active()
        self._current()

    def _connector(self, request: Request, body: bytes) -> None:
        self._owner(request)
        installer = self._installation
        if (
            installer is None
            or request.url.scheme != "https"
            or request.url.query
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("actual installed restart action required")
        fields = parse_qs(
            body.decode("ascii"), strict_parsing=True, keep_blank_values=True, max_num_fields=2
        )
        expected = (
            {"csrf", "reviewed_scope_digest"}
            if request.url.path == "/connector-review"
            else {"csrf"}
        )
        if set(fields) != expected or any(len(v) != 1 for v in fields.values()):
            raise ValueError("new bounded installed profile review required")
        authority = installer.prepare_connector()
        plan = installer.new_plan()
        if request.url.path == "/connector-review":
            if self._reviewed:
                raise ValueError("new review already consumed")
            authority.approve_review(
                plan,
                request=request,
                csrf=fields["csrf"][0],
                reviewed_scope_digest=fields["reviewed_scope_digest"][0],
                payload_digest=None,
            )
            self._current()
            installer.current_active()
            self._reviewed = True
        else:
            if not self._reviewed or self._coverage is not None:
                raise ValueError("one newly reviewed current profile required")
            gateway = authority.for_request(request, csrf=fields["csrf"][0])
            self._coverage = preflight(
                plan,
                gateway=gateway,
                gmail=GmailReadTransport(
                    connection_factory=lambda: installer._transport._connection(
                        "gmail.googleapis.com"
                    )
                ),
                slack=SlackReadTransport(),
                clock=self._join._hr._clock,
            )
            installer.current_active()
            self._current()

    def mount(self, app: FastAPI) -> None:
        if type(app) is not FastAPI:
            raise ValueError("actual load-only owner app required")

        async def page(request: Request) -> Response:
            async with self._lock:
                try:
                    text = await anyio.to_thread.run_sync(self._page, request)
                    return HTMLResponse(
                        text,
                        headers={"cache-control": "no-store", "referrer-policy": "same-origin"},
                    )
                except Exception:  # noqa: BLE001 - discard private load/owner frames
                    if self._action is not None:
                        self._stop()
                    return HTMLResponse(
                        "Gmail reopening unavailable; stop and review.", status_code=403
                    )
                except BaseException:  # noqa: BLE001 - actual worker drains under both leases
                    self._stop()
            del request
            text = ""
            raise GmailRecoveryWebFatal("Gmail reopening interrupted; stop and review.") from None

        async def post(request: Request) -> Response:
            async with self._lock:
                try:
                    body = await self._body(request)
                    if request.url.path == "/connections/gmail/recover/pair":
                        await anyio.to_thread.run_sync(self._pair, request, body)
                    else:
                        await anyio.to_thread.run_sync(self._connector, request, body)
                        if request.url.path == "/connector-execute":
                            return JSONResponse(
                                {
                                    "installed": True,
                                    "profile_verified": True,
                                    "live_access_proven": True,
                                    "original_actor_verified": False,
                                    "processing_authorized": False,
                                    "execution_authorized": False,
                                },
                                headers={
                                    "cache-control": "no-store",
                                    "referrer-policy": "no-referrer",
                                },
                            )
                    return RedirectResponse("/connections/gmail/reopen", status_code=303)
                except Exception:  # noqa: BLE001 - fixed load/gateway failure
                    self._stop()
                    return HTMLResponse(
                        "Gmail reopening unavailable; stop and review.", status_code=403
                    )
                except BaseException:  # noqa: BLE001 - private cancellation frames discarded
                    self._stop()
            del request
            body = b""
            raise GmailRecoveryWebFatal("Gmail reopening interrupted; stop and review.") from None

        app.add_api_route("/connections/gmail/reopen", page, methods=["GET"])
        for path in ("/connections/gmail/recover/pair", "/connector-review", "/connector-execute"):
            app.add_api_route(path, post, methods=["POST"])
