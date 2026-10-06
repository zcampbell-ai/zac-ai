"""Unmounted private web factory; current zacai.main remains health-only.

Requires independently reviewed host identity enrollment, session backend and view
callback. Synthetic adapters prove request behavior only, never live auth. Serve
TLS/Tailscale setup, secrets, persistence and safe operational logging are separate
release gates. Uvicorn/proxy raw query/header/body access logging MUST be disabled
before mounting; existing generic redaction does not protect OAuth callback codes.
No route dispatches actions or interprets client claims as identity/permission.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.types import ASGIApp

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER, IdentityProvider
from zacai.interfaces.presentation import CAZ_STYLE, render_sign_in
from zacai.interfaces.session_store import Identity, SessionStore, UserSession
from zacai.policy import DataClassification, TrustBoundary

if TYPE_CHECKING:
    from zacai.interfaces.named_followup_web import NamedFollowupWeb
    from zacai.interfaces.work_choice_web import WorkChoiceWeb

_LOGIN = "__Host-zac-login"
_USER = "__Host-zac-session"
_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Expires": "0",
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
}


@dataclass(frozen=True)
class BoundaryScope:
    boundary: TrustBoundary
    classifications: frozenset[DataClassification]


@dataclass(frozen=True)
class OwnerGrant:
    identity: Identity
    scopes: tuple[BoundaryScope, ...]

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not Identity
            or self.identity.issuer != GOOGLE_ISSUER
            or not isinstance(self.identity.subject, str)
            or not self.identity.subject
            or type(self.scopes) is not tuple
            or not self.scopes
            or any(type(scope) is not BoundaryScope for scope in self.scopes)
            or len({s.boundary for s in self.scopes}) != len(self.scopes)
            or any(type(s.classifications) is not frozenset for s in self.scopes)
            or any(
                not s.classifications
                or any(not isinstance(c, DataClassification) for c in s.classifications)
                for s in self.scopes
            )
            or any(not isinstance(s.boundary, TrustBoundary) for s in self.scopes)
        ):
            raise ValueError("owner enrollment unavailable")


@dataclass(frozen=True)
class InterfacePrincipal:
    identity: Identity
    scopes: tuple[BoundaryScope, ...]


class _SecurityHeaders(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, google_start_path: str | None = None) -> None:
        if google_start_path not in (None, "/login", "/enroll"):
            raise ValueError("private sign-in policy unavailable")
        super().__init__(app)
        self._google_start_path = google_start_path

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in _HEADERS.items():
            response.headers[name] = value
        if (
            request.method == "GET"
            and request.url.path == self._google_start_path
            and response.status_code == 200
        ):
            # Only fixed, data-free sign-in documents may navigate to Google.
            # Untrusted view headers and all protected responses remain overwritten.
            response.headers["Content-Security-Policy"] = _HEADERS[
                "Content-Security-Policy"
            ].replace("form-action 'self';", "form-action 'self' https://accounts.google.com;")
        return response


def _cookie(request: Request, name: str) -> str:
    # Reject ambiguity rather than letting a parser pick among duplicate cookies.
    values = [
        part.strip().split("=", 1)[1]
        for raw in request.headers.getlist("cookie")
        for part in raw.split(";")
        if part.strip().startswith(name + "=")
    ]
    return values[0] if len(values) == 1 else ""


def _set_cookie(response: Response, name: str, token: str, max_age: int) -> None:
    response.set_cookie(
        name, token, max_age=max_age, secure=True, httponly=True, samesite="lax", path="/"
    )


def create_private_web(
    *,
    origin: str,
    identities: IdentityProvider,
    sessions: SessionStore,
    owner: Callable[[], OwnerGrant],
    view: Callable[[InterfacePrincipal], Awaitable[str]],
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    work_choices: WorkChoiceWeb | None = None,
    named_questions: NamedFollowupWeb | None = None,
) -> FastAPI:
    """Create an isolated app, never mount/run it or alter existing service binding.

    `owner` is current host enrollment, refreshed each request; arbitrary claimed
    email, domain/admin membership, forwarded headers or login status grant no
    source access. Per-boundary classifications never form a cross-boundary union.
    `view` must refresh protected canonical source permissions/recovery itself.
    Optional trusted work_choices mounts non-executing preference capture only.
    Disabled default exposes no choice route; no executable approval is granted.
    """
    if work_choices is not None:
        from zacai.interfaces.work_choice_web import WorkChoiceWeb

        if type(work_choices) is not WorkChoiceWeb:
            raise ValueError("private work choice configuration unavailable")
    if named_questions is not None:
        from zacai.interfaces.named_followup_web import NamedFollowupWeb
        if (type(named_questions) is not NamedFollowupWeb or clock is not named_questions.host_clock
            or named_questions._continuity._sessions is not sessions
            or named_questions._continuity._owner is not owner
            or json.loads(named_questions._continuity._context)["origin"] != origin
            or named_questions._store._context != named_questions._continuity._context):
            raise ValueError("private named question configuration unavailable")
    target = urlsplit(origin)
    if (
        target.scheme != "https"
        or not target.hostname
        or target.netloc != target.hostname
        or target.path
        or target.query
        or target.fragment
    ):
        raise ValueError("private origin unavailable")
    # Validate initial enrollment, but refresh it for every request/transition.
    initial = owner()
    OwnerGrant(initial.identity, initial.scopes)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(_SecurityHeaders, google_start_path="/login")

    def valid_host(request: Request) -> bool:
        return request.headers.getlist("host") == [target.netloc]

    def current_owner() -> OwnerGrant:
        configured = owner()
        return OwnerGrant(configured.identity, configured.scopes)

    def authenticated(request: Request) -> tuple[UserSession, InterfacePrincipal] | None:
        # A revoked/unavailable owner cannot keep denied cookies idle-alive.
        grant = current_owner()
        session = sessions.user(_cookie(request, _USER), clock())
        if session is None:
            return None
        if session.identity != grant.identity:
            sessions.revoke(_cookie(request, _USER))
            return None
        return session, InterfacePrincipal(grant.identity, grant.scopes)

    @app.get("/login")
    async def login_page(request: Request) -> Response:
        if not valid_host(request):
            return Response(status_code=400)
        return HTMLResponse(render_sign_in())

    @app.post("/login")
    async def login(request: Request) -> Response:
        try:
            if not valid_host(request) or request.headers.getlist("origin") != [origin]:
                return Response(status_code=403)
            request.scope["session"] = {}
            response = await identities.begin(request, origin + "/auth/callback")
            data = request.session
            # Replace any old transaction; raw token is never stored or logged.
            sessions.revoke(_cookie(request, _LOGIN))
            token = sessions.start_login(data, clock())
            _set_cookie(response, _LOGIN, token, 300)
            return response
        except Exception:  # noqa: BLE001 - no token/private diagnostics or logs
            return Response("Sign-in unavailable", status_code=503)

    @app.get("/auth/callback")
    async def callback(request: Request) -> Response:
        try:
            if not valid_host(request) or len(request.scope.get("query_string", b"")) > 4096:
                return Response(status_code=400)
            # Consume before provider exchange; duplicate callbacks cannot replay.
            data = sessions.consume_login(_cookie(request, _LOGIN), clock())
            if data is None:
                return Response("Sign-in unavailable", status_code=401)
            request.scope["session"] = data
            if any(len(request.query_params.getlist(k)) != 1 for k in ("code", "state")):
                return Response("Sign-in unavailable", status_code=401)
            identity = await identities.finish(request)
            grant = current_owner()
            if identity != grant.identity:
                return Response("Sign-in unavailable", status_code=401)
            sessions.revoke(_cookie(request, _USER))
            token = sessions.start_user(identity, clock())
            response = RedirectResponse("/", status_code=303)
            response.delete_cookie(_LOGIN, path="/", secure=True, httponly=True, samesite="lax")
            _set_cookie(response, _USER, token, 8 * 60 * 60)
            return response
        except Exception:  # noqa: BLE001 - never include callback/provider diagnostics
            return Response("Sign-in unavailable", status_code=401)

    @app.get("/")
    async def home(request: Request) -> Response:
        try:
            if not valid_host(request):
                return Response(status_code=400)
            found = authenticated(request)
            if found is None:
                return RedirectResponse("/login", status_code=303)
            session, principal = found
            html = await view(principal)
            # Rendering can await private I/O. Do not release its result if the
            # owner, scopes or original browser session changed meanwhile.
            refreshed = authenticated(request)
            if (
                refreshed is None
                or refreshed[1] != principal
                or not secrets.compare_digest(refreshed[0].csrf, session.csrf)
                or refreshed[0].issued_at != session.issued_at
                or refreshed[0].expires_at != session.expires_at
            ):
                return Response("Private view unavailable", status_code=403)
            logout = (
                '<form class="caz-session-control" method="post" action="/logout"><input type="hidden" name="csrf" value="'
                + escape(session.csrf, quote=True)
                + '"><button>Sign out</button></form>'
            )
            extra = (
                '<p><a href="/work-choice">Review a work preference</a></p>'
                if work_choices is not None
                else ""
            ) + logout
            return HTMLResponse(
                html.replace("</main>", extra + "</main>") if "</main>" in html else html + extra
            )
        except Exception:  # noqa: BLE001 - fixed view diagnostic, no private error chains
            return Response("Private view unavailable", status_code=503)

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        try:
            if not valid_host(request) or request.headers.getlist("origin") != [origin]:
                return Response(status_code=403)
            found = authenticated(request)
            if found is None:
                return Response(status_code=401)
            if request.headers.get("content-type") != "application/x-www-form-urlencoded":
                return Response(status_code=403)
            body = b""
            async for chunk in request.stream():
                if len(body) + len(chunk) > 256:
                    return Response(status_code=403)
                body += chunk
            fields = parse_qs(body.decode("ascii"), strict_parsing=True, max_num_fields=1)
            if (
                list(fields) != ["csrf"]
                or len(fields["csrf"]) != 1
                or not secrets.compare_digest(fields["csrf"][0], found[0].csrf)
            ):
                return Response(status_code=403)
            sessions.revoke(_cookie(request, _USER))
            response = RedirectResponse("/login", status_code=303)
            response.delete_cookie(_USER, path="/", secure=True, httponly=True, samesite="lax")
            return response
        except Exception:  # noqa: BLE001 - fixed diagnostic without tokens or private data
            return Response(status_code=403)

    if work_choices is not None:
        # Exact trusted injection is validated above. No request constructs a
        # controller, selection callback, retained receipt or protection adapter.
        controller = work_choices

        @app.get("/work-choice")
        async def work_choice_page(request: Request) -> Response:
            try:
                if not valid_host(request) or request.scope.get("query_string", b""):
                    return Response(status_code=400)
                found = authenticated(request)
                if found is None:
                    return RedirectResponse("/login", status_code=303)
                session, principal = found

                def form() -> str:
                    handle = controller.issue(principal)
                    return controller.render(handle=handle, principal=principal, csrf=session.csrf)

                html = await run_in_threadpool(form)
                refreshed = authenticated(request)
                if (
                    refreshed is None
                    or refreshed[1] != principal
                    or refreshed[0].csrf != session.csrf
                ):
                    return Response("Private preference unavailable", status_code=403)
                return HTMLResponse(
                    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width, initial-scale=1">'
                    "<title>Caz AI · Work preference</title><style>" + CAZ_STYLE + "</style>"
                    "</head><body><main><h1>Work preference</h1>"
                    + html
                    + '<p><a href="/">Back to your review</a></p></main></body></html>'
                )
            except Exception:  # noqa: BLE001 - fixed text, no request/backend locals
                return Response("Private preference unavailable", status_code=503)

        @app.post("/work-choice")
        async def record_work_choice(request: Request) -> Response:
            try:
                if (
                    not valid_host(request)
                    or request.headers.getlist("origin") != [origin]
                    or request.scope.get("query_string", b"")
                ):
                    return Response(status_code=403)
                found = authenticated(request)
                if found is None:
                    return Response(status_code=401)
                session, principal = found
                if request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]:
                    return Response(status_code=403)
                body = b""
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 8192:
                        return Response(status_code=413)
                    body += chunk
                try:
                    text = body.decode("utf-8", errors="strict")
                    if re.search(r"%(?![0-9a-fA-F]{2})", text):
                        return Response(status_code=403)
                    parsed = parse_qs(
                        text,
                        keep_blank_values=True,
                        strict_parsing=True,
                        max_num_fields=4,
                        encoding="utf-8",
                        errors="strict",
                    )
                except (UnicodeError, ValueError):
                    return Response(status_code=403)
                if (
                    set(parsed)
                    not in ({"handle", "choice", "csrf"}, {"handle", "choice", "csrf", "changes"})
                    or any(len(values) != 1 for values in parsed.values())
                    or not secrets.compare_digest(parsed["csrf"][0], session.csrf)
                ):
                    return Response(status_code=403)
                fields = {key: values[0] for key, values in parsed.items() if key != "csrf"}
                saved = await run_in_threadpool(
                    controller.submit, principal=principal, fields=fields
                )
                from zacai.interfaces.work_choice_capture import SavedWorkChoice

                refreshed = authenticated(request)
                if (
                    type(saved) is not SavedWorkChoice
                    or refreshed is None
                    or refreshed[1] != principal
                    or refreshed[0].csrf != session.csrf
                ):
                    return Response("Private preference unavailable", status_code=403)
                return HTMLResponse(
                    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width, initial-scale=1">'
                    "<title>Caz AI · Preference saved</title><style>" + CAZ_STYLE + "</style>"
                    "</head><body><main><h1>Preference saved</h1>"
                    "<p>Your preference was recorded with verified recovery. No work was executed.</p>"
                    '<p><a href="/">Back to your review</a></p></main></body></html>'
                )
            except Exception:  # noqa: BLE001 - no saved claim or unverified choice-state disclosure
                return Response(
                    "Preference not acknowledged. Retry or request a review.", status_code=503
                )

    if named_questions is not None:
        named_controller = named_questions
        pointer_cookie = "__Host-zac-named-action"

        def original_session(before: tuple[UserSession, InterfacePrincipal],
                             after: tuple[UserSession, InterfacePrincipal] | None) -> bool:
            return (after is not None and before[1] == after[1]
                and before[0].identity == after[0].identity
                and before[0].issued_at == after[0].issued_at
                and before[0].expires_at == after[0].expires_at
                and secrets.compare_digest(before[0].csrf, after[0].csrf))

        def browser_pointer(request: Request) -> str | None:
            values = [part.strip().split("=", 1)[1]
                for raw in request.headers.getlist("cookie") for part in raw.split(";")
                if part.strip().startswith(pointer_cookie + "=")]
            if len(values) > 1:
                raise ValueError("ambiguous browser pointer")
            return values[0] if values else None

        def named_document(content: str) -> str:
            return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                '<title>Caz AI · Local question</title><style>' + CAZ_STYLE + '</style></head>'
                '<body><main>' + content + '<p><a href="/">Back to your review</a></p></main></body></html>')

        @app.get("/ask-caz-locally")
        async def named_question_page(request: Request) -> Response:
            try:
                if not valid_host(request) or request.scope.get("query_string", b""):
                    return Response(status_code=400)
                before = authenticated(request)
                if before is None:
                    return RedirectResponse("/login", status_code=303)
                pointer = browser_pointer(request)
                operation = named_controller.for_cookie(_cookie(request, _USER))
                page = await run_in_threadpool(named_controller.page,
                    operation=operation, pointer=pointer, csrf=before[0].csrf)
                if not original_session(before, authenticated(request)):
                    return Response("Private local question unavailable", status_code=403)
                # Last external session callback precedes final actual row gate.
                page = await run_in_threadpool(named_controller.recheck_page, operation=operation, page=page)
                now = clock()
                if now >= min(before[0].expires_at, page.deadline):
                    return Response("Private local question unavailable", status_code=403)
                response = HTMLResponse(named_document(page.html))
                manifest = page.reused.record.manifest
                maximum = min(before[0].expires_at, manifest.admission_expires_at +
                    timedelta(seconds=manifest.processing_ttl_seconds))
                response.set_cookie(pointer_cookie, page.reused.sealed_pointer,
                    max_age=max(0, int((maximum - now).total_seconds())), secure=True,
                    httponly=True, samesite="strict", path="/")
                return response
            except Exception:  # noqa: BLE001 - no private fields/backend locals in response
                return Response("Private local question unavailable", status_code=503)

        if named_controller.submission_enabled:
            @app.post("/ask-caz-locally")
            async def named_question_submit(request: Request) -> Response:
                try:
                    if (not valid_host(request) or request.headers.getlist("origin") != [origin]
                        or request.scope.get("query_string", b"")):
                        return Response(status_code=403)
                    before = authenticated(request)
                    if before is None:
                        return Response(status_code=401)
                    if request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]:
                        return Response(status_code=403)
                    pointer = browser_pointer(request)
                    if pointer is None:
                        return Response(status_code=403)
                    body = b""
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > 32768:
                            return Response(status_code=413)
                        body += chunk
                    if not original_session(before, authenticated(request)):
                        return Response("Private local question unavailable", status_code=403)
                    from zacai.interfaces.named_followup_web import (
                        parse_named_question_form,
                    )
                    try:
                        question_form = parse_named_question_form(body, before[0].csrf)
                    except ValueError:
                        return Response(status_code=403)
                    operation = named_controller.for_cookie(_cookie(request, _USER))
                    # Starlette awaits the blocking worker; no client-triggered retry or
                    # background dispatch is created here. Durable one-shot claim is
                    # mandatory inside the concrete host pipeline.
                    result = await run_in_threadpool(named_controller.submit,
                        operation=operation, pointer=pointer, original_utf8=question_form.original_utf8,
                        manifest_digest=question_form.manifest_digest)
                    if not original_session(before, authenticated(request)):
                        return Response("Private local reply unavailable", status_code=403)
                    saved = await run_in_threadpool(named_controller.recheck_result,
                        operation=operation, result=result)
                    expiry = result.admitted.processing_expires_at
                    if expiry is None or clock() >= min(before[0].expires_at, expiry):
                        return Response("Private local reply unavailable", status_code=403)
                    citations = ''.join('<li>Source ' + escape(str(c.reference.source_id))
                        + ', characters ' + str(c.quote.start) + '–' + str(c.quote.end) + '</li>'
                        for c in saved.reply.citations)
                    html = '<section class="decision-card"><h1>Caz reply</h1><p style="white-space:pre-wrap">' + escape(saved.reply.display_text) + '</p><details><summary>Source evidence</summary><ul>' + citations + '</ul></details></section>'
                    return HTMLResponse(named_document(html))
                except Exception:  # noqa: BLE001 - no claims, request text or private exceptions
                    return Response("Local question not acknowledged. Review request status.", status_code=503)

    return app
