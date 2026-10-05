"""Unmounted private web factory; current zacai.main remains health-only.

Requires independently reviewed host identity enrollment, session backend and view
callback. Synthetic adapters prove request behavior only, never live auth. Serve
TLS/Tailscale setup, secrets, persistence and safe operational logging are separate
release gates. Uvicorn/proxy raw query/header/body access logging MUST be disabled
before mounting; existing generic redaction does not protect OAuth callback codes.
No route dispatches actions or interprets client claims as identity/permission.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.types import ASGIApp

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER, IdentityProvider
from zacai.interfaces.presentation import render_sign_in
from zacai.interfaces.session_store import Identity, SessionStore, UserSession
from zacai.policy import DataClassification, TrustBoundary

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
) -> FastAPI:
    """Create an isolated app, never mount/run it or alter existing service binding.

    `owner` is current host enrollment, refreshed each request; arbitrary claimed
    email, domain/admin membership, forwarded headers or login status grant no
    source access. Per-boundary classifications never form a cross-boundary union.
    `view` must refresh protected canonical source permissions/recovery itself.
    This factory has no approved-action endpoint; logout is its only user change.
    """
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
        session = sessions.user(_cookie(request, _USER), clock())
        if session is None:
            return None
        grant = current_owner()
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
            logout = (
                '<form class="caz-session-control" method="post" action="/logout"><input type="hidden" name="csrf" value="'
                + escape(session.csrf, quote=True)
                + '"><button>Sign out</button></form>'
            )
            return HTMLResponse(
                html.replace("</main>", logout + "</main>") if "</main>" in html else html + logout
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

    return app
