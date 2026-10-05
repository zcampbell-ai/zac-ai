"""Unmounted zero-data enrollment; local confirmation is separate host authority.

No source, State, view or action callback is accepted. A host-opened short window
captures only library-validated Google identity. Browser sign-in never issues a
user session or grant. The trusted local operator inspects and explicitly confirms
that identity, matching browser/Mac code and private origin, then supplies
separate boundary scopes; returned OwnerGrant is a
proposal, not persisted enrollment. Safe logging/TLS/Google registration/Keychain
and actual host configuration remain independent release gates.
"""

from __future__ import annotations

import base64
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER, IdentityProvider
from zacai.interfaces.private_web import (
    BoundaryScope,
    OwnerGrant,
    _cookie,
    _SecurityHeaders,
    _set_cookie,
)
from zacai.interfaces.session_store import Identity, SessionStore, _aware

_COOKIE = "__Host-zac-enrollment"


@dataclass(frozen=True)
class PendingOwner:
    identity: Identity
    created_at: datetime
    expires_at: datetime
    candidate_id: str = field(repr=False)
    origin: str
    pairing_code: str = field(repr=False)


class OwnerEnrollment:
    """Host-only volatile candidate registry; restarting requires sign-in again."""

    def __init__(self, *, opened_at: datetime, lifetime: timedelta = timedelta(minutes=5)):
        _aware(opened_at)
        if not timedelta(0) < lifetime <= timedelta(minutes=5):
            raise ValueError("enrollment unavailable")
        self._last_seen = opened_at
        self._expires = opened_at + lifetime
        self._pending: PendingOwner | None = None
        self._closed = False
        self._lock = threading.Lock()

    def _valid(self, now: datetime) -> bool:
        _aware(now)
        if now < self._last_seen or now >= self._expires:
            self._closed = True
            self._pending = None
        self._last_seen = now
        return not self._closed

    def available(self, now: datetime) -> bool:
        with self._lock:
            return self._valid(now) and self._pending is None

    def capture(self, identity: Identity, now: datetime, *, origin: str) -> PendingOwner:
        with self._lock:
            if (
                not self._valid(now)
                or self._pending is not None
                or identity.issuer != GOOGLE_ISSUER
                or not isinstance(identity.subject, str)
                or not 1 <= len(identity.subject) <= 255
            ):
                raise ValueError("enrollment unavailable")
            target = urlsplit(origin)
            if (
                target.scheme != "https"
                or not target.hostname
                or target.netloc != target.hostname
                or target.path
                or target.query
                or target.fragment
            ):
                raise ValueError("enrollment unavailable")
            raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
            code = "-".join(raw[i : i + 4] for i in range(0, 16, 4))
            self._pending = PendingOwner(
                identity, now, self._expires, secrets.token_urlsafe(32), origin, code
            )
            return self._pending

    def pending(self, now: datetime) -> PendingOwner | None:
        """Trusted local inspection only; never expose this through a route."""
        with self._lock:
            return self._pending if self._valid(now) else None

    def confirm(
        self,
        *,
        candidate_id: str,
        pairing_code: str,
        origin: str,
        identity: Identity,
        scopes: tuple[BoundaryScope, ...],
        now: datetime,
    ) -> OwnerGrant:
        """Local operator explicitly binds identity and independent scope choices.

        Pairing code correlates this pending sign-in only; it is never a bearer
        credential or browser authorization. This returns a proposal only.
        The caller must separately persist it through
        reviewed host configuration; no web request or enrollment cookie can call
        this method. Account domain/email/company administration grant no scopes.
        """
        with self._lock:
            if not self._valid(now) or self._pending is None:
                raise ValueError("enrollment unavailable")
            pending = self._pending
            if (
                not isinstance(candidate_id, str)
                or not candidate_id.isascii()
                or not secrets.compare_digest(candidate_id, pending.candidate_id)
                or not isinstance(pairing_code, str)
                or not pairing_code.isascii()
                or not secrets.compare_digest(pairing_code, pending.pairing_code)
                or origin != pending.origin
                or identity != pending.identity
                or now < pending.created_at
            ):
                raise ValueError("enrollment unavailable")
            proposed = OwnerGrant(identity, scopes)
            self._closed = True
            self._pending = None
            return proposed

    def cancel(self) -> None:
        with self._lock:
            self._closed = True
            self._pending = None


def create_owner_enrollment(
    *,
    origin: str,
    identities: IdentityProvider,
    sessions: SessionStore,
    enrollment: OwnerEnrollment,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    """Build a separately deployed enrollment-only app; never mount/run it.

    Session backend stores only pending OIDC transactions, never user sessions.
    Raw callback queries/cookies must be excluded from operational access logs.
    Reuses existing header/cookie primitives; no protected view callback exists.
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
        raise ValueError("enrollment unavailable")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(_SecurityHeaders, google_start_path="/enroll")

    def host(request: Request) -> bool:
        return request.headers.getlist("host") == [target.netloc]

    @app.get("/enroll")
    async def page(request: Request) -> Response:
        if not host(request) or not enrollment.available(clock()):
            return Response("Enrollment unavailable", status_code=403)
        return HTMLResponse(
            "<h1>Connect your Caz AI sign-in</h1><p>Select your intended Google account. "
            'This step gives no access to your data.</p><form method="post" action="/enroll">'
            "<button>Sign in with Google</button></form>"
        )

    @app.post("/enroll")
    async def begin(request: Request) -> Response:
        try:
            if (
                not host(request)
                or request.headers.getlist("origin") != [origin]
                or not enrollment.available(clock())
            ):
                return Response("Enrollment unavailable", status_code=403)
            request.scope["session"] = {}
            response = await identities.begin(request, origin + "/enroll/callback")
            sessions.revoke(_cookie(request, _COOKIE))
            token = sessions.start_login(request.session, clock())
            _set_cookie(response, _COOKIE, token, 300)
            return response
        except Exception:  # noqa: BLE001 - no private query/token diagnostics
            return Response("Enrollment unavailable", status_code=503)

    @app.get("/enroll/callback")
    async def finish(request: Request) -> Response:
        try:
            if not host(request) or len(request.scope.get("query_string", b"")) > 4096:
                return Response("Enrollment unavailable", status_code=400)
            data = sessions.consume_login(_cookie(request, _COOKIE), clock())
            if (
                data is None
                or not enrollment.available(clock())
                or any(len(request.query_params.getlist(k)) != 1 for k in ("code", "state"))
            ):
                return Response("Enrollment unavailable", status_code=401)
            request.scope["session"] = data
            identity = await identities.finish(request)
            pending = enrollment.capture(identity, clock(), origin=origin)
            # Correlation only: no endpoint accepts this code as authentication.
            response = HTMLResponse(
                "<h1>Confirm this sign-in on your Mac</h1><p>Match this code on your Mac:</p><strong>"
                + escape(pending.pairing_code)
                + "</strong><p>Then confirm the account and separate access choices. "
                "No data access has been granted. This code expires with setup.</p>"
            )
            response.delete_cookie(_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
            return response
        except Exception:  # noqa: BLE001 - sanitized provider/backend errors
            return Response("Enrollment unavailable", status_code=401)

    @app.get("/enroll/complete")
    async def complete(request: Request) -> Response:
        if not host(request):
            return Response(status_code=400)
        # Generic instructions disclose neither candidate identity nor registry state.
        return HTMLResponse(
            "<h1>Finish setup on your Mac</h1><p>If your sign-in completed, "
            "confirm the account and access choices locally. No data access has been granted.</p>"
        )

    return app
