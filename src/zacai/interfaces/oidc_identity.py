"""Library-backed Google OIDC adapter; no configured owner or credentials.

Static Google endpoints avoid client-controlled discovery URLs. OAuth transactions
live only in the host-owned session store. This module never reads Keychain,
registers an OAuth client, logs tokens, fetches source data or grants data scope.
"""

from __future__ import annotations

import secrets
from typing import Any, Protocol, cast

from starlette.requests import Request
from starlette.responses import Response

from zacai.interfaces.session_store import Identity

GOOGLE_ISSUER = "https://accounts.google.com"
# Google documents exactly these two signed issuer values; normalize only after validation.
_GOOGLE_ISSUERS = [GOOGLE_ISSUER, "accounts.google.com"]


class IdentityProvider(Protocol):
    async def begin(self, request: Request, redirect_uri: str) -> Response: ...
    async def finish(self, request: Request) -> Identity: ...


class _Remote(Protocol):
    async def authorize_redirect(
        self, request: Request, redirect_uri: str, **kwargs: object
    ) -> Response: ...
    async def authorize_access_token(
        self, request: Request, **kwargs: object
    ) -> dict[str, Any]: ...

    async def parse_id_token(self, token: dict[str, Any], **kwargs: object) -> dict[str, Any]: ...


class AuthlibGoogleIdentity:
    """Validate signature/issuer/audience/expiry/nonce/state using Authlib.

    Host supplies actual client credentials only after separately approved setup.
    No email/domain/admin status can select an owner or authorize PERSONAL data.
    Construction and tests alone are not successful real identity verification.
    """

    def __init__(self, *, client_id: str, client_secret: str) -> None:
        if not client_id or not client_secret:
            raise ValueError("identity configuration unavailable")
        from authlib.integrations.starlette_client import OAuth  # type: ignore[import-untyped]

        self._client = cast(
            _Remote,
            OAuth().register(
                name="google",
                client_id=client_id,
                client_secret=client_secret,
                authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
                access_token_url="https://oauth2.googleapis.com/token",
                issuer=GOOGLE_ISSUER,
                jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
                id_token_signing_alg_values_supported=["RS256"],
                client_kwargs={
                    "scope": "openid email",
                    "code_challenge_method": "S256",
                    "timeout": 10.0,
                    "follow_redirects": False,
                    "trust_env": False,
                },
            ),
        )

    async def begin(self, request: Request, redirect_uri: str) -> Response:
        result: Response | None = None
        try:
            result = await self._begin(request, redirect_uri)
        except Exception:  # noqa: BLE001, S110 - do not release provider/token diagnostics
            pass
        if result is None:
            raise ValueError("identity unavailable")
        return result

    async def _begin(self, request: Request, redirect_uri: str) -> Response:
        nonce = secrets.token_urlsafe(32)
        request.session["zac_nonce"] = nonce
        return await self._client.authorize_redirect(request, redirect_uri, nonce=nonce)

    async def finish(self, request: Request) -> Identity:
        result: Identity | None = None
        try:
            result = await self._finish(request)
        except Exception:  # noqa: BLE001, S110 - suppress private provider exception chains
            pass
        if result is None:
            raise ValueError("identity unavailable")
        return result

    async def _finish(self, request: Request) -> Identity:
        expected_nonce = request.session.pop("zac_nonce", None)
        if not isinstance(expected_nonce, str) or not expected_nonce:
            raise ValueError("identity unavailable")
        # The surrounding host atomically consumes the whole transaction first.
        token = await self._client.authorize_access_token(
            request,
            claims_options={"iss": {"essential": True, "values": _GOOGLE_ISSUERS}},
            leeway=0,
        )
        if not isinstance(token.get("id_token"), str) or not token["id_token"]:
            raise ValueError("identity unavailable")
        # Never trust a raw token-response userinfo field. The web adapter may
        # skip its automatic ID-token parse if either token or state nonce is
        # absent. Explicit parsing always validates the ID token with our nonce.
        user = await self._client.parse_id_token(
            token,
            nonce=expected_nonce,
            claims_options={"iss": {"essential": True, "values": _GOOGLE_ISSUERS}},
            leeway=0,
        )
        if (
            not isinstance(user, dict)
            or user.get("iss") not in _GOOGLE_ISSUERS
            or user.get("nonce") != expected_nonce
            or not isinstance(user.get("sub"), str)
            or not 1 <= len(user["sub"]) <= 255
        ):
            raise ValueError("identity unavailable")
        # Do not retain email, provider tokens, scopes, or domain/admin claims.
        return Identity(GOOGLE_ISSUER, user["sub"])
