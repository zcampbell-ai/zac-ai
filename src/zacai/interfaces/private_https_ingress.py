"""Explicit normalization for a verified private HTTPS-to-loopback proxy.

The trusted host must verify its actual tailnet-only TLS origin/proxy before
selecting this wrapper. It is disabled by default in the listener. A loopback
peer and forwarded-proto header alone are NOT TLS authentication: another local
process can forge them. Same-UID/local-host isolation and fixed reviewed proxy
configuration remain required. No forwarded user, host or IP is identity proof.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send


class TrustedLoopbackHttpsIngress:
    def __init__(self, app: ASGIApp, *, origin: str) -> None:
        if type(origin) is not str:
            raise ValueError("private HTTPS ingress unavailable")
        parsed = urlsplit(origin)
        host = parsed.hostname
        if (
            type(origin) is not str
            or not host
            or origin != "https://" + host
            or parsed.netloc != host
            or parsed.path
            or parsed.query
            or parsed.fragment
            or len(host) > 253
            or len(host.split(".")) < 2
            or re.fullmatch(r"[a-z]+", host.split(".")[-1]) is None
            or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                for label in host.split(".")
            )
        ):
            raise ValueError("private HTTPS ingress unavailable")
        self._app, self._host = app, host.encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._app(scope, receive, send)
            return
        raw = scope.get("headers", [])
        client = scope.get("client")
        if (
            scope["type"] != "http"
            or scope.get("scheme") != "http"
            or not isinstance(client, tuple)
            or len(client) != 2
            or client[0] != "127.0.0.1"
            or [value for name, value in raw if name.lower() == b"host"] != [self._host]
            or [value for name, value in raw if name.lower() == b"x-forwarded-proto"] != [b"https"]
        ):
            await Response(
                "Private ingress unavailable",
                status_code=403,
                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
            )(scope, receive, send)
            return
        normalized = dict(scope)
        normalized["scheme"] = "https"
        # Discard forwarding hints after the fixed check; downstream code cannot
        # infer identity/authority from a claimed user/IP/host/protocol header.
        normalized["headers"] = [
            (name, value)
            for name, value in raw
            if not name.lower().startswith(b"x-forwarded-") and name.lower() != b"forwarded"
        ]
        await self._app(normalized, receive, send)
