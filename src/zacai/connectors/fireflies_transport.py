"""Fixed-purpose HTTPS reads for a trusted host, not an agent tool or approval.

No proxies, redirects, retries, caller-defined URL/query, mutation or listing.
Default TLS certificate/hostname verification is mandatory. Socket operations
have a timeout; this is NOT a hard total-duration guarantee against trickle data.
No client instance stores the key. Never enable HTTP debug logging in this host.
"""

from __future__ import annotations

import http.client
import json
import ssl
from collections.abc import Callable
from typing import Protocol

from pydantic import SecretStr

from zacai.connectors.fireflies_identity import build_account_request
from zacai.connectors.fireflies_wire import MAX_RESPONSE_BYTES, build_transcript_request


class TransportError(RuntimeError):
    """Sanitized transport failure, without headers/response/credential content."""


class _Reply(Protocol):
    status: int

    def getheader(self, name: str) -> str | None: ...
    def read(self, amount: int) -> bytes: ...


class _Connection(Protocol):
    def request(self, method: str, url: str, body: bytes, headers: dict[str, str]) -> None: ...
    def getresponse(self) -> _Reply: ...
    def close(self) -> None: ...


def _connect() -> _Connection:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    return http.client.HTTPSConnection(
        "api.fireflies.ai",
        port=443,
        timeout=20,
        context=context,
    )


class FirefliesReadTransport:
    """Credentials and authority stay with the trusted host.

    Optional connection factory is a trusted Python test/backend seam, not a
    configurable endpoint or an agent-provided dependency. Default connections
    go directly to the fixed HTTPS endpoint and ignore proxy environment vars.
    """

    def __init__(self, *, connection_factory: Callable[[], _Connection] = _connect) -> None:
        self._connection_factory = connection_factory

    def account_reply(self, key: SecretStr) -> bytes:
        return self._post(key, build_account_request())

    def transcript_reply(self, key: SecretStr, transcript_id: str) -> bytes:
        return self._post(key, build_transcript_request(transcript_id))

    def _post(self, key: SecretStr, request: dict[str, object]) -> bytes:
        secret = key.get_secret_value()
        if (
            not secret
            or len(secret) > 4096
            or any(ord(character) < 33 or ord(character) > 126 for character in secret)
        ):
            raise TransportError("invalid credential format")
        connection: _Connection | None = None
        try:
            connection = self._connection_factory()
            connection.request(
                "POST",
                "/graphql",
                json.dumps(request).encode(),
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {secret}",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise TransportError("Fireflies request rejected")
            media_type = (response.getheader("Content-Type") or "").split(";", 1)[0].lower().strip()
            if media_type not in {"application/json", "application/graphql-response+json"}:
                raise TransportError("unsupported response type")
            if (response.getheader("Content-Encoding") or "identity").lower() != "identity":
                raise TransportError("encoded responses are unsupported")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise TransportError("response exceeds size limit")
            return raw
        except TransportError as exc:
            raise TransportError(str(exc)) from None
        except Exception:  # noqa: BLE001 - never expose secret-bearing HTTP exception text
            raise TransportError("Fireflies transport failed") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # noqa: BLE001,S110 - cleanup errors must not leak headers
                    pass
