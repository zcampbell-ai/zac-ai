"""Fixed HTTPS Slack reads for a trusted host; no authority or source capture.

Direct TLS ignores proxy environment variables. No redirects, arbitrary URLs,
retries or write methods. Socket timeout is not a hard total-duration bound.
Never enable HTTP debug logging. Mock factories are trusted Python test seams.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import SecretStr

from zacai.connectors.slack_wire import (
    MAX_RESPONSE_BYTES,
    HistorySelection,
    InventorySelection,
    ReadMethod,
    RepliesSelection,
    build_history_request,
    build_inventory_request,
    build_replies_request,
)


class SlackTransportError(RuntimeError):
    """Fixed diagnostics without source, headers or credentials."""


class SlackThrottleError(SlackTransportError):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Slack read throttled; host rescheduling required")


class _Reply(Protocol):
    status: int

    def getheader(self, name: str) -> str | None: ...
    def read(self, amount: int) -> bytes: ...


class _Connection(Protocol):
    def request(self, method: str, url: str, body: bytes, headers: dict[str, str]) -> None: ...
    def getresponse(self) -> _Reply: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class SlackReply:
    response_bytes: bytes = field(repr=False)
    declared_scopes: frozenset[str] | None


def _connect() -> _Connection:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    return http.client.HTTPSConnection("slack.com", port=443, timeout=20, context=context)


def _scopes(header: str | None) -> frozenset[str] | None:
    if header is None:
        return None  # Missing scope header does not imply zero scopes or approval.
    if len(header) > 8192:
        raise ValueError("invalid scope header")
    values = header.split(",") if header else []
    if len(values) > 100:
        raise ValueError("invalid scope header")
    scopes = [value.strip() for value in values]
    if any(re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", value) is None for value in scopes):
        raise ValueError("invalid scope header")
    return frozenset(scopes)


class SlackReadTransport:
    """Host must independently pin identity and approve exact declared scope.

    Scope metadata is provider-reported information, never an authorization.
    Instances do not store keys; only explicit read methods are exposed.
    """

    def __init__(self, *, connection_factory: Callable[[], _Connection] = _connect) -> None:
        self._connection_factory = connection_factory

    def account_reply(self, key: SecretStr) -> SlackReply:
        return self._post(key, ReadMethod.ACCOUNT, {})

    def inventory_reply(self, key: SecretStr, selection: InventorySelection) -> SlackReply:
        return self._post(key, ReadMethod.INVENTORY, build_inventory_request(selection))

    def history_reply(self, key: SecretStr, selection: HistorySelection) -> SlackReply:
        return self._post(key, ReadMethod.HISTORY, build_history_request(selection))

    def replies_reply(self, key: SecretStr, selection: RepliesSelection) -> SlackReply:
        return self._post(key, ReadMethod.REPLIES, build_replies_request(selection))

    def _post(self, key: SecretStr, method: ReadMethod, request: dict[str, object]) -> SlackReply:
        if type(method) is not ReadMethod:
            raise SlackTransportError("unsupported Slack read method")
        connection: _Connection | None = None
        result: SlackReply | None = None
        failure = "Slack transport failed"
        throttle: int | None = None
        try:
            secret = key.get_secret_value()
            if not secret or len(secret) > 4096 or any(not 33 <= ord(c) <= 126 for c in secret):
                raise ValueError("invalid credential format")
            connection = self._connection_factory()
            connection.request(
                "POST",
                "/api/" + method.value,
                json.dumps(request).encode(),
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": "Bearer " + secret,
                },
            )
            response = connection.getresponse()
            if response.status == 429:
                retry = response.getheader("Retry-After") or ""
                if re.fullmatch(r"[0-9]{1,5}", retry) and 1 <= int(retry) <= 86400:
                    throttle = int(retry)
                raise ValueError("throttled")
            if response.status != 200:
                raise ValueError("request rejected")
            media = (response.getheader("Content-Type") or "").split(";", 1)[0].lower().strip()
            if media != "application/json":
                raise ValueError("unsupported response")
            encoding = (response.getheader("Content-Encoding") or "identity").lower().strip()
            if encoding != "identity":
                raise ValueError("unsupported encoding")
            length = response.getheader("Content-Length")
            if length is not None and (
                re.fullmatch(r"[0-9]{1,10}", length) is None or int(length) > MAX_RESPONSE_BYTES
            ):
                raise ValueError("invalid response size")
            scopes = _scopes(response.getheader("X-OAuth-Scopes"))
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
                raise ValueError("invalid response size")
            if length is not None and len(raw) != int(length):
                raise ValueError("incomplete response")
            result = SlackReply(raw, scopes)
        except Exception:  # noqa: BLE001,S110 - do not expose private diagnostics or contexts
            pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # noqa: BLE001,S110
                    pass
        if throttle is not None:
            raise SlackThrottleError(throttle)
        if result is None:
            raise SlackTransportError(failure)
        return result
