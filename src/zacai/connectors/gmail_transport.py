"""Fixed read-only Gmail HTTPS transport for an explicitly labeled trusted host.

Inert construction; no Keychain, OAuth, source persistence or agent authority.
Direct TLS ignores proxy environment; no redirects/retries/arbitrary endpoints.
A socket timeout is not a hard total-duration bound. Never enable HTTP debug
logging. Future orchestration must verify profile identity before content reads,
then enforce selected-source approval/recovery; this seam proves neither.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Literal, Protocol
from urllib.parse import urlencode

from pydantic import SecretStr

from zacai.connectors.gmail_wire import (
    MAX_WIRE_BYTES,
    GmailHistory,
    GmailInspection,
    GmailPage,
    GmailProfile,
    GmailRawMessage,
    GmailScope,
    _history_id,
    _id,
    _token,
    inspect_history_page,
    inspect_message_page,
    inspect_profile,
    inspect_raw_message,
)

_BASE = "/gmail/v1/users/me/"


class GmailTransportError(RuntimeError):
    """Fixed diagnostics without credentials, IDs, headers or provider prose."""


class GmailHistoryExpired(GmailTransportError):
    @property
    def rescan_authorized(self) -> Literal[False]:
        return False


class GmailThrottleError(GmailTransportError):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Gmail read throttled; host rescheduling required")


class _Response(Protocol):
    status: int

    def getheader(self, name: str) -> str | None: ...
    def read(self, amount: int) -> bytes: ...


class _Connection(Protocol):
    def request(
        self, method: str, url: str, body: bytes | None, headers: dict[str, str]
    ) -> None: ...
    def getresponse(self) -> _Response: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class GmailReply[T]:
    response_bytes: bytes = field(repr=False)
    inspection: GmailInspection[T]


def _connect() -> _Connection:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    return http.client.HTTPSConnection(
        "gmail.googleapis.com", port=443, timeout=20, context=context
    )


def _closed[**P, R](operation: Callable[P, R]) -> Callable[P, R]:
    @wraps(operation)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        result: R
        error: GmailTransportError | None = None
        try:
            result = operation(*args, **kwargs)
        except GmailTransportError as failure:
            error = failure
        except Exception:  # noqa: BLE001 - suppress private validation/provider exception diagnostics
            error = GmailTransportError("Gmail read unavailable or invalid")
        else:
            return result
        raise error

    return wrapped


def _limit(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 500:
        raise ValueError("invalid page bound")
    return value


def _path(route: str, params: list[tuple[str, str]]) -> str:
    # Only module-defined route grammar; neither query nor IDs select a host.
    if re.fullmatch(r"(?:profile|messages|messages/[A-Za-z0-9_-]{1,200}|history)", route) is None:
        raise ValueError("invalid route")
    query = urlencode(params)
    return _BASE + route + ("?" + query if query else "")


class GmailReadTransport:
    """Internal host seam; declared account/labels are not authenticated grants.

    No keys are retained. Each call gates declared scope before opening a socket
    and parses the reply under that same scope before private data is returned.
    Only an approved host can establish live token/profile binding and readiness.
    """

    def __init__(self, *, connection_factory: Callable[[], _Connection] = _connect) -> None:
        self._connection_factory = connection_factory

    @_closed
    def profile_reply(self, key: SecretStr, *, scope: GmailScope) -> GmailReply[GmailProfile]:
        raw = self._get(key, scope, _path("profile", []))
        return GmailReply(raw, inspect_profile(raw, scope))

    @_closed
    def messages_reply(
        self,
        key: SecretStr,
        *,
        scope: GmailScope,
        max_results: int = 100,
        page_token: str | None = None,
        label_ids: tuple[str, ...] = (),
        query: str | None = None,
        include_spam_trash: bool = False,
    ) -> GmailReply[GmailPage]:
        if (
            type(label_ids) is not tuple
            or len(label_ids) > 100
            or len(set(label_ids)) != len(label_ids)
            or type(include_spam_trash) is not bool
        ):
            raise ValueError("invalid collection selection")
        params = [
            ("maxResults", str(_limit(max_results))),
            ("includeSpamTrash", "true" if include_spam_trash else "false"),
        ]
        params.extend(("labelIds", _id(label)) for label in label_ids)
        token = _token(page_token)
        if token is not None:
            params.append(("pageToken", token))
        if query is not None:
            if (
                type(query) is not str
                or not 1 <= len(query) <= 1_024
                or any(ord(c) < 32 or ord(c) == 127 for c in query)
            ):
                raise ValueError("invalid search declaration")
            params.append(("q", query))
        raw = self._get(key, scope, _path("messages", params))
        inspected = inspect_message_page(raw, scope)
        if len(inspected.value.messages) > max_results or (
            page_token is not None and inspected.value.next_page_token == page_token
        ):
            raise ValueError("oversized or stalled page")
        return GmailReply(raw, inspected)

    @_closed
    def raw_message_reply(
        self,
        key: SecretStr,
        *,
        scope: GmailScope,
        message_id: str,
    ) -> GmailReply[GmailRawMessage]:
        message_id = _id(message_id)
        raw = self._get(key, scope, _path("messages/" + message_id, [("format", "raw")]))
        return GmailReply(raw, inspect_raw_message(raw, scope, expected_message_id=message_id))

    @_closed
    def history_reply(
        self,
        key: SecretStr,
        *,
        scope: GmailScope,
        start_history_id: str,
        max_results: int = 100,
        page_token: str | None = None,
    ) -> GmailReply[GmailHistory]:
        params = [
            ("startHistoryId", _history_id(start_history_id)),
            ("maxResults", str(_limit(max_results))),
        ]
        token = _token(page_token)
        if token is not None:
            params.append(("pageToken", token))
        raw = self._get(key, scope, _path("history", params), history=True)
        inspected = inspect_history_page(raw, scope)
        # Wire validation already rejects duplicate keys/malformed records.
        # Count provider records, not flattened changes: empty records count,
        # and a single record can legitimately contain multiple changes.
        records = json.loads(raw.decode("utf-8")).get("history", [])
        if len(records) > max_results:
            raise ValueError("history exceeds requested record bound")
        if page_token is not None and inspected.value.next_page_token == page_token:
            raise ValueError("stalled history page")
        return GmailReply(raw, inspected)

    def _get(self, key: SecretStr, scope: GmailScope, path: str, *, history: bool = False) -> bytes:
        connection: _Connection | None = None
        result: bytes | None = None
        expired = False
        retry: int | None = None
        try:
            if type(scope) is not GmailScope:
                raise TypeError("invalid declared scope contract")
            GmailScope.check(scope)
            # key is caller-injected SecretStr; no environment/Keychain reads.
            secret = key.get_secret_value()
            if not secret or len(secret) > 4_096 or any(not 33 <= ord(c) <= 126 for c in secret):
                raise ValueError("invalid credential")
            connection = self._connection_factory()
            connection.request(
                "GET",
                path,
                None,
                {
                    "Authorization": "Bearer " + secret,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            if history and response.status == 404:
                expired = True
                raise ValueError("history unavailable")
            if response.status == 429:
                header = response.getheader("Retry-After") or ""
                if re.fullmatch(r"[0-9]{1,5}", header) and 1 <= int(header) <= 86_400:
                    retry = int(header)
                raise ValueError("throttled")
            if response.status != 200:
                raise ValueError("request rejected")
            media = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            encoding = (response.getheader("Content-Encoding") or "identity").strip().lower()
            if media != "application/json" or encoding != "identity":
                raise ValueError("unsupported response")
            length = response.getheader("Content-Length")
            if length is not None and (
                re.fullmatch(r"[0-9]{1,10}", length) is None or int(length) > MAX_WIRE_BYTES
            ):
                raise ValueError("invalid declared size")
            raw = response.read(MAX_WIRE_BYTES + 1)
            if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
                raise ValueError("invalid actual size")
            if length is not None and int(length) != len(raw):
                raise ValueError("incomplete response")
            result = raw
        except Exception:  # noqa: BLE001,S110 - discard private provider/validation diagnostics
            pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # noqa: BLE001,S110 - no private cleanup diagnostic
                    pass
        if expired:
            raise GmailHistoryExpired("Gmail history unavailable; host rescan review required")
        if retry is not None:
            raise GmailThrottleError(retry)
        if result is None:
            raise GmailTransportError("Gmail read unavailable or invalid")
        return result
