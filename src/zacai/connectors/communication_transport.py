"""Inert fixed direct TLS communication writer for a separately approved host.

No mount, credentials, OAuth, drafts, source store or network on construction.
Only the existing approval engine establishes authority; calling this trusted
low-level transport directly establishes none. Host must approve live setup
before invocation. Injected connections are trusted Python seams, not sandboxes.
Direct TLS ignores proxy variables; no redirects, retries, refresh or arbitrary
endpoints. Socket timeout is not a hard total-duration bound. Never enable HTTP
debug logs. A failed/ambiguous write requires reconciliation, never retry.
"""

from __future__ import annotations

import http.client
import json
import math
import re
import ssl
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import SecretStr

from zacai.connectors.account_preflight import Provider

if TYPE_CHECKING:
    from zacai.connectors.approved_communications import CommunicationPlan

_MAX_BYTES = 65_536


class CommunicationTransportError(RuntimeError):
    """Fixed diagnostic without payload, token, header or provider prose."""


class CommunicationTransportCancelled(BaseException):
    """Sanitized cancellation; write may have occurred, never retry."""


def _closed[**P, R](operation: Callable[P, R]) -> Callable[P, R]:
    @wraps(operation)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return operation(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard private provider/validation frames
            failure = CommunicationTransportError
        except BaseException:  # noqa: BLE001 - discard private cancellation diagnostics
            failure = CommunicationTransportCancelled
        del args, kwargs
        raise failure("communication transport unavailable; host reconciliation required")

    return call


class Response(Protocol):
    """Trusted decoded http.client response; read raises for incomplete chunks."""

    status: int

    def getheaders(self) -> list[tuple[str, str]]: ...
    def getheader(self, name: str) -> str | None: ...
    def read(self, amount: int) -> bytes: ...


class Connection(Protocol):
    def request(self, method: str, url: str, body: bytes, headers: dict[str, str]) -> None: ...
    def getresponse(self) -> Response: ...
    def close(self) -> None: ...


def _connect(provider: Provider) -> Connection:
    if type(provider) is not Provider:
        raise ValueError("fixed provider required")
    host = "gmail.googleapis.com" if provider is Provider.GMAIL else "slack.com"
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    return http.client.HTTPSConnection(host, port=443, timeout=20, context=context)


def _response(response: Response) -> bytes:
    if type(response.status) is not int or response.status != 200:
        raise ValueError("provider request rejected")
    pairs = response.getheaders()
    if type(pairs) is not list or len(pairs) > 64:
        raise ValueError("bounded response headers required")
    sensitive = {
        "content-type",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "location",
        "x-oauth-scopes",
        "x-accepted-oauth-scopes",
        "retry-after",
    }
    seen: set[str] = set()
    size = 0
    for pair in pairs:
        if type(pair) is not tuple or len(pair) != 2 or any(type(x) is not str for x in pair):
            raise ValueError("invalid header")
        name, value = pair
        size += len(name) + len(value)
        if (
            size > 16_384
            or re.fullmatch(r"[A-Za-z0-9-]{1,128}", name) is None
            or any(ord(c) < 32 or ord(c) > 126 for c in value)
        ):
            raise ValueError("invalid bounded header")
        lower = name.lower()
        if lower in sensitive and lower in seen:
            raise ValueError("duplicate security header")
        seen.add(lower)
    transfer = response.getheader("Transfer-Encoding")
    if response.getheader("Location") is not None or (
        transfer is not None and transfer.lower() != "chunked"
    ):
        raise ValueError("redirect/unsupported framing rejected")
    if (response.getheader("Content-Type") or "").split(";", 1)[
        0
    ].lower().strip() != "application/json":
        raise ValueError("JSON response required")
    if (response.getheader("Content-Encoding") or "identity").lower().strip() != "identity":
        raise ValueError("compressed response rejected")
    length = response.getheader("Content-Length")
    if transfer is not None and length is not None:
        raise ValueError("ambiguous response framing")
    if length is not None and (
        re.fullmatch(r"[0-9]{1,8}", length) is None or int(length) > _MAX_BYTES
    ):
        raise ValueError("bounded response required")
    raw = response.read(_MAX_BYTES + 1)
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= _MAX_BYTES
        or (length is not None and int(length) != len(raw))
    ):
        raise ValueError("incomplete bounded response")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    def invalid(_: str) -> Any:
        raise ValueError("nonfinite JSON")

    def finite(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite JSON")
        return number

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite)
    if type(value) is not dict or "error" in value:
        raise ValueError("invalid response")
    return raw


class ApprovedWriteTransport:
    """Explicit provider-bound adapter, no approval/credential authority itself.

    Exact engine-created bytes are independently matched against the immutable
    reviewed plan before a connection is opened. No caller JSON selects the
    recipients, route or provider. A trusted connection factory can still lie;
    Python nominal types do not sandbox malicious host implementations.
    """

    @_closed
    def __init__(
        self, *, provider: Provider, connection_factory: Callable[[], Connection] | None = None
    ) -> None:
        if type(provider) is not Provider or (
            connection_factory is not None and not callable(connection_factory)
        ):
            raise ValueError("exact trusted provider composition required")
        self._provider = provider
        self._connection_factory = (
            connection_factory if connection_factory is not None else lambda: _connect(provider)
        )

    @property
    def provider(self) -> Provider:
        return self._provider

    @_closed
    def send(self, token: SecretStr, payload: bytes, *, plan: CommunicationPlan) -> bytes:
        # Local import avoids the engine/nominal adapter import cycle.
        from zacai.connectors.approved_communications import CommunicationPlan, prepare_payload

        if (
            type(plan) is not CommunicationPlan
            or type(token) is not SecretStr
            or type(payload) is not bytes
        ):
            raise ValueError("exact reviewed plan and transient token required")
        plan = CommunicationPlan.model_validate(plan)
        if plan.provider is not self.provider or payload != prepare_payload(plan):
            raise ValueError("exact provider/payload binding required")
        secret = token.get_secret_value()
        if not 1 <= len(secret) <= 4096 or any(not 33 <= ord(c) <= 126 for c in secret):
            raise ValueError("invalid token")
        route = (
            "/gmail/v1/users/me/messages/send"
            if self.provider is Provider.GMAIL
            else "/api/chat.postMessage"
        )
        connection = self._connection_factory()
        try:
            connection.request(
                "POST",
                route,
                payload,
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": "Bearer " + secret,
                },
            )
            return _response(connection.getresponse())
        finally:
            connection.close()
