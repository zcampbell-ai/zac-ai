"""Mocked HTTPS only; never use a real Slack credential or connection."""

import json
import ssl
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from zacai.connectors.slack_transport import (
    SlackReadTransport,
    SlackThrottleError,
    SlackTransportError,
    _connect,
)
from zacai.connectors.slack_wire import (
    MAX_RESPONSE_BYTES,
    HistorySelection,
    InventorySelection,
    ReadMethod,
    RepliesSelection,
    SlackAccount,
)


class Reply:
    def __init__(
        self, status: int = 200, headers: dict[str, str] | None = None, body: bytes = b'{"ok":true}'
    ) -> None:
        self.status = status
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.body = body
        self.reads = 0

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, amount: int) -> bytes:
        self.reads += 1
        return self.body[:amount]


class Connection:
    def __init__(self, reply: Reply) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.closed = False

    def request(self, method: str, url: str, body: bytes, headers: dict[str, str]) -> None:
        self.calls.append((method, url, body, headers))

    def getresponse(self) -> Reply:
        return self.reply

    def close(self) -> None:
        self.closed = True


KEY = SecretStr("invented-key")
ACCOUNT = SlackAccount(team_id="TTEST", user_id="UTEST")
HISTORY = HistorySelection(
    account=ACCOUNT, channel_id="CTEST", oldest="100.000001", latest="200.000001"
)


def test_fixed_read_methods_and_no_stored_key() -> None:
    connection = Connection(Reply(headers={"X-OAuth-Scopes": "channels:read,groups:history"}))
    client = SlackReadTransport(connection_factory=lambda: connection)
    result = client.account_reply(KEY)
    client.inventory_reply(KEY, InventorySelection(account=ACCOUNT))
    client.history_reply(KEY, HISTORY)
    client.replies_reply(KEY, RepliesSelection(**HISTORY.model_dump(), parent_ts="100.000001"))
    assert [call[1] for call in connection.calls] == [
        "/api/" + method.value for method in ReadMethod
    ]
    assert all(call[0] == "POST" for call in connection.calls)
    assert json.loads(connection.calls[1][2])["exclude_archived"] is False
    assert json.loads(connection.calls[2][2])["oldest"] == "100.000001"
    assert result.declared_scopes == frozenset({"channels:read", "groups:history"})
    assert "invented-key" not in repr(client.__dict__)
    assert connection.closed


@pytest.mark.parametrize(
    "key", ["", "bad\r\nAuthorization: leak", "bad key", "nonasciié", "x" * 4097]
)
def test_bad_key_before_connection(key: str) -> None:
    def forbidden() -> Connection:
        pytest.fail("connection must not be created")

    with pytest.raises(SlackTransportError) as error:
        SlackReadTransport(connection_factory=forbidden).account_reply(SecretStr(key))
    assert error.value.__context__ is None


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 403, 500])
def test_status_no_redirect_or_error_body_read(status: int) -> None:
    reply = Reply(status=status, headers={"Location": "https://attacker.invalid"})
    connection = Connection(reply)
    with pytest.raises(SlackTransportError):
        SlackReadTransport(connection_factory=lambda: connection).account_reply(KEY)
    assert len(connection.calls) == 1 and reply.reads == 0 and connection.closed


def test_throttle_no_retry_and_sanitized_header() -> None:
    reply = Reply(status=429, headers={"Retry-After": "60"})
    connection = Connection(reply)
    with pytest.raises(SlackThrottleError) as error:
        SlackReadTransport(connection_factory=lambda: connection).account_reply(KEY)
    assert error.value.retry_after_seconds == 60
    assert error.value.__context__ is None
    assert len(connection.calls) == 1 and reply.reads == 0


@pytest.mark.parametrize("retry", ["0", "-1", "86401", "private\nsecret", "1.5", ""])
def test_bad_throttle_header_not_exposed(retry: str) -> None:
    with pytest.raises(SlackTransportError) as error:
        SlackReadTransport(
            connection_factory=lambda: Connection(Reply(429, {"Retry-After": retry}))
        ).account_reply(KEY)
    assert type(error.value) is SlackTransportError
    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/html"},
        {"Content-Encoding": "gzip"},
        {"Content-Length": str(MAX_RESPONSE_BYTES + 1)},
        {"Content-Length": "-1"},
        {"X-OAuth-Scopes": "channels:read\nprivate"},
        {"X-OAuth-Scopes": "x" * 8193},
    ],
)
def test_rejected_headers_before_body_read(headers: dict[str, str]) -> None:
    reply = Reply(headers=headers)
    with pytest.raises(SlackTransportError):
        SlackReadTransport(connection_factory=lambda: Connection(reply)).account_reply(KEY)
    assert reply.reads == 0


@pytest.mark.parametrize(
    "body,headers",
    [
        (b"", {}),
        (b"x" * (MAX_RESPONSE_BYTES + 1), {}),
        (b"short", {"Content-Length": "100"}),
    ],
)
def test_size_and_truncation(body: bytes, headers: dict[str, str]) -> None:
    with pytest.raises(SlackTransportError):
        SlackReadTransport(
            connection_factory=lambda: Connection(Reply(body=body, headers=headers))
        ).account_reply(KEY)


def test_exception_private_content_not_chained() -> None:
    def broken() -> Connection:
        raise RuntimeError("invented-key private-response")

    with pytest.raises(SlackTransportError) as error:
        SlackReadTransport(connection_factory=broken).account_reply(KEY)
    assert error.value.__context__ is None
    assert str(error.value) == "Slack transport failed"


def test_arbitrary_url_not_method() -> None:
    with pytest.raises(SlackTransportError):
        SlackReadTransport()._post(KEY, "https://attacker.invalid", {})  # type: ignore[arg-type]


def test_default_tls_fixed_host_no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid")
    with patch("zacai.connectors.slack_transport.http.client.HTTPSConnection") as connection:
        _connect()
    args, kwargs = connection.call_args
    assert args == ("slack.com",)
    assert kwargs["port"] == 443 and kwargs["timeout"] == 20
    context = kwargs["context"]
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
