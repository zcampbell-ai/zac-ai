"""Fake connections only; never opens a socket or transmits a credential."""

import json
import ssl

import pytest
from pydantic import SecretStr

from zacai.connectors import fireflies_transport as module
from zacai.connectors.fireflies_identity import ACCOUNT_QUERY
from zacai.connectors.fireflies_transport import FirefliesReadTransport, TransportError
from zacai.connectors.fireflies_wire import MAX_RESPONSE_BYTES, TRANSCRIPT_QUERY


class FakeConnection:
    def __init__(self) -> None:
        self.status = 200
        self.body = b'{"data":{"user":null}}'
        self.headers = {"Content-Type": "application/json"}
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.closed = False
        self.fail = False
        self.read_limit = 0

    def request(self, method: str, url: str, body: bytes, headers: dict[str, str]) -> None:
        self.requests.append((method, url, body, headers))
        if self.fail:
            raise OSError("synthetic credential marker")

    def getresponse(self) -> "FakeConnection":
        return self

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, amount: int) -> bytes:
        self.read_limit = amount
        return self.body[:amount]

    def close(self) -> None:
        self.closed = True


def test_queries_are_fixed_and_connections_always_close() -> None:
    connection = FakeConnection()
    transport = FirefliesReadTransport(connection_factory=lambda: connection)
    key = SecretStr("synthetic-test-only-credential")
    assert transport.account_reply(key) == connection.body
    assert json.loads(connection.requests[0][2]) == {"query": ACCOUNT_QUERY, "variables": {}}
    transport.transcript_reply(key, "synthetic-selected")
    method, path, body, headers = connection.requests[1]
    assert method == "POST" and path == "/graphql"
    assert json.loads(body) == {
        "query": TRANSCRIPT_QUERY,
        "variables": {"transcriptId": "synthetic-selected"},
    }
    assert headers["Authorization"] == "Bearer synthetic-test-only-credential"
    assert headers["Accept-Encoding"] == "identity"
    assert connection.closed and connection.read_limit == MAX_RESPONSE_BYTES + 1


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 429, 500])
def test_redirects_and_errors_do_not_retry_or_read_response(status: int) -> None:
    connection = FakeConnection()
    connection.status = status
    with pytest.raises(TransportError):
        FirefliesReadTransport(connection_factory=lambda: connection).account_reply(
            SecretStr("synthetic-test-only-credential")
        )
    assert len(connection.requests) == 1 and not connection.read_limit and connection.closed


@pytest.mark.parametrize("change", ["gzip", "html", "size", "exception"])
def test_invalid_or_failing_transport_is_sanitized(change: str) -> None:
    connection = FakeConnection()
    if change == "gzip":
        connection.headers["Content-Encoding"] = "gzip"
    elif change == "html":
        connection.headers["Content-Type"] = "text/html"
    elif change == "size":
        connection.body = b"x" * (MAX_RESPONSE_BYTES + 1)
    else:
        connection.fail = True
    with pytest.raises(TransportError) as failure:
        FirefliesReadTransport(connection_factory=lambda: connection).account_reply(
            SecretStr("synthetic-test-only-credential")
        )
    assert "credential marker" not in str(failure.value)
    assert failure.value.__suppress_context__ is True and connection.closed


@pytest.mark.parametrize("key", ["", "x\r\ny", "x y", "é", "x" * 4097])
def test_header_injection_is_rejected_before_connection(key: str) -> None:
    def connect() -> FakeConnection:
        pytest.fail("must not construct a connection")

    with pytest.raises(TransportError, match="credential format"):
        FirefliesReadTransport(connection_factory=connect).account_reply(SecretStr(key))


def test_default_destination_tls_timeout_and_proxy_ignoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "https://untrusted.example.invalid")
    observed: list[str] = []

    def connection(host: str, **kwargs: object) -> FakeConnection:
        observed.append(host)
        assert kwargs["port"] == 443 and kwargs["timeout"] == 20
        context = kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        return FakeConnection()

    monkeypatch.setattr(module.http.client, "HTTPSConnection", connection)
    FirefliesReadTransport().account_reply(SecretStr("synthetic-test-only-credential"))
    assert observed == ["api.fireflies.ai"]
