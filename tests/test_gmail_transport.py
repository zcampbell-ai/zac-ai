"""Invented keys/mail and fake connections only; never actual sockets or accounts."""

import base64
import json
import ssl
from dataclasses import replace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretStr

from zacai.connectors import gmail_transport as module
from zacai.connectors.gmail_wire import MAX_WIRE_BYTES, GmailScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

KEY = SecretStr("invented-token")
SCOPE = GmailScope(
    "invented",
    "invented@example.test",
    B.BRAINSTORM,
    C.CONFIDENTIAL,
    frozenset({B.BRAINSTORM}),
    frozenset({C.CONFIDENTIAL}),
)


class Reply:
    def __init__(self, value=None, *, status=200, headers=None, raw=None):
        self.status = status
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.body = json.dumps(value or {}).encode() if raw is None else raw
        self.reads = []

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, amount):
        self.reads.append(amount)
        return self.body[:amount]


class Connection:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []
        self.closed = False

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))

    def getresponse(self):
        return self.reply

    def close(self):
        self.closed = True


def client(reply):
    connection = Connection(reply)
    return module.GmailReadTransport(connection_factory=lambda: connection), connection


def profile():
    return {
        "emailAddress": "invented@example.test",
        "historyId": "5",
        "messagesTotal": 12,
        "threadsTotal": 6,
    }


def test_profile_route_parses_declared_account_without_grant():
    transport, connection = client(Reply(profile()))
    result = transport.profile_reply(KEY, scope=SCOPE)
    assert connection.calls[0][:3] == ("GET", "/gmail/v1/users/me/profile", None)
    assert result.inspection.value.reported_messages == 12
    assert not result.inspection.account_ownership_verified
    assert not result.inspection.capture_authorized
    assert connection.closed
    assert "invented-token" not in repr(transport.__dict__)


def test_profile_mismatch_denied_before_private_release():
    obj = profile() | {"emailAddress": "other@example.test"}
    transport, connection = client(Reply(obj))
    with pytest.raises(module.GmailTransportError) as error:
        transport.profile_reply(KEY, scope=SCOPE)
    assert error.value.__context__ is None
    assert "other" not in str(error.value)
    assert connection.closed


def test_message_list_query_encoding_fixed_me_and_read_fields():
    transport, connection = client(Reply({"messages": [{"id": "a", "threadId": "t"}]}))
    query = "from:invented@example.test after:123&format=full https://attacker.invalid"
    transport.messages_reply(
        KEY,
        scope=SCOPE,
        max_results=12,
        page_token="opaque+/=",
        label_ids=("SENT", "Label_123"),
        query=query,
    )
    method, path, body, headers = connection.calls[0]
    parts = urlsplit(path)
    assert method == "GET" and body is None
    assert not parts.scheme and not parts.netloc
    assert parts.path == "/gmail/v1/users/me/messages"
    assert parse_qs(parts.query) == {
        "maxResults": ["12"],
        "includeSpamTrash": ["false"],
        "pageToken": ["opaque+/="],
        "labelIds": ["SENT", "Label_123"],
        "q": [query],
    }
    assert headers == {
        "Authorization": "Bearer invented-token",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }


def test_raw_message_only_fixed_format_preserves_original_and_repr_privacy():
    original = b"From: invented@example.test\r\n\r\ninvented private body\xff"
    reply = Reply(
        {
            "id": "abc",
            "threadId": "thread",
            "historyId": "5",
            "internalDate": "1000",
            "raw": base64.urlsafe_b64encode(original).decode(),
        }
    )
    transport, connection = client(reply)
    result = transport.raw_message_reply(KEY, scope=SCOPE, message_id="abc")
    assert connection.calls[0][1] == "/gmail/v1/users/me/messages/abc?format=raw"
    assert result.inspection.value.original_bytes == original
    assert "private body" not in repr(result)
    assert "response_bytes=" not in repr(result)
    assert reply.reads == [MAX_WIRE_BYTES + 1]


def test_history_route_noncontiguous_ids_and_no_complete_claim():
    transport, connection = client(Reply({"historyId": "999", "history": []}))
    result = transport.history_reply(KEY, scope=SCOPE, start_history_id="1", page_token="opaque")
    assert parse_qs(urlsplit(connection.calls[0][1]).query) == {
        "startHistoryId": ["1"],
        "maxResults": ["100"],
        "pageToken": ["opaque"],
    }
    assert not result.inspection.completeness_verified


@pytest.mark.parametrize(
    "scope",
    [
        replace(SCOPE, boundary=B.PERSONAL),
        replace(SCOPE, boundary=B.SHARED),
        replace(SCOPE, allowed_classifications=frozenset()),
        replace(SCOPE, classification=C.HIGHLY_RESTRICTED),
    ],
)
def test_policy_denial_before_connection(scope):
    def forbidden():
        pytest.fail("socket factory must not be called")

    transport = module.GmailReadTransport(connection_factory=forbidden)
    with pytest.raises(module.GmailTransportError):
        transport.messages_reply(KEY, scope=scope)


@pytest.mark.parametrize("key", ["", "bad key", "private\r\nHeader: injected", "é", "x" * 4097])
def test_bad_token_before_connection(key):
    def forbidden():
        pytest.fail("socket factory must not be called")

    with pytest.raises(module.GmailTransportError) as error:
        module.GmailReadTransport(connection_factory=forbidden).profile_reply(
            SecretStr(key), scope=SCOPE
        )
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_results": True},
        {"max_results": 0},
        {"max_results": 501},
        {"page_token": "private\n"},
        {"page_token": "x" * 4097},
        {"label_ids": ("SENT", "SENT")},
        {"label_ids": ("../private",)},
        {"label_ids": ["SENT"]},
        {"query": ""},
        {"query": "x" * 1025},
        {"query": "private\n"},
        {"include_spam_trash": 1},
    ],
)
def test_bad_collection_selection_before_connection(kwargs):
    def forbidden():
        pytest.fail("socket factory must not be called")

    with pytest.raises(module.GmailTransportError):
        module.GmailReadTransport(connection_factory=forbidden).messages_reply(
            KEY, scope=SCOPE, **kwargs
        )


@pytest.mark.parametrize(
    "message_id", ["../private", "x?alt=media", "https://evil.invalid", "", "x" * 201]
)
def test_no_arbitrary_message_path(message_id):
    def forbidden():
        pytest.fail("socket factory must not be called")

    with pytest.raises(module.GmailTransportError):
        module.GmailReadTransport(connection_factory=forbidden).raw_message_reply(
            KEY, scope=SCOPE, message_id=message_id
        )


@pytest.mark.parametrize("start", ["abc", 1, "", "1&labelId=other", "1" * 31])
def test_bad_history_selection_before_connection(start):
    def forbidden():
        pytest.fail("socket factory must not be called")

    with pytest.raises(module.GmailTransportError):
        module.GmailReadTransport(connection_factory=forbidden).history_reply(
            KEY, scope=SCOPE, start_history_id=start
        )


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 403, 404, 500])
def test_status_no_redirect_retry_or_error_body_read(status):
    reply = Reply(status=status, headers={"Location": "https://attacker.invalid"})
    transport, connection = client(reply)
    with pytest.raises(module.GmailTransportError):
        transport.messages_reply(KEY, scope=SCOPE)
    assert reply.reads == []
    assert len(connection.calls) == 1
    assert connection.closed


def test_history_404_is_review_signal_only_and_no_response_body_read():
    reply = Reply(status=404)
    transport, connection = client(reply)
    with pytest.raises(module.GmailHistoryExpired) as error:
        transport.history_reply(KEY, scope=SCOPE, start_history_id="1")
    assert not error.value.rescan_authorized
    assert error.value.__context__ is None
    assert reply.reads == [] and connection.closed


def test_throttle_is_bounded_host_signal_only():
    reply = Reply(status=429, headers={"Retry-After": "30"})
    transport, connection = client(reply)
    with pytest.raises(module.GmailThrottleError) as error:
        transport.messages_reply(KEY, scope=SCOPE)
    assert error.value.retry_after_seconds == 30
    assert error.value.__context__ is None
    assert reply.reads == [] and len(connection.calls) == 1


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/html"},
        {"Content-Encoding": "gzip"},
        {"Content-Length": str(MAX_WIRE_BYTES + 1)},
        {"Content-Length": "-1"},
        {"Content-Length": "private"},
    ],
)
def test_invalid_headers_rejected_before_body_read(headers):
    reply = Reply(headers=headers)
    transport, connection = client(reply)
    with pytest.raises(module.GmailTransportError):
        transport.messages_reply(KEY, scope=SCOPE)
    assert reply.reads == [] and connection.closed


@pytest.mark.parametrize(
    "raw,headers",
    [
        (b"", {}),
        (b"x" * (MAX_WIRE_BYTES + 1), {}),
        (b"{}", {"Content-Length": "3"}),
        (b"not json private body", {}),
        (b'{"error":{"message":"private"}}', {}),
    ],
)
def test_size_truncation_and_malformed_error_payload_fail_closed(raw, headers):
    reply = Reply(raw=raw, headers=headers)
    transport, connection = client(reply)
    with pytest.raises(module.GmailTransportError) as error:
        transport.messages_reply(KEY, scope=SCOPE)
    assert reply.reads == [MAX_WIRE_BYTES + 1]
    assert connection.closed and error.value.__context__ is None
    assert "private" not in str(error.value)


def test_stalled_page_and_over_request_page_rejected():
    for value, kwargs in [
        ({"nextPageToken": "same"}, {"page_token": "same"}),
        (
            {"messages": [{"id": "a", "threadId": "t"}, {"id": "b", "threadId": "t"}]},
            {"max_results": 1},
        ),
    ]:
        transport, _ = client(Reply(value))
        with pytest.raises(module.GmailTransportError):
            transport.messages_reply(KEY, scope=SCOPE, **kwargs)


def test_private_connection_exception_is_sanitized_and_connection_closed():
    transport, connection = client(Reply())

    def fail():
        raise RuntimeError("invented private token/provider diagnostics")

    connection.getresponse = fail
    with pytest.raises(module.GmailTransportError) as error:
        transport.messages_reply(KEY, scope=SCOPE)
    assert error.value.__context__ is None
    assert "diagnostics" not in str(error.value)
    assert connection.closed


def test_default_tls_host_validation_and_no_proxy_lookup(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid")
    with patch.object(module.http.client, "HTTPSConnection") as constructor:
        module._connect()
    args, kwargs = constructor.call_args
    assert args == ("gmail.googleapis.com",)
    assert kwargs["port"] == 443 and kwargs["timeout"] == 20
    assert kwargs["context"].check_hostname
    assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED


def test_scope_duck_check_never_runs_and_never_opens_connection():
    from types import SimpleNamespace

    checked = []
    duck = SimpleNamespace(
        check=lambda: checked.append(True),
        account_ref="invented",
        boundary=B.SHARED,
        classification=C.HIGHLY_RESTRICTED,
    )

    def forbidden():
        pytest.fail("socket factory must not be called")

    with pytest.raises(module.GmailTransportError) as error:
        module.GmailReadTransport(connection_factory=forbidden).messages_reply(KEY, scope=duck)
    assert checked == []
    assert error.value.__context__ is None


def test_scope_subclass_cannot_override_gate_before_connection():
    class BadScope(GmailScope):
        def check(self):
            pytest.fail("overridden scope gate must not run")

    forged = BadScope(
        "invented", "invented@example.test", B.SHARED, C.HIGHLY_RESTRICTED, frozenset(), frozenset()
    )

    def forbidden():
        pytest.fail("socket factory must not be called")

    with pytest.raises(module.GmailTransportError):
        module.GmailReadTransport(connection_factory=forbidden).messages_reply(KEY, scope=forged)


def test_history_requested_bound_counts_records_even_without_changes():
    transport, connection = client(Reply({"historyId": "4", "history": [{"id": "2"}, {"id": "3"}]}))
    with pytest.raises(module.GmailTransportError) as error:
        transport.history_reply(KEY, scope=SCOPE, start_history_id="1", max_results=1)
    assert error.value.__context__ is None
    assert connection.closed


def test_history_one_record_can_contain_multiple_changes_within_global_cap():
    rows = [{"message": {"id": "a", "threadId": "t"}}, {"message": {"id": "b", "threadId": "t"}}]
    transport, _ = client(
        Reply({"historyId": "3", "history": [{"id": "2", "messagesAdded": rows}]})
    )
    result = transport.history_reply(KEY, scope=SCOPE, start_history_id="1", max_results=1)
    assert len(result.inspection.value.changes) == 2
