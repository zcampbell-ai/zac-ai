"""Nominal write adapter with disposable encrypted approvals and invented TLS IO."""

from __future__ import annotations

import base64
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from tests.test_account_preflight import Fixture as Reads
from tests.test_account_preflight import Response as ReadResponse
from tests.test_account_preflight import gmail_identity
from tests.test_connector_authority import TOKEN, ledger_row, read_plan, send_plan
from tests.test_connector_authority import Fixture as Authority
from tests.test_oauth_exchange import Response
from zacai.connectors.account_preflight import Provider
from zacai.connectors.approved_communications import (
    CommunicationCancellationHoldUnconfirmed,
    CommunicationCancelledUncertain,
    CommunicationError,
    CommunicationHoldUnconfirmed,
    CommunicationUncertain,
    execute_approved,
    prepare_payload,
)
from zacai.connectors.communication_transport import (
    ApprovedWriteTransport,
    CommunicationTransportError,
)
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.connectors.slack_wire import SlackAccount

PRIVATE = "invented-private-transport-detail"


class Connection:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.closed = False

    def request(self, method: str, route: str, body: bytes, headers: dict[str, str]) -> None:
        f = self.fixture
        assert ledger_row(f.authority, f.plan)["state"] == "in_flight"
        assert ledger_row(f.authority, f.plan)["loaded"] is True
        assert len(f.reads.calls) == 1
        f.writes.append((method, route, body, headers))
        if f.failure:
            raise f.failure

    def getresponse(self) -> Response:
        if self.fixture.revoke_after_ack:
            self.fixture.authority.sessions.revoke(self.fixture.authority.cookie)
        return self.fixture.response

    def close(self) -> None:
        self.closed = True


class Fixture:
    def __init__(
        self, temporary: Path, provider: Provider = Provider.GMAIL, *, reply: bool = False
    ) -> None:
        self.authority = Authority(temporary)
        fields: dict[str, Any] = {"provider": provider}
        if provider is Provider.GMAIL:
            fields.update(
                to=("one@example.invalid", "two@example.invalid"),
                cc=("cc@example.invalid",),
                text="Invented exact body\nSecond line",
            )
            if reply:
                fields.update(
                    gmail_thread_id="invented-parent-thread",
                    in_reply_to="<invented-parent@example.invalid>",
                    references=("<invented-parent@example.invalid>",),
                )
            identity = gmail_identity()
            self.response = Response(
                {
                    "id": "invented-message",
                    "threadId": "invented-parent-thread" if reply else "invented-thread",
                }
            )
        else:
            account = SlackAccount(team_id="TTEST", user_id="UTEST")
            fields.update(
                subject_id=account.user_id,
                to=(),
                subject="",
                slack_account=account,
                channel_id="CTEST",
                text="Invented <!channel> <@UTEST> & literal",
            )
            if reply:
                fields.update(thread_ts="120.000000")
            identity = ReadResponse(
                {
                    "ok": True,
                    "team_id": account.team_id,
                    "user_id": account.user_id,
                    "url": "https://invented.slack.com",
                    "team": "invented",
                    "user": "invented",
                },
                scopes=frozenset(
                    {
                        "channels:read",
                        "channels:history",
                        "groups:read",
                        "groups:history",
                        "users:read",
                        "chat:write",
                    }
                ),
            )
            value: dict[str, Any] = {"ok": True, "channel": "CTEST", "ts": "123.000001"}
            if reply:
                value["message"] = {"thread_ts": "120.000000"}
            self.response = Response(value)
        self.plan = send_plan(**fields)
        if provider is Provider.SLACK:
            from dataclasses import replace

            identity.scopes = self.plan.scopes
            original_credential = self.authority.backend.credential

            def slack_user_credential(plan: Any, generation: str) -> Any:
                return replace(original_credential(plan, generation), token_kind="slack_user")

            self.authority.backend.credential = slack_user_credential
        self.authority.approve(self.plan)
        self.gateway = self.authority.gateway()
        self.reads = Reads(read_plan(), [identity])
        self.writes: list[Any] = []
        self.connections: list[Connection] = []
        self.failure: BaseException | None = None
        self.revoke_after_ack = False
        self.writer = ApprovedWriteTransport(provider=provider, connection_factory=self.connect)

    def connect(self) -> Connection:
        connection = Connection(self)
        self.connections.append(connection)
        return connection

    def execute(self) -> Any:
        return execute_approved(
            self.plan,
            gateway=self.gateway,
            gmail=GmailReadTransport(connection_factory=self.reads.connect),
            slack=SlackReadTransport(connection_factory=self.reads.connect),
            writer=self.writer,
            clock=lambda: self.authority.now,
        )

    def row(self) -> Any:
        return ledger_row(self.authority, self.plan)


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    return Fixture(tmp_path)


def safe(error: BaseException) -> None:
    assert error.__cause__ is None and error.__context__ is None
    assert all(
        secret not in str(error) and secret not in repr(error) for secret in [TOKEN, PRIVATE]
    )
    current = error.__traceback__
    while current:
        frame = current.tb_frame
        if frame.f_globals.get("__name__") == "zacai.connectors.communication_transport":
            assert frame.f_code.co_name in {"call", "wrapped"}
            assert "args" not in frame.f_locals and "kwargs" not in frame.f_locals
        current = current.tb_next


@pytest.mark.parametrize("provider", [Provider.GMAIL, Provider.SLACK])
@pytest.mark.parametrize("reply", [False, True])
def test_exact_reviewed_message_one_fixed_write_after_durable_approval_and_identity(
    tmp_path: Path, provider: Provider, reply: bool
) -> None:
    f = Fixture(tmp_path, provider, reply=reply)
    result = f.execute()
    assert f.row()["state"] == "completed" and f.authority.backend.loads == 1
    assert len(f.writes) == len(f.reads.calls) == 1 and f.connections[0].closed
    method, route, body, headers = f.writes[0]
    assert method == "POST" and body == prepare_payload(f.plan)
    assert route == (
        "/gmail/v1/users/me/messages/send"
        if provider is Provider.GMAIL
        else "/api/chat.postMessage"
    )
    assert headers["Authorization"] == "Bearer " + TOKEN
    assert (
        headers["Content-Type"] == "application/json" and headers["Accept-Encoding"] == "identity"
    )
    value = json.loads(body)
    if provider is Provider.GMAIL:
        message = BytesParser(policy=policy.default).parsebytes(
            base64.urlsafe_b64decode(value["raw"])
        )
        assert str(message["To"]) == ", ".join(f.plan.to)
        assert str(message["Cc"]) == ", ".join(f.plan.cc)
        assert message.get_content().replace("\r\n", "\n").rstrip("\n") == f.plan.text
        if reply:
            assert (
                value["threadId"] == f.plan.gmail_thread_id
                and str(message["In-Reply-To"]) == f.plan.in_reply_to
            )
    else:
        assert value["text"] == "Invented &lt;!channel&gt; &lt;@UTEST&gt; &amp; literal"
        assert (
            value["reply_broadcast"] is False
            and value["unfurl_links"] is False
            and value["unfurl_media"] is False
        )
        if reply:
            assert value["thread_ts"] == f.plan.thread_ts
    assert result.provider_id
    with pytest.raises(CommunicationError):
        f.execute()
    assert len(f.writes) == 1 and f.authority.backend.loads == 1


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 429, 500])
def test_rejected_status_holds_once_without_retry_or_redirect(
    fixture: Fixture, status: int
) -> None:
    fixture.response = Response(
        {"error": PRIVATE},
        status=status,
        headers=[
            ("Content-Type", "application/json"),
            ("Location", "https://evil.example"),
            ("Retry-After", "1"),
        ],
    )
    with pytest.raises(CommunicationUncertain) as raised:
        fixture.execute()
    safe(raised.value)
    assert len(fixture.writes) == 1 and fixture.connections[0].closed
    assert fixture.row()["state"] == "held" and fixture.row()["uncertain"] is True


@pytest.mark.parametrize(
    "body",
    [
        b"x" * 65537,
        b'{"id":"x","id":"y","threadId":"t"}',
        b'{"error":"invented-private-transport-detail"}',
        b'{"id":NaN,"threadId":"t"}',
        b'{"id":"x"}',
    ],
)
def test_bounded_unique_valid_provider_receipt_or_uncertain_hold(
    fixture: Fixture, body: bytes
) -> None:
    fixture.response = Response(body)
    with pytest.raises(CommunicationUncertain) as raised:
        fixture.execute()
    safe(raised.value)
    assert (
        len(fixture.writes) == 1
        and fixture.row()["state"] == "held"
        and fixture.row()["observed"] is None
    )


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Type", "application/json"), ("content-type", "application/json")],
        [("Content-Type", "text/plain")],
        [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
        [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")],
        [
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
            ("transfer-encoding", "chunked"),
        ],
        [("Content-Type", "application/json"), ("Content-Length", "1"), ("content-length", "1")],
        [
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", "1"),
        ],
        [("Content-Type", "application/json"), ("Content-Length", "65537")],
        [("Content-Type", "application/json"), ("Location", "https://evil.example")],
    ],
)
def test_security_response_headers_fail_closed(fixture: Fixture, headers: Any) -> None:
    fixture.response.headers = headers
    with pytest.raises(CommunicationUncertain):
        fixture.execute()
    assert len(fixture.writes) == 1 and fixture.row()["state"] == "held"


@pytest.mark.parametrize("failure", ["revoked", "confirm"])
def test_valid_ack_preserved_on_postwrite_failure_no_positive_result(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    if failure == "revoked":
        fixture.revoke_after_ack = True
    else:

        def failed_confirm(plan: Any, receipt: Any) -> None:
            raise RuntimeError(PRIVATE)

        monkeypatch.setattr(fixture.gateway, "confirm", failed_confirm)
    with pytest.raises(CommunicationUncertain) as raised:
        fixture.execute()
    safe(raised.value)
    row = fixture.row()
    assert row["state"] == "held" and row["uncertain"] is True
    assert (
        row["observed"]["provider_id"] == "invented-message"
        and row["observed"]["thread_id"] == "invented-thread"
    )
    assert len(fixture.writes) == 1


@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("bad_hold", [False, True])
def test_failure_cancellation_and_unconfirmed_hold_distinct_private_safe_categories(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, cancel: bool, bad_hold: bool
) -> None:
    fixture.failure = KeyboardInterrupt(PRIVATE) if cancel else RuntimeError(PRIVATE)
    if bad_hold:

        def failed_hold(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError(PRIVATE)

        monkeypatch.setattr(fixture.gateway, "hold", failed_hold)
    category = (
        (CommunicationCancellationHoldUnconfirmed if cancel else CommunicationHoldUnconfirmed)
        if bad_hold
        else CommunicationCancelledUncertain
        if cancel
        else CommunicationUncertain
    )
    with pytest.raises(category) as raised:
        fixture.execute()
    assert type(raised.value) is category
    safe(raised.value)
    assert len(fixture.writes) == 1 and fixture.connections[0].closed


@pytest.mark.parametrize("mutation", ["payload", "provider", "plan"])
def test_direct_adapter_revalidates_exact_reviewed_payload_before_socket(
    fixture: Fixture, mutation: str
) -> None:
    plan = fixture.plan
    payload = prepare_payload(plan)
    writer = fixture.writer
    if mutation == "payload":
        payload = b'{"raw":"invented-different-payload"}'
    elif mutation == "provider":
        writer = ApprovedWriteTransport(provider=Provider.SLACK, connection_factory=fixture.connect)
    else:
        plan = plan.model_copy(update={"to": ("injected\r\nBcc: private@example.invalid",)})
    with pytest.raises(CommunicationTransportError) as raised:
        writer.send(SecretStr(TOKEN), payload, plan=plan)
    safe(raised.value)
    assert not fixture.connections and not fixture.writes


@pytest.mark.parametrize(
    "metadata",
    [
        {"warning": "message_truncated"},
        {"response_metadata": {"warnings": ["message_truncated"]}},
        {"warning": 37},
        {"response_metadata": {"warnings": "malformed"}},
        {"response_metadata": None},
    ],
)
def test_slack_valid_receipt_with_warning_or_malformed_warning_is_held_with_observed_ids(
    tmp_path: Path,
    metadata: Any,
) -> None:
    f = Fixture(tmp_path, Provider.SLACK)
    value = json.loads(f.response.body)
    value.update(metadata)
    f.response.body = json.dumps(value).encode()
    with pytest.raises(CommunicationUncertain) as raised:
        f.execute()
    safe(raised.value)
    row = f.row()
    assert row["state"] == "held" and row["uncertain"] is True
    assert row["observed"]["provider_id"] == "123.000001"
    assert row["observed"]["thread_id"] == "123.000001"
    assert len(f.writes) == 1


@pytest.mark.parametrize("truncated", [False, True])
def test_real_http_client_chunk_decoder_accepts_complete_and_holds_incomplete_reply(
    fixture: Fixture, truncated: bool
) -> None:
    import http.client
    import io

    body = fixture.response.body
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    wire += format(len(body), "x").encode() + b"\r\n" + body + b"\r\n"
    wire += b"" if truncated else b"0\r\n\r\n"

    class Socket:
        def makefile(self, *args: Any, **kwargs: Any) -> Any:
            return io.BytesIO(wire)

    response = http.client.HTTPResponse(Socket())
    response.begin()
    fixture.response = response
    if truncated:
        with pytest.raises(CommunicationUncertain):
            fixture.execute()
        assert fixture.row()["state"] == "held" and fixture.row()["observed"] is None
    else:
        assert fixture.execute().provider_id == "invented-message"
        assert fixture.row()["state"] == "completed"
    assert len(fixture.writes) == 1 and fixture.connections[0].closed


@pytest.mark.parametrize(
    "provider,host", [(Provider.GMAIL, "gmail.googleapis.com"), (Provider.SLACK, "slack.com")]
)
def test_inert_default_writer_direct_tls_fixed_host_no_proxy_or_socket(
    provider: Provider, host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zacai.connectors import communication_transport as module

    opened = []

    class Context:
        def set_alpn_protocols(self, protocols: Any) -> None:
            assert protocols == ["http/1.1"]

    def fake_https(selected: str, **options: Any) -> Any:
        opened.append((selected, options))
        return object()

    monkeypatch.setenv("HTTPS_PROXY", "https://invented-proxy.example")
    monkeypatch.setenv("ALL_PROXY", "https://invented-proxy.example")
    monkeypatch.setattr(module.ssl, "create_default_context", Context)
    monkeypatch.setattr(module.http.client, "HTTPSConnection", fake_https)
    ApprovedWriteTransport(provider=provider)
    assert not opened
    module._connect(provider)
    assert opened[0][0] == host
    assert opened[0][1]["port"] == 443 and opened[0][1]["timeout"] == 20


def test_actual_owner_revocation_before_execution_never_loads_reads_or_writes(
    fixture: Fixture,
) -> None:
    fixture.authority.sessions.revoke(fixture.authority.cookie)
    with pytest.raises(CommunicationError):
        fixture.execute()
    assert fixture.authority.backend.loads == 0
    assert not fixture.reads.calls and not fixture.connections and not fixture.writes


@pytest.mark.parametrize("provider", [Provider.GMAIL, Provider.SLACK])
def test_actual_nominal_writer_never_opens_after_wrong_identity_or_scope_evidence(
    tmp_path: Path, provider: Provider
) -> None:
    f = Fixture(tmp_path, provider)
    if provider is Provider.GMAIL:
        f.reads.responses[0] = ReadResponse(
            {
                "emailAddress": "other@example.invalid",
                "messagesTotal": 0,
                "threadsTotal": 0,
                "historyId": "123",
            }
        )
    else:
        f.reads.responses[0].scopes = frozenset({"chat:write"})
    with pytest.raises(CommunicationError) as raised:
        f.execute()
    safe(raised.value)
    assert f.authority.backend.loads == 1 and len(f.reads.calls) == 1
    assert not f.connections and not f.writes
    assert f.row()["state"] == "held" and f.row()["observed"] is None
