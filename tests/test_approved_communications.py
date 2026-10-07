"""Invented offline acceptance only: no network, accounts or persistence."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from typing import Any
from uuid import uuid4

import pytest
from pydantic import SecretStr

from zacai.connectors.account_preflight import Provider, VerifiedCredential
from zacai.connectors.approved_communications import (
    CommunicationCancellationHoldUnconfirmed,
    CommunicationCancelled,
    CommunicationCancelledUncertain,
    CommunicationError,
    CommunicationPlan,
    SyntheticWriteTransport,
    execute_approved,
    prepare_payload,
)
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.connectors.slack_wire import SlackAccount
from zacai.policy import DataClassification, TrustBoundary

NOW = datetime(2026, 10, 6, tzinfo=UTC)
SECRET = "invented-secret-never-display"
ACCOUNT = SlackAccount(team_id="TTEST", user_id="UTEST")


def plan(provider: Provider = Provider.GMAIL, **changes: Any) -> CommunicationPlan:
    fields: dict[str, Any] = {
        "attempt_id": uuid4(),
        "provider": provider,
        "client_id": "invented-client",
        "subject_id": "invented-subject" if provider is Provider.GMAIL else "UTEST",
        "purpose": "Invented test communication",
        "text": "Please review the invented example.",
        "data_boundary": TrustBoundary.BRAINSTORM,
        "classification": DataClassification.INTERNAL,
    }
    if provider is Provider.GMAIL:
        fields.update(
            to=("recipient@example.invalid",),
            cc=("reviewer@example.invalid",),
            subject="Invented example",
        )
    else:
        fields.update(slack_account=ACCOUNT, channel_id="CTEST")
    fields.update(changes)
    return CommunicationPlan(**fields)


class Gateway:
    def __init__(self, selected: CommunicationPlan) -> None:
        self.approved = selected
        self.digest = hashlib.sha256(prepare_payload(selected)).hexdigest()
        self.value = VerifiedCredential(
            SecretStr(SECRET),
            selected.provider,
            selected.client_id,
            selected.subject_id,
            selected.scopes,
            "oauth_access" if selected.provider is Provider.GMAIL else "slack_user",
            TrustBoundary.BRAINSTORM,
            NOW + timedelta(hours=1),
        )
        self.consumed: set[object] = set()
        self.events: list[str] = []
        self.holds: list[bool] = []
        self.receipts: list[Any] = []
        self.observed: list[Any] = []
        self.checks = 0
        self.revoke_at: int | None = None
        self.fail_load = self.fail_hold = self.fail_confirm = False

    def consume_exact(self, selected: CommunicationPlan, payload_digest: str) -> None:
        self.events.append("consume")
        if (
            selected != self.approved
            or payload_digest != self.digest
            or selected.attempt_id in self.consumed
        ):
            raise RuntimeError(SECRET)
        self.consumed.add(selected.attempt_id)

    def assert_current(self, selected: CommunicationPlan, payload_digest: str) -> None:
        self.events.append("current")
        self.checks += 1
        if (
            selected != self.approved
            or payload_digest != self.digest
            or self.revoke_at is not None
            and self.checks >= self.revoke_at
        ):
            raise RuntimeError(SECRET)

    def credential(self, selected: CommunicationPlan) -> VerifiedCredential:
        self.events.append("credential")
        assert selected.attempt_id in self.consumed
        if self.fail_load:
            raise RuntimeError(SECRET)
        return self.value

    def hold(self, selected: CommunicationPlan, *, uncertain: bool, observed: Any) -> None:
        self.events.append("hold")
        self.holds.append(uncertain)
        self.observed.append(observed)
        if self.fail_hold:
            raise RuntimeError(SECRET)

    def confirm(self, selected: CommunicationPlan, receipt: Any) -> None:
        self.events.append("confirm")
        if self.fail_confirm:
            raise RuntimeError(SECRET)
        self.receipts.append(receipt)


class Response:
    status = 200

    def __init__(self, body: dict[str, Any], scopes: frozenset[str] | None) -> None:
        self.body, self.scopes = json.dumps(body).encode(), scopes

    def getheader(self, name: str) -> str | None:
        if name == "Content-Type":
            return "application/json"
        if name == "X-OAuth-Scopes" and self.scopes is not None:
            return ",".join(sorted(self.scopes))
        return None

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class Fixture:
    def __init__(self, selected: CommunicationPlan) -> None:
        self.selected = selected
        self.gateway = Gateway(selected)
        self.reads: list[str] = []
        self.writes: list[bytes] = []
        self.fail_write: BaseException | None = None
        self.after_write: Any = None
        self.response = (
            {
                "emailAddress": "zcampbell@brainstormtech.io",
                "historyId": "100",
                "messagesTotal": 1,
                "threadsTotal": 1,
            }
            if selected.provider is Provider.GMAIL
            else {"ok": True, "team_id": "TTEST", "user_id": "UTEST"}
        )
        self.response_scopes: frozenset[str] | None = selected.scopes
        self.write_response = (
            {"id": "sent123", "threadId": selected.gmail_thread_id or "thread123"}
            if selected.provider is Provider.GMAIL
            else {"ok": True, "channel": "CTEST", "ts": "1234567890.123456"}
        )

    def connect(self) -> Any:
        fixture = self

        class Connection:
            def request(self, method: str, path: str, body: Any, headers: Any) -> None:
                fixture.reads.append(path)
                fixture.gateway.events.append("identity")

            def getresponse(self) -> Response:
                return Response(fixture.response, fixture.response_scopes)

            def close(self) -> None:
                pass

        return Connection()

    def exchange(self, key: SecretStr, payload: bytes) -> bytes:
        assert key.get_secret_value() == SECRET
        self.gateway.events.append("write")
        self.writes.append(payload)
        if self.after_write:
            self.after_write()
        if self.fail_write:
            raise self.fail_write
        return json.dumps(self.write_response).encode()

    def run(self, selected: CommunicationPlan | None = None) -> Any:
        return execute_approved(
            selected or self.selected,
            gateway=self.gateway,
            gmail=GmailReadTransport(connection_factory=self.connect),
            slack=SlackReadTransport(connection_factory=self.connect),
            writer=SyntheticWriteTransport(provider=self.selected.provider, exchange=self.exchange),
            clock=lambda: NOW,
        )


@pytest.mark.parametrize("provider", list(Provider))
def test_exact_approval_identity_single_attempt_and_confirmed_receipt(provider: Provider) -> None:
    fixture = Fixture(plan(provider))
    receipt = fixture.run()
    events = fixture.gateway.events
    assert events.index("consume") < events.index("credential") < events.index("identity")
    assert events.index("identity") < events.index("write") < events.index("confirm")
    assert fixture.gateway.receipts == [receipt] and not fixture.gateway.holds
    assert fixture.writes == [prepare_payload(fixture.selected)]
    assert len(fixture.reads) == 1 and receipt.payload_digest == fixture.gateway.digest
    with pytest.raises(CommunicationError):
        fixture.run()
    assert len(fixture.writes) == len(fixture.reads) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"text": "Different wording"},
        {"to": ("other@example.invalid",)},
        {"cc": ()},
        {"subject": "Other subject"},
        {"purpose": "Other commitment"},
        {
            "gmail_thread_id": "otherthread",
            "in_reply_to": "<other@example.invalid>",
            "references": ("<other@example.invalid>",),
        },
    ],
)
def test_approval_mutation_before_credential(changes: dict[str, Any]) -> None:
    fixture = Fixture(plan())
    changed = CommunicationPlan.model_validate({**fixture.selected.model_dump(), **changes})
    with pytest.raises(CommunicationError):
        fixture.run(changed)
    assert "credential" not in fixture.gateway.events and not fixture.reads and not fixture.writes


@pytest.mark.parametrize("provider", list(Provider))
@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": frozenset()},
        {"token_kind": "refresh"},
        {"token_kind": "id_token"},
        {"client_id": "other"},
        {"subject_id": "other"},
        {"boundary": TrustBoundary.PERSONAL},
        {"expires_at": NOW},
        {"token": SecretStr("bad\nsecret")},
    ],
)
def test_invalid_credentials_no_read_or_send(provider: Provider, changes: dict[str, Any]) -> None:
    fixture = Fixture(plan(provider))
    fixture.gateway.value = replace(fixture.gateway.value, **changes)
    with pytest.raises(CommunicationError):
        fixture.run()
    assert not fixture.reads and not fixture.writes and fixture.gateway.holds == [False]


@pytest.mark.parametrize("provider", list(Provider))
def test_wrong_live_account_no_send(provider: Provider) -> None:
    fixture = Fixture(plan(provider))
    fixture.response.update(
        {"emailAddress": "other@example.invalid"}
        if provider is Provider.GMAIL
        else {"team_id": "TOTHER"}
    )
    with pytest.raises(CommunicationError):
        fixture.run()
    assert len(fixture.reads) == 1 and not fixture.writes and fixture.gateway.holds == [False]


@pytest.mark.parametrize("scopes", [None, frozenset(), frozenset({"chat:write"})])
def test_slack_scope_evidence_required(scopes: frozenset[str] | None) -> None:
    fixture = Fixture(plan(Provider.SLACK))
    fixture.response_scopes = scopes
    with pytest.raises(CommunicationError):
        fixture.run()
    assert not fixture.writes


def test_revoked_after_identity_prevents_send() -> None:
    fixture = Fixture(plan())
    original = fixture.connect

    def connect() -> Any:
        connection = original()
        getresponse = connection.getresponse

        def revoke() -> Response:
            response = getresponse()
            fixture.gateway.revoke_at = fixture.gateway.checks + 1
            return response

        connection.getresponse = revoke
        return connection

    fixture.connect = connect  # type: ignore[method-assign]
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.reads and not fixture.writes and fixture.gateway.holds == [False]


@pytest.mark.parametrize("failure", [RuntimeError(SECRET), TimeoutError(SECRET)])
@pytest.mark.parametrize("provider", list(Provider))
def test_lost_response_durably_uncertain_no_retry(
    failure: BaseException, provider: Provider
) -> None:
    fixture = Fixture(plan(provider))
    fixture.fail_write = failure
    with pytest.raises(CommunicationError) as error:
        fixture.run()
    assert len(fixture.writes) == 1 and fixture.gateway.holds == [True]
    assert not fixture.gateway.receipts and SECRET not in str(error.value)
    assert error.value.__context__ is None and error.value.__cause__ is None
    with pytest.raises(CommunicationError):
        fixture.run()
    assert len(fixture.writes) == 1


def test_post_send_revocation_no_acknowledgement() -> None:
    fixture = Fixture(plan())
    fixture.after_write = lambda: setattr(fixture.gateway, "revoke_at", fixture.gateway.checks + 1)
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and not fixture.gateway.receipts
    assert len(fixture.writes) == 1
    assert fixture.gateway.observed[0].provider_id == "sent123"
    assert fixture.gateway.observed[0].thread_id == "thread123"


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_cancelled_send_secret_safe_and_uncertain(failure: type[BaseException]) -> None:
    fixture = Fixture(plan())
    fixture.fail_write = failure(SECRET)
    with pytest.raises(CommunicationCancelled) as error:
        fixture.run()
    assert fixture.gateway.holds == [True] and len(fixture.writes) == 1
    assert SECRET not in str(error.value) and error.value.__context__ is None
    assert type(error.value) is CommunicationCancelledUncertain
    assert not isinstance(error.value, Exception)
    names = []
    frame = error.value.__traceback__
    while frame:
        names.append(frame.tb_frame.f_code.co_name)
        frame = frame.tb_next
    assert "exchange" not in names


@pytest.mark.parametrize("stage", ["fail_load", "fail_hold", "fail_confirm"])
def test_gateway_failure_safe_no_retry(stage: str) -> None:
    fixture = Fixture(plan())
    setattr(fixture.gateway, stage, True)
    if stage == "fail_hold":
        fixture.fail_write = RuntimeError(SECRET)
    with pytest.raises(CommunicationError) as error:
        fixture.run()
    assert SECRET not in str(error.value) and error.value.__context__ is None
    assert len(fixture.writes) == (0 if stage == "fail_load" else 1)
    assert not fixture.gateway.receipts


@pytest.mark.parametrize(
    "changes",
    [
        {"to": ("safe@example.invalid\r\nBcc: hidden@example.invalid",)},
        {"to": ("one@example.invalid,two@example.invalid",)},
        {"cc": ("Display <hidden@example.invalid>",)},
        {"subject": "subject\r\nBcc: hidden@example.invalid"},
        {"in_reply_to": "<id@example.invalid>\r\nBcc: hidden@example.invalid"},
        {"references": ("<id@example.invalid>\nBad: yes",)},
    ],
)
def test_header_injection_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        plan(**changes)


def test_gmail_exact_mime_reply_thread_no_provider_draft() -> None:
    selected = plan(
        gmail_thread_id="thread123",
        in_reply_to="<parent@example.invalid>",
        references=("<root@example.invalid>", "<parent@example.invalid>"),
    )
    payload = json.loads(prepare_payload(selected))
    assert set(payload) == {"raw", "threadId"} and payload["threadId"] == "thread123"
    raw = base64.urlsafe_b64decode(payload["raw"] + "=" * (-len(payload["raw"]) % 4))
    message = BytesParser(policy=policy.default).parsebytes(raw)
    assert str(message["From"]) == "zcampbell@brainstormtech.io"
    assert str(message["To"]) == "recipient@example.invalid"
    assert str(message["Cc"]) == "reviewer@example.invalid"
    assert str(message["Subject"]) == selected.subject
    assert str(message["In-Reply-To"]) == selected.in_reply_to
    assert str(message["References"]) == " ".join(selected.references)
    assert message.get_content().rstrip("\r\n") == selected.text
    assert message.get_content_type() == "text/plain" and message["Bcc"] is None
    fixture = Fixture(selected)
    fixture.run()
    assert fixture.reads == ["/gmail/v1/users/me/profile"]


def test_slack_plain_text_reply_no_broadcast_or_unfurls() -> None:
    selected = plan(Provider.SLACK, thread_ts="1234567890.000001")
    payload = json.loads(prepare_payload(selected))
    assert payload["channel"] == "CTEST" and payload["text"] == selected.text
    assert payload["thread_ts"] == selected.thread_ts and payload["mrkdwn"] is False
    assert payload["unfurl_links"] is False and payload["unfurl_media"] is False
    assert payload.get("reply_broadcast", False) is False
    assert not ({"blocks", "attachments", "username", "icon_url", "link_names"} & payload.keys())


@pytest.mark.parametrize(
    "changes",
    [
        {"channel_id": "https://evil.invalid/api"},
        {"thread_ts": "123\n456"},
        {"to": ("recipient@example.invalid",)},
        {"gmail_thread_id": "thread123"},
    ],
)
def test_slack_route_and_provider_mixing_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        plan(Provider.SLACK, **changes)


def test_synthetic_writer_requires_explicit_exchange() -> None:
    with pytest.raises(TypeError):
        SyntheticWriteTransport(provider=Provider.GMAIL)


def test_forged_model_copy_revalidated_before_consumption() -> None:
    fixture = Fixture(plan())
    forged = fixture.selected.model_copy(update={"to": ("bad\nrecipient@example.invalid",)})
    with pytest.raises(CommunicationError):
        fixture.run(forged)
    assert not fixture.gateway.events and not fixture.writes


@pytest.mark.parametrize(
    "changes",
    [
        {"data_boundary": TrustBoundary.PERSONAL},
        {"classification": "HIGHLY_RESTRICTED"},
    ],
)
def test_boundary_and_restricted_content_policy_before_approval(changes: dict[str, Any]) -> None:
    selected = plan(**changes)
    fixture = Fixture(selected)
    with pytest.raises(CommunicationError):
        fixture.run()
    assert not fixture.gateway.events and not fixture.reads and not fixture.writes


@pytest.mark.parametrize("provider", list(Provider))
def test_elevated_actual_grant_never_used(provider: Provider) -> None:
    fixture = Fixture(plan(provider))
    fixture.gateway.value = replace(
        fixture.gateway.value,
        scopes=fixture.selected.scopes
        | {"https://mail.google.com/" if provider is Provider.GMAIL else "chat:write.customize"},
    )
    with pytest.raises(CommunicationError):
        fixture.run()
    assert not fixture.reads and not fixture.writes and fixture.gateway.holds == [False]


@pytest.mark.parametrize(
    "changes",
    [
        {"channel_id": "COTHER"},
        {"thread_ts": "1234567890.000002"},
        {"slack_account": SlackAccount(team_id="TOTHER", user_id="UTEST")},
    ],
)
def test_slack_exact_target_approval_cannot_change(changes: dict[str, Any]) -> None:
    fixture = Fixture(plan(Provider.SLACK, thread_ts="1234567890.000001"))
    changed = CommunicationPlan.model_validate({**fixture.selected.model_dump(), **changes})
    with pytest.raises(CommunicationError):
        fixture.run(changed)
    assert "credential" not in fixture.gateway.events and not fixture.writes


@pytest.mark.parametrize(
    "provider,payload",
    [
        (Provider.GMAIL, b'{"error":{"code":429,"message":"invented-secret"}}'),
        (Provider.SLACK, b'{"ok":false,"error":"ratelimited"}'),
        (Provider.GMAIL, b'{"id":"sent123","threadId":"thread123","id":"other"}'),
        (Provider.SLACK, b'{"ok":true,"channel":"COTHER","ts":"1234567890.123456"}'),
        (Provider.GMAIL, b'{"id":true,"threadId":"thread123"}'),
        (Provider.SLACK, b'{"ok":1,"channel":"CTEST","ts":"1234567890.123456"}'),
        (Provider.GMAIL, b""),
        (Provider.GMAIL, b"x" * 65537),
        (Provider.SLACK, b"not json"),
    ],
)
def test_invalid_or_throttled_receipt_durably_uncertain_no_retry(
    provider: Provider,
    payload: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan(provider))
    original = fixture.exchange

    def malformed(key: SecretStr, body: bytes) -> bytes:
        original(key, body)
        return payload

    monkeypatch.setattr(fixture, "exchange", malformed)
    with pytest.raises(CommunicationError) as error:
        fixture.run()
    assert len(fixture.writes) == 1 and fixture.gateway.holds == [True]
    assert not fixture.gateway.receipts and error.value.__context__ is None
    with pytest.raises(CommunicationError):
        fixture.run()
    assert len(fixture.writes) == 1


def test_wrong_gmail_reply_thread_receipt_held_uncertain() -> None:
    fixture = Fixture(
        plan(
            gmail_thread_id="thread123",
            in_reply_to="<parent@example.invalid>",
            references=("<parent@example.invalid>",),
        )
    )
    fixture.write_response["threadId"] = "otherthread"
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and not fixture.gateway.receipts


@pytest.mark.parametrize(
    "changes",
    [
        {"text": "x" * 20001},
        {"purpose": "x" * 501},
        {"to": tuple(f"person{i}@example.invalid" for i in range(51)), "cc": ()},
        {"to": ("recipient@example.invalid",), "cc": ("RECIPIENT@example.invalid",)},
        {"gmail_thread_id": "thread123"},
        {"in_reply_to": "<parent@example.invalid>"},
        {"references": ("<parent@example.invalid>",)},
    ],
)
def test_bounded_proposal_and_complete_reply_contract(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        plan(**changes)


@pytest.mark.parametrize("provider", list(Provider))
def test_payload_deterministic_preserves_plain_text_and_private_repr(provider: Provider) -> None:
    selected = plan(provider, text="  Exact text\n\nSecond line\t  ")
    assert prepare_payload(selected) == prepare_payload(selected)
    assert "Exact text" not in repr(selected) and "recipient@example.invalid" not in repr(selected)
    if provider is Provider.SLACK:
        assert json.loads(prepare_payload(selected))["text"] == selected.text
    else:
        encoded = json.loads(prepare_payload(selected))["raw"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        message = BytesParser(policy=policy.default).parsebytes(raw)
        assert message.get_content().replace("\r\n", "\n") == selected.text + "\n"


@pytest.mark.parametrize("stage", ["credential", "identity"])
def test_pre_send_cancellation_held_without_write(
    stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan())

    def cancel(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt(SECRET)

    monkeypatch.setattr(
        fixture.gateway if stage == "credential" else fixture,
        "credential" if stage == "credential" else "connect",
        cancel,
    )
    with pytest.raises(CommunicationCancelled) as error:
        fixture.run()
    assert fixture.gateway.holds == [False] and not fixture.writes
    assert SECRET not in str(error.value) and error.value.__context__ is None


def test_slack_reply_receipt_tracks_provider_confirmed_parent() -> None:
    fixture = Fixture(plan(Provider.SLACK, thread_ts="1234567888.000001"))
    fixture.write_response["message"] = {"thread_ts": fixture.selected.thread_ts}
    receipt = fixture.run()
    assert receipt.thread_id == fixture.selected.thread_ts
    assert receipt.provider_id == "1234567890.123456"


@pytest.mark.parametrize(
    "message", [None, {}, {"thread_ts": "1234567888.000002"}, {"thread_ts": True}]
)
def test_slack_reply_requires_actual_provider_thread_confirmation(message: Any) -> None:
    fixture = Fixture(plan(Provider.SLACK, thread_ts="1234567888.000001"))
    if message is not None:
        fixture.write_response["message"] = message
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and not fixture.gateway.receipts


def test_slack_root_cannot_silently_become_reply() -> None:
    fixture = Fixture(plan(Provider.SLACK))
    fixture.write_response["message"] = {"thread_ts": "1234567888.000001"}
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and not fixture.gateway.receipts


@pytest.mark.parametrize(
    "payload",
    [
        b'{"id":"sent123","threadId":"thread123","error":{"message":"secret"}}',
        b'{"id":"sent123","threadId":"thread123","extra":NaN}',
        b'{"id":"sent123","threadId":"thread123","extra":Infinity}',
    ],
)
def test_gmail_ambiguous_error_or_nonfinite_receipt_never_confirmed(
    payload: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan())
    original = fixture.exchange

    def malformed(key: SecretStr, body: bytes) -> bytes:
        original(key, body)
        return payload

    monkeypatch.setattr(fixture, "exchange", malformed)
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and not fixture.gateway.receipts


@pytest.mark.parametrize(
    "text",
    [
        "Hello <!channel>",
        "Hello <!here>",
        "Hello <!everyone>",
        "Hello <!subteam^STEST>",
        "Hello <!subteam^STEST|group>",
    ],
)
def test_slack_broadcast_control_syntax_escaped_in_exact_approved_payload(text: str) -> None:
    selected = plan(Provider.SLACK, text=text)
    fixture = Fixture(selected)
    receipt = fixture.run()
    payload = json.loads(fixture.writes[0])
    assert payload["text"] == text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    assert "<!" not in payload["text"]
    assert receipt.payload_digest == hashlib.sha256(fixture.writes[0]).hexdigest()
    assert selected.text == text


def test_slack_user_mentions_and_entities_preserve_literal_display() -> None:
    selected = plan(Provider.SLACK, text="Hello <@UTEST> & <literal>")
    payload = json.loads(prepare_payload(selected))
    assert payload["text"] == "Hello &lt;@UTEST&gt; &amp; &lt;literal&gt;"
    assert payload["parse"] == "none" and payload["mrkdwn"] is False


@pytest.mark.parametrize("field", ["data_boundary", "classification"])
def test_content_authority_classification_never_defaults(field: str) -> None:
    fields = plan().model_dump()
    del fields[field]
    with pytest.raises(ValueError):
        CommunicationPlan.model_validate(fields)


@pytest.mark.parametrize("local_length", [100, 232])
def test_long_gmail_reply_ids_raw_header_exact_without_encoded_words(local_length: int) -> None:
    # B2 predecessor RED: a 118-character ID became RFC2047 encoded under SMTP78.
    parent = "<" + "a" * local_length + "@example.invalid>"
    selected = plan(gmail_thread_id="thread123", in_reply_to=parent, references=(parent,))
    encoded = json.loads(prepare_payload(selected))["raw"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    message = BytesParser(policy=policy.compat32).parsebytes(raw)
    assert message["In-Reply-To"] == parent
    assert message["References"] == parent
    assert b"=?" not in raw.split(b"\r\n\r\n", 1)[0]
    assert len(parent) <= 250


def test_gmail_reply_id_over_250_rejected() -> None:
    parent = "<" + "a" * 233 + "@example.invalid>"
    assert len(parent) == 251
    with pytest.raises(ValueError):
        plan(gmail_thread_id="thread123", in_reply_to=parent, references=(parent,))


@pytest.mark.parametrize("field", ["to", "cc"])
def test_gmail_encoded_word_address_grammar_rejected(field: str) -> None:
    with pytest.raises(ValueError):
        plan(**{field: ("=?utf-8?q?invented?=@example.invalid",)})


@pytest.mark.parametrize("text", ["&" * 20000, "<" * 1001, "a" * 4001])
def test_oversized_escaped_slack_payload_before_consumption(text: str) -> None:
    fixture = Fixture(plan(Provider.SLACK))
    forged = fixture.selected.model_copy(update={"text": text})
    with pytest.raises(CommunicationError):
        fixture.run(forged)
    assert not fixture.gateway.events and not fixture.writes and not fixture.reads


@pytest.mark.parametrize("cancel_hold", [False, True])
@pytest.mark.parametrize("after_write", [False, True])
def test_cancellation_with_failed_hold_preserves_baseexception_and_uncertainty(
    cancel_hold: bool,
    after_write: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan())

    def cancel(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt(SECRET)

    def failed_hold(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt(SECRET) if cancel_hold else RuntimeError(SECRET)

    if after_write:
        fixture.fail_write = KeyboardInterrupt(SECRET)
    else:
        monkeypatch.setattr(fixture.gateway, "credential", cancel)
    monkeypatch.setattr(fixture.gateway, "hold", failed_hold)
    with pytest.raises(CommunicationCancelled) as error:
        fixture.run()
    assert type(error.value) is CommunicationCancellationHoldUnconfirmed
    assert not isinstance(error.value, Exception)
    assert SECRET not in str(error.value) and error.value.__context__ is None
    assert len(fixture.writes) == int(after_write)


def test_confirm_failure_retains_observed_provider_acknowledgment() -> None:
    fixture = Fixture(plan())
    fixture.gateway.fail_confirm = True
    with pytest.raises(CommunicationError):
        fixture.run()
    assert not fixture.gateway.receipts and fixture.gateway.holds == [True]
    assert fixture.gateway.observed[0].provider_id == "sent123"
    assert fixture.gateway.observed[0].thread_id == "thread123"


@pytest.mark.parametrize("provider,field", [(Provider.GMAIL, "id"), (Provider.SLACK, "ts")])
def test_finite_float_provider_identifier_never_confirmed(provider: Provider, field: str) -> None:
    fixture = Fixture(plan(provider))
    fixture.write_response[field] = 1.5
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and fixture.gateway.observed == [None]
    assert not fixture.gateway.receipts


def test_interrupted_hold_retains_cancellation_class_for_regular_send_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan())
    fixture.fail_write = RuntimeError(SECRET)

    def cancelled_hold(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt(SECRET)

    monkeypatch.setattr(fixture.gateway, "hold", cancelled_hold)
    with pytest.raises(CommunicationCancellationHoldUnconfirmed) as error:
        fixture.run()
    assert error.value.uncertain is True
    assert not isinstance(error.value, Exception) and len(fixture.writes) == 1
    assert SECRET not in str(error.value) and error.value.__context__ is None


def test_gmail_exact_complex_plain_address_roundtrip() -> None:
    selected = plan(to=("first+tag@example.invalid",), cc=("o'brien@example.invalid",))
    encoded = json.loads(prepare_payload(selected))["raw"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    message = BytesParser(policy=policy.compat32).parsebytes(raw)
    assert message["To"] == "first+tag@example.invalid"
    assert message["Cc"] == "o'brien@example.invalid"


def test_exponent_overflow_json_number_receipt_never_confirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan())
    original = fixture.exchange

    def overflow(key: SecretStr, body: bytes) -> bytes:
        original(key, body)
        return b'{"id":"sent123","threadId":"thread123","extra":1e400}'

    monkeypatch.setattr(fixture, "exchange", overflow)
    with pytest.raises(CommunicationError):
        fixture.run()
    assert fixture.gateway.holds == [True] and fixture.gateway.observed == [None]
    assert not fixture.gateway.receipts


def test_slack_revocation_after_reply_ack_retains_observed_parent() -> None:
    fixture = Fixture(plan(Provider.SLACK, thread_ts="1234567888.000001"))
    fixture.write_response["message"] = {"thread_ts": fixture.selected.thread_ts}
    fixture.after_write = lambda: setattr(fixture.gateway, "revoke_at", fixture.gateway.checks + 1)
    with pytest.raises(CommunicationError):
        fixture.run()
    observed = fixture.gateway.observed[0]
    assert observed.provider_id == "1234567890.123456"
    assert observed.thread_id == "1234567888.000001"
    assert not fixture.gateway.receipts and fixture.gateway.holds == [True]


def test_gmail_cancelled_after_ack_preserves_observation_and_uncertainty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan())
    original = fixture.gateway.assert_current

    def cancel_after_write(*args: Any, **kwargs: Any) -> None:
        if fixture.writes:
            raise KeyboardInterrupt(SECRET)
        original(*args, **kwargs)

    monkeypatch.setattr(fixture.gateway, "assert_current", cancel_after_write)
    with pytest.raises(CommunicationCancelledUncertain) as error:
        fixture.run()
    assert error.value.uncertain is True and not isinstance(error.value, Exception)
    assert fixture.gateway.observed[0].provider_id == "sent123"
    assert fixture.gateway.holds == [True] and not fixture.gateway.receipts


def test_gmail_multiple_long_reference_ids_fold_between_exact_ids() -> None:
    references = tuple(f"<m{i}-" + "a" * 179 + "@example.invalid>" for i in range(5))
    assert all(len(value) == 200 for value in references)
    selected = plan(gmail_thread_id="thread123", in_reply_to=references[-1], references=references)
    encoded = json.loads(prepare_payload(selected))["raw"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    message = BytesParser(policy=policy.compat32).parsebytes(raw)
    assert " ".join(message["References"].split()) == " ".join(references)
    assert message["In-Reply-To"] == references[-1]
    assert b"=?" not in raw.split(b"\r\n\r\n", 1)[0]
    assert all(len(line) <= 998 for line in raw.split(b"\r\n"))


def test_gmail_many_approved_addresses_preserve_order_when_headers_fold() -> None:
    addresses = tuple(f"person{i}" + "a" * 40 + "@example.invalid" for i in range(50))
    selected = plan(to=addresses[:30], cc=addresses[30:])
    encoded = json.loads(prepare_payload(selected))["raw"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    message = BytesParser(policy=policy.compat32).parsebytes(raw)
    assert " ".join(message["To"].split()) == ", ".join(selected.to)
    assert " ".join(message["Cc"].split()) == ", ".join(selected.cc)
    assert b"=?" not in raw.split(b"\r\n\r\n", 1)[0]
    assert all(len(line) <= 998 for line in raw.split(b"\r\n"))


def test_gmail_literal_encoded_word_subject_rejected_before_consumption() -> None:
    fixture = Fixture(plan())
    forged = fixture.selected.model_copy(update={"subject": "=?utf-8?q?Invoice_approved?="})
    with pytest.raises(CommunicationError):
        fixture.run(forged)
    assert not fixture.gateway.events and not fixture.reads and not fixture.writes
    with pytest.raises(ValueError):
        plan(subject="=?utf-8?q?Invoice_approved?=")


def test_gmail_legitimate_unicode_subject_exact_decoded_roundtrip() -> None:
    selected = plan(subject="Résumé café 東京 ✔")
    encoded = json.loads(prepare_payload(selected))["raw"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    message = BytesParser(policy=policy.default).parsebytes(raw)
    assert len(message.get_all("Subject", [])) == 1
    assert str(message["Subject"]) == selected.subject
    fixture = Fixture(selected)
    fixture.run()
    assert fixture.writes == [prepare_payload(selected)]
