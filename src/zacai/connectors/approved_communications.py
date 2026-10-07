"""Unmounted exact-message approval seam with explicit provider-bound writers.

No mounted writes, provider drafts, credential issuer, approval issuer,
canonical store or reply importer. Injected host interfaces are trusted code,
not a security sandbox. The host must independently authenticate the owner and
attest the actual content provenance/classification, not accept caller labels.
New commitments, deliverables, recipients or scope require a newly reviewed
plan. Provider/source text cannot grant authority. Every attempt is consumed
once; uncertain outcomes require host reconciliation, never automatic retries.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import SMTP, compat32, default
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from zacai.connectors.account_preflight import (
    GMAIL_COMMUNICATION_SCOPES,
    SLACK_COMMUNICATION_SCOPES,
    Provider,
    VerifiedCredential,
)
from zacai.connectors.communication_transport import ApprovedWriteTransport
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.connectors.slack_wire import SlackAccount, prepare_account_reply
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary

_ADDRESS = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_MESSAGE_ID = re.compile(r"<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+>")
_GMAIL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_CHANNEL = re.compile(r"[CG][A-Z0-9]{2,31}")
_TIMESTAMP = re.compile(r"(?:0|[1-9][0-9]{0,11})\.[0-9]{6}")


class CommunicationError(RuntimeError):
    """Fixed diagnostic without provider prose, private content or secrets."""


class CommunicationUncertain(CommunicationError):
    """Write may have succeeded; reconcile externally before another proposal."""


class CommunicationHoldUnconfirmed(CommunicationError):
    """Hold unconfirmed; conservatively possibly sent, durable attempt stays held."""

    @property
    def uncertain(self) -> Literal[True]:
        return True


class CommunicationCancelled(BaseException):
    """Sanitized interruption; consumed attempt must remain held externally."""


class CommunicationCancelledUncertain(CommunicationCancelled):
    """Interrupted after write invocation; possibly sent, never retry."""

    @property
    def uncertain(self) -> Literal[True]:
        return True


class CommunicationCancellationHoldUnconfirmed(CommunicationCancelled):
    """Interrupted with unconfirmed hold; conservatively possibly sent."""

    @property
    def uncertain(self) -> Literal[True]:
        return True


class CommunicationPlan(BaseModel):
    """Exact proposal, not an authorization or trustworthy classification.

    Plain text only. No attachments, Bcc, Slack blocks, link expansion, DMs or
    thread broadcasts. An owner reviews every address and exact wording. Gmail
    reply context must be independently verified by the host, not inferred from
    untrusted message text. Purpose is part of approval but never sent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    attempt_id: UUID
    provider: Provider
    client_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+$")
    subject_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    purpose: str = Field(min_length=1, max_length=500, repr=False)
    data_boundary: TrustBoundary
    classification: DataClassification
    mailbox: Literal["zcampbell@brainstormtech.io"] = "zcampbell@brainstormtech.io"
    slack_account: SlackAccount | None = None
    to: tuple[str, ...] = Field(default=(), repr=False)
    cc: tuple[str, ...] = Field(default=(), repr=False)
    subject: str = Field(default="", max_length=998, repr=False)
    text: str = Field(min_length=1, max_length=20_000, repr=False)
    gmail_thread_id: str | None = Field(default=None, repr=False)
    in_reply_to: str | None = Field(default=None, repr=False)
    references: tuple[str, ...] = Field(default=(), repr=False)
    channel_id: str | None = Field(default=None, repr=False)
    thread_ts: str | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def exact_shape(self) -> CommunicationPlan:
        if not self.text.strip() or any(ord(c) < 32 and c not in "\n\t" for c in self.text):
            raise ValueError("plain text required")
        if not self.purpose.strip() or any(ord(c) < 32 for c in self.purpose):
            raise ValueError("invalid purpose")
        if self.provider is Provider.GMAIL:
            if (
                self.slack_account is not None
                or self.channel_id is not None
                or self.thread_ts is not None
            ):
                raise ValueError("unexpected Slack fields")
            addresses = self.to + self.cc
            if not self.to or len(addresses) > 50:
                raise ValueError("bounded recipients required")
            if len({a.casefold() for a in addresses}) != len(addresses):
                raise ValueError("duplicate recipient")
            if any(len(a) > 254 or "=?" in a or _ADDRESS.fullmatch(a) is None for a in addresses):
                raise ValueError("exact addresses required")
            if (
                not self.subject.strip()
                or "=?" in self.subject
                or any(ord(c) < 32 for c in self.subject)
            ):
                raise ValueError("exact subject required")
            reply = self.gmail_thread_id is not None
            if reply:
                if (
                    _GMAIL_ID.fullmatch(self.gmail_thread_id or "") is None
                    or _MESSAGE_ID.fullmatch(self.in_reply_to or "") is None
                    or not self.references
                    or len(self.references) > 30
                    or self.references[-1] != self.in_reply_to
                    or any(
                        len(r) > 250 or "=?" in r or _MESSAGE_ID.fullmatch(r) is None
                        for r in self.references
                    )
                ):
                    raise ValueError("complete exact reply target required")
            elif self.in_reply_to is not None or self.references:
                raise ValueError("unexpected reply fields")
        else:
            if (
                self.slack_account is None
                or self.slack_account.token_kind != "user"
                or self.subject_id != self.slack_account.user_id
                or _CHANNEL.fullmatch(self.channel_id or "") is None
            ):
                raise ValueError("exact Slack user and channel required")
            if (
                self.to
                or self.cc
                or self.subject
                or self.gmail_thread_id is not None
                or self.in_reply_to is not None
            ):
                raise ValueError("unexpected Gmail fields")
            if self.references:
                raise ValueError("unexpected references")
            if self.thread_ts is not None and _TIMESTAMP.fullmatch(self.thread_ts) is None:
                raise ValueError("exact Slack thread required")
            if len(_slack_text(self.text)) > 4000:
                raise ValueError("bounded literal Slack text required")
        return self

    @property
    def scopes(self) -> frozenset[str]:
        return (
            GMAIL_COMMUNICATION_SCOPES
            if self.provider is Provider.GMAIL
            else SLACK_COMMUNICATION_SCOPES
        )

    @property
    def scope_digest(self) -> str:
        """Bind identity, provenance, recipients, wording, targets and purpose."""
        document = self.model_dump(mode="json")
        document["scopes"] = sorted(self.scopes)
        return hashlib.sha256(_json(document)).hexdigest()


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _slack_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _verify_headers(raw: bytes, plan: CommunicationPlan) -> None:
    """Inspect raw RFC headers without decoding encoded words into apparent IDs."""
    message = BytesParser(policy=compat32).parsebytes(raw)
    expected = {"From": plan.mailbox, "To": ", ".join(plan.to)}
    if plan.cc:
        expected["Cc"] = ", ".join(plan.cc)
    if plan.in_reply_to is not None:
        expected["In-Reply-To"] = plan.in_reply_to
        expected["References"] = " ".join(plan.references)
    for name in ("From", "To", "Cc", "In-Reply-To", "References"):
        values = message.get_all(name, [])
        if name not in expected:
            if values:
                raise ValueError("unexpected RFC header")
            continue
        if len(values) != 1 or type(values[0]) is not str:
            raise ValueError("invalid RFC header")
        unfolded = re.sub(r"\r?\n[ \t]+", " ", values[0])
        if "=?" in unfolded or unfolded != expected[name]:
            raise ValueError("altered RFC header")
    if message.get_all("Bcc", []):
        raise ValueError("unexpected hidden recipient")
    # Subject may legitimately use RFC2047 for Unicode, but its decoded
    # wording must round-trip exactly to the owner's reviewed subject.
    decoded_subjects = BytesParser(policy=default).parsebytes(raw).get_all("Subject", [])
    if len(decoded_subjects) != 1 or str(decoded_subjects[0]) != plan.subject:
        raise ValueError("altered subject wording")


def _payload(plan: CommunicationPlan) -> bytes:
    if type(plan) is not CommunicationPlan:
        raise ValueError("exact plan required")
    plan = CommunicationPlan.model_validate(plan)
    if plan.provider is Provider.GMAIL:
        message = EmailMessage(policy=SMTP.clone(max_line_length=998))
        message["From"] = plan.mailbox
        message["To"] = ", ".join(plan.to)
        if plan.cc:
            message["Cc"] = ", ".join(plan.cc)
        message["Subject"] = plan.subject
        message["Message-ID"] = f"<{plan.attempt_id}@caz.local>"
        if plan.in_reply_to is not None:
            message["In-Reply-To"] = plan.in_reply_to
            message["References"] = " ".join(plan.references)
        message.set_content(plan.text, subtype="plain", charset="utf-8")
        raw = message.as_bytes()
        _verify_headers(raw, plan)
        body: dict[str, object] = {"raw": base64.urlsafe_b64encode(raw).decode("ascii")}
        if plan.gmail_thread_id is not None:
            body["threadId"] = plan.gmail_thread_id
    else:
        body = {
            "channel": plan.channel_id,
            # Escape Slack control characters so exact reviewed text remains
            # literal, including <@user>/<!channel>, never implicit recipients.
            "text": _slack_text(plan.text),
            "client_msg_id": str(plan.attempt_id),
            "mrkdwn": False,
            "parse": "none",
            "unfurl_links": False,
            "unfurl_media": False,
            "reply_broadcast": False,
        }
        if plan.thread_ts is not None:
            body["thread_ts"] = plan.thread_ts
    payload = _json(body)
    if len(payload) > 150_000:
        raise ValueError("payload too large")
    return payload


def prepare_payload(plan: CommunicationPlan) -> bytes:
    """Offline draft preparation only; creates no provider draft or action."""
    result: bytes | None = None
    try:
        result = _payload(plan)
    except Exception:  # noqa: BLE001,S110 - fixed public errors
        pass
    if result is None:
        raise CommunicationError("communication proposal invalid")
    return result


@dataclass(frozen=True)
class CommunicationReceipt:
    provider: Provider
    attempt_id: UUID
    provider_id: str
    thread_id: str
    payload_digest: str


class ApprovalCredentialGateway(Protocol):
    """Trusted external host contract, intentionally no permissive implementation.

    consume_exact atomically authenticates the current owner, independently
    attests provenance and reply context, validates their exact reviewed plan
    AND payload digest, serializes the credential generation and consumes the
    attempt. No caller boolean/token is authority. The durable default state
    is held/in-flight, including crashes. It must reject stale approvals,
    previously attempted messages and unresolved prior uncertain outcomes.
    Credential access occurs only after this method succeeds. assert_current
    checks approval, owner/session, scopes and credential generation/revocation.
    confirm atomically persists receipt and releases serialization only if still
    current. hold durably quarantines/reconciles failures and never reissues
    permission. For Slack it must verify actual channel metadata is neither im
    nor mpim, regardless of a C/G identifier, and independently attest any Slack
    Connect sharing against owner-reviewed channel membership/recipient scope.
    hold is idempotent, preserves observed provider IDs/hash even if confirm
    persisted then interrupted, and never erases a previously durable receipt.
    A thrown consume must leave any partially consumed attempt held.
    """

    def consume_exact(self, plan: CommunicationPlan, payload_digest: str) -> None: ...
    def assert_current(self, plan: CommunicationPlan, payload_digest: str) -> None: ...
    def credential(self, plan: CommunicationPlan) -> VerifiedCredential: ...
    def confirm(self, plan: CommunicationPlan, receipt: CommunicationReceipt) -> None: ...
    def hold(
        self,
        plan: CommunicationPlan,
        *,
        uncertain: bool,
        observed: CommunicationReceipt | None,
    ) -> None: ...


@dataclass(frozen=True)
class SyntheticWriteTransport:
    """Explicit injected offline exchange. No live HTTP factory or mounted path.

    Callable must be a synthetic/offline exchange for this implementation.
    A future real adapter needs separately reviewed host enforcement, bounded
    HTTPS, no redirects/retries, and exact owner-authorized communication. Python
    cannot sandbox a malicious injected callable. client_msg_id/Message-ID are
    references for reconciliation, never guarantees of provider idempotency.
    """

    provider: Provider
    exchange: Callable[[SecretStr, bytes], bytes] = field(repr=False)

    def send(self, credential: SecretStr, payload: bytes) -> bytes:
        return self.exchange(credential, payload)


def _check(plan: CommunicationPlan, credential: VerifiedCredential, now: datetime) -> None:
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("aware clock required")
    kind = "oauth_access" if plan.provider is Provider.GMAIL else "slack_user"
    if (
        type(credential) is not VerifiedCredential
        or type(credential.token) is not SecretStr
        or credential.provider is not plan.provider
        or credential.boundary is not TrustBoundary.BRAINSTORM
        or credential.client_id != plan.client_id
        or credential.subject_id != plan.subject_id
        or type(credential.scopes) is not frozenset
        or credential.scopes != plan.scopes
        or credential.token_kind != kind
        or (plan.provider is Provider.GMAIL and credential.expires_at is None)
    ):
        raise ValueError("unexpected grant")
    token = credential.token.get_secret_value()
    if not 1 <= len(token) <= 4096 or any(not 33 <= ord(c) <= 126 for c in token):
        raise ValueError("invalid credential")
    expiry = credential.expires_at
    if expiry is not None and (
        type(expiry) is not datetime
        or expiry.tzinfo is None
        or expiry.utcoffset() is None
        or expiry <= now
    ):
        raise ValueError("expired credential")


def _receipt(plan: CommunicationPlan, raw: bytes, digest: str) -> CommunicationReceipt:
    if type(raw) is not bytes or not 1 <= len(raw) <= 65_536:
        raise ValueError("bounded receipt required")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        row: dict[str, object] = {}
        for key, value in pairs:
            if key in row:
                raise ValueError("duplicate response field")
            row[key] = value
        return row

    def invalid_constant(_: str) -> object:
        raise ValueError("nonfinite response")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite response")
        return number

    value = json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=invalid_constant,
        parse_float=finite_float,
    )
    if type(value) is not dict or "error" in value:
        raise ValueError("invalid receipt")
    if plan.provider is Provider.GMAIL:
        provider_id, thread_id = value.get("id"), value.get("threadId")
        if (
            type(provider_id) is not str
            or type(thread_id) is not str
            or _GMAIL_ID.fullmatch(provider_id) is None
            or _GMAIL_ID.fullmatch(thread_id) is None
            or (plan.gmail_thread_id is not None and thread_id != plan.gmail_thread_id)
        ):
            raise ValueError("invalid Gmail receipt")
    else:
        provider_id = value.get("ts")
        if (
            value.get("ok") is not True
            or value.get("channel") != plan.channel_id
            or type(provider_id) is not str
            or _TIMESTAMP.fullmatch(provider_id) is None
        ):
            raise ValueError("invalid Slack receipt")
        message = value.get("message")
        if message is not None and type(message) is not dict:
            raise ValueError("invalid Slack message receipt")
        observed_thread = message.get("thread_ts") if type(message) is dict else None
        if plan.thread_ts is not None:
            if observed_thread != plan.thread_ts:
                raise ValueError("unconfirmed Slack reply target")
            thread_id = observed_thread
        else:
            if observed_thread is not None and observed_thread != provider_id:
                raise ValueError("unexpected Slack thread")
            thread_id = provider_id
    return CommunicationReceipt(plan.provider, plan.attempt_id, provider_id, thread_id, digest)


def _execute(
    plan: CommunicationPlan,
    *,
    gateway: ApprovalCredentialGateway,
    gmail: GmailReadTransport,
    slack: SlackReadTransport,
    writer: SyntheticWriteTransport | ApprovedWriteTransport,
    clock: Callable[[], datetime],
) -> CommunicationReceipt:
    receipt: CommunicationReceipt | None = None
    observed: CommunicationReceipt | None = None
    consumed = attempted = cancelled = hold_unconfirmed = False
    try:
        if type(plan) is not CommunicationPlan:
            raise ValueError("exact plan required")
        plan = CommunicationPlan.model_validate(plan)
        plan_digest = plan.scope_digest
        payload = _payload(plan)
        digest = hashlib.sha256(payload).hexdigest()
        if (
            type(writer) not in {SyntheticWriteTransport, ApprovedWriteTransport}
            or writer.provider is not plan.provider
        ):
            raise ValueError("exact provider transport required")
        action = (
            ActionType.SEND_EMAIL
            if plan.provider is Provider.GMAIL
            else ActionType.SEND_SLACK_MESSAGE
        )
        decision = evaluate_gateway(
            ActionRequest(
                action_type=action,
                access=AccessRequest(
                    data_boundary=plan.data_boundary,
                    data_classification=plan.classification,
                    requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
                    destination=Destination.EXTERNAL,
                ),
                description="exact owner-reviewed communication",
            )
        )
        if decision.outcome is not GatewayOutcome.REQUIRE_APPROVAL:
            raise ValueError("send policy denied")
        # REQUIRE_APPROVAL is not ALLOW. Only the trusted external host below
        # can authenticate and consume the exact independent owner approval.
        gateway.consume_exact(plan, digest)
        consumed = True

        def current_plan() -> None:
            gateway.assert_current(plan, digest)
            if plan.scope_digest != plan_digest:
                raise ValueError("changed plan")

        current_plan()
        credential = gateway.credential(plan)
        _check(plan, credential, clock())
        fingerprint = hashlib.sha256(credential.token.get_secret_value().encode()).digest()

        def current() -> None:
            current_plan()
            _check(plan, credential, clock())
            if hashlib.sha256(credential.token.get_secret_value().encode()).digest() != fingerprint:
                raise ValueError("changed credential")

        current()
        if plan.provider is Provider.GMAIL:
            scope = GmailScope(
                account_ref=plan.subject_id,
                expected_email=plan.mailbox,
                boundary=TrustBoundary.BRAINSTORM,
                classification=DataClassification.HIGHLY_RESTRICTED,
                requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
                allowed_classifications=frozenset({DataClassification.HIGHLY_RESTRICTED}),
            )
            gmail.profile_reply(credential.token, scope=scope)
            current()
        else:
            account = plan.slack_account
            if account is None:
                raise ValueError("missing Slack account")
            reply = slack.account_reply(credential.token)
            current()
            prepare_account_reply(reply.response_bytes, expected=account)
            if reply.declared_scopes != plan.scopes:
                raise ValueError("unexpected provider scopes")
        current()
        # Mark uncertain BEFORE invocation: even a raised/cancelled exchange
        # may have transmitted. No provider failure can authorize a retry.
        attempted = True
        raw = (
            writer.send(credential.token, payload, plan=plan)
            if isinstance(writer, ApprovedWriteTransport)
            else writer.send(credential.token, payload)
        )
        # Validate and retain acknowledgement IDs before the current check so
        # revocation holds useful reconciliation evidence without returning an
        # authorized success. Host holds must never erase confirmed evidence.
        observed = _receipt(plan, raw, digest)
        if plan.provider is Provider.SLACK:
            # _receipt already bounded and validated this exact JSON including
            # duplicates/nonfinite values. Preserve its IDs before warning holds.
            value = json.loads(raw)
            metadata = value.get("response_metadata")
            if "warning" in value or (
                "response_metadata" in value
                and (
                    type(metadata) is not dict
                    or (
                        "warnings" in metadata
                        and (type(metadata["warnings"]) is not list or metadata["warnings"])
                    )
                )
            ):
                raise ValueError("Slack delivery warning requires reconciliation")
        current()
        gateway.confirm(plan, observed)
        receipt = observed
    except Exception:  # noqa: BLE001 - no private diagnostic chains
        receipt = None
    except BaseException:  # noqa: BLE001 - sanitize interruption
        cancelled = True
        receipt = None
    finally:
        if consumed and receipt is None:
            try:
                gateway.hold(plan, uncertain=attempted, observed=observed)
            except Exception:  # noqa: BLE001 - honest hold status
                hold_unconfirmed = True
            except BaseException:  # noqa: BLE001 - sanitize interrupted hold
                hold_unconfirmed = True
                cancelled = True
    if cancelled:
        if hold_unconfirmed:
            raise CommunicationCancellationHoldUnconfirmed(
                "communication cancellation hold unconfirmed; possibly sent"
            )
        if attempted:
            raise CommunicationCancelledUncertain(
                "communication cancelled; possibly sent; host reconciliation required"
            )
        raise CommunicationCancelled("communication cancelled; host reconciliation required")
    if hold_unconfirmed:
        raise CommunicationHoldUnconfirmed("communication hold unconfirmed; host review required")
    if attempted and receipt is None:
        raise CommunicationUncertain(
            "communication outcome uncertain; host reconciliation required"
        )
    if receipt is None:
        raise CommunicationError("communication held; host review required")
    return receipt


def execute_approved(
    plan: CommunicationPlan,
    *,
    gateway: ApprovalCredentialGateway,
    gmail: GmailReadTransport,
    slack: SlackReadTransport,
    writer: SyntheticWriteTransport | ApprovedWriteTransport,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> CommunicationReceipt:
    """Closed public boundary. Never log tracebacks with private frame locals.

    At most one identity read and one explicit write. Durable host records are
    required before secrets; no live-send readiness is proven by this function.
    """
    result: CommunicationReceipt | None = None
    failure: type[BaseException] = CommunicationError
    try:
        result = _execute(
            plan, gateway=gateway, gmail=gmail, slack=slack, writer=writer, clock=clock
        )
    except CommunicationCancellationHoldUnconfirmed:
        failure = CommunicationCancellationHoldUnconfirmed
    except CommunicationCancelledUncertain:
        failure = CommunicationCancelledUncertain
    except CommunicationHoldUnconfirmed:
        failure = CommunicationHoldUnconfirmed
    except CommunicationCancelled:
        failure = CommunicationCancelled
    except CommunicationUncertain:
        failure = CommunicationUncertain
    except Exception:  # noqa: BLE001,S110 - discard secret-bearing private frames
        pass
    except BaseException:  # noqa: BLE001 - sanitize cancellation
        failure = CommunicationCancelled
    if result is None:
        raise failure("communication held; host reconciliation required")
    return result
