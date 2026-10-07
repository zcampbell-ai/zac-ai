"""Unmounted, host-only Gmail/Slack preflight. No grant issuer or canonical writes.

The external credential/approval gateway supplies authenticated, single-attempt
owner authority and verified OAuth grant metadata for the exact token. Python
interfaces are trusted host seams, not a security sandbox for malicious callers.
No permissive default gateway, environment secret fallback, refresh, provider
mutation, message body method, model processing or persistent account store.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from zacai.config import get_secret
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.connectors.slack_wire import (
    InventorySelection,
    SlackAccount,
    prepare_account_reply,
    prepare_inventory_reply,
)
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary

GMAIL_SCOPES = frozenset({"https://www.googleapis.com/auth/gmail.readonly"})
SLACK_SCOPES = frozenset({"channels:read", "groups:read", "channels:history", "groups:history"})
GMAIL_COMMUNICATION_SCOPES = GMAIL_SCOPES | {"https://www.googleapis.com/auth/gmail.send"}
SLACK_COMMUNICATION_SCOPES = SLACK_SCOPES | {"chat:write"}


class Provider(str, Enum):
    GMAIL = "gmail"
    SLACK = "slack"


class PreflightError(RuntimeError):
    """Fixed diagnostic, no private exception chains or provider prose."""


class PreflightQuarantineUnconfirmed(PreflightError):
    """Host quarantine failed; the generation must remain held externally."""


class PreflightCancelled(BaseException):
    """Sanitized cancellation; no original provider/credential traceback chain."""


class PreflightCancellationQuarantineUnconfirmed(PreflightCancelled):
    """Cancellation with unconfirmed quarantine; host must retain the hold."""


class PreflightPlan(BaseModel):
    """An exact proposal, never proof of owner authorization or OAuth access.

    Slack team/user must come from owner-reviewed installation metadata. There
    is no historical-team default. An identity-only plan makes one API request.
    Metadata adds at most max_pages of fixed 100-item inventory requests.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    attempt_id: UUID
    provider: Provider
    client_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+$")
    subject_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    mailbox: Literal["zcampbell@brainstormtech.io"] = "zcampbell@brainstormtech.io"
    slack_account: SlackAccount | None = None
    grant_profile: Literal["read", "approved_communications"] = "read"
    metadata: bool = Field(default=False, strict=True)
    max_pages: int = Field(default=1, ge=1, le=10, strict=True)
    gmail_labels: tuple[Literal["SENT"], ...] = ("SENT",)

    @model_validator(mode="after")
    def selected_account(self) -> PreflightPlan:
        if self.provider is Provider.SLACK:
            if self.slack_account is None or self.slack_account.token_kind != "user":
                raise ValueError("exact Slack user account required")
            if self.subject_id != self.slack_account.user_id:
                raise ValueError("subject mismatch")
        elif self.slack_account is not None:
            raise ValueError("unexpected Slack account")
        if self.gmail_labels != ("SENT",):
            raise ValueError("fixed sent inventory only")
        return self

    @property
    def scopes(self) -> frozenset[str]:
        if self.grant_profile == "approved_communications":
            return (
                GMAIL_COMMUNICATION_SCOPES
                if self.provider is Provider.GMAIL
                else SLACK_COMMUNICATION_SCOPES
            )
        return GMAIL_SCOPES if self.provider is Provider.GMAIL else SLACK_SCOPES


@dataclass(frozen=True)
class VerifiedCredential:
    """Trusted gateway attestation from OAuth exchange/current grant verification.

    Must describe THIS access token, not a config's requested scopes, ID token,
    refresh token, consumer subscription or Codex connector. Never construct
    this from untrusted request JSON. Expiring tokens require an expiry; a Slack
    legacy non-expiring user token may have None only if verified by the host.
    """

    token: SecretStr = field(repr=False)
    provider: Provider
    client_id: str
    subject_id: str
    scopes: frozenset[str]
    token_kind: Literal["oauth_access", "slack_user"]
    boundary: TrustBoundary
    expires_at: datetime | None


class CredentialGateway(Protocol):
    """External security gateway, not implemented by agents or HTTP input.

    consume must atomically authenticate/consume exact owner-approved plan once,
    before secret access; attempts remain consumed on error. assert_current
    checks current owner/session, unchanged exact plan and credential generation,
    including revocation. complete atomically records successful coverage only
    under still-current exact owner authority and releases the generation hold.
    credential securely loads and independently verifies
    actual grant/client/subject/scopes/token kind. invalidate quarantines that
    credential generation on any failure; no automatic refresh/retry. Host owns
    audit without secrets, serialization, secure escrow and approved renewal.
    Consumed generations default to in-flight/held until positive host completion,
    so process death or interruption cannot depend on Python cleanup for safety.
    """

    def consume(self, plan: PreflightPlan) -> None: ...
    def assert_current(self, plan: PreflightPlan) -> None: ...
    def credential(self, plan: PreflightPlan) -> VerifiedCredential: ...
    def invalidate(self, plan: PreflightPlan) -> None: ...
    def complete(self, plan: PreflightPlan, coverage: Coverage) -> None: ...


@dataclass(frozen=True)
class Coverage:
    provider: Provider
    observed_at: datetime
    account_identity_matched: bool
    requests: int
    pages: int
    records: int
    pagination_exhausted: bool
    continuation: str | None = field(repr=False)
    inventory_limited_reported: bool | None = None
    archived_channels: int = 0
    mixed_or_restricted_channels: int = 0

    @property
    def full_history_verified(self) -> Literal[False]:
        return False

    @property
    def source_capture_authorized(self) -> Literal[False]:
        return False

    @property
    def model_processing_authorized(self) -> Literal[False]:
        return False


def _now() -> datetime:
    return datetime.now(UTC)


def _time(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware time required")
    return value


def _scope(plan: PreflightPlan) -> GmailScope:
    return GmailScope(
        account_ref=plan.subject_id,
        expected_email=plan.mailbox,
        boundary=TrustBoundary.BRAINSTORM,
        classification=DataClassification.HIGHLY_RESTRICTED,
        requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
        allowed_classifications=frozenset({DataClassification.HIGHLY_RESTRICTED}),
    )


def _check_credential(plan: PreflightPlan, credential: VerifiedCredential, now: datetime) -> None:
    expected_kind = "oauth_access" if plan.provider is Provider.GMAIL else "slack_user"
    if (
        type(credential) is not VerifiedCredential
        or type(credential.token) is not SecretStr
        or credential.provider is not plan.provider
        or credential.boundary is not TrustBoundary.BRAINSTORM
        or credential.client_id != plan.client_id
        or credential.subject_id != plan.subject_id
        or type(credential.scopes) is not frozenset
        or credential.scopes != plan.scopes
        or credential.token_kind != expected_kind
        or (plan.provider is Provider.GMAIL and credential.expires_at is None)
    ):
        raise ValueError("unverified or unexpected grant")
    token = credential.token.get_secret_value()
    if not 1 <= len(token) <= 4096 or any(not 33 <= ord(c) <= 126 for c in token):
        raise ValueError("invalid credential")
    if credential.expires_at is not None and _time(credential.expires_at) <= now:
        raise ValueError("expired credential")


def _preflight(
    plan: PreflightPlan,
    *,
    gateway: CredentialGateway,
    gmail: GmailReadTransport,
    slack: SlackReadTransport,
    clock: Callable[[], datetime] = _now,
) -> Coverage:
    """One bounded attempt; identity first, metadata only if separately selected.

    Provider failures and changing grants hold the whole result. Missing Slack
    scope headers hold, even when the host attestation has scopes. Cursors stay
    metadata and never imply full coverage. No partial result on error. Existing
    transports retain their byte caps and socket timeouts, which are not a hard
    wall-clock deadline; trusted host must isolate/cancel execution as required.
    Cancellation is re-raised as PreflightCancelled after quarantine, with no
    original provider traceback. Hosts must never record traceback locals.
    inventory_limited_reported is only a top-level inventory response claim,
    never evidence of message retention or its absence.
    """
    result: Coverage | None = None
    consumed = False
    cancelled = False
    quarantine_unconfirmed = False
    try:
        if type(plan) is not PreflightPlan:
            raise ValueError("exact plan required")
        plan = PreflightPlan.model_validate(plan)
        access = AccessRequest(
            data_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.HIGHLY_RESTRICTED,
            requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
            destination=Destination.LOCAL,
        )
        if (
            evaluate_gateway(
                ActionRequest(
                    action_type=ActionType.READ_DATA, access=access, description="account preflight"
                )
            ).outcome
            is not GatewayOutcome.ALLOW
        ):
            raise ValueError("gateway denied")
        gateway.consume(plan)
        consumed = True
        gateway.assert_current(plan)
        credential = gateway.credential(plan)
        fingerprint = hashlib.sha256(credential.token.get_secret_value().encode()).digest()

        def current() -> None:
            gateway.assert_current(plan)
            _check_credential(plan, credential, _time(clock()))
            if hashlib.sha256(credential.token.get_secret_value().encode()).digest() != fingerprint:
                raise ValueError("changed credential")

        current()
        requests = 1
        pages = records = archived = mixed = 0
        exhausted = False
        cursor: str | None = None
        retention: bool | None = None
        if plan.provider is Provider.GMAIL:
            scope = _scope(plan)
            gmail.profile_reply(credential.token, scope=scope)
            current()
            seen: set[str] = set()
            if plan.metadata:
                for _ in range(plan.max_pages):
                    current()
                    page = gmail.messages_reply(
                        credential.token,
                        scope=scope,
                        max_results=100,
                        page_token=cursor,
                        label_ids=plan.gmail_labels,
                    ).inspection.value
                    current()
                    requests += 1
                    pages += 1
                    records += len(page.messages)
                    cursor = page.next_page_token
                    if cursor is None:
                        exhausted = True
                        break
                    if cursor in seen:
                        raise ValueError("cursor cycle")
                    seen.add(cursor)
        else:
            account = plan.slack_account
            if account is None:
                raise ValueError("missing account")
            reply = slack.account_reply(credential.token)
            current()
            prepare_account_reply(reply.response_bytes, expected=account)
            if reply.declared_scopes != plan.scopes:
                raise ValueError("missing or changed provider scopes")
            seen = set()
            retention_reports: list[bool | None] = []
            if plan.metadata:
                for _ in range(plan.max_pages):
                    current()
                    selection = InventorySelection(account=account, cursor=cursor or "", limit=100)
                    reply = slack.inventory_reply(credential.token, selection)
                    current()
                    if reply.declared_scopes != plan.scopes:
                        raise ValueError("changed provider scopes")
                    page_slack = prepare_inventory_reply(reply.response_bytes, selection=selection)
                    requests += 1
                    pages += 1
                    records += len(page_slack.record_bytes)
                    for raw in page_slack.record_bytes:
                        row = json.loads(raw)
                        archived += row.get("is_archived") is True
                        # Uncertain sharing metadata needs review, not classification.
                        flags = (
                            "is_private",
                            "is_shared",
                            "is_ext_shared",
                            "is_org_shared",
                            "is_pending_ext_shared",
                        )
                        if any(flag in row and type(row[flag]) is not bool for flag in flags):
                            raise ValueError("invalid sharing flag")
                        attention = (
                            row["id"].startswith("G")
                            or any(flag not in row for flag in flags)
                            or any(row.get(flag) is True for flag in flags)
                        )
                        for name in (
                            "pending_shared",
                            "pending_connected_team_ids",
                            "shared_team_ids",
                            "connected_team_ids",
                            "internal_team_ids",
                        ):
                            if name in row:
                                teams = row[name]
                                if type(teams) is not list or any(
                                    type(team) is not str for team in teams
                                ):
                                    raise ValueError("invalid sharing metadata")
                                attention = attention or bool(teams)
                        if "conversation_host_id" in row:
                            host = row["conversation_host_id"]
                            if type(host) is not str or not host:
                                raise ValueError("invalid sharing host")
                            attention = attention or host != account.team_id
                        mixed += attention
                    retention_reports.append(page_slack.retention_limited)
                    cursor = page_slack.next_cursor
                    exhausted = page_slack.pagination_exhausted
                    if exhausted or cursor is None:
                        if exhausted:
                            cursor = None
                        break
                    if cursor in seen:
                        raise ValueError("cursor cycle")
                    seen.add(cursor)
                if any(value is True for value in retention_reports):
                    retention = True
                elif retention_reports and all(value is False for value in retention_reports):
                    retention = False
        current()
        result = Coverage(
            plan.provider,
            _time(clock()),
            True,
            requests,
            pages,
            records,
            exhausted,
            cursor,
            retention,
            archived,
            mixed,
        )
        gateway.complete(plan, result)
    except Exception:  # noqa: BLE001 - no credential, callback or provider diagnostics
        result = None
    except BaseException:  # noqa: BLE001 - sanitize cancellation with raw provider frames
        result = None
        cancelled = True
    finally:
        if consumed and result is None:
            try:
                gateway.invalidate(plan)
            except Exception:  # noqa: BLE001 - quarantine status must stay honest
                quarantine_unconfirmed = True
            except BaseException:  # noqa: BLE001 - sanitized interrupted quarantine
                quarantine_unconfirmed = True
                cancelled = True
    if cancelled and quarantine_unconfirmed:
        raise PreflightCancellationQuarantineUnconfirmed(
            "account cancellation quarantine unconfirmed"
        )
    if quarantine_unconfirmed:
        raise PreflightQuarantineUnconfirmed("account credential quarantine unconfirmed")
    if cancelled:
        raise PreflightCancelled("account preflight cancelled; host review required")
    if result is None:
        raise PreflightError("account preflight held; host review required")
    return result


def preflight(
    plan: PreflightPlan,
    *,
    gateway: CredentialGateway,
    gmail: GmailReadTransport,
    slack: SlackReadTransport,
    clock: Callable[[], datetime] = _now,
) -> Coverage:
    """Sanitized outer boundary; private provider locals never enter error frames."""
    outcome: Coverage | None = None
    failure_type: type[BaseException] = PreflightError
    try:
        outcome = _preflight(plan, gateway=gateway, gmail=gmail, slack=slack, clock=clock)
    except PreflightCancellationQuarantineUnconfirmed:
        failure_type = PreflightCancellationQuarantineUnconfirmed
    except PreflightCancelled:
        failure_type = PreflightCancelled
    except PreflightQuarantineUnconfirmed:
        failure_type = PreflightQuarantineUnconfirmed
    except Exception:  # noqa: BLE001,S110 - closed boundary
        pass
    except BaseException:  # noqa: BLE001 - discard interrupted private frames
        failure_type = PreflightCancelled
    if outcome is None:
        raise failure_type("account preflight held; host review required")
    return outcome


_SERVICES = {
    Provider.GMAIL: ("BRAINSTORM_GMAIL_ACCESS_TOKEN", "zacai-brainstorm-gmail-access-token"),
    Provider.SLACK: ("BRAINSTORM_SLACK_USER_TOKEN", "zacai-brainstorm-slack-user-token"),
}


def _load_keychain_token(provider: Provider) -> SecretStr:
    """Only fixed proposed entries; host must authorize before calling.

    Read-only secret-loader building block, not a VerifiedCredential or an OAuth
    flow. No entries are created here. No environment fallback or secrets in argv.
    Python cannot guarantee memory zeroization. Tests mock subprocess exclusively.
    """
    result: SecretStr | None = None
    try:
        if type(provider) is not Provider:
            raise ValueError("unsupported provider")
        name, service = _SERVICES[provider]
        completed = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-a",
                "zac-owner-source-access",
                "-s",
                service,
                "-w",
            ],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env={},
        )
        if completed.returncode != 0 or type(completed.stdout) is not bytes:
            raise ValueError("credential unavailable")
        raw = completed.stdout.removesuffix(b"\n")
        if not 1 <= len(raw) <= 4096:
            raise ValueError("invalid size")
        value = raw.decode("ascii")
        if re.fullmatch(r"[\x21-\x7e]+", value) is None:
            raise ValueError("invalid credential")
        checked = get_secret(name, TrustBoundary.BRAINSTORM, env={name: value})
        if checked is None:
            raise ValueError("credential unavailable")
        result = SecretStr(checked)
    except Exception:  # noqa: BLE001,S110 - suppress captured Keychain failures
        pass
    if result is None:
        raise PreflightError("account credential unavailable; host review required")
    return result


def load_keychain_token(provider: Provider) -> SecretStr:
    """Fixed Keychain load with cancellation and private-frame sanitization."""
    result: SecretStr | None = None
    cancelled = False
    try:
        result = _load_keychain_token(provider)
    except Exception:  # noqa: BLE001,S110 - discard inner secret-bearing frames
        pass
    except BaseException:  # noqa: BLE001 - sanitize interrupted Keychain subprocess
        cancelled = True
    if cancelled:
        raise PreflightCancelled("account credential load cancelled")
    if result is None:
        raise PreflightError("account credential unavailable; host review required")
    return result
