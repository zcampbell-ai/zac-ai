"""Invented account/credential fixtures only; no network, Keychain or database."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from pydantic import SecretStr

from zacai.connectors.account_preflight import (
    Coverage,
    PreflightCancellationQuarantineUnconfirmed,
    PreflightCancelled,
    PreflightError,
    PreflightPlan,
    PreflightQuarantineUnconfirmed,
    Provider,
    VerifiedCredential,
    load_keychain_token,
    preflight,
)
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.connectors.slack_wire import SlackAccount
from zacai.policy import TrustBoundary

NOW = datetime(2026, 10, 6, tzinfo=UTC)
KEY = SecretStr("invented-secret-for-offline-tests")
ACCOUNT = SlackAccount(team_id="TTEST", user_id="UTEST")


def plan(provider: Provider = Provider.GMAIL, **changes: Any) -> PreflightPlan:
    fields: dict[str, Any] = {
        "attempt_id": uuid4(),
        "provider": provider,
        "client_id": "invented-client",
        "subject_id": "invented-subject" if provider is Provider.GMAIL else "UTEST",
        "slack_account": None if provider is Provider.GMAIL else ACCOUNT,
    }
    fields.update(changes)
    return PreflightPlan(**fields)


class Gateway:
    def __init__(self, selected: PreflightPlan) -> None:
        self.value = VerifiedCredential(
            KEY,
            selected.provider,
            selected.client_id,
            selected.subject_id,
            selected.scopes,
            "oauth_access" if selected.provider is Provider.GMAIL else "slack_user",
            TrustBoundary.BRAINSTORM,
            NOW + timedelta(hours=1),
        )
        self.consumed: set[object] = set()
        self.loads = self.checks = self.invalidations = 0
        self.completed: list[Coverage] = []
        self.reject = False
        self.revoke_at: int | None = None

    def consume(self, selected: PreflightPlan) -> None:
        if self.reject or selected.attempt_id in self.consumed:
            raise RuntimeError("invented-secret approval denied")
        self.consumed.add(selected.attempt_id)

    def assert_current(self, selected: PreflightPlan) -> None:
        self.checks += 1
        if self.revoke_at is not None and self.checks >= self.revoke_at:
            raise RuntimeError("invented-secret revoked")

    def credential(self, selected: PreflightPlan) -> VerifiedCredential:
        self.loads += 1
        return self.value

    def invalidate(self, selected: PreflightPlan) -> None:
        self.invalidations += 1

    def complete(self, selected: PreflightPlan, coverage: Coverage) -> None:
        self.completed.append(coverage)


class Response:
    def __init__(
        self, payload: dict[str, Any], scopes: frozenset[str] | None = None, status: int = 200
    ) -> None:
        self.status = status
        self.body = json.dumps(payload).encode()
        self.scopes = scopes
        self.reads = 0

    def getheader(self, name: str) -> str | None:
        if name == "Content-Type":
            return "application/json"
        if name == "X-OAuth-Scopes" and self.scopes is not None:
            return ",".join(sorted(self.scopes))
        return None

    def read(self, amount: int) -> bytes:
        self.reads += 1
        return self.body[:amount]


class Connection:
    def __init__(self, response: Response, calls: list[str]) -> None:
        self.response = response
        self.calls = calls
        self.closed = False

    def request(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> None:
        self.calls.append(url)

    def getresponse(self) -> Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class Fixture:
    def __init__(self, selected: PreflightPlan, responses: list[Response]) -> None:
        self.selected = selected
        self.gateway = Gateway(selected)
        self.responses = responses
        self.calls: list[str] = []
        self.connections: list[Connection] = []

    def connect(self) -> Connection:
        connection = Connection(self.responses.pop(0), self.calls)
        self.connections.append(connection)
        return connection

    def run(self, clock: Any = lambda: NOW) -> Coverage:
        return preflight(
            self.selected,
            gateway=self.gateway,
            gmail=GmailReadTransport(connection_factory=self.connect),
            slack=SlackReadTransport(connection_factory=self.connect),
            clock=clock,
        )


def gmail_identity(email: str = "zcampbell@brainstormtech.io") -> Response:
    return Response(
        {"emailAddress": email, "historyId": "100", "messagesTotal": 500, "threadsTotal": 400}
    )


def slack_identity(selected: PreflightPlan, **changes: Any) -> Response:
    fields = {"ok": True, "team_id": "TTEST", "user_id": "UTEST"}
    fields.update(changes)
    return Response(fields, selected.scopes)


def slack_page(selected: PreflightPlan, cursor: str = "", **changes: Any) -> Response:
    fields: dict[str, Any] = {
        "ok": True,
        "channels": [],
        "response_metadata": {"next_cursor": cursor},
    }
    fields.update(changes)
    return Response(fields, selected.scopes)


@pytest.mark.parametrize("provider", list(Provider))
def test_identity_only_fixed_call_and_consumed_replay(provider: Provider) -> None:
    selected = plan(provider)
    fixture = Fixture(
        selected, [gmail_identity() if provider is Provider.GMAIL else slack_identity(selected)]
    )
    result = fixture.run()
    assert result.requests == 1 and result.pages == result.records == 0
    assert result.account_identity_matched and not result.pagination_exhausted
    assert fixture.gateway.completed == [result]
    assert result.inventory_limited_reported is None
    assert not result.full_history_verified and not result.source_capture_authorized
    assert not result.model_processing_authorized
    assert fixture.calls == (
        ["/gmail/v1/users/me/profile"] if provider is Provider.GMAIL else ["/api/auth.test"]
    )
    assert all(c.closed for c in fixture.connections)
    assert "invented-secret" not in repr(fixture.gateway.value)
    with pytest.raises(PreflightError):
        fixture.run()
    assert fixture.gateway.loads == 1 and len(fixture.calls) == 1


def test_gmail_selected_pagination_is_bounded_without_body_reads() -> None:
    selected = plan(metadata=True, max_pages=2)
    fixture = Fixture(
        selected,
        [
            gmail_identity(),
            Response({"messages": [{"id": "a", "threadId": "t"}], "nextPageToken": "page2"}),
            Response({"messages": [], "nextPageToken": "page3"}),
        ],
    )
    result = fixture.run()
    assert (result.requests, result.pages, result.records) == (3, 2, 1)
    assert result.continuation == "page3" and not result.pagination_exhausted
    assert "page3" not in repr(result)
    assert all(
        "maxResults=100" in path and "labelIds=SENT" in path and "includeSpamTrash=false" in path
        for path in fixture.calls[1:]
    )
    assert all("format=raw" not in path for path in fixture.calls)


def test_gmail_exhaustion_is_only_selected_page_coverage() -> None:
    fixture = Fixture(plan(metadata=True), [gmail_identity(), Response({"messages": []})])
    result = fixture.run()
    assert result.pagination_exhausted and not result.full_history_verified
    assert result.inventory_limited_reported is None


@pytest.mark.parametrize("provider", list(Provider))
def test_wrong_live_account_before_metadata(provider: Provider) -> None:
    selected = plan(provider, metadata=True)
    fixture = Fixture(
        selected,
        [
            gmail_identity("other@example.invalid")
            if provider is Provider.GMAIL
            else slack_identity(selected, team_id="TOTHER")
        ],
    )
    with pytest.raises(PreflightError) as error:
        fixture.run()
    assert len(fixture.calls) == 1 and fixture.gateway.invalidations == 1
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "other" not in str(error.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": frozenset()},
        {"scopes": frozenset({"https://mail.google.com/"})},
        {"token_kind": "refresh"},
        {"token_kind": "id_token"},
        {"client_id": "other"},
        {"subject_id": "other"},
        {"provider": Provider.SLACK},
        {"boundary": TrustBoundary.PERSONAL},
        {"expires_at": NOW},
        {"expires_at": None},
        {"expires_at": NOW.replace(tzinfo=None)},
        {"token": SecretStr("bad\nsecret")},
    ],
)
def test_bad_credential_before_socket(changes: dict[str, Any]) -> None:
    fixture = Fixture(plan(), [])
    fixture.gateway.value = replace(fixture.gateway.value, **changes)
    with pytest.raises(PreflightError):
        fixture.run()
    assert not fixture.calls and fixture.gateway.invalidations == 1


@pytest.mark.parametrize("extra", ["chat:write", "im:history", "files:read"])
def test_elevated_slack_grants_rejected_before_socket(extra: str) -> None:
    selected = plan(Provider.SLACK)
    fixture = Fixture(selected, [])
    fixture.gateway.value = replace(fixture.gateway.value, scopes=selected.scopes | {extra})
    with pytest.raises(PreflightError):
        fixture.run()
    assert not fixture.calls


@pytest.mark.parametrize("bot", ["BTEST", ""])
def test_slack_wrong_token_kind_at_identity(bot: str) -> None:
    selected = plan(Provider.SLACK, metadata=True)
    fixture = Fixture(selected, [slack_identity(selected, bot_id=bot)])
    with pytest.raises(PreflightError):
        fixture.run()
    assert len(fixture.calls) == 1


@pytest.mark.parametrize("scopes", [None, frozenset(), frozenset({"channels:read"})])
def test_missing_slack_provider_scope_evidence_holds(scopes: frozenset[str] | None) -> None:
    selected = plan(Provider.SLACK, metadata=True)
    response = slack_identity(selected)
    response.scopes = scopes
    fixture = Fixture(selected, [response])
    with pytest.raises(PreflightError):
        fixture.run()
    assert len(fixture.calls) == 1


def test_slack_archived_retention_and_mixed_metadata_kept_honest() -> None:
    selected = plan(Provider.SLACK, metadata=True, max_pages=2)
    fixture = Fixture(
        selected,
        [
            slack_identity(selected),
            slack_page(
                selected,
                "next",
                channels=[{"id": "CTEST", "is_archived": True, "is_private": True}],
                is_limited=True,
            ),
            slack_page(selected),
        ],
    )
    result = fixture.run()
    assert result.requests == 3 and result.pages == 2 and result.records == 1
    assert result.pagination_exhausted and result.inventory_limited_reported is True
    assert result.archived_channels == result.mixed_or_restricted_channels == 1
    assert not result.full_history_verified


def test_slack_missing_cursor_is_unknown_not_exhaustion() -> None:
    selected = plan(Provider.SLACK, metadata=True, max_pages=10)
    fixture = Fixture(
        selected,
        [slack_identity(selected), Response({"ok": True, "channels": []}, selected.scopes)],
    )
    result = fixture.run()
    assert result.requests == 2 and not result.pagination_exhausted
    assert result.inventory_limited_reported is None


@pytest.mark.parametrize("provider", list(Provider))
def test_cursor_cycle_rejected_with_bounded_calls(provider: Provider) -> None:
    selected = plan(provider, metadata=True, max_pages=10)
    if provider is Provider.GMAIL:
        replies = [gmail_identity()] + [
            Response({"messages": [], "nextPageToken": c}) for c in ("a", "b", "a")
        ]
    else:
        replies = [slack_identity(selected)] + [slack_page(selected, c) for c in ("a", "b", "a")]
    fixture = Fixture(selected, replies)
    with pytest.raises(PreflightError):
        fixture.run()
    assert len(fixture.calls) == 4 and fixture.gateway.invalidations == 1


@pytest.mark.parametrize("at,calls", [(1, 0), (2, 0), (3, 1), (4, 1), (5, 2), (6, 2)])
def test_current_owner_revocation_before_and_after_io(at: int, calls: int) -> None:
    fixture = Fixture(plan(metadata=True), [gmail_identity(), Response({"messages": []})])
    fixture.gateway.revoke_at = at
    with pytest.raises(PreflightError):
        fixture.run()
    assert len(fixture.calls) == calls and fixture.gateway.invalidations == 1


def test_expiry_during_identity_holds_before_inventory() -> None:
    fixture = Fixture(plan(metadata=True), [gmail_identity()])
    reads = 0

    def advancing_clock() -> datetime:
        nonlocal reads
        reads += 1
        return NOW if reads == 1 else NOW + timedelta(hours=2)

    with pytest.raises(PreflightError):
        fixture.run(advancing_clock)
    assert len(fixture.calls) == 1


def test_denied_authority_before_secret_load() -> None:
    fixture = Fixture(plan(), [])
    fixture.gateway.reject = True
    with pytest.raises(PreflightError):
        fixture.run()
    assert fixture.gateway.loads == 0 and not fixture.calls


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_provider_failure_quarantines_no_retry_or_body_read(status: int) -> None:
    response = Response({"error": "invented-secret"}, status=status)
    fixture = Fixture(plan(), [response])
    with pytest.raises(PreflightError) as error:
        fixture.run()
    assert len(fixture.calls) == 1 and response.reads == 0
    assert fixture.gateway.invalidations == 1 and error.value.__context__ is None


@pytest.mark.parametrize(
    "changes",
    [
        {"max_pages": True},
        {"max_pages": 11},
        {"mailbox": "other@example.invalid"},
        {"gmail_labels": ()},
        {"metadata": "true"},
    ],
)
def test_bad_plan_no_effects(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        plan(**changes)


def test_mutated_plan_revalidated_before_gateway() -> None:
    fixture = Fixture(plan().model_copy(update={"max_pages": 1000}), [])
    with pytest.raises(PreflightError):
        fixture.run()
    assert not fixture.gateway.consumed and fixture.gateway.loads == 0


@pytest.mark.parametrize("provider", list(Provider))
def test_fixed_keychain_loader_no_environment_fallback(
    provider: Provider, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, Any]] = []
    monkeypatch.setenv("BRAINSTORM_GMAIL_ACCESS_TOKEN", "environment-must-not-be-used")

    def run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, b"invented-token\n")

    monkeypatch.setattr(subprocess, "run", run)
    result = load_keychain_token(provider)
    assert result.get_secret_value() == "invented-token"
    args, kwargs = calls[0]
    assert args[:2] == ["/usr/bin/security", "find-generic-password"]
    assert args[3] == "zac-owner-source-access"
    assert args[5] == "zacai-brainstorm-" + (
        "gmail-access-token" if provider is Provider.GMAIL else "slack-user-token"
    )
    assert kwargs["env"] == {} and kwargs["timeout"] == 5 and not kwargs["shell"]
    assert "invented-token" not in repr(args)


@pytest.mark.parametrize("raw", [b"", b"bad token", b"bad\n\n", b"x" * 4097, b"\xff"])
def test_keychain_failure_secret_safe(raw: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, raw))
    with pytest.raises(PreflightError) as error:
        load_keychain_token(Provider.GMAIL)
    assert error.value.__context__ is None


def test_scope_change_on_inventory_holds_before_return() -> None:
    selected = plan(Provider.SLACK, metadata=True)
    page = slack_page(selected)
    page.scopes = selected.scopes | {"chat:write"}
    fixture = Fixture(selected, [slack_identity(selected), page])
    with pytest.raises(PreflightError):
        fixture.run()
    assert len(fixture.calls) == 2 and fixture.gateway.invalidations == 1


def test_secret_load_failure_and_quarantine_failure_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan(), [])

    def fail(*args: Any) -> Any:
        raise RuntimeError("invented-secret must never be exposed")

    monkeypatch.setattr(fixture.gateway, "credential", fail)
    monkeypatch.setattr(fixture.gateway, "invalidate", fail)
    with pytest.raises(PreflightError) as error:
        fixture.run()
    assert not fixture.calls and error.value.__context__ is None
    assert "invented-secret" not in str(error.value)


@pytest.mark.parametrize("failure", ["missing", "exception"])
def test_keychain_os_failure_no_fallback(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if failure == "exception":
            raise RuntimeError("invented-secret subprocess failure")
        return subprocess.CompletedProcess(args, 1, b"invented-secret")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(PreflightError) as error:
        load_keychain_token(Provider.GMAIL)
    assert error.value.__context__ is None and "invented-secret" not in str(error.value)


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_cancellation_quarantines_and_sanitizes_provider_traceback(
    failure: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan(metadata=True), [gmail_identity()])

    def cancelled(*args: Any, **kwargs: Any) -> Any:
        raise failure("invented-secret from provider frame")

    monkeypatch.setattr(Connection, "getresponse", cancelled)
    with pytest.raises(PreflightCancelled) as error:
        fixture.run()
    assert fixture.gateway.invalidations == 1 and fixture.connections[0].closed
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "invented-secret" not in str(error.value)
    frame = error.value.__traceback__
    names = []
    while frame is not None:
        names.append(frame.tb_frame.f_code.co_name)
        frame = frame.tb_next
    assert "_get" not in names and "getresponse" not in names


@pytest.mark.parametrize(
    "flag", ["is_shared", "is_ext_shared", "is_org_shared", "is_pending_ext_shared"]
)
@pytest.mark.parametrize("value", [1, "true", None])
def test_malformed_sharing_flags_hold(flag: str, value: Any) -> None:
    selected = plan(Provider.SLACK, metadata=True)
    row = {"id": "CTEST", "is_private": False, flag: value}
    fixture = Fixture(selected, [slack_identity(selected), slack_page(selected, channels=[row])])
    with pytest.raises(PreflightError):
        fixture.run()
    assert fixture.gateway.invalidations == 1


@pytest.mark.parametrize(
    "row",
    [
        {"id": "GTEST"},
        {"id": "CTEST"},
        {"id": "CTEST", "is_private": False, "is_pending_ext_shared": True},
    ],
)
def test_unknown_legacy_and_pending_sharing_count_conservatively(row: dict[str, Any]) -> None:
    selected = plan(Provider.SLACK, metadata=True)
    fixture = Fixture(selected, [slack_identity(selected), slack_page(selected, channels=[row])])
    assert fixture.run().mixed_or_restricted_channels == 1


def test_keychain_timeout_secret_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("invented-secret", 5, output=b"invented-secret")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(PreflightError) as error:
        load_keychain_token(Provider.GMAIL)
    assert error.value.__context__ is None
    assert "invented-secret" not in str(error.value)


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_keychain_cancellation_discards_plaintext_frames(
    failure: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, b"invented-token\n")
    )

    def cancel(*args: Any, **kwargs: Any) -> Any:
        raise failure("invented-token")

    monkeypatch.setattr("zacai.connectors.account_preflight.get_secret", cancel)
    with pytest.raises(PreflightCancelled) as error:
        load_keychain_token(Provider.GMAIL)
    assert error.value.__context__ is None
    frame = error.value.__traceback__
    while frame is not None:
        assert frame.tb_frame.f_code.co_name != "_load_keychain_token"
        frame = frame.tb_next


def test_failed_quarantine_is_distinct_and_remains_held(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = Fixture(plan(), [Response({}, status=401)])

    def fail(*args: Any) -> None:
        raise RuntimeError("invented-secret")

    monkeypatch.setattr(fixture.gateway, "invalidate", fail)
    with pytest.raises(PreflightQuarantineUnconfirmed) as error:
        fixture.run()
    assert error.value.__context__ is None


def test_interrupted_quarantine_keeps_cancellation_and_uncertainty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan(), [Response({}, status=401)])

    def fail(*args: Any) -> None:
        raise KeyboardInterrupt("invented-secret")

    monkeypatch.setattr(fixture.gateway, "invalidate", fail)
    with pytest.raises(PreflightCancellationQuarantineUnconfirmed) as error:
        fixture.run()
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    "row",
    [
        {"id": "CTEST", "is_private": False},
        {"id": "CTEST", "shared_team_ids": ["TFOREIGN"]},
        {"id": "CTEST", "conversation_host_id": "TFOREIGN"},
    ],
)
def test_unresolved_or_shared_inventory_requires_attention(row: dict[str, Any]) -> None:
    selected = plan(Provider.SLACK, metadata=True)
    fixture = Fixture(selected, [slack_identity(selected), slack_page(selected, channels=[row])])
    result = fixture.run()
    assert result.mixed_or_restricted_channels == 1 and result.continuation is None


@pytest.mark.parametrize("provider", list(Provider))
def test_communications_grant_requires_explicit_owner_plan_profile(provider: Provider) -> None:
    selected = plan(provider, grant_profile="approved_communications")
    fixture = Fixture(
        selected, [gmail_identity() if provider is Provider.GMAIL else slack_identity(selected)]
    )
    assert fixture.run().account_identity_matched
    narrow = plan(provider)
    fixture_narrow = Fixture(narrow, [])
    fixture_narrow.gateway.value = replace(fixture_narrow.gateway.value, scopes=selected.scopes)
    with pytest.raises(PreflightError):
        fixture_narrow.run()
    assert not fixture_narrow.calls


def test_completion_failure_quarantines_without_positive_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(plan(), [gmail_identity()])

    def fail(*args: Any) -> None:
        raise RuntimeError("invented-secret")

    monkeypatch.setattr(fixture.gateway, "complete", fail)
    with pytest.raises(PreflightError) as error:
        fixture.run()
    assert fixture.gateway.invalidations == 1 and not fixture.gateway.completed
    assert error.value.__context__ is None
