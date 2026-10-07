"""Real disposable encrypted owner sessions/ledger with invented offline grants."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import SecretStr
from starlette.requests import Request

from zacai.connectors.account_preflight import PreflightPlan, Provider, VerifiedCredential
from zacai.connectors.approved_communications import (
    CommunicationPlan,
    CommunicationReceipt,
    prepare_payload,
)
from zacai.connectors.connector_authority import (
    ConnectorApprovalUnconfirmed,
    ConnectorAuthority,
    ConnectorAuthorityCancelled,
    ConnectorAuthorityError,
    review_scope_digest,
)
from zacai.connectors.slack_wire import SlackAccount
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)
TOKEN = "invented-private-token-not-persisted"
OWNER = Identity("https://accounts.google.com", "invented-private-owner")


def read_plan(**changes: Any) -> PreflightPlan:
    fields = {
        "attempt_id": uuid4(),
        "provider": Provider.GMAIL,
        "client_id": "invented-client",
        "subject_id": "invented-gmail-subject",
    }
    fields.update(changes)
    return PreflightPlan(**fields)


def send_plan(**changes: Any) -> CommunicationPlan:
    fields = {
        "attempt_id": uuid4(),
        "provider": Provider.GMAIL,
        "client_id": "invented-client",
        "subject_id": "invented-gmail-subject",
        "purpose": "Invented exact purpose",
        "data_boundary": B.BRAINSTORM,
        "classification": C.INTERNAL,
        "to": ("invented-recipient@example.invalid",),
        "subject": "Invented private subject",
        "text": "Invented private message body not persisted",
    }
    fields.update(changes)
    return CommunicationPlan(**fields)


def payload_digest(selected: CommunicationPlan) -> str:
    return hashlib.sha256(prepare_payload(selected)).hexdigest()


def scope_digest(selected: PreflightPlan | CommunicationPlan) -> str:
    return review_scope_digest(selected)


class Backend:
    def __init__(self) -> None:
        self.current = "invented-generation-1"
        self.loads = self.attestations = self.quarantines = 0
        self.reject = False
        self.fail_load = self.fail_quarantine = False

    def generation(self, selected: Any) -> str:
        if self.reject:
            raise RuntimeError(TOKEN)
        return self.current

    def attest(self, selected: Any) -> None:
        self.attestations += 1
        if self.reject:
            raise RuntimeError(TOKEN)

    def credential(self, selected: Any, generation: str) -> VerifiedCredential:
        self.loads += 1
        if self.fail_load or generation != self.current:
            raise RuntimeError(TOKEN)
        return VerifiedCredential(
            SecretStr(TOKEN),
            selected.provider,
            selected.client_id,
            selected.subject_id,
            selected.scopes,
            "oauth_access",
            B.BRAINSTORM,
            NOW + timedelta(hours=1),
        )

    def quarantine(self, selected: Any, generation: str) -> None:
        self.quarantines += 1
        if self.fail_quarantine:
            raise RuntimeError(TOKEN)


class Fixture:
    def __init__(self, temporary: Path) -> None:
        self.now = NOW
        self.key = b"A" * 32
        self.directory = temporary / "connector-operational"
        self.backend = Backend()
        self.owner = OwnerGrant(
            OWNER,
            (
                BoundaryScope(
                    B.BRAINSTORM, frozenset({C.INTERNAL, C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})
                ),
            ),
        )
        self.sessions = SqliteSessionStore(temporary / "sessions", key=b"S" * 32)
        self.cookie = self.sessions.start_user(OWNER, self.now)
        self.csrf = self.sessions.peek_user(self.cookie, self.now).csrf
        self.clock = HostObservedClock(lambda: self.now)
        self.continuity = NamedSessionContinuity(
            sessions=self.sessions,
            owner=lambda: self.owner,
            clock=self.clock,
            key=b"S" * 32,
            origin="https://caz.example",
            client_id="invented-client",
        )
        self.authority = self.reopen()
        self.authority.initialize()

    def reopen(self, **changes: Any) -> ConnectorAuthority:
        fields = {"key": self.key, "continuity": self.continuity, "backend": self.backend}
        fields.update(changes)
        return ConnectorAuthority(self.directory, **fields)

    def request(self, *, cookie: str | None = None, **changes: Any) -> Request:
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/connector-review",
            "scheme": "https",
            "query_string": b"",
            "server": ("caz.example", 443),
            "client": ("127.0.0.1", 1),
            "headers": [
                (b"host", b"caz.example"),
                (b"origin", b"https://caz.example"),
                (b"cookie", ("__Host-zac-session=" + (cookie or self.cookie)).encode()),
            ],
        }
        scope.update(changes)
        return Request(scope)

    def approve(self, selected: Any, **changes: Any) -> None:
        fields = {
            "request": self.request(),
            "csrf": self.csrf,
            "reviewed_scope_digest": scope_digest(selected),
            "payload_digest": payload_digest(selected)
            if isinstance(selected, CommunicationPlan)
            else None,
        }
        fields.update(changes)
        self.authority.approve_review(selected, **fields)

    def gateway(
        self,
        authority: ConnectorAuthority | None = None,
        request: Request | None = None,
        csrf: str | None = None,
    ) -> Any:
        return (authority or self.authority).for_request(
            request or self.request(path="/connector-execute"),
            csrf=self.csrf if csrf is None else csrf,
        )


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    return Fixture(tmp_path)


def consume(gateway: Any, selected: Any) -> None:
    if isinstance(selected, CommunicationPlan):
        gateway.consume_exact(selected, payload_digest(selected))
    else:
        gateway.consume(selected)


def confirmed(selected: CommunicationPlan) -> CommunicationReceipt:
    return CommunicationReceipt(
        selected.provider,
        selected.attempt_id,
        "invented-sent-id",
        "invented-thread-id",
        payload_digest(selected),
    )


@pytest.mark.parametrize("kind", ["read", "send"])
def test_approved_consumption_survives_reopen_and_replay_never_loads(
    fixture: Fixture, kind: str
) -> None:
    selected = read_plan() if kind == "read" else send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway(fixture.reopen())
    consume(gateway, selected)
    assert fixture.backend.loads == 0
    gateway.assert_current(selected, payload_digest(selected) if kind == "send" else None)
    credential = gateway.credential(selected)
    assert credential.token.get_secret_value() == TOKEN and fixture.backend.loads == 1
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    assert fixture.backend.loads == 1


def test_exact_plan_and_payload_approval_binding_before_consumption(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    changed = selected.model_copy(update={"text": "Different exact wording"})
    gateway = fixture.gateway()
    with pytest.raises(ConnectorAuthorityError):
        gateway.consume_exact(changed, payload_digest(changed))
    with pytest.raises(ConnectorAuthorityError):
        gateway.consume_exact(selected, "0" * 64)
    assert fixture.backend.loads == 0
    gateway.consume_exact(selected, payload_digest(selected))


def test_concurrent_instances_atomically_consume_once(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateways = [fixture.gateway(fixture.reopen()) for _ in range(2)]

    def attempt(gateway: Any) -> bool:
        try:
            consume(gateway, selected)
            return True
        except ConnectorAuthorityError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, gateways)) == [False, True]
    assert fixture.backend.loads == 0


def test_crashed_inflight_blocks_new_attempt_and_generation(fixture: Fixture) -> None:
    first = send_plan()
    fixture.approve(first)
    consume(fixture.gateway(), first)
    # No confirm/hold cleanup: this models death immediately after durable consume.
    fixture.backend.current = "invented-generation-2"
    second = send_plan()
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(second)
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), first)
    assert fixture.backend.loads == 0


def test_current_generation_change_cannot_transfer_old_approval(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    fixture.backend.current = "invented-generation-2"
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(), selected)
    assert fixture.backend.loads == 0


def test_generation_revoked_after_consume_prevents_credential(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    fixture.backend.current = "invented-generation-2"
    with pytest.raises(ConnectorAuthorityError):
        gateway.assert_current(selected, payload_digest(selected))
    with pytest.raises(ConnectorAuthorityError):
        gateway.credential(selected)
    assert fixture.backend.loads == 0


def test_receipt_confirm_releases_account_but_attempt_remains_spent(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.credential(selected)
    gateway.confirm(selected, confirmed(selected))
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    replacement = send_plan()
    fixture.approve(replacement)
    consume(fixture.gateway(fixture.reopen()), replacement)


def test_uncertain_hold_preserves_receipt_and_blocks_new_approvals(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.credential(selected)
    receipt = confirmed(selected)
    fixture.sessions.revoke(fixture.cookie)
    # Receipt-only hold must survive owner revocation; it grants no execution.
    gateway.hold(selected, uncertain=True, observed=receipt)
    replacement_cookie = fixture.sessions.start_user(OWNER, fixture.now)
    fixture.cookie = replacement_cookie
    fixture.csrf = fixture.sessions.peek_user(fixture.cookie, fixture.now).csrf
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    assert fixture.backend.quarantines == 1


@pytest.mark.parametrize("where", ["approval", "consume", "credential"])
def test_actual_session_revocation_never_loads_credentials(fixture: Fixture, where: str) -> None:
    selected = send_plan()
    gateway = fixture.gateway()
    if where != "approval":
        fixture.approve(selected)
    if where == "credential":
        consume(gateway, selected)
    fixture.sessions.revoke(fixture.cookie)
    with pytest.raises(ConnectorAuthorityError):
        if where == "approval":
            fixture.approve(selected)
        elif where == "consume":
            consume(gateway, selected)
        else:
            gateway.credential(selected)
    assert fixture.backend.loads == 0


def test_renewed_same_owner_session_does_not_transfer_reviewed_approval(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    cookie = fixture.sessions.start_user(OWNER, fixture.now)
    with pytest.raises(ConnectorAuthorityError):
        consume(
            fixture.gateway(
                request=fixture.request(cookie=cookie, path="/connector-execute"),
                csrf=fixture.sessions.peek_user(cookie, fixture.now).csrf,
            ),
            selected,
        )
    assert fixture.backend.loads == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"csrf": "wrong"},
        {"reviewed_scope_digest": "0" * 64},
        {"payload_digest": "0" * 64},
    ],
)
def test_incorrect_review_proof_denied(fixture: Fixture, changes: dict[str, Any]) -> None:
    selected = send_plan()
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(selected, **changes)
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(), selected)
    assert fixture.backend.loads == 0


@pytest.mark.parametrize(
    "request_change",
    [
        {"method": "GET"},
        {"path": "/other"},
        {"headers": [(b"host", b"evil.invalid"), (b"origin", b"https://evil.invalid")]},
        {
            "headers": [
                (b"host", b"caz.example"),
                (b"origin", b"https://caz.example"),
                (b"cookie", b"__Host-zac-session=one; __Host-zac-session=two"),
            ]
        },
    ],
)
def test_bad_request_origin_method_cookie_denied(
    fixture: Fixture, request_change: dict[str, Any]
) -> None:
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan(), request=fixture.request(**request_change))
    assert fixture.backend.loads == 0


def test_owner_scope_change_denies_previously_reviewed_plan(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    fixture.owner = OwnerGrant(OWNER, (BoundaryScope(B.PERSONAL, frozenset({C.INTERNAL})),))
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(), selected)
    assert fixture.backend.loads == 0


def test_review_expiry_does_not_renew_on_read(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    fixture.now += timedelta(minutes=5)
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    assert fixture.backend.loads == 0


def test_backend_failure_errors_fixed_and_secret_safe(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.backend.reject = True
    with pytest.raises(ConnectorAuthorityError) as error:
        fixture.approve(selected)
    assert TOKEN not in str(error.value) and error.value.__context__ is None
    assert fixture.backend.loads == 0


def test_operational_files_have_no_cookie_key_token_or_message(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    consume(fixture.gateway(), selected)
    assert fixture.directory.stat().st_mode & 0o777 == 0o700
    for path in fixture.directory.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        raw = path.read_bytes()
        for private in [
            TOKEN,
            fixture.cookie,
            fixture.csrf,
            selected.text,
            selected.subject,
            selected.to[0],
            OWNER.subject,
        ]:
            assert private.encode() not in raw
        assert fixture.key not in raw


def test_missing_ledger_does_not_auto_initialize_on_use(fixture: Fixture, tmp_path: Path) -> None:
    authority = ConnectorAuthority(
        tmp_path / "missing",
        key=fixture.key,
        continuity=fixture.continuity,
        backend=fixture.backend,
    )
    with pytest.raises(ConnectorAuthorityError):
        authority.approve_review(
            send_plan(),
            request=fixture.request(),
            csrf=fixture.csrf,
            reviewed_scope_digest="0" * 64,
            payload_digest="0" * 64,
        )
    assert fixture.backend.loads == 0


def test_same_mailbox_alternate_client_subject_cannot_escape_inflight_hold(
    fixture: Fixture,
) -> None:
    first = send_plan()
    fixture.approve(first)
    consume(fixture.gateway(), first)
    replacement = send_plan(client_id="other-invented-app", subject_id="other-invented-subject")
    fixture.backend.current = "invented-generation-2"
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(replacement)
    assert fixture.backend.loads == 0


def test_inflight_read_blocks_write_for_same_provider_account(fixture: Fixture) -> None:
    selected = read_plan()
    fixture.approve(selected)
    consume(fixture.gateway(), selected)
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())


def test_repeated_hold_cannot_clear_uncertainty_or_replace_observed_evidence(
    fixture: Fixture,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.credential(selected)
    receipt = confirmed(selected)
    gateway.hold(selected, uncertain=True, observed=receipt)
    gateway.hold(selected, uncertain=False, observed=None)
    with pytest.raises(ConnectorAuthorityError):
        gateway.hold(
            selected,
            uncertain=True,
            observed=CommunicationReceipt(
                selected.provider,
                selected.attempt_id,
                "different-sent-id",
                "different-thread-id",
                payload_digest(selected),
            ),
        )
    reopened = fixture.reopen()
    with reopened._locked():
        row = reopened._read()["rows"][str(selected.attempt_id)]
    assert row["state"] == "held" and row["uncertain"] is True
    assert row["observed"]["provider_id"] == receipt.provider_id
    assert row["observed"]["thread_id"] == receipt.thread_id
    with pytest.raises(ConnectorAuthorityError):
        fixture.gateway(reopened).confirm(selected, receipt)


def test_receipt_with_wrong_attempt_or_payload_never_releases_inflight(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    bad = CommunicationReceipt(
        selected.provider, uuid4(), "invented-id", "invented-thread", payload_digest(selected)
    )
    with pytest.raises(ConnectorAuthorityError):
        gateway.confirm(selected, bad)
    bad = CommunicationReceipt(
        selected.provider, selected.attempt_id, "invented-id", "invented-thread", "0" * 64
    )
    with pytest.raises(ConnectorAuthorityError):
        gateway.confirm(selected, bad)
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())


def test_backend_quarantine_failure_keeps_durable_hold(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.credential(selected)
    fixture.backend.fail_quarantine = True
    with pytest.raises(ConnectorAuthorityError) as error:
        gateway.hold(selected, uncertain=True, observed=confirmed(selected))
    assert error.value.__context__ is None and TOKEN not in str(error.value)
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())
    reopened = fixture.reopen()
    with reopened._locked():
        row = reopened._read()["rows"][str(selected.attempt_id)]
    assert row["state"] == "held" and row["observed"]["provider_id"] == "invented-sent-id"


@pytest.mark.parametrize("damage", ["wrong_key", "ciphertext", "missing", "file_mode"])
def test_ledger_loss_corruption_wrong_key_never_load_or_silently_recreate(
    fixture: Fixture,
    damage: str,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    ledger = fixture.directory / "connector-authority.bin"
    authority = fixture.authority
    if damage == "wrong_key":
        authority = fixture.reopen(key=b"W" * 32)
    elif damage == "ciphertext":
        raw = ledger.read_bytes()
        ledger.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    elif damage == "missing":
        ledger.unlink()
    else:
        ledger.chmod(0o644)
    with pytest.raises(ConnectorAuthorityError) as error:
        consume(fixture.gateway(authority), selected)
    assert fixture.backend.loads == 0 and error.value.__context__ is None
    if damage == "missing":
        assert not ledger.exists()


@pytest.mark.parametrize(
    "unsafe",
    [
        "directory_mode",
        "directory_link",
        "file_link",
        "lock_link",
        "file_hardlink",
        "lock_hardlink",
    ],
)
def test_unsafe_paths_fail_closed(fixture: Fixture, tmp_path: Path, unsafe: str) -> None:
    path = fixture.directory / (
        "connector-authority.lock" if unsafe.startswith("lock") else "connector-authority.bin"
    )
    directory = fixture.directory
    if unsafe == "directory_mode":
        directory.chmod(0o755)
    elif unsafe == "directory_link":
        directory = tmp_path / "directory-link"
        directory.symlink_to(fixture.directory, target_is_directory=True)
    elif unsafe.endswith("hardlink"):
        import os

        os.link(path, fixture.directory / "extra-hardlink")
    else:
        target = fixture.directory / "real-target"
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(ConnectorAuthorityError):
        authority = ConnectorAuthority(
            directory, key=fixture.key, continuity=fixture.continuity, backend=fixture.backend
        )
        authority.approve_review(
            send_plan(),
            request=fixture.request(),
            csrf=fixture.csrf,
            reviewed_scope_digest="0" * 64,
            payload_digest="0" * 64,
        )
    assert fixture.backend.loads == 0


def test_backend_credential_failure_never_refunds_consumption(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    fixture.backend.fail_load = True
    with pytest.raises(ConnectorAuthorityError) as error:
        gateway.credential(selected)
    assert TOKEN not in str(error.value) and error.value.__context__ is None
    fixture.backend.fail_load = False
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())


@pytest.mark.parametrize("callback", ["attest", "generation"])
def test_backend_callback_crosses_review_deadline_before_consume_denied(
    fixture: Fixture,
    callback: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    original = getattr(fixture.backend, callback)

    def advancing(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        fixture.now += timedelta(minutes=5)
        return result

    monkeypatch.setattr(fixture.backend, callback, advancing)
    with pytest.raises(ConnectorAuthorityError):
        consume(gateway, selected)
    assert fixture.backend.loads == 0


def test_independent_attestation_revoked_before_credential_denies(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    fixture.backend.reject = True
    with pytest.raises(ConnectorAuthorityError):
        gateway.credential(selected)
    assert fixture.backend.loads == 0


def slack_send(**changes: Any) -> CommunicationPlan:
    fields = send_plan().model_dump()
    fields.update(
        provider=Provider.SLACK,
        subject_id="UTEST",
        to=(),
        cc=(),
        subject="",
        slack_account=SlackAccount(team_id="TTEST", user_id="UTEST"),
        channel_id="CTEST",
    )
    fields.update(changes)
    return CommunicationPlan.model_validate(fields)


def test_slack_same_team_user_alternate_client_cannot_escape_hold(fixture: Fixture) -> None:
    first = slack_send()
    fixture.approve(first)
    consume(fixture.gateway(), first)
    replacement = slack_send(client_id="different-invented-client")
    fixture.backend.current = "invented-generation-2"
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(replacement)
    assert fixture.backend.loads == 0


def test_distinct_verified_slack_account_can_proceed_while_other_held(fixture: Fixture) -> None:
    first = slack_send()
    fixture.approve(first)
    consume(fixture.gateway(), first)
    second = slack_send(slack_account=SlackAccount(team_id="TOTHER", user_id="UTEST"))
    fixture.approve(second)
    consume(fixture.gateway(), second)
    assert fixture.backend.loads == 0


def test_read_completion_releases_account_without_replaying_attempt(fixture: Fixture) -> None:
    from zacai.connectors.account_preflight import Coverage

    selected = read_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    coverage = Coverage(Provider.GMAIL, NOW, True, 1, 0, 0, False, None)
    gateway.credential(selected)
    gateway.complete(selected, coverage)
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    fixture.approve(send_plan())


def test_successful_consumption_does_not_touch_browser_idle_activity(fixture: Fixture) -> None:
    selected = send_plan()
    before = fixture.sessions.peek_user(fixture.cookie, fixture.now)
    fixture.approve(selected)
    fixture.now += timedelta(minutes=1)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.assert_current(selected, payload_digest(selected))
    gateway.credential(selected)
    after = fixture.sessions.peek_user(fixture.cookie, fixture.now)
    assert before.last_seen_at == after.last_seen_at and before.csrf == after.csrf


def test_completed_capacity_never_evicts_spent_attempts(fixture: Fixture) -> None:
    first = None
    for _ in range(256):
        selected = send_plan()
        first = first or selected
        fixture.approve(selected)
        gateway = fixture.gateway()
        consume(gateway, selected)
        gateway.credential(selected)
        gateway.confirm(selected, confirmed(selected))
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), first)
    assert fixture.backend.loads == 256


def ledger_row(fixture: Fixture, selected: Any) -> dict[str, Any]:
    reopened = fixture.reopen()
    with reopened._locked():
        return reopened._read()["rows"][str(selected.attempt_id)]


def test_actual_authority_preflight_completes_and_replay_never_reads(fixture: Fixture) -> None:
    from tests.test_account_preflight import Fixture as WireFixture
    from tests.test_account_preflight import gmail_identity
    from zacai.connectors.account_preflight import Coverage, PreflightError, preflight
    from zacai.connectors.gmail_transport import GmailReadTransport
    from zacai.connectors.slack_transport import SlackReadTransport

    selected = read_plan()
    fixture.approve(selected)
    wires = WireFixture(selected, [gmail_identity()])
    gateway = fixture.gateway()

    def run() -> Coverage:
        return preflight(
            selected,
            gateway=gateway,
            gmail=GmailReadTransport(connection_factory=wires.connect),
            slack=SlackReadTransport(connection_factory=wires.connect),
            clock=lambda: fixture.now,
        )

    result = run()
    assert result.account_identity_matched and result.requests == 1
    assert fixture.backend.loads == 1 and wires.calls == ["/gmail/v1/users/me/profile"]
    assert ledger_row(fixture, selected)["state"] == "completed"
    with pytest.raises(PreflightError):
        run()
    assert fixture.backend.loads == 1 and len(wires.calls) == 1


@pytest.mark.parametrize("revoke_after_ack", [False, True])
def test_actual_authority_approved_send_complete_or_preserve_revoked_ack(
    fixture: Fixture,
    revoke_after_ack: bool,
) -> None:
    import json

    from tests.test_account_preflight import Fixture as WireFixture
    from tests.test_account_preflight import gmail_identity
    from zacai.connectors.approved_communications import (
        CommunicationUncertain,
        SyntheticWriteTransport,
        execute_approved,
    )
    from zacai.connectors.gmail_transport import GmailReadTransport
    from zacai.connectors.slack_transport import SlackReadTransport

    selected = send_plan()
    fixture.approve(selected)
    wires = WireFixture(read_plan(), [gmail_identity()])
    writes = []
    gateway = fixture.gateway()

    def exchange(key: SecretStr, payload: bytes) -> bytes:
        assert key.get_secret_value() == TOKEN
        writes.append(payload)
        if revoke_after_ack:
            fixture.sessions.revoke(fixture.cookie)
        return json.dumps(
            {"id": "actual-invented-sent", "threadId": "actual-invented-thread"}
        ).encode()

    def run() -> Any:
        return execute_approved(
            selected,
            gateway=gateway,
            gmail=GmailReadTransport(connection_factory=wires.connect),
            slack=SlackReadTransport(connection_factory=wires.connect),
            writer=SyntheticWriteTransport(provider=Provider.GMAIL, exchange=exchange),
            clock=lambda: fixture.now,
        )

    if revoke_after_ack:
        with pytest.raises(CommunicationUncertain):
            run()
    else:
        result = run()
        assert result.provider_id == "actual-invented-sent"
    row = ledger_row(fixture, selected)
    assert row["state"] == ("held" if revoke_after_ack else "completed")
    assert row["uncertain"] is revoke_after_ack
    assert row["observed"]["provider_id"] == "actual-invented-sent"
    assert row["observed"]["thread_id"] == "actual-invented-thread"
    assert row["observed"]["payload_digest"] == payload_digest(selected)
    assert fixture.backend.loads == 1 and len(writes) == len(wires.calls) == 1
    from zacai.connectors.approved_communications import CommunicationError

    with pytest.raises(CommunicationError):
        run()
    assert fixture.backend.loads == 1 and len(writes) == len(wires.calls) == 1


def test_credential_is_single_issuance_per_consumed_attempt(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.credential(selected)
    with pytest.raises(ConnectorAuthorityError):
        gateway.credential(selected)
    assert fixture.backend.loads == 1


@pytest.mark.parametrize("method", ["credential", "current", "confirm"])
def test_fresh_gateway_cannot_resume_inflight_same_session_generation(
    fixture: Fixture,
    method: str,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    original = fixture.gateway()
    consume(original, selected)
    if method == "confirm":
        original.credential(selected)
    restarted = fixture.gateway(fixture.reopen())
    with pytest.raises(ConnectorAuthorityError):
        if method == "credential":
            restarted.credential(selected)
        elif method == "current":
            restarted.assert_current(selected, payload_digest(selected))
        else:
            restarted.confirm(selected, confirmed(selected))
    # Original capability can hold; restart preservation is allowed but cannot release.
    restarted.hold(selected, uncertain=True, observed=None)
    assert ledger_row(fixture, selected)["state"] == "held"
    assert fixture.backend.loads == int(method == "confirm")


def test_restart_cannot_complete_read_but_can_preserve_invalidation(fixture: Fixture) -> None:
    from zacai.connectors.account_preflight import Coverage

    selected = read_plan()
    fixture.approve(selected)
    original = fixture.gateway()
    consume(original, selected)
    original.credential(selected)
    restarted = fixture.gateway(fixture.reopen())
    with pytest.raises(ConnectorAuthorityError):
        restarted.complete(selected, Coverage(Provider.GMAIL, NOW, True, 1, 0, 0, False, None))
    restarted.invalidate(selected)
    assert ledger_row(fixture, selected)["state"] == "held"


def test_send_cannot_use_read_completion_to_release_without_ack(fixture: Fixture) -> None:
    from zacai.connectors.account_preflight import Coverage

    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    gateway.credential(selected)
    with pytest.raises(ConnectorAuthorityError):
        gateway.complete(selected, Coverage(Provider.GMAIL, NOW, True, 1, 0, 0, False, None))
    assert ledger_row(fixture, selected)["state"] == "in_flight"
    with pytest.raises(ConnectorAuthorityError):
        fixture.approve(send_plan())


@pytest.mark.parametrize("method", ["consume_exact", "hold"])
def test_read_plan_cannot_enter_communication_lifecycle(fixture: Fixture, method: str) -> None:
    selected = read_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    if method == "hold":
        consume(gateway, selected)
    with pytest.raises(ConnectorAuthorityError):
        if method == "consume_exact":
            gateway.consume_exact(selected, None)
        else:
            gateway.hold(selected, uncertain=False, observed=None)


def test_send_plan_cannot_enter_preflight_invalidation(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    with pytest.raises(ConnectorAuthorityError):
        gateway.invalidate(selected)
    assert ledger_row(fixture, selected)["state"] == "in_flight"


def test_credential_issuance_flag_is_durable_before_backend_secret_call(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    original = fixture.backend.credential
    observed = []

    def inspect_without_acquiring_lock(plan: Any, generation: str) -> VerifiedCredential:
        # Atomic file reads only; backend never re-enters the authority lock.
        row = fixture.authority._read()["rows"][str(plan.attempt_id)]
        observed.append(row["loaded"])
        return original(plan, generation)

    monkeypatch.setattr(fixture.backend, "credential", inspect_without_acquiring_lock)
    gateway.credential(selected)
    assert observed == [True] and fixture.backend.loads == 1


def test_failed_secret_loader_cannot_be_called_again_on_same_gateway(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)
    fixture.backend.fail_load = True
    with pytest.raises(ConnectorAuthorityError):
        gateway.credential(selected)
    fixture.backend.fail_load = False
    with pytest.raises(ConnectorAuthorityError):
        gateway.credential(selected)
    assert fixture.backend.loads == 1 and ledger_row(fixture, selected)["loaded"] is True


@pytest.mark.parametrize("change", ["csrf", "method", "path", "origin"])
def test_execution_gate_requires_actual_post_origin_and_csrf(fixture: Fixture, change: str) -> None:
    request = fixture.request(path="/connector-execute")
    csrf = fixture.csrf
    if change == "csrf":
        csrf = "incorrect-csrf"
    elif change == "method":
        request = fixture.request(path="/connector-execute", method="GET")
    elif change == "path":
        request = fixture.request(path="/connector-review")
    else:
        headers = list(request.scope["headers"])
        headers = [
            (name, b"https://evil.invalid" if name == b"origin" else value)
            for name, value in headers
        ]
        request = fixture.request(path="/connector-execute", headers=headers)
    with pytest.raises(ConnectorAuthorityError):
        fixture.authority.for_request(request, csrf=csrf)
    assert fixture.backend.loads == 0


@pytest.mark.parametrize("cancelled", [False, True])
def test_approval_directory_fsync_failure_after_replace_is_conservatively_held(
    fixture: Fixture,
    cancelled: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import stat

    selected = send_plan()
    original = os.fsync
    failed = False

    def fail_first_directory(fd: int) -> None:
        nonlocal failed
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed = True
            if cancelled:
                raise KeyboardInterrupt(TOKEN)
            raise OSError(TOKEN)
        original(fd)

    monkeypatch.setattr(os, "fsync", fail_first_directory)
    expected = ConnectorAuthorityCancelled if cancelled else ConnectorAuthorityError
    with pytest.raises(expected) as error:
        fixture.approve(selected)
    assert failed and TOKEN not in str(error.value) and error.value.__context__ is None
    assert ledger_row(fixture, selected)["state"] == "held"
    with pytest.raises(ConnectorAuthorityError):
        consume(fixture.gateway(fixture.reopen()), selected)
    assert fixture.backend.loads == 0


def test_unconfirmed_issuance_recovery_disables_original_authority(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import stat

    selected = send_plan()
    original = os.fsync

    def fail_directory(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(TOKEN)
        original(fd)

    monkeypatch.setattr(os, "fsync", fail_directory)
    with pytest.raises(ConnectorApprovalUnconfirmed) as error:
        fixture.approve(selected)
    assert TOKEN not in str(error.value) and error.value.__context__ is None
    monkeypatch.setattr(os, "fsync", original)
    with pytest.raises(ConnectorApprovalUnconfirmed):
        fixture.gateway()
    with pytest.raises(ConnectorApprovalUnconfirmed):
        fixture.approve(send_plan())
    assert fixture.backend.loads == 0


def test_interrupted_secret_loader_is_sanitized_and_never_reissued(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    gateway = fixture.gateway()
    consume(gateway, selected)

    def cancelled(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt(TOKEN)

    monkeypatch.setattr(fixture.backend, "credential", cancelled)
    with pytest.raises(ConnectorAuthorityCancelled) as error:
        gateway.credential(selected)
    assert not isinstance(error.value, Exception)
    assert TOKEN not in str(error.value) and error.value.__context__ is None
    names = []
    frame = error.value.__traceback__
    while frame:
        names.append(frame.tb_frame.f_code.co_name)
        frame = frame.tb_next
    assert "cancelled" not in names
    assert ledger_row(fixture, selected)["loaded"] is True
    with pytest.raises(ConnectorAuthorityError):
        gateway.credential(selected)


def test_fresh_gateway_unknown_send_hold_forces_uncertain(fixture: Fixture) -> None:
    selected = send_plan()
    fixture.approve(selected)
    original = fixture.gateway()
    consume(original, selected)
    original.credential(selected)
    # A newly composed gateway has no observation of whether the old process sent.
    fixture.gateway(fixture.reopen()).hold(selected, uncertain=False, observed=None)
    row = ledger_row(fixture, selected)
    assert row["state"] == "held" and row["uncertain"] is True and row["observed"] is None


def test_fresh_gateway_cannot_install_fabricated_ack_before_original_preservation(
    fixture: Fixture,
) -> None:
    selected = send_plan()
    fixture.approve(selected)
    original = fixture.gateway()
    consume(original, selected)
    original.credential(selected)
    fake = CommunicationReceipt(
        selected.provider,
        selected.attempt_id,
        "fabricated-sent-id",
        "fabricated-thread-id",
        payload_digest(selected),
    )
    restarted = fixture.gateway(fixture.reopen())
    with pytest.raises(ConnectorAuthorityError):
        restarted.hold(selected, uncertain=True, observed=fake)
    assert ledger_row(fixture, selected)["observed"] is None
    actual = confirmed(selected)
    original.hold(selected, uncertain=True, observed=actual)
    row = ledger_row(fixture, selected)
    assert row["uncertain"] is True and row["observed"]["provider_id"] == actual.provider_id
    assert row["observed"]["thread_id"] == actual.thread_id
