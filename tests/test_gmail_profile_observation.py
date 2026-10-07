"""Private same-exchange observation with invented HTTP and disposable owner state."""

from dataclasses import replace
from datetime import timedelta

import pytest

from tests.test_oauth_exchange import Fixture, safe
from zacai.connectors.oauth_exchange import (
    CheckedOAuthExchange,
    GmailProfileObservation,
    OAuthExchangeCancelled,
    OAuthExchangeError,
    OAuthExchangeTransport,
)


def test_exact_existing_profile_call_retained_without_extra_http_or_installation(tmp_path):
    f = Fixture(tmp_path)
    checked = f.execute()
    before = list(f.calls)
    observation = checked.gmail_profile_observation(f.operation)
    assert type(observation) is GmailProfileObservation
    assert observation is checked.gmail_profile_observation(f.operation)
    assert len(before) == 3 and f.calls == before
    assert [item[:3] for item in f.calls] == [
        ("oauth2.googleapis.com", "POST", "/token"),
        ("oauth2.googleapis.com", "POST", "/tokeninfo"),
        ("gmail.googleapis.com", "GET", "/gmail/v1/users/me/profile"),
    ]
    assert all(connection.closed for connection in f.connections)
    assert observation.observed_at == f.transactions.sessions.now
    assert observation.profile_verified is True
    assert checked.installed is observation.installed is False
    assert observation.processing_authorized is observation.execution_authorized is False
    assert repr(observation) == "GmailProfileObservation()"
    assert repr(checked) == "CheckedOAuthExchange()"
    assert f.row()["state"] == "exchange_started"
    f.operation.hold()
    with pytest.raises(OAuthExchangeError):
        checked.gmail_profile_observation(f.operation)
    assert f.calls == before and f.row()["state"] == "held"


def test_result_parser_and_candidate_constructor_cannot_issue_observation(tmp_path):
    f = Fixture(tmp_path)
    checked = f.execute()
    with pytest.raises(TypeError):
        GmailProfileObservation()
    with pytest.raises(TypeError):
        CheckedOAuthExchange(checked.candidate, _gmail_observation=checked._gmail_observation)
    parsed = CheckedOAuthExchange(checked.candidate)
    with pytest.raises(OAuthExchangeError):
        parsed.gmail_profile_observation(f.operation)
    transplanted = CheckedOAuthExchange(checked.candidate)
    object.__setattr__(transplanted, "_gmail_observation", checked._gmail_observation)
    with pytest.raises(OAuthExchangeError):
        transplanted.gmail_profile_observation(f.operation)
    assert len(f.calls) == 3


@pytest.mark.parametrize(
    "change",
    ["authority", "configuration", "named_operation", "state", "capability", "candidate", "token"],
)
def test_original_composition_and_same_token_required_without_http(tmp_path, change):
    f = Fixture(tmp_path)
    checked = f.execute()
    before = list(f.calls)
    if change == "authority":
        f.operation._authority = f.transactions.reopen()
    elif change == "configuration":
        f.operation._configuration = f.operation._configuration.model_copy()
    elif change == "named_operation":
        f.operation._operation = f.transactions.sessions.continuity.for_cookie(
            f.transactions.sessions.cookie
        )
    elif change == "state":
        f.operation._state_hash = "b" * 64
    elif change == "capability":
        f.operation._capability = "invented-foreign-capability"
    elif change == "candidate":
        object.__setattr__(checked, "candidate", replace(checked.candidate))
    else:
        checked.candidate.access_token._secret_value = "invented-changed-token"
    with pytest.raises(OAuthExchangeError) as raised:
        checked.gmail_profile_observation(f.operation)
    safe(raised.value)
    assert f.calls == before


def test_foreign_operation_and_slack_result_have_no_gmail_observation(tmp_path):
    for name in ("first", "second", "slack"):
        (tmp_path / name).mkdir(mode=0o700)
    first, second = Fixture(tmp_path / "first"), Fixture(tmp_path / "second")
    checked = first.execute()
    with pytest.raises(OAuthExchangeError):
        checked.gmail_profile_observation(second.operation)
    slack = Fixture(tmp_path / "slack", "slack")
    slack_checked = slack.execute()
    assert slack_checked._gmail_observation is None
    with pytest.raises(OAuthExchangeError):
        slack_checked.gmail_profile_observation(slack.operation)
    assert len(first.calls) == 3 and not second.calls and len(slack.calls) == 2


@pytest.mark.parametrize("change", ["revoked", "expired", "registration"])
def test_observation_requires_current_original_owner_grant(tmp_path, change):
    f = Fixture(tmp_path)
    checked = f.execute()
    before = list(f.calls)
    if change == "revoked":
        f.transactions.sessions.sessions.revoke(f.transactions.sessions.cookie)
    elif change == "expired":
        f.transactions.sessions.now += timedelta(hours=1)
    else:
        f.transactions.registration.current = "different-reviewed-registration"
    with pytest.raises(OAuthExchangeError):
        checked.gmail_profile_observation(f.operation)
    assert f.calls == before


@pytest.mark.parametrize("change", ["mailbox", "revocation", "changed_token"])
def test_profile_failure_or_late_change_never_issues_observation(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path)
    if change == "mailbox":
        f.responses[
            2
        ].body = b'{"emailAddress":"wrong@example.com","historyId":"123","messagesTotal":0,"threadsTotal":0}'
    elif change == "revocation":
        f.revoke_after_request = 3
    else:
        original = OAuthExchangeTransport.gmail_profile

        def profile(transport, access, configuration):
            original(transport, access, configuration)
            access._secret_value = "invented-changed-after-profile"

        monkeypatch.setattr(OAuthExchangeTransport, "gmail_profile", profile)
    with pytest.raises(OAuthExchangeError):
        f.execute()
    assert len(f.calls) == 3 and f.row()["state"] == "held"
    assert all(connection.closed for connection in f.connections)


def test_observation_cancellation_is_fixed_and_never_returns_receipt(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    checked = f.execute()

    def cancel():
        raise KeyboardInterrupt("invented-private-interruption")

    monkeypatch.setattr(f.operation, "current", cancel)
    with pytest.raises(OAuthExchangeCancelled) as raised:
        checked.gmail_profile_observation(f.operation)
    safe(raised.value)
    assert len(f.calls) == 3


def test_replacement_during_profile_cannot_rebaseline_original_authority(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    original = OAuthExchangeTransport.gmail_profile

    def profile(transport, access, configuration):
        original(transport, access, configuration)
        f.operation._authority = f.transactions.reopen()

    monkeypatch.setattr(OAuthExchangeTransport, "gmail_profile", profile)
    with pytest.raises(OAuthExchangeError):
        f.execute()
    assert len(f.calls) == 3 and f.row()["state"] == "held"


@pytest.mark.parametrize(
    "field",
    ["refresh_token", "refresh_expires_at", "slack_app_id", "slack_team_id", "slack_rotation"],
)
def test_complete_candidate_changes_after_issuance_deny(tmp_path, field):
    f = Fixture(tmp_path)
    checked = f.execute()
    if field == "refresh_token":
        checked.candidate.refresh_token._secret_value = "invented-changed-refresh"
    elif field == "refresh_expires_at":
        object.__setattr__(
            checked.candidate, field, f.transactions.sessions.now + timedelta(hours=2)
        )
    else:
        object.__setattr__(checked.candidate, field, "invented-unexpected-slack-field")
    with pytest.raises(OAuthExchangeError):
        checked.gmail_profile_observation(f.operation)
    assert len(f.calls) == 3


@pytest.mark.parametrize(
    "field",
    ["refresh_token", "refresh_expires_at", "slack_app_id", "slack_team_id", "slack_rotation"],
)
def test_complete_candidate_changes_during_profile_cannot_be_staged_as_checked(
    tmp_path, monkeypatch, field
):
    import zacai.connectors.oauth_exchange as module

    f = Fixture(tmp_path)
    parsed = []
    original_parser = module.parse_google_oauth_evidence
    original_profile = OAuthExchangeTransport.gmail_profile

    def parse(*args, **kwargs):
        candidate = original_parser(*args, **kwargs)
        parsed.append(candidate)
        return candidate

    def profile(transport, access, configuration):
        original_profile(transport, access, configuration)
        candidate = parsed[0]
        if field == "refresh_token":
            candidate.refresh_token._secret_value = "invented-changed-refresh"
        elif field == "refresh_expires_at":
            object.__setattr__(candidate, field, f.transactions.sessions.now + timedelta(hours=2))
        else:
            object.__setattr__(candidate, field, "invented-unexpected-slack-field")

    monkeypatch.setattr(module, "parse_google_oauth_evidence", parse)
    monkeypatch.setattr(OAuthExchangeTransport, "gmail_profile", profile)
    with pytest.raises(OAuthExchangeError):
        f.execute()
    assert len(f.calls) == 3 and f.row()["state"] == "held"
    assert all(connection.closed for connection in f.connections)


def test_late_added_recovery_capability_cannot_change_observation_provenance(tmp_path):
    f = Fixture(tmp_path)
    checked = f.execute()
    f.operation._recovery_admission = object()
    f.operation._original_recovery_admission = f.operation._recovery_admission
    with pytest.raises(OAuthExchangeError):
        checked.gmail_profile_observation(f.operation)
    assert len(f.calls) == 3
