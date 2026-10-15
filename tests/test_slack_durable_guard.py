"""Canonical guard, actual owner assembly, new instances and invented faults."""

from datetime import timedelta

import pytest
from pydantic import SecretStr

from test_slack_mounted_host import RamSlack, enroll, inputs
from zacai.connectors.oauth_host_guard import OAuthHostGuard, OAuthHostGuardError
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.slack_connect_host import open_slack_connect_host


def arguments(now, slack, values, ram):
    return dict(
        **values,
        configuration=slack,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=lambda _: SecretStr("invented-slack-secret"),
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    )


@pytest.mark.parametrize("state", ["ready", "missing", "corrupt", "halted"])
def test_actual_new_owner_host_reopens_exact_guard_without_reinitialization(tmp_path, state):
    now, startup, slack, values = inputs(tmp_path)
    enroll(values)
    ram = RamSlack(slack)
    args = arguments(now, slack, values, ram)
    with open_slack_connect_host(**args, initialize_new_guard=True) as original:
        guard = original._guard
        guard.ready()
        directory = guard._directory
        assert directory == values["directory"] / "slack-oauth-guard"
    if state == "missing":
        guard._ready_path.unlink()
    if state == "corrupt":
        guard._ready_path.write_bytes(b"invented corrupt marker")
    if state == "halted":
        guard.halt_unconfirmed()
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    # A distinct guard object performs fresh descriptor-bound checks of same state.
    new = OAuthHostGuard(
        directory, key=startup.session_key, origin=values["origin"], client_id=values["client_id"]
    )
    if state == "ready":
        new.ready()
        with open_slack_connect_host(**args) as reopened:
            assert reopened._guard is not guard
            reopened._guard.ready()
    else:
        with pytest.raises(OAuthHostGuardError):
            new.ready()
        with pytest.raises(OAuthHostGuardError), open_slack_connect_host(**args):
            pytest.fail("stopped host must not open")
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    # Explicit fresh initialization also refuses an existing namespace, unchanged.
    with pytest.raises(FileExistsError):  # noqa: SIM117 - show namespace refusal separately
        with open_slack_connect_host(**args, initialize_new_guard=True):
            pytest.fail("must not reset")
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    assert ram.paths == []


@pytest.mark.parametrize("mismatch", ["key", "origin", "owner_client"])
def test_guard_ready_binding_rejects_wrong_host_inputs(tmp_path, mismatch):
    now, startup, slack, values = inputs(tmp_path)
    enroll(values)
    ram = RamSlack(slack)
    with open_slack_connect_host(
        **arguments(now, slack, values, ram), initialize_new_guard=True
    ) as host:
        path = host._guard._directory
    new = OAuthHostGuard(
        path,
        key=b"x" * 32 if mismatch == "key" else startup.session_key,
        origin="https://foreign.example" if mismatch == "origin" else values["origin"],
        client_id="456-other.apps.googleusercontent.com"
        if mismatch == "owner_client"
        else values["client_id"],
    )
    with pytest.raises(OAuthHostGuardError):
        new.ready()
    assert ram.paths == []
