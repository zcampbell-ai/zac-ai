"""Fresh consumer failures use actual dual owner stores and invented provider data."""

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_gmail_recovery_host import Fixture, form
from tests.test_private_host import ORIGIN, sign_in
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError, GmailRecoveryHostFatal


def run(f, plan, action):
    failures = []
    done = []

    def browse(browser):
        try:
            action(browser)
            done.append(True)
        except BaseException as error:
            failures.append(error)
            raise

    f.browser_action = browse
    try:
        plan.run()
    except (GmailRecoveryHostError, GmailRecoveryHostFatal):
        pass
    if failures:
        raise failures[0]
    assert done == [True]
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    assert rows[f.old_state] == f.old_row
    return rows


def begin(browser):
    sign_in(browser)
    for target in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
        assert (
            browser.post(target, data=form(browser), headers={"origin": ORIGIN}).status_code == 303
        )
    reply = browser.post(
        "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
    )
    assert reply.status_code == 303
    return parse_qs(urlsplit(reply.headers["location"]).query)["state"][0]


@pytest.mark.parametrize("failure", ["denied", "foreign_state", "duplicate_code"])
def test_fresh_callback_failure_preserves_original_and_stops_without_provider(
    tmp_path, monkeypatch, failure
):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    def action(browser):
        state = begin(browser)
        query = [("state", state), ("code", "invented-fresh-code")]
        if failure == "denied":
            query = [("state", state), ("error", "access_denied")]
        elif failure == "foreign_state":
            query[0] = ("state", "invented-foreign-state")
        else:
            query.append(("code", "invented-second-code"))
        reply = browser.get("/connections/gmail/callback", params=query)
        assert reply.status_code == 403
        assert plan._consumer._spent and plan._consumer._admission._callback_started
        assert f.servers[-1].should_exit
        f.both_leases()
        assert browser.get("/connections/gmail/callback", params=query).status_code == 403

    rows = run(f, plan, action)
    assert len(rows) == 2
    fresh = next(row for key, row in rows.items() if key != f.old_state)
    assert fresh["state"] in {"denied", "held"} and fresh["verifier"] is None
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_interrupted_before_callback_holds_only_new_pending_row(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    def action(browser):
        begin(browser)
        with plan._authority._locked():
            rows = plan._authority._read()["rows"]
        fresh = next(row for key, row in rows.items() if key != f.old_state)
        assert fresh["state"] == "pending" and fresh["verifier"] is not None
        assert rows[f.old_state] == f.old_row
        f.both_leases()

    rows = run(f, plan, action)
    fresh = next(row for key, row in rows.items() if key != f.old_state)
    assert fresh["state"] == "held" and fresh["verifier"] is None and fresh["loaded"] is False
    assert not f.secret_reads and not f.provider_calls and not f.native_factories


def test_existing_spend_is_not_replaced_and_no_fresh_state_is_disclosed(tmp_path, monkeypatch):
    from zacai.connectors.gmail_recovery_consumer import SPEND_NAME

    f = Fixture(tmp_path, monkeypatch)
    path = f.authority._directory / SPEND_NAME
    path.write_bytes(b"invented retained crash evidence")
    path.chmod(0o600)
    plan = f.recovery_plan(monkeypatch)

    def action(browser):
        sign_in(browser)
        reply = browser.post(
            "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
        )
        assert reply.status_code == 403
        assert not f.secret_reads and not f.provider_calls and not f.native_factories
        f.both_leases()

    rows = run(f, plan, action)
    assert rows == {f.old_state: f.old_row}
    assert path.read_bytes() == b"invented retained crash evidence"
