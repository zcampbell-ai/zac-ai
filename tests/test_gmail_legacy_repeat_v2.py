"""Actual mounted preserved-history recovery; disposable owner and provider inventions."""

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_gmail_installation import fixture, fresh, install, run
from tests.test_gmail_recovery_host import form
from tests.test_private_host import ORIGIN, sign_in
from zacai.connectors.gmail_recovery_history import LEGACY_JOURNAL, LEGACY_SPEND
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError, GmailRecoveryHostFatal


def previous_attempt(f, monkeypatch):
    plan = f.recovery_plan(monkeypatch, action_generation="invented-legacy-action")

    def prior(browser):
        sign_in(browser)
        for path in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
            assert (
                browser.post(path, data=form(browser), headers={"origin": ORIGIN}).status_code
                == 303
            )
        reply = browser.post(
            "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
        )
        assert reply.status_code == 303
        assert parse_qs(urlsplit(reply.headers["location"]).query)["state"]
        # Honest foreground ends before consent; actual cleanup holds its new row.

    run(f, plan, prior)
    assert f.secret_reads == f.provider_calls == f.native_factories == []
    directory = f.authority._directory
    preserved = {name: (directory / name).read_bytes() for name in (LEGACY_JOURNAL, LEGACY_SPEND)}
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    assert len(rows) == 2 and all(row["state"] == "held" for row in rows.values())
    return preserved, rows


def test_actual_repeat_pair_quarantine_begin_keeps_entire_legacy_history(tmp_path, monkeypatch):
    f, _ = fixture(tmp_path, monkeypatch)
    preserved, rows = previous_attempt(f, monkeypatch)
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-independent-repeat",
        recovery_profile="legacy_repeat_v2",
    )
    seen = []

    def again(browser):
        sign_in(browser)
        assert f.secret_reads == f.provider_calls == f.native_factories == []
        for path in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
            assert (
                browser.post(path, data=form(browser), headers={"origin": ORIGIN}).status_code
                == 303
            )
            assert f.secret_reads == f.provider_calls == f.native_factories == []
        consumer = plan._consumer
        assert consumer._journal_name != LEGACY_JOURNAL and consumer._spend_name != LEGACY_SPEND
        seen.append(consumer._history.descriptor())
        reply = browser.post(
            "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
        )
        assert reply.status_code == 303
        assert f.secret_reads == f.provider_calls == f.native_factories == []

    run(f, plan, again)
    assert seen[0]["rows"] == rows
    assert {name: (f.authority._directory / name).read_bytes() for name in preserved} == preserved
    with f.authority._locked():
        after = f.authority._read()["rows"]
    assert len(after) == 3 and all(after[state] == row for state, row in rows.items())


@pytest.mark.parametrize("failure", ["default", "journal_mac", "spend_mac", "unknown_child"])
def test_repeat_invalid_or_unapproved_history_denied_before_provider(
    tmp_path, monkeypatch, failure
):
    f, _ = fixture(tmp_path, monkeypatch)
    _preserved, rows = previous_attempt(f, monkeypatch)
    if failure in {"journal_mac", "spend_mac"}:
        name = LEGACY_JOURNAL if failure == "journal_mac" else LEGACY_SPEND
        path = f.authority._directory / name
        raw = path.read_bytes()
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    elif failure == "unknown_child":
        child = f.authority._directory / "invented-unreviewed-child"
        child.write_bytes(b"invented")
        child.chmod(0o600)
    profile = "fresh_v1" if failure == "default" else "legacy_repeat_v2"
    plan = f.recovery_plan(
        monkeypatch, action_generation="invented-invalid-repeat", recovery_profile=profile
    )
    result = []

    def again(browser):
        sign_in(browser)
        result.append(
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
        )

    f.browser_action = again
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        plan.run()
    assert result == [403]
    assert f.secret_reads == f.provider_calls == f.native_factories == []
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows


def test_repeat_full_fresh_install_and_honest_new_owner_reopen(tmp_path, monkeypatch):
    from tests.test_gmail_installed_load_audit import paired_restart, reopen_form, run_restarted
    from tests.test_private_host import enroll
    from zacai.interfaces.private_web import BoundaryScope
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B

    f, _ = fixture(tmp_path, monkeypatch)
    # Exact real legacy extended original grant; HR root remains distinct HR-only.
    enroll(
        f.directory,
        f.clock,
        scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})),),
    )
    prior = f.recovery_plan

    def legacy_plan(monkeypatch, **changes):
        return prior(
            monkeypatch, original_grant_profile="legacy_confidential_highly_restricted", **changes
        )

    f.recovery_plan = legacy_plan
    preserved, historical_rows = previous_attempt(f, monkeypatch)
    owner_bytes = [
        (root / "owner/owner.json").read_bytes() for root in (f.directory, f.hr_directory)
    ]
    guard_bytes = [
        (f.directory / "gmail-oauth-guard" / name).read_bytes()
        for name in ("oauth-host.ready", "oauth-host.halted")
    ]
    plan = f.recovery_plan(
        monkeypatch, action_generation="invented-full-repeat", recovery_profile="legacy_repeat_v2"
    )

    def completed(browser):
        fresh(browser)
        install(browser)
        assert (
            browser.post(
                "/connector-review", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        reply = browser.post("/connector-execute", data=form(browser), headers={"origin": ORIGIN})
        assert reply.status_code == 200 and reply.json()["profile_verified"] is True

    run(f, plan, completed)
    assert {name: (f.authority._directory / name).read_bytes() for name in preserved} == preserved
    assert owner_bytes == [
        (root / "owner/owner.json").read_bytes() for root in (f.directory, f.hr_directory)
    ]
    assert guard_bytes == [
        (f.directory / "gmail-oauth-guard" / name).read_bytes()
        for name in ("oauth-host.ready", "oauth-host.halted")
    ]
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    assert len(rows) == 3 and all(rows[state] == row for state, row in historical_rows.items())
    restart = f.recovery_plan(
        monkeypatch,
        action_generation="invented-new-owner-reopen",
        recovery_profile="legacy_repeat_v2",
        load_existing=True,
    )

    def reopened(browser):
        paired_restart(browser)
        assert (
            browser.post(
                "/connector-review", data=reopen_form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        result = browser.post(
            "/connector-execute", data=reopen_form(browser), headers={"origin": ORIGIN}
        )
        assert result.status_code == 200 and result.json()["profile_verified"] is True

    run_restarted(f, restart, reopened)
    assert {name: (f.authority._directory / name).read_bytes() for name in preserved} == preserved
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
