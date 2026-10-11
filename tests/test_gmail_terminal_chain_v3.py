"""Authentic disposable sessions/leases; invented consent, no provider/native I/O."""

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_gmail_installation import fixture, run
from tests.test_gmail_recovery_host import form
from tests.test_private_host import ORIGIN, sign_in
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError, GmailRecoveryHostFatal


def begin(browser):
    sign_in(browser)
    for path in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
        assert browser.post(path, data=form(browser), headers={"origin": ORIGIN}).status_code == 303
    reply = browser.post(
        "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
    )
    assert reply.status_code == 303
    return parse_qs(urlsplit(reply.headers["location"]).query)["state"][0]


def spent_v2(tmp_path, monkeypatch):
    f, _ = fixture(tmp_path, monkeypatch)
    first = f.recovery_plan(monkeypatch, action_generation="invented-v1-spent")
    run(f, first, lambda browser: begin(browser))
    with f.authority._locked():
        f.legacy_before_v2 = set(f.authority._read()["rows"])
    second = f.recovery_plan(
        monkeypatch, action_generation="invented-v2-spent", recovery_profile="legacy_repeat_v2"
    )
    run(f, second, lambda browser: begin(browser))
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    files = {p.name: p.read_bytes() for p in f.authority._directory.iterdir()}
    assert f.secret_reads == f.provider_calls == f.native_factories == []
    return f, rows, files


def test_third_actual_fresh_begin_preserves_all_terminal_epochs(tmp_path, monkeypatch):
    f, old, files = spent_v2(tmp_path, monkeypatch)
    third = f.recovery_plan(
        monkeypatch, action_generation="invented-v3-fresh", recovery_profile="terminal_chain_v3"
    )
    run(f, third, lambda browser: begin(browser))
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    assert len(rows) == len(old) + 1
    assert all(rows[state] == row for state, row in old.items())
    assert all(
        (f.authority._directory / name).read_bytes() == data
        for name, data in files.items()
        if name != f.authority._path.name
    )
    assert f.secret_reads == f.provider_calls == f.native_factories == []


@pytest.mark.parametrize("change", ["loaded", "inflight", "corrupt", "unknown"])
def test_terminal_chain_denies_uncertain_or_corrupt_predecessor(tmp_path, monkeypatch, change):
    f, _rows, files = spent_v2(tmp_path, monkeypatch)
    if change in {"loaded", "inflight"}:
        with f.authority._locked():
            ledger = f.authority._read()
            state = next(s for s in ledger["rows"] if s not in f.legacy_before_v2)
            ledger["rows"][state]["loaded"] = change == "loaded"
            if change == "inflight":
                ledger["rows"][state]["state"] = "exchange_started"
            f.authority._persist(ledger, state)
    elif change == "corrupt":
        name = next(name for name in files if name.startswith("gmail-recovery-attempt-"))
        raw = bytearray((f.authority._directory / name).read_bytes())
        raw[-1] ^= 1
        (f.authority._directory / name).write_bytes(raw)
    else:
        (f.authority._directory / "foreign.bin").write_bytes(b"invented")
    third = f.recovery_plan(
        monkeypatch, action_generation="invented-v3-denied", recovery_profile="terminal_chain_v3"
    )
    seen = []

    def denied(browser):
        sign_in(browser)
        reply = browser.post(
            "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
        )
        assert reply.status_code == 403
        seen.append(True)

    f.browser_action = denied
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        third.run()
    assert f.secret_reads == f.provider_calls == f.native_factories == []


def test_mounted_native_cancellation_and_failed_hold_remain_interruption(tmp_path, monkeypatch):
    from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAuthorizationCancelled
    from zacai.connectors.gmail_recovery_consumer import GmailRecoveryConsumer
    from zacai.connectors.oauth_transactions import OAuthExchangeOperation

    f, plan = fixture(tmp_path, monkeypatch)
    f.bindings.failure = "add"
    f.bindings.cancel = True
    observed = []
    original = GmailRecoveryConsumer.callback_once

    def callback(self, request):
        try:
            return original(self, request)
        except BaseException as error:
            observed.append(type(error))
            f.both_leases()
            raise

    monkeypatch.setattr(GmailRecoveryConsumer, "callback_once", callback)
    holds = []

    def failing_hold(self):
        holds.append(True)
        f.both_leases()
        raise ValueError("invented preservation unavailable")

    monkeypatch.setattr(OAuthExchangeOperation, "hold", failing_hold)

    def browse(browser):
        state = begin(browser)
        with pytest.raises(BaseException):  # noqa: B017 - ASGI may wrap the fixed fatal cancellation
            browser.get(
                "/connections/gmail/callback", params={"state": state, "code": "invented-code"}
            )

    f.browser_action = browse
    with pytest.raises(GmailRecoveryHostFatal):
        plan.run()
    assert observed == [GmailRecoveryAuthorizationCancelled]
    assert holds and any(event[0] == "add" for event in f.bindings.events)
    assert (
        plan._runtime is None
        and plan._windows is None
        and plan._original_continuity is None
        and plan._hr_continuity is None
    )


def test_terminal_third_install_and_honest_new_owner_reopen(tmp_path, monkeypatch):
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
    from tests.test_gmail_installation import fresh, install
    from tests.test_gmail_legacy_repeat_v2 import previous_attempt

    preserved, historical_rows = previous_attempt(f, monkeypatch)
    second = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v2-terminal-before-install",
        recovery_profile="legacy_repeat_v2",
    )
    run(f, second, lambda browser: begin(browser))
    preserved = {
        p.name: p.read_bytes()
        for p in f.authority._directory.iterdir()
        if p.name not in {f.authority._path.name, f.authority._lock_path.name}
    }
    with f.authority._locked():
        historical_rows = f.authority._read()["rows"]
    owner_bytes = [
        (root / "owner/owner.json").read_bytes() for root in (f.directory, f.hr_directory)
    ]
    guard_bytes = [
        (f.directory / "gmail-oauth-guard" / name).read_bytes()
        for name in ("oauth-host.ready", "oauth-host.halted")
    ]
    plan = f.recovery_plan(
        monkeypatch, action_generation="invented-full-repeat", recovery_profile="terminal_chain_v3"
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
    assert len(rows) == 4 and all(rows[state] == row for state, row in historical_rows.items())
    restart = f.recovery_plan(
        monkeypatch,
        action_generation="invented-new-owner-reopen",
        recovery_profile="terminal_chain_v3",
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


def test_namespace_capacity_is_three_prior_epochs_plus_one_current():
    from zacai.connectors.gmail_recovery_terminal_chain import namespace_pairs

    names = set()
    for index in range(4):
        suffix = f"{index:032x}"
        names.update(
            (f"gmail-quarantine-intent-{suffix}.bin", f"gmail-recovery-attempt-{suffix}.bin")
        )
    assert not namespace_pairs(names)
    assert namespace_pairs(names, maximum=4)
    names.add("unrecognized.bin")
    assert not namespace_pairs(names, maximum=4)


def test_full_row_capacity_denies_before_history_file_reads(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_terminal_chain as chain

    f, rows, files = spent_v2(tmp_path, monkeypatch)  # noqa: RUF059 - preserve fixture-return shape
    with f.authority._locked():
        ledger = f.authority._read()
        while len(ledger["rows"]) < 8:
            state = f"{len(ledger['rows']):064x}"
            ledger["rows"][state] = dict(f.old_row)
        f.authority._persist(ledger, state)
    reads = []
    original = chain._file

    def tracked(*args, **kw):
        reads.append(True)
        return original(*args, **kw)

    monkeypatch.setattr(chain, "_file", tracked)
    third = f.recovery_plan(
        monkeypatch,
        action_generation="invented-capacity-deny",
        recovery_profile="terminal_chain_v3",
    )

    def browse(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 403
        )

    f.browser_action = browse
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        third.run()
    assert reads == [] and f.secret_reads == f.provider_calls == f.native_factories == []
