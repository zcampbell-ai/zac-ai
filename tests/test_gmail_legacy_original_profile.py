"""Actual encrypted disposable owner stores and held rows; no live credentials/SQL."""

import pytest

from tests.test_gmail_installation import fixture, fresh, install
from tests.test_gmail_recovery_host import PATH, Fixture, form
from tests.test_private_host import ORIGIN, enroll, sign_in
from zacai.interfaces.gmail_recovery_host import (
    GmailRecoveryHostError,
    GmailRecoveryHostFatal,
    GmailRecoveryHostPlan,
)
from zacai.interfaces.private_web import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

LEGACY = "legacy_confidential_highly_restricted"
LEGACY_SCOPE = (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})),)


def legacy_fixture(tmp_path, monkeypatch):
    f, _unused = fixture(tmp_path, monkeypatch)
    enroll(f.directory, f.clock, scopes=LEGACY_SCOPE)
    f.legacy_owner_bytes = (f.directory / "owner/owner.json").read_bytes()
    return f, f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)


def legacy_fixture_restarted(tmp_path, monkeypatch):
    f, original = legacy_fixture(tmp_path, monkeypatch)
    failures = []

    def baseline(browser):
        try:
            fresh(browser)
            install(browser)
            assert (
                browser.post(
                    "/connector-review", data=form(browser), headers={"origin": ORIGIN}
                ).status_code
                == 303
            )
            reply = browser.post(
                "/connector-execute", data=form(browser), headers={"origin": ORIGIN}
            )
            assert reply.status_code == 200 and reply.json()["profile_verified"] is True
        except BaseException as error:  # noqa: BLE001 - only invented fixture diagnostics
            failures.append(error)

    f.browser_action = baseline
    original.run()
    if failures:
        raise failures[0]
    assert original._runtime is original._windows is original._consumer is None
    new = GmailRecoveryHostPlan(
        configuration=f.configuration,
        original_directory=f.directory,
        hr_directory=f.hr_directory,
        owner_client_id=original._owner_client_id,
        startup_loader=original._loader,
        clock=f.clock,
        escrow_confirmed_by_operator=True,
        reviewed_registration_generation=original._generation,
        console_observed_at=original._observed,
        review_expires_at=original._expires,
        action_generation="invented-new-reopen-action",
        identities=original._identities,
        load_existing=True,
        original_grant_profile=LEGACY,
    )
    new._server._factory = f.server_factory
    return f, new


def test_actual_legacy_foreground_restart_and_profile_gateway(tmp_path, monkeypatch):
    f, plan = legacy_fixture_restarted(tmp_path, monkeypatch)
    failures = []
    before = len(f.shared_reads), len(f.secret_reads), len(f.provider_calls)

    def browse(browser):
        try:
            sign_in(browser)
            assert browser.get("/connections/gmail/reopen").status_code == 200
            for path in (
                "/connections/gmail/recover/begin",
                "/connections/gmail/install",
                "/connections/gmail/callback",
            ):
                assert browser.get(path).status_code in (404, 405)
            page = browser.get("/connections/gmail/reopen")
            import re

            fields = dict(re.findall('name="([^"]+)" value="([^"]*)"', page.text))
            paired = browser.post(
                "/connections/gmail/recover/pair", data=fields, headers={"origin": ORIGIN}
            )
            assert paired.status_code == 303
            f.both_leases()
            assert plan._loaded._issued is not None and plan._consumer is None
            page = browser.get("/connections/gmail/reopen")
            fields = dict(re.findall('name="([^"]+)" value="([^"]*)"', page.text))
            assert (
                browser.post(
                    "/connector-review", data=fields, headers={"origin": ORIGIN}
                ).status_code
                == 303
            )
            page = browser.get("/connections/gmail/reopen")
            fields = dict(re.findall('name="([^"]+)" value="([^"]*)"', page.text))
            reply = browser.post("/connector-execute", data=fields, headers={"origin": ORIGIN})
            assert reply.status_code == 200 and reply.json()["profile_verified"] is True
            assert reply.json()["original_actor_verified"] is False
        except BaseException as error:  # noqa: BLE001 - surface invented failures after teardown
            failures.append(error)

    f.browser_action = browse
    try:
        plan.run()
    except (GmailRecoveryHostError, GmailRecoveryHostFatal):
        if not failures:
            raise
    if failures:
        raise failures[0]
    assert len(f.shared_reads) == before[0] + 2 and len(f.secret_reads) == before[1]
    assert plan._loaded is plan._runtime is plan._windows is None
    assert (f.directory / "owner/owner.json").read_bytes() == f.legacy_owner_bytes
    with f.authority._locked():
        assert f.authority._read()["rows"][f.old_state] == f.old_row


def test_closed_profile_default_and_exact_original_scope(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)

    class FakeProfile(str):
        pass

    for value in (None, True, "unknown", FakeProfile(LEGACY)):
        with pytest.raises(GmailRecoveryHostError):
            f.recovery_plan(monkeypatch, original_grant_profile=value)
    wrong = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        wrong.run()  # C-only original cannot use legacy profile
    assert wrong.startup_stage == "authenticated_owners" and not f.server_runs
    enroll(f.directory, f.clock, scopes=LEGACY_SCOPE)
    default = f.recovery_plan(monkeypatch)
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        default.run()  # default behavior remains C-only
    assert not f.server_runs and not f.secret_reads and not f.provider_calls
    for boundary, classifications in (
        (B.PERSONAL, {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        (B.BRAINSTORM, {C.HIGHLY_RESTRICTED}),
        (B.BRAINSTORM, {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED, C.INTERNAL}),
    ):
        enroll(f.directory, f.clock, scopes=(BoundaryScope(boundary, frozenset(classifications)),))
        bad = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)
        with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
            bad.run()
        assert bad.startup_stage == "authenticated_owners"
    assert not f.server_runs and not f.secret_reads and not f.provider_calls


def test_exact_hr_and_identity_remain_required(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    enroll(f.directory, f.clock, scopes=LEGACY_SCOPE)
    enroll(f.hr_directory, f.clock, scopes=LEGACY_SCOPE)
    bad = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        bad.run()
    import tests.test_private_host as owners
    from zacai.interfaces.session_store import Identity

    with monkeypatch.context() as altered:
        altered.setattr(owners, "OWNER", Identity(owners.OWNER.issuer, "invented-other-owner"))
        enroll(
            f.hr_directory,
            f.clock,
            scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.HIGHLY_RESTRICTED})),),
        )
    bad = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        bad.run()
    assert not f.server_runs and not f.secret_reads and not f.provider_calls


def test_profile_mutation_denies_before_startup_and_current_callback(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    enroll(f.directory, f.clock, scopes=LEGACY_SCOPE)
    for value in ("confidential", None):
        plan = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)
        plan._original_grant_profile = value
        with pytest.raises(GmailRecoveryHostError):
            plan.run()
    assert not f.shared_reads
    plan = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)

    def browse(browser):
        sign_in(browser)
        plan._original_grant_profile = "confidential"
        assert browser.get(PATH).status_code == 403

    f.browser_action = browse
    with pytest.raises((GmailRecoveryHostError, GmailRecoveryHostFatal)):
        plan.run()
    assert not f.secret_reads and not f.provider_calls
    plan._startup_stage = "private-injected-value"
    assert plan.startup_stage == "unavailable"
