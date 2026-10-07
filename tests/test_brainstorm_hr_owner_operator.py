"""Genuine local pending/pairing/store mechanics; invented OIDC/config only."""

import pytest

from tests.test_private_host import CONFIG, NOW, OWNER, InventedIdentity, enroll
from tests.test_private_operator import browser_enrollment, closed, enter
from zacai.interfaces import private_operator as m
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def setup(tmp_path):
    calls = []

    def loader(**kwargs):
        calls.append(kwargs)
        return CONFIG

    return {
        "client_id": CONFIG.client_id,
        "origin": CONFIG.origin,
        "directory": tmp_path / "fresh-bhr",
        "escrow_confirmed_by_operator": True,
        "clock": lambda: NOW,
        "startup_loader": loader,
        "identities": InventedIdentity(lambda: NOW),
    }, calls


def confirm(window, phrase="CONFIRM BRAINSTORM / HIGHLY_RESTRICTED", identity=OWNER):
    pending = window.pending_owner()
    return window.confirm_owner(
        pairing_code=pending.pairing_code, expected_identity=identity, confirmation=phrase
    )


def test_actual_pending_then_exact_hr_signed_grant(setup):
    values, calls = setup
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:
        closed(lambda: confirm(window))
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        grant = confirm(window)
        assert grant.identity == OWNER
        assert [(s.boundary, s.classifications) for s in grant.scopes] == [
            (B.BRAINSTORM, frozenset({C.HIGHLY_RESTRICTED}))
        ]
        raw = (values["directory"] / "owner/owner.json").read_bytes()
        closed(
            lambda: window.confirm_owner(
                pairing_code=pending.pairing_code,
                expected_identity=OWNER,
                confirmation="CONFIRM BRAINSTORM / HIGHLY_RESTRICTED",
            )
        )
        assert (values["directory"] / "owner/owner.json").read_bytes() == raw
        assert not window.source_access_authorized and not window.credential_recovery_verified
    assert len(calls) == 1


@pytest.mark.parametrize(
    "phrase",
    [
        "CONFIRM BRAINSTORM / CONFIDENTIAL",
        "CONFIRM PERSONAL / HIGHLY_RESTRICTED",
        "CONFIRM BRAINSTORM / HIGHLY_RESTRICTED ",
        "",
    ],
)
def test_wrong_phrase_burns_window_no_grant(setup, phrase):
    values, _ = setup
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:
        window.serve(server=browser_enrollment)
        closed(lambda: confirm(window, phrase))
        closed(lambda: confirm(window))
        assert not (values["directory"] / "owner/owner.json").exists()


def test_wrong_expected_identity_holds_without_grant(setup):
    values, _ = setup
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:
        window.serve(server=browser_enrollment)
        closed(lambda: confirm(window, identity=Identity(OWNER.issuer, "other-invented-owner")))
        assert not (values["directory"] / "owner/owner.json").exists()


@pytest.mark.parametrize("existing", ["empty", "brainstorm", "personal"])
def test_fresh_only_before_loader_existing_store_unchanged(setup, existing):
    values, calls = setup
    directory = values["directory"]
    if existing == "empty":
        directory.mkdir(mode=0o700)
    elif existing == "brainstorm":
        enroll(directory, lambda: NOW)
    else:
        enroll(directory, lambda: NOW, scopes=m._PERSONAL_SCOPE)
    before = {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    }
    closed(lambda: enter(mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values))
    assert calls == []
    assert {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    } == before


def test_first_clock_replacement_holds_before_store_creation(setup, tmp_path):
    values, calls = setup
    directory = values["directory"]
    existing = tmp_path / "existing-default"
    enroll(existing, lambda: NOW)
    before = {
        str(p.relative_to(existing)): p.read_bytes() for p in existing.rglob("*") if p.is_file()
    }
    fired = []

    def clock():
        if not fired:
            assert {p.name for p in directory.iterdir()} == {"private-mode.lock"}
            directory.rename(tmp_path / "displaced")
            existing.rename(directory)
            fired.append(True)
        return NOW

    values["clock"] = clock
    closed(lambda: enter(mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values))
    assert fired == [True] and len(calls) == 1
    assert {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    } == before


def test_enrollment_cannot_mount_owner_factories_before_loader(setup):
    values, calls = setup
    closed(
        lambda: enter(
            mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT,
            **values,
            named_factory=lambda **kw: None,
        )
    )
    assert calls == [] and not values["directory"].exists()


def test_wrong_pairing_burns_attempt(setup):
    values, _ = setup
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:
        window.serve(server=browser_enrollment)
        closed(
            lambda: window.confirm_owner(
                pairing_code="wrong-invented-code",
                expected_identity=OWNER,
                confirmation="CONFIRM BRAINSTORM / HIGHLY_RESTRICTED",
            )
        )
        closed(lambda: confirm(window))
        assert not (values["directory"] / "owner/owner.json").exists()


def test_original_confirmation_deadline_not_renewed(setup):
    from datetime import timedelta

    values, _ = setup
    clock = [NOW]
    values["clock"] = lambda: clock[0]
    values["identities"] = InventedIdentity(lambda: clock[0])
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:
        window.serve(server=browser_enrollment)
        window.pending_owner()
        clock[0] = NOW + timedelta(minutes=5)
        closed(lambda: confirm(window))
        assert not (values["directory"] / "owner/owner.json").exists()


def test_confirmation_clock_replacement_holds_actual_guard(setup, tmp_path):
    values, _ = setup
    directory = values["directory"]
    other = tmp_path / "other-default"
    enroll(other, lambda: NOW)
    before = {str(p.relative_to(other)): p.read_bytes() for p in other.rglob("*") if p.is_file()}
    mutate, fired = [], []

    def clock():
        if mutate and not fired:
            directory.rename(tmp_path / "displaced-hr")
            other.rename(directory)
            fired.append(True)
        return NOW

    values["clock"] = clock
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values
    ) as window:
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        mutate.append(True)
        closed(
            lambda: window.confirm_owner(
                pairing_code=pending.pairing_code,
                expected_identity=OWNER,
                confirmation="CONFIRM BRAINSTORM / HIGHLY_RESTRICTED",
            )
        )
    assert fired == [True]
    assert {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    } == before


@pytest.mark.parametrize(
    "mode", [m.PrivateOperatorMode.ENROLLMENT, m.PrivateOperatorMode.PERSONAL_ENROLLMENT]
)
def test_hr_phrase_cannot_upgrade_default_or_personal_window(setup, mode):
    values, _ = setup
    with m.open_private_operator(mode=mode, **values) as window:
        window.serve(server=browser_enrollment)
        closed(lambda: confirm(window))
        closed(lambda: confirm(window))
        assert not (values["directory"] / "owner/owner.json").exists()


def test_raw_hr_string_denies_before_loader_or_directory(setup):
    values, calls = setup
    closed(lambda: enter(mode="brainstorm-hr-enrollment", **values))
    assert calls == []
    assert not values["directory"].exists()


def test_hr_leaf_symlink_denies_before_loader_without_changes(setup, tmp_path):
    values, calls = setup
    target = tmp_path / "existing-target"
    enroll(target, lambda: NOW)
    before = {str(p.relative_to(target)): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    values["directory"].symlink_to(target, target_is_directory=True)
    closed(lambda: enter(mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values))
    assert calls == []
    assert values["directory"].is_symlink()
    assert {
        str(p.relative_to(target)): p.read_bytes() for p in target.rglob("*") if p.is_file()
    } == before


def test_hr_noncanonical_parent_denies_before_loader_or_directory(setup, tmp_path):
    values, calls = setup
    target = tmp_path / "actual-parent"
    target.mkdir(mode=0o700)
    alias = tmp_path / "alias-parent"
    alias.symlink_to(target, target_is_directory=True)
    values["directory"] = alias / "fresh-hr"
    closed(lambda: enter(mode=m.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT, **values))
    assert calls == []
    assert list(target.iterdir()) == []
