"""Actual encrypted disposable enrollment stores, invented identity/config only.

No Keychain, real Google, network listener, source data, SQL or source authority.
"""

import pytest

from tests.test_private_host import CONFIG, NOW, OWNER, InventedIdentity, enroll
from tests.test_private_operator import browser_enrollment, closed, enter
from zacai.interfaces.private_operator import PrivateOperatorMode as Mode
from zacai.interfaces.private_operator import open_private_operator
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
        "directory": tmp_path / "personal-host",
        "escrow_confirmed_by_operator": True,
        "clock": lambda: NOW,
        "startup_loader": loader,
        "identities": InventedIdentity(lambda: NOW),
    }, calls


def confirm(window, phrase="CONFIRM PERSONAL / HIGHLY_RESTRICTED"):
    pending = window.pending_owner()
    return window.confirm_owner(
        pairing_code=pending.pairing_code,
        expected_identity=OWNER,
        confirmation=phrase,
    )


def test_personal_genuine_pending_exact_scope_and_consumed_pairing(setup):
    values, calls = setup
    with open_private_operator(mode=Mode.PERSONAL_ENROLLMENT, **values) as window:
        closed(lambda: confirm(window))
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        grant = confirm(window)
        assert grant.identity == OWNER
        assert [(s.boundary, s.classifications) for s in grant.scopes] == [
            (B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED}))
        ]
        stored = (values["directory"] / "owner" / "owner.json").read_bytes()
        closed(
            lambda: window.confirm_owner(
                pairing_code=pending.pairing_code,
                expected_identity=OWNER,
                confirmation="CONFIRM BRAINSTORM / CONFIDENTIAL",
            )
        )
        assert (values["directory"] / "owner" / "owner.json").read_bytes() == stored
        assert not window.source_access_authorized and not window.credential_recovery_verified
    assert len(calls) == 1
    assert values["directory"].stat().st_mode & 0o777 == 0o700
    assert (values["directory"] / "private-mode.lock").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "phrase",
    [
        "CONFIRM BRAINSTORM / CONFIDENTIAL",
        "CONFIRM PERSONAL / CONFIDENTIAL",
        "CONFIRM PERSONAL / HIGHLY_RESTRICTED ",
        "",
    ],
)
def test_wrong_personal_phrase_burns_window_without_owner_file(setup, phrase):
    values, _ = setup
    with open_private_operator(mode=Mode.PERSONAL_ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        closed(lambda: confirm(window, phrase))
        closed(lambda: confirm(window))
        assert not (values["directory"] / "owner" / "owner.json").exists()


@pytest.mark.parametrize("existing", ["empty", "brainstorm", "failed-setup", "symlink"])
def test_existing_directory_denies_before_loader_lease_or_any_change(setup, existing, tmp_path):
    values, calls = setup
    directory = values["directory"]
    if existing == "brainstorm":
        enroll(directory, lambda: NOW)
    elif existing == "symlink":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        directory.symlink_to(target, target_is_directory=True)
    else:
        directory.mkdir(mode=0o700)
        if existing == "failed-setup":
            (directory / "private-mode.lock").write_bytes(b"invented")
    before = {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    }
    closed(lambda: enter(mode=Mode.PERSONAL_ENROLLMENT, **values))
    assert calls == []
    assert {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    } == before


def test_separate_directory_preserves_existing_brainstorm_owner_and_sessions(setup, tmp_path):
    values, _ = setup
    brainstorm = tmp_path / "brainstorm-host"
    enroll(brainstorm, lambda: NOW)
    before = {
        str(p.relative_to(brainstorm)): p.read_bytes() for p in brainstorm.rglob("*") if p.is_file()
    }
    with open_private_operator(mode=Mode.PERSONAL_ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        confirm(window)
    assert {
        str(p.relative_to(brainstorm)): p.read_bytes() for p in brainstorm.rglob("*") if p.is_file()
    } == before


def test_personal_parent_symlink_alias_denies_before_loader_or_creation(setup, tmp_path):
    values, calls = setup
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    values["directory"] = alias / "personal-host"
    closed(lambda: enter(mode=Mode.PERSONAL_ENROLLMENT, **values))
    assert calls == []
    assert not (tmp_path / "personal-host").exists()


def test_startup_callback_cannot_fill_fresh_directory_and_trigger_factory(setup):
    values, calls = setup

    def loader(**kwargs):
        calls.append(kwargs)
        (values["directory"] / "owner").mkdir(mode=0o700)
        return CONFIG

    values["startup_loader"] = loader
    closed(lambda: enter(mode=Mode.PERSONAL_ENROLLMENT, **values))
    assert len(calls) == 1
    assert not (values["directory"] / "sessions").exists()
    assert not (values["directory"] / "owner" / "owner.json").exists()


def test_startup_callback_root_replacement_denies_before_factory(setup):
    values, _ = setup
    directory = values["directory"]

    def loader(**kwargs):
        directory.rename(directory.with_name("old"))
        directory.mkdir(mode=0o700)
        return CONFIG

    values["startup_loader"] = loader
    closed(lambda: enter(mode=Mode.PERSONAL_ENROLLMENT, **values))
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("mode", ["personal-enrollment", object(), None])
def test_closed_mode_rejects_shaped_choices_before_loader(setup, mode):
    values, calls = setup
    closed(lambda: enter(mode=mode, **values))
    assert calls == [] and not values["directory"].exists()


def test_default_phrase_still_cannot_grant_personal(setup):
    values, _ = setup
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        closed(lambda: confirm(window))
        assert not (values["directory"] / "owner" / "owner.json").exists()


def test_fresh_failed_personal_setup_is_not_reusable(setup):
    values, _ = setup
    with open_private_operator(mode=Mode.PERSONAL_ENROLLMENT, **values):
        pass
    closed(lambda: enter(mode=Mode.PERSONAL_ENROLLMENT, **values))


@pytest.mark.parametrize("fault", ["identity", "pairing"])
def test_personal_pending_identity_and_pairing_must_match(setup, fault):
    from zacai.interfaces.session_store import Identity

    values, _ = setup
    with open_private_operator(mode=Mode.PERSONAL_ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        closed(
            lambda: window.confirm_owner(
                pairing_code="wrong" if fault == "pairing" else pending.pairing_code,
                expected_identity=(
                    Identity(OWNER.issuer, "another-owner") if fault == "identity" else OWNER
                ),
                confirmation="CONFIRM PERSONAL / HIGHLY_RESTRICTED",
            )
        )
        assert not (values["directory"] / "owner" / "owner.json").exists()
        closed(lambda: confirm(window))


def test_expired_personal_google_candidate_cannot_be_confirmed(setup):
    from datetime import timedelta

    values, _ = setup
    now = [NOW]
    values["clock"] = lambda: now[0]
    values["identities"] = InventedIdentity(lambda: now[0])
    with open_private_operator(mode=Mode.PERSONAL_ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        now[0] += timedelta(minutes=5)
        closed(
            lambda: window.confirm_owner(
                pairing_code=pending.pairing_code,
                expected_identity=OWNER,
                confirmation="CONFIRM PERSONAL / HIGHLY_RESTRICTED",
            )
        )
        assert not (values["directory"] / "owner" / "owner.json").exists()


def test_personal_setup_rejects_source_view_before_directory_or_credentials(setup):
    values, calls = setup

    async def view(principal):
        raise AssertionError("view cannot run during enrollment")

    closed(lambda: enter(mode=Mode.PERSONAL_ENROLLMENT, view=view, **values))
    assert calls == [] and not values["directory"].exists()
