"""Invented enrollments in disposable directories; no credentials/DB/network."""

import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

NOW = datetime(2026, 10, 5, tzinfo=UTC)
ORIGIN = "https://caz.example.test"
CLIENT_ID = "123456-invented.apps.googleusercontent.com"
IDENTITY = Identity("https://accounts.google.com", "invented-owner")
SCOPES = (
    BoundaryScope(B.PERSONAL, frozenset({C.INTERNAL})),
    BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),
)


@pytest.fixture
def setup(tmp_path):
    directory, key = tmp_path / "owner-enrollment", secrets.token_bytes(32)
    return directory, key, OwnerGrantStore(directory, key=key, origin=ORIGIN, client_id=CLIENT_ID)


def confirmation():
    enrollment = OwnerEnrollment(opened_at=NOW)
    pending = enrollment.capture(IDENTITY, NOW, origin=ORIGIN)
    return {
        "enrollment": enrollment,
        "candidate_id": pending.candidate_id,
        "pairing_code": pending.pairing_code,
        "origin": ORIGIN,
        "identity": IDENTITY,
        "scopes": SCOPES,
        "now": NOW,
    }


def saved(setup):
    directory, key, store = setup
    confirmed = store.confirm_and_save(**confirmation())
    return directory, key, store, confirmed


def closed(call):
    with pytest.raises(ValueError, match="^owner enrollment unavailable$") as error:
        call()
    assert error.value.__context__ is None


def test_explicit_confirmation_survives_restart_with_exact_separate_scopes(setup):
    directory, key, store, grant = saved(setup)
    assert grant == OwnerGrant(IDENTITY, SCOPES)
    assert OwnerGrantStore(directory, key=key, origin=ORIGIN, client_id=CLIENT_ID).load() == grant
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "owner.json").stat().st_mode & 0o777 == 0o600
    raw = (directory / "owner.json").read_bytes()
    assert key not in raw and not list(directory.glob(".owner-*"))
    envelope = json.loads(raw)
    assert set(envelope) == {"mac", "payload"}
    assert envelope["payload"]["version"] == 2
    assert len(envelope["payload"]["owner"]["scopes"]) == 2
    assert not hasattr(store, "save")


def test_revocation_is_authenticated_durable_and_has_no_old_owner_fallback(setup):
    directory, key, store, _ = saved(setup)
    store.revoke()
    closed(store.load)
    closed(OwnerGrantStore(directory, key=key, origin=ORIGIN, client_id=CLIENT_ID).load)
    assert json.loads((directory / "owner.json").read_bytes())["payload"]["owner"] is None
    # Refresh each read; a fresh explicit enrollment is required after revocation.
    restored = store.confirm_and_save(**confirmation())
    assert restored == OwnerGrant(IDENTITY, SCOPES)


@pytest.mark.parametrize(
    "failure", ["candidate", "pairing", "origin", "identity", "expired", "duck", "scopes"]
)
def test_invalid_confirmation_never_writes_owner(setup, failure):
    directory, _, store = setup
    values = confirmation()
    if failure == "candidate":
        values["candidate_id"] = "wrong"
    elif failure == "pairing":
        values["pairing_code"] = "wrong"
    elif failure == "origin":
        values["origin"] = "https://wrong.example.test"
    elif failure == "identity":
        values["identity"] = Identity(IDENTITY.issuer, "wrong-owner")
    elif failure == "expired":
        values["now"] = NOW + timedelta(minutes=5)
    elif failure == "scopes":
        values["scopes"] = ()
    else:
        values["enrollment"] = SimpleNamespace(
            confirm=lambda **kwargs: OwnerGrant(IDENTITY, SCOPES)
        )
    closed(lambda: store.confirm_and_save(**values))
    assert not (directory / "owner.json").exists()


def test_confirmation_is_one_use_and_failure_after_consumption_requires_reenrollment(
    setup, monkeypatch
):
    directory, _, store = setup
    values = confirmation()

    def fail(*args, **kwargs):
        raise OSError("private storage path")

    monkeypatch.setattr(os, "replace", fail)
    closed(lambda: store.confirm_and_save(**values))
    assert not (directory / "owner.json").exists() and not list(directory.glob(".owner-*"))
    assert values["enrollment"].pending(NOW) is None
    closed(lambda: store.confirm_and_save(**values))


@pytest.mark.parametrize(
    "tamper",
    [
        "scopes",
        "subject",
        "version",
        "mac",
        "unknown_envelope",
        "duplicate",
        "truncated",
        "missing",
        "oversized",
        "wrong_key",
    ],
)
def test_missing_or_tampered_owner_denies_without_cached_grant(setup, tamper):
    directory, _key, store, _ = saved(setup)
    path = directory / "owner.json"
    envelope = json.loads(path.read_bytes())
    if tamper == "scopes":
        envelope["payload"]["owner"]["scopes"][0]["classifications"] = ["HIGHLY_RESTRICTED"]
    elif tamper == "subject":
        envelope["payload"]["owner"]["subject"] = "replacement"
    elif tamper == "version":
        envelope["payload"]["version"] = 1
    elif tamper == "mac":
        envelope["mac"] = "0" * 64
    elif tamper == "unknown_envelope":
        envelope["extra"] = "unknown"
    elif tamper == "missing":
        path.unlink()
    elif tamper == "wrong_key":
        store = OwnerGrantStore(directory, key=secrets.token_bytes(32), origin=ORIGIN, client_id=CLIENT_ID)
    if tamper == "duplicate":
        path.write_bytes(b'{"payload":{},"payload":{},"mac":"' + b"0" * 64 + b'"}')
    elif tamper == "truncated":
        path.write_bytes(b'{"payload":')
    elif tamper == "oversized":
        path.write_bytes(b"X" * 16385)
    elif tamper not in ("missing", "wrong_key"):
        path.write_text(json.dumps(envelope))
    closed(store.load)


@pytest.mark.parametrize(
    "change",
    [
        "unknown_owner",
        "unknown_scope",
        "unknown_payload",
        "unknown_boundary",
        "unknown_classification",
        "duplicate_boundary",
        "duplicate_classification",
        "legacy_issuer",
        "unicode_subject",
        "long_subject",
        "bool_version",
        "list_scope_type",
    ],
)
def test_even_authenticated_unknown_or_noncanonical_schema_denies(setup, change):
    directory, _, store, _ = saved(setup)
    payload = json.loads((directory / "owner.json").read_bytes())["payload"]
    owner = payload["owner"]
    if change == "unknown_owner":
        owner["email"] = "invented@example.test"
    elif change == "unknown_scope":
        owner["scopes"][0]["admin"] = True
    elif change == "unknown_payload":
        payload["ready"] = True
    elif change == "unknown_boundary":
        owner["scopes"][0]["boundary"] = "COMPANY_ADMIN"
    elif change == "unknown_classification":
        owner["scopes"][0]["classifications"] = ["SECRET"]
    elif change == "duplicate_boundary":
        owner["scopes"].append(owner["scopes"][0])
    elif change == "duplicate_classification":
        owner["scopes"][0]["classifications"] = ["INTERNAL", "INTERNAL"]
    elif change == "legacy_issuer":
        owner["issuer"] = "accounts.google.com"
    elif change == "unicode_subject":
        owner["subject"] = "é"
    elif change == "long_subject":
        owner["subject"] = "s" * 256
    elif change == "bool_version":
        payload["version"] = True
    else:
        owner["scopes"] = {}
    (directory / "owner.json").write_bytes(store._envelope(payload))
    closed(store.load)


@pytest.mark.parametrize(
    "unsafe",
    ["directory_mode", "file_mode", "directory_symlink", "file_symlink", "hardlink", "wrong_owner"],
)
def test_unsafe_host_paths_rejected(setup, tmp_path, monkeypatch, unsafe):
    directory, key, store, _ = saved(setup)
    path = directory / "owner.json"
    if unsafe == "directory_mode":
        directory.chmod(0o755)
    elif unsafe == "file_mode":
        path.chmod(0o644)
    elif unsafe == "directory_symlink":
        actual = tmp_path / "actual-directory"
        directory.rename(actual)
        directory.symlink_to(actual, target_is_directory=True)
    elif unsafe == "file_symlink":
        actual = directory / "actual.json"
        path.rename(actual)
        path.symlink_to(actual)
    elif unsafe == "hardlink":
        os.link(path, directory / "linked.json")
    else:
        monkeypatch.setattr(os, "getuid", lambda: path.stat().st_uid + 1)
    closed(store.load)
    closed(lambda: OwnerGrantStore(directory, key=key, origin=ORIGIN, client_id=CLIENT_ID))
    closed(store.revoke)


def test_failed_atomic_replace_preserves_previous_owner_and_reports_revoke_failure(
    setup, monkeypatch
):
    directory, key, store, grant = saved(setup)
    previous = (directory / "owner.json").read_bytes()

    def fail(*args, **kwargs):
        raise OSError("private storage details")

    monkeypatch.setattr(os, "replace", fail)
    closed(store.revoke)
    assert (directory / "owner.json").read_bytes() == previous
    assert OwnerGrantStore(directory, key=key, origin=ORIGIN, client_id=CLIENT_ID).load() == grant
    assert not list(directory.glob(".owner-*"))


def test_same_uid_authenticated_snapshot_replay_is_explicitly_not_prevented(setup):
    # Operational isolation is mandatory: HMAC integrity is not anti-rollback.
    directory, _, store, grant = saved(setup)
    snapshot = (directory / "owner.json").read_bytes()
    store.revoke()
    closed(store.load)
    (directory / "owner.json").write_bytes(snapshot)
    assert store.load() == grant


def test_successful_write_fsyncs_file_then_parent_directory(setup, monkeypatch):
    import stat

    events = []
    original = os.fsync

    def synced(fd):
        events.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        return original(fd)

    monkeypatch.setattr(os, "fsync", synced)
    setup[2].confirm_and_save(**confirmation())
    assert events == [False, True]
    setup[2].revoke()
    assert events == [False, True, False, True]


def test_completed_confirmation_cannot_be_replayed_to_change_saved_scopes(setup):
    directory, _, store = setup
    values = confirmation()
    store.confirm_and_save(**values)
    previous = (directory / "owner.json").read_bytes()
    closed(lambda: store.confirm_and_save(**{**values, "scopes": (SCOPES[1],)}))
    assert (directory / "owner.json").read_bytes() == previous


@pytest.mark.parametrize("replacement", ["identity", "scopes", "tombstone"])
def test_concurrent_authenticated_replacement_cannot_acknowledge_different_confirmation(
    setup, monkeypatch, replacement
):
    from zacai.interfaces.owner_store import _payload

    _, _, store = setup
    original = store._write
    alternate = (
        OwnerGrant(Identity(IDENTITY.issuer, "other-confirmed-owner"), SCOPES)
        if replacement == "identity"
        else OwnerGrant(IDENTITY, (SCOPES[1],))
        if replacement == "scopes"
        else None
    )

    def replaced(payload):
        original(payload)
        # Simulate another authenticated host write before confirmation readback.
        original(_payload(alternate, origin=ORIGIN, client_id=CLIENT_ID))

    monkeypatch.setattr(store, "_write", replaced)
    closed(lambda: store.confirm_and_save(**confirmation()))
    if alternate is None:
        closed(store.load)
    else:
        assert store.load() == alternate  # No false success acknowledgement of original.


@pytest.mark.parametrize("phase", ["file", "directory"])
def test_failed_fsync_reports_no_success_and_preserves_actual_visibility(setup, monkeypatch, phase):
    import stat

    directory, _, store = setup
    values = confirmation()
    original = os.fsync

    def failed(fd):
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if is_directory == (phase == "directory"):
            raise OSError("private synchronization diagnostic")
        return original(fd)

    monkeypatch.setattr(os, "fsync", failed)
    closed(lambda: store.confirm_and_save(**values))
    assert values["enrollment"].pending(NOW) is None
    assert not list(directory.glob(".owner-*"))
    if phase == "directory":
        # Replacement already happened; failure is not absence or rollback.
        assert store.load() == OwnerGrant(IDENTITY, SCOPES)
    else:
        closed(store.load)
        assert not (directory / "owner.json").exists()


def test_directory_fsync_failure_can_leave_revocation_tombstone_visible(setup, monkeypatch):
    import stat

    _, _, store, _ = saved(setup)
    original = os.fsync

    def failed(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("private synchronization diagnostic")
        return original(fd)

    monkeypatch.setattr(os, "fsync", failed)
    closed(store.revoke)  # No durability acknowledgement despite visible tombstone.
    closed(store.load)


@pytest.mark.parametrize("changed", ["origin", "client_id"])
def test_changed_host_configuration_cannot_reuse_authenticated_owner(setup, changed):
    directory, key, _, _ = saved(setup)
    configured = {"origin": ORIGIN, "client_id": CLIENT_ID}
    configured[changed] = (
        "https://other.example.test" if changed == "origin"
        else "987654-other.apps.googleusercontent.com"
    )
    closed(OwnerGrantStore(directory, key=key, **configured).load)


@pytest.mark.parametrize("invalid", ["origin", "client_id"])
def test_invalid_host_configuration_precedes_all_filesystem_io(tmp_path, monkeypatch, invalid):
    from pathlib import Path

    consulted = []

    def forbidden(*args, **kwargs):
        consulted.append(True)
        raise AssertionError("filesystem must not be consulted")

    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(Path, "lstat", forbidden)
    configured = {"origin": ORIGIN, "client_id": CLIENT_ID}
    configured[invalid] = "invalid"
    closed(lambda: OwnerGrantStore(tmp_path / "not-created", key=b"X" * 32, **configured))
    assert not consulted
    assert not (tmp_path / "not-created").exists()


def test_valid_candidate_for_other_origin_cannot_be_confirmed_by_store(setup):
    directory, _, store = setup
    other = "https://other.example.test"
    enrollment = OwnerEnrollment(opened_at=NOW)
    pending = enrollment.capture(IDENTITY, NOW, origin=other)
    closed(lambda: store.confirm_and_save(
        enrollment=enrollment, candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code, origin=other, identity=IDENTITY,
        scopes=SCOPES, now=NOW,
    ))
    assert enrollment.pending(NOW) == pending
    assert not (directory / "owner.json").exists()


@pytest.mark.parametrize("old_shape", ["v1", "unbound_v2"])
def test_authenticated_old_or_unbound_payload_requires_fresh_enrollment(setup, old_shape):
    directory, _, store, _ = saved(setup)
    path = directory / "owner.json"
    payload = json.loads(path.read_bytes())["payload"]
    payload.pop("origin")
    payload.pop("client_id")
    if old_shape == "v1":
        payload["version"] = 1
    path.write_bytes(store._envelope(payload))
    closed(store.load)


def test_revocation_tombstone_keeps_exact_authenticated_host_binding(setup):
    directory, key, store, _ = saved(setup)
    store.revoke()
    payload = json.loads((directory / "owner.json").read_bytes())["payload"]
    assert payload == {"version": 2, "origin": ORIGIN, "client_id": CLIENT_ID, "owner": None}
    changed = OwnerGrantStore(
        directory, key=key, origin="https://other.example.test", client_id=CLIENT_ID
    )
    closed(changed.load)
