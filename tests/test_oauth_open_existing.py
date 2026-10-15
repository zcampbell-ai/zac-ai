"""Existing encrypted OAuth evidence only, with invented sessions/registrations."""

from __future__ import annotations

import copy
import fcntl
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.test_oauth_transactions import Fixture
from zacai.connectors.oauth_transactions import (
    OAuthTransactionAuthority,
    OAuthTransactionCancelled,
    OAuthTransactionError,
)


def reopened(f, **changes):
    options = {"key": f.key, "continuity": f.sessions.continuity,
               "registration_backend": f.registration}
    return OAuthTransactionAuthority.open_existing(f.directory, **(options | changes))


def snapshot(directory):
    return {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
            for p in directory.iterdir()}


def test_existing_held_row_reopens_exactly_without_renewal_or_callbacks(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    state = f.state()
    operation = f.callback(state)
    operation.hold()
    with f.authority._locked():
        original = f.authority._read()
    assert next(iter(original["rows"].values()))["state"] == "held"
    before = snapshot(f.directory)

    def forbidden(*args, **kwargs):
        pytest.fail("reopen must not create/write/initialize/attest or observe current owner")

    monkeypatch.setattr(OAuthTransactionAuthority, "__init__", forbidden)
    monkeypatch.setattr(OAuthTransactionAuthority, "initialize", forbidden)
    monkeypatch.setattr(OAuthTransactionAuthority, "_write", forbidden)
    monkeypatch.setattr(f.registration, "attest", forbidden)
    monkeypatch.setattr(f.registration, "generation", forbidden)
    monkeypatch.setattr(f.sessions.continuity, "_clock", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    actual_open = os.open

    def no_create(path, flags, *args, **kwargs):
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
        return actual_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_create)
    result = reopened(f)
    assert type(result) is OAuthTransactionAuthority
    assert result._backend is f.registration
    assert result._continuity is f.sessions.continuity
    with result._locked():
        assert result._read() == original
    assert snapshot(f.directory) == before


@pytest.mark.parametrize("missing", ["directory", "provider-oauth-transactions.lock",
                                      "provider-oauth-transactions.bin"])
def test_missing_assets_are_never_created_or_reset(tmp_path, missing):
    f = Fixture(tmp_path)
    if missing == "directory":
        directory = tmp_path / "missing"
    else:
        directory = f.directory
        (directory / missing).unlink()
    before = snapshot(directory) if directory.exists() else None
    with pytest.raises(OAuthTransactionError):
        OAuthTransactionAuthority.open_existing(directory, key=f.key,
            continuity=f.sessions.continuity, registration_backend=f.registration)
    assert (snapshot(directory) if directory.exists() else None) == before


@pytest.mark.parametrize("fault", ["key", "ciphertext", "extra", "binding", "schema", "rows"])
def test_unauthenticated_or_foreign_ledger_is_denied_unchanged(tmp_path, fault):
    f = Fixture(tmp_path)
    options = {}
    if fault == "key":
        options["key"] = b"X" * 32
    elif fault == "ciphertext":
        f.authority._path.write_bytes(b"invented-corrupt-ciphertext" * 4)
    elif fault == "extra":
        child = f.directory / "unknown.bin"
        child.write_bytes(b"invented-extra")
        child.chmod(0o600)
    elif fault == "binding":
        continuity = copy.copy(f.sessions.continuity)
        continuity._context = b'{"client_id":"different","origin":"https://caz.example"}'
        options["continuity"] = continuity
    else:
        with f.authority._locked():
            data = f.authority._read()
            if fault == "schema":
                data["version"] = True
            else:
                data["rows"] = {"a" * 64: {"state": "held"}}
            f.authority._write(data)
    before = snapshot(f.directory)
    with pytest.raises(OAuthTransactionError):
        reopened(f, **options)
    assert snapshot(f.directory) == before


@pytest.mark.parametrize("member,mode", [("directory", 0o755),
                                          ("provider-oauth-transactions.lock", 0o644),
                                          ("provider-oauth-transactions.bin", 0o644)])
def test_private_permissions_remain_required(tmp_path, member, mode):
    f = Fixture(tmp_path)
    target = f.directory if member == "directory" else f.directory / member
    target.chmod(mode)
    before = snapshot(f.directory)
    with pytest.raises(OAuthTransactionError):
        reopened(f)
    assert target.stat().st_mode & 0o777 == mode
    assert snapshot(f.directory) == before


@pytest.mark.parametrize("member", ["directory", "provider-oauth-transactions.lock",
                                    "provider-oauth-transactions.bin"])
def test_symlink_assets_are_never_followed(tmp_path, member):
    f = Fixture(tmp_path)
    if member == "directory":
        alias = tmp_path / "oauth-alias"
        alias.symlink_to(f.directory, target_is_directory=True)
        directory = alias
    else:
        target = f.directory / member
        moved = tmp_path / (member + ".original")
        target.rename(moved)
        target.symlink_to(moved)
        directory = f.directory
    with pytest.raises(OAuthTransactionError):
        OAuthTransactionAuthority.open_existing(directory, key=f.key,
            continuity=f.sessions.continuity, registration_backend=f.registration)
    assert directory.is_symlink() if member == "directory" else (directory/member).is_symlink()


def test_symlinked_parent_and_hardlinked_lock_are_denied(tmp_path):
    f = Fixture(tmp_path)
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OAuthTransactionError):
        OAuthTransactionAuthority.open_existing(parent_alias / f.directory.name, key=f.key,
            continuity=f.sessions.continuity, registration_backend=f.registration)
    os.link(f.authority._lock_path, tmp_path / "lock-hardlink")
    with pytest.raises(OAuthTransactionError):
        reopened(f)


def test_read_occurs_only_under_actual_original_flock(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    original = OAuthTransactionAuthority._read
    observed = []

    def checked(value):
        fd = os.open(value._lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observed.append(True)
        finally:
            os.close(fd)
        return original(value)

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", checked)
    reopened(f)
    assert observed == [True]


@pytest.mark.parametrize("member", ["provider-oauth-transactions.lock",
                                    "provider-oauth-transactions.bin"])
def test_replacement_between_guard_and_actual_lock_is_rejected(tmp_path, monkeypatch, member):
    f = Fixture(tmp_path)
    original = OAuthTransactionAuthority._locked

    @contextmanager
    def replaced(value):
        target = value._directory / member
        replacement = tmp_path / "replacement"
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, target)
        with original(value) as current:
            yield current

    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", replaced)
    with pytest.raises(OAuthTransactionError):
        reopened(f)


@pytest.mark.parametrize("member", ["provider-oauth-transactions.lock",
                                    "provider-oauth-transactions.bin"])
def test_replacement_during_read_cannot_return_authority(tmp_path, monkeypatch, member):
    f = Fixture(tmp_path)
    original = OAuthTransactionAuthority._read

    def replaced(value):
        result = original(value)
        target = value._directory / member
        replacement = tmp_path / "replacement"
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, target)
        return result

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", replaced)
    with pytest.raises(OAuthTransactionError):
        reopened(f)


def test_no_reopen_after_new_unrelated_child_during_read(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    original = OAuthTransactionAuthority._read

    def changed(value):
        result = original(value)
        extra = value._directory / "foreign"
        extra.write_bytes(b"invented")
        extra.chmod(0o600)
        return result

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", changed)
    with pytest.raises(OAuthTransactionError):
        reopened(f)


@pytest.mark.parametrize("changes", [{"key": b"short"}, {"key": "x" * 32},
                                     {"continuity": object()}, {"registration_backend": object()}])
def test_invalid_dependencies_fail_before_effects(tmp_path, changes):
    f = Fixture(tmp_path)
    before = snapshot(f.directory)
    with pytest.raises(OAuthTransactionError):
        reopened(f, **changes)
    assert snapshot(f.directory) == before


def test_subclass_cannot_issue_opened_authority(tmp_path):
    f = Fixture(tmp_path)

    class Foreign(OAuthTransactionAuthority):
        pass

    with pytest.raises(OAuthTransactionError):
        Foreign.open_existing(f.directory, key=f.key, continuity=f.sessions.continuity,
                              registration_backend=f.registration)


def test_interrupted_read_is_sanitized_and_lock_is_released(tmp_path, monkeypatch):
    f = Fixture(tmp_path)

    def interrupted(value):
        raise KeyboardInterrupt("INVENTED PRIVATE DETAIL")

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", interrupted)
    with pytest.raises(OAuthTransactionCancelled) as exc:
        reopened(f)
    assert exc.value.__context__ is None
    assert "PRIVATE" not in str(exc.value)
    fd = os.open(f.authority._lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_directory_replacement_before_existing_lock_is_denied(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    original = OAuthTransactionAuthority._locked

    @contextmanager
    def replaced(value):
        previous = tmp_path / "original-oauth-directory"
        value._directory.rename(previous)
        value._directory.mkdir(mode=0o700)
        for p in previous.iterdir():
            target = value._directory / p.name
            target.write_bytes(p.read_bytes())
            target.chmod(0o600)
        with original(value) as current:
            yield current

    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", replaced)
    with pytest.raises(OAuthTransactionError):
        reopened(f)


def test_current_cipher_is_not_authenticated_by_stale_registration_callbacks(tmp_path):
    f = Fixture(tmp_path)
    # Existing evidence can be inspected without attesting a registration or owner.
    calls = f.registration.calls
    f.registration.failure = RuntimeError("INVENTED PRIVATE BACKEND DETAIL")
    result = reopened(f)
    assert type(result) is OAuthTransactionAuthority
    assert f.registration.calls == calls
