from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from zacai.connectors.oauth_host_guard import (
    OAuthHostGuard,
    OAuthHostGuardError,
    OAuthHostHaltUnconfirmed,
)

ORIGIN = "https://private.example.test"
CLIENT = "123-invented.apps.googleusercontent.com"
KEY = b"x" * 32


def guard(
    path: Path, *, key: bytes = KEY, origin: str = ORIGIN, client: str = CLIENT
) -> OAuthHostGuard:
    return OAuthHostGuard(path, key=key, origin=origin, client_id=client)


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    path = tmp_path / "guard"
    path.mkdir(mode=0o700)
    return path


def test_constructor_inert_missing_state_denies(directory: Path) -> None:
    gate = guard(directory)
    assert list(directory.iterdir()) == []
    with pytest.raises(OAuthHostGuardError):
        gate.ready()
    assert list(directory.iterdir()) == []


def test_initialize_restart_and_one_way_halt(directory: Path) -> None:
    gate = guard(directory)
    gate.initialize()
    guard(directory).ready()
    gate.halt_unconfirmed()
    guard(directory).halt_unconfirmed()
    for candidate in (gate, guard(directory)):
        with pytest.raises(OAuthHostGuardError):
            candidate.ready()
        with pytest.raises(OAuthHostGuardError):
            candidate.initialize()
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())


def test_halt_blocks_separate_process(directory: Path) -> None:
    gate = guard(directory)
    gate.initialize()
    code = """
import sys
from pathlib import Path
from zacai.connectors.oauth_host_guard import OAuthHostGuard, OAuthHostGuardError
try:
 OAuthHostGuard(Path(sys.argv[1]),key=b"x"*32,origin="https://private.example.test",client_id="123-invented.apps.googleusercontent.com").ready()
except OAuthHostGuardError:
 sys.exit(9)
"""
    command = [sys.executable, "-c", code, str(directory)]
    assert subprocess.run(command, check=False, capture_output=True).returncode == 0
    gate.halt_unconfirmed()
    assert subprocess.run(command, check=False, capture_output=True).returncode == 9


@pytest.mark.parametrize("change", ["key", "origin", "client"])
def test_wrong_host_binding_denies(directory: Path, change: str) -> None:
    guard(directory).initialize()
    kwargs = (
        {"key": b"y" * 32}
        if change == "key"
        else {
            change: "https://other.example.test"
            if change == "origin"
            else "456-other.apps.googleusercontent.com"
        }
    )
    with pytest.raises(OAuthHostGuardError):
        guard(directory, **kwargs).ready()


@pytest.mark.parametrize("change", ["missing", "corrupt", "mode", "symlink", "hardlink"])
def test_changed_ready_denies(directory: Path, tmp_path: Path, change: str) -> None:
    gate = guard(directory)
    gate.initialize()
    path = directory / "oauth-host.ready"
    if change == "missing":
        path.unlink()
    elif change == "corrupt":
        path.write_bytes(b"wrong" * 8)
    elif change == "mode":
        path.chmod(0o644)
    elif change == "symlink":
        target = tmp_path / "target"
        path.rename(target)
        path.symlink_to(target)
    else:
        os.link(path, tmp_path / "link")
    with pytest.raises(OAuthHostGuardError):
        gate.ready()


@pytest.mark.parametrize("change", ["missing", "mode", "symlink", "hardlink"])
def test_changed_lock_denies(directory: Path, tmp_path: Path, change: str) -> None:
    gate = guard(directory)
    gate.initialize()
    path = directory / "oauth-host.lock"
    if change == "missing":
        path.unlink()
    elif change == "mode":
        path.chmod(0o644)
    elif change == "symlink":
        target = tmp_path / "target"
        path.rename(target)
        path.symlink_to(target)
    else:
        os.link(path, tmp_path / "link")
    with pytest.raises(OAuthHostGuardError):
        gate.ready()
    with pytest.raises(OAuthHostHaltUnconfirmed):
        gate.halt_unconfirmed()


@pytest.mark.parametrize("kind", ["empty", "symlink", "directory"])
def test_any_halt_marker_denies(directory: Path, tmp_path: Path, kind: str) -> None:
    guard(directory).initialize()
    path = directory / "oauth-host.halted"
    if kind == "empty":
        path.touch(mode=0o600)
    elif kind == "symlink":
        path.symlink_to(tmp_path / "absent")
    else:
        path.mkdir(mode=0o700)
    with pytest.raises(OAuthHostGuardError):
        guard(directory).ready()


def test_failed_initialization_is_spent(directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gate = guard(directory)
    create = gate._create

    def broken(path: Path, value: bytes) -> None:
        if path.name.endswith(".ready"):
            raise OSError("invented-private-error")
        create(path, value)

    monkeypatch.setattr(gate, "_create", broken)
    with pytest.raises(OAuthHostGuardError):
        gate.initialize()
    with pytest.raises(OAuthHostGuardError):
        guard(directory).initialize()
    with pytest.raises(OAuthHostGuardError):
        guard(directory).ready()


@pytest.mark.parametrize("interrupted", [False, True])
def test_failed_halt_latches_and_is_fatal(
    directory: Path, monkeypatch: pytest.MonkeyPatch, interrupted: bool
) -> None:
    gate = guard(directory)
    gate.initialize()

    def broken(*_: object) -> None:
        if interrupted:
            raise KeyboardInterrupt("invented-private-error")
        raise OSError("invented-private-error")

    monkeypatch.setattr(gate, "_sync_directory", broken)
    with pytest.raises(OAuthHostHaltUnconfirmed) as failure:
        gate.halt_unconfirmed()
    assert failure.value.__context__ is None
    assert "invented-private-error" not in str(failure.value)
    with pytest.raises(OAuthHostGuardError):
        gate.ready()
    # The marker was visible even though durable acknowledgement failed.
    with pytest.raises(OAuthHostGuardError):
        guard(directory).ready()


def test_directory_symlink_denies(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(OAuthHostGuardError):
        guard(alias).initialize()
    assert list(actual.iterdir()) == []


@pytest.mark.parametrize("failure_after_publication", ["create", "directory_sync"])
def test_ambiguous_ready_publication_is_stopped(
    directory: Path, monkeypatch: pytest.MonkeyPatch, failure_after_publication: str
) -> None:
    gate = guard(directory)
    create, sync = gate._create, gate._sync_directory
    if failure_after_publication == "create":

        def broken(path: Path, value: bytes) -> None:
            create(path, value)
            if path.name.endswith(".ready"):
                raise OSError("invented-after-publication")

        monkeypatch.setattr(gate, "_create", broken)
    else:
        calls = 0

        def broken_sync() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("invented-directory-sync")
            sync()

        monkeypatch.setattr(gate, "_sync_directory", broken_sync)
    with pytest.raises(OAuthHostGuardError):
        gate.initialize()
    for candidate in (gate, guard(directory)):
        with pytest.raises(OAuthHostGuardError):
            candidate.ready()
    assert (directory / "oauth-host.halted").exists()
