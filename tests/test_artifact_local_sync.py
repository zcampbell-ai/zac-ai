"""Invented real filesystem bytes and injected faults, no power-loss/backup proof."""

import os
import stat

import pytest

from zacai.ingestion import artifact_store as m
from zacai.policy import TrustBoundary as B

RAW = b"Invented complete artifact \xf0\x9f\x98\x80"
DIGEST = m.content_hash_of(RAW)


def store(tmp_path):
    return m.LocalFilesystemArtifactStore(tmp_path / "artifacts")


def path(s):
    return s.root / B.BRAINSTORM.value / s.location_for(DIGEST)


def durable(s):
    return s.put_durable(B.BRAINSTORM, DIGEST, RAW, max_bytes=1000)


def test_actual_fsync_order_and_complete_reuse(tmp_path, monkeypatch):
    s = store(tmp_path)
    original, calls = os.fsync, []

    def sync(fd):
        info = os.fstat(fd)
        calls.append((info.st_dev, info.st_ino, stat.S_ISREG(info.st_mode)))
        original(fd)

    monkeypatch.setattr(os, "fsync", sync)
    location = durable(s)
    assert s.get_bounded(B.BRAINSTORM, location, max_bytes=1000) == RAW
    first = list(calls)
    expected = [path(s), path(s), path(s).parent, path(s).parent.parent, s.root, *s.root.parents]
    assert [(dev, ino) for dev, ino, _ in first] == [
        (p.stat().st_dev, p.stat().st_ino) for p in expected
    ]
    assert first[0][2] and first[1][2] and all(not row[2] for row in first[2:])
    assert stat.S_IMODE(path(s).stat().st_mode) == 0o600
    calls.clear()
    assert durable(s) == location and calls == first[1:]


@pytest.mark.parametrize("at", [0, 1, 2, 3, 4])
def test_fsync_failure_never_acknowledges_new_or_reused_file(tmp_path, monkeypatch, at):
    for reused in (False, True):
        s = store(tmp_path / ("reused" if reused else "new"))
        if reused:
            durable(s)
        calls = []
        original = os.fsync

        def fail(fd, calls=calls, original=original):
            calls.append(fd)
            if len(calls) == at + 1:
                raise OSError("invented sync fault")
            original(fd)

        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", fail)
            with pytest.raises(OSError, match="invented sync fault"):
                durable(s)
        assert len(calls) == at + 1
        if reused or at > 0:
            assert path(s).read_bytes() == RAW
        else:
            assert not path(s).exists()
        assert not list(path(s).parent.glob(".tmp-*"))
        # Do not retry: readable bytes or a later successful fsync cannot prove
        # a previous writeback error harmless. Capture acknowledgment is held
        # until independently verified/replaced by the operator.


def test_complete_new_inode_synced_before_name_install_and_again_after(tmp_path, monkeypatch):
    s = store(tmp_path)
    original, observations = os.fsync, []

    def observed(fd):
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode):
            observations.append((path(s).exists(), os.pread(fd, len(RAW), 0)))
        original(fd)

    monkeypatch.setattr(os, "fsync", observed)
    durable(s)
    # All syscall observations completed before asserting causal ordering.
    assert observations == [(False, RAW), (True, RAW)]


def test_double_linked_temporary_orphan_holds_without_automatic_cleanup(tmp_path):
    s = store(tmp_path)
    durable(s)
    temporary = path(s).parent / ".tmp-invented-interrupted-link"
    os.link(path(s), temporary)
    assert path(s).stat().st_ino == temporary.stat().st_ino
    with pytest.raises(OSError, match="unsafe"):
        durable(s)
    assert temporary.exists() and path(s).stat().st_nlink == 2


def test_configured_root_attribute_change_during_sync_holds(tmp_path, monkeypatch):
    s = store(tmp_path)
    original = os.fsync
    alternate = tmp_path / "alternate"
    alternate.mkdir(mode=0o700)
    changed = []

    def swap(fd):
        original(fd)
        if not changed:
            s._root = alternate
            changed.append(True)

    monkeypatch.setattr(os, "fsync", swap)
    with pytest.raises(OSError, match="configured root changed"):
        durable(s)
    assert changed == [True]


def test_0644_reuse_holds_without_fixing_permissions_or_sync(tmp_path, monkeypatch):
    s = store(tmp_path)
    s.put(B.BRAINSTORM, DIGEST, RAW)
    path(s).chmod(0o644)
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    with pytest.raises(OSError, match="unsafe"):
        durable(s)
    assert calls == [] and path(s).read_bytes() == RAW
    assert stat.S_IMODE(path(s).stat().st_mode) == 0o644


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "corrupt", "oversized"])
def test_existing_target_faults_hold_before_sync_and_preserve_target(tmp_path, monkeypatch, kind):
    s = store(tmp_path)
    s.put(B.BRAINSTORM, DIGEST, RAW)
    outside = tmp_path / "outside"
    outside.write_bytes(RAW)
    if kind == "symlink":
        path(s).unlink()
        path(s).symlink_to(outside)
    elif kind == "hardlink":
        os.link(path(s), tmp_path / "second-link")
    elif kind == "corrupt":
        path(s).write_bytes(b"invented corrupt")
    else:
        path(s).write_bytes(b"x" * 1001)
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    with pytest.raises(OSError):
        durable(s)
    assert calls == [] and outside.read_bytes() == RAW


@pytest.mark.parametrize("component", ["root", "boundary", "shard"])
def test_directory_modes_hold_without_silent_permission_repair(tmp_path, component):
    s = store(tmp_path)
    durable(s)
    target = {"root": s.root, "boundary": path(s).parent.parent, "shard": path(s).parent}[component]
    target.chmod(0o755)
    with pytest.raises(OSError, match="unsafe"):
        durable(s)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


@pytest.mark.parametrize("component", ["root", "ancestor", "shard"])
def test_path_swap_during_sync_holds_real_descriptor_identity(tmp_path, monkeypatch, component):
    s = store(tmp_path)
    durable(s)
    target = {"root": s.root, "ancestor": s.root.parent, "shard": path(s).parent}[component]
    original, changed = os.fsync, []

    def swap(fd):
        original(fd)
        if not changed:
            moved = target.with_name(target.name + "-moved")
            target.rename(moved)
            target.mkdir(mode=0o700)
            changed.append(moved)

    monkeypatch.setattr(os, "fsync", swap)
    with pytest.raises(OSError):
        durable(s)
    assert len(changed) == 1 and changed[0].is_dir()


def test_final_sync_file_mutation_holds(tmp_path, monkeypatch):
    s = store(tmp_path)
    durable(s)
    original, changed = os.fsync, []

    def corrupt(fd):
        original(fd)
        if not changed:
            path(s).write_bytes(b"changed invented bytes")
            changed.append(True)

    monkeypatch.setattr(os, "fsync", corrupt)
    with pytest.raises(OSError, match="bytes changed"):
        durable(s)
    assert changed == [True]


def test_link_race_does_not_overwrite_concurrent_unsafe_target(tmp_path, monkeypatch):
    s = store(tmp_path)
    original, created = os.link, []

    def race(src, dst, **kwargs):
        path(s).write_bytes(b"concurrent unsafe target")
        created.append(True)
        original(src, dst, **kwargs)

    monkeypatch.setattr(os, "link", race)
    with pytest.raises(FileExistsError):
        durable(s)
    assert created == [True] and path(s).read_bytes() == b"concurrent unsafe target"
    assert not list(path(s).parent.glob(".tmp-*"))


@pytest.mark.parametrize("cap", [0, True, 100_000_001])
def test_invalid_capacity_before_directory_allocation(tmp_path, cap):
    s = store(tmp_path)
    with pytest.raises(ValueError):
        s.put_durable(B.BRAINSTORM, DIGEST, RAW, max_bytes=cap)
    assert not (s.root / B.BRAINSTORM.value).exists()


def test_alias_root_supported_but_later_symlink_substitution_holds(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    s = m.LocalFilesystemArtifactStore(alias)
    assert s.root == actual.resolve()
    durable(s)
    actual.rename(tmp_path / "moved")
    actual.symlink_to(tmp_path / "moved", target_is_directory=True)
    with pytest.raises(OSError):
        durable(s)


def test_owner_mismatch_metadata_fault_holds_before_sync(tmp_path, monkeypatch):
    s = store(tmp_path)
    durable(s)
    original, syncs = os.fstat, []

    def changed_owner(fd):
        info = original(fd)
        if stat.S_ISREG(info.st_mode):
            fields = list(info)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", changed_owner)
    monkeypatch.setattr(os, "fsync", lambda fd: syncs.append(fd))
    with pytest.raises(OSError, match="unsafe"):
        durable(s)
    assert syncs == []


def test_complete_reuse_reads_always_request_observed_size_plus_one(tmp_path, monkeypatch):
    s = store(tmp_path)
    durable(s)
    original, reads = os.fdopen, []

    class ObservedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size):
            reads.append(size)
            return self.stream.read(size)

    def bounded(fd, mode, **kwargs):
        assert mode == "rb"
        return ObservedReader(original(fd, mode, **kwargs))

    monkeypatch.setattr(os, "fdopen", bounded)
    durable(s)
    assert reads == [len(RAW) + 1, len(RAW) + 1]
