"""Invented local files only; no Source ACL, capture, DB or crypto proof."""

from __future__ import annotations

import errno
import os

import pytest

from zacai.ingestion import artifact_store as m
from zacai.policy import TrustBoundary as B


def stored(tmp_path, raw=b"invented original"):
    store = m.LocalFilesystemArtifactStore(tmp_path / "artifacts")
    digest = m.content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    return store, location, store.root / B.BRAINSTORM.value / location


def test_complete_exact_read_and_ordinary_get_remain_compatible(tmp_path):
    raw = "invented 😀 original".encode()
    store, location, target = stored(tmp_path, raw)
    assert store.get_bounded(B.BRAINSTORM, location, max_bytes=len(raw)) == raw
    assert store.get(B.BRAINSTORM, location) == raw
    assert store.put(B.BRAINSTORM, m.content_hash_of(raw), raw) == location
    assert target.stat().st_mode & 0o777 == 0o600


def test_overlegacy_read_is_explicit_not_implicit_cap_change(tmp_path):
    raw = b"x" * 8_000_001
    store, location, _ = stored(tmp_path, raw)
    with pytest.raises(OSError, match="outside bounded capacity"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=8_000_000)
    assert store.get_bounded(B.BRAINSTORM, location, max_bytes=len(raw)) == raw
    assert store.get(B.BRAINSTORM, location) == raw


@pytest.mark.parametrize("limit", [True, False, 0, -1, 1.0, "4", 100_000_001, None])
def test_closed_limit_is_checked_before_filesystem_open(tmp_path, monkeypatch, limit):
    store, location, _ = stored(tmp_path)
    calls = []
    monkeypatch.setattr(m.os, "open", lambda *a, **k: calls.append(1))
    with pytest.raises(ValueError, match="exact bounded artifact limit required"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=limit)
    assert calls == []


def test_size_hold_precedes_body_read_and_closes_open_descriptor(tmp_path, monkeypatch):
    store, location, _ = stored(tmp_path)
    opened = []
    real_open = m.os.open

    def track_open(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        opened.append(fd)
        return fd

    reads = []
    monkeypatch.setattr(m.os, "open", track_open)
    monkeypatch.setattr(m.os, "fdopen", lambda *a, **k: reads.append(1))
    with pytest.raises(OSError, match="outside bounded capacity"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=2)
    assert reads == [] and opened
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("fault", ["grow_before", "shrink_before", "grow_after", "link_after"])
def test_actual_file_drift_holds_before_hash_and_uses_limit_plus_one(tmp_path, monkeypatch, fault):
    raw = b"invented"
    store, location, target = stored(tmp_path, raw)
    original_fdopen = m.os.fdopen
    arguments = []
    hashes = []

    class Stream:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def read(self, count):
            arguments.append(count)
            if fault == "grow_before":
                target.write_bytes(raw + b"x" * 20)
            elif fault == "shrink_before":
                target.write_bytes(b"xx")
            answer = self.inner.read(count)
            if fault == "grow_after":
                target.write_bytes(raw + b"later")
            elif fault == "link_after":
                os.link(target, tmp_path / "late-hardlink")
            return answer

    monkeypatch.setattr(m.os, "fdopen", lambda *a, **k: Stream(original_fdopen(*a, **k)))
    monkeypatch.setattr(m, "content_hash_of", lambda raw: hashes.append(raw))
    with pytest.raises(OSError, match="bounded local artifact changed"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=len(raw))
    assert arguments == [len(raw) + 1]
    assert hashes == []


def test_same_length_corruption_holds_at_actual_whole_hash(tmp_path):
    store, location, target = stored(tmp_path, b"invented")
    target.write_bytes(b"tampered")
    with pytest.raises(OSError, match="content hash differs"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=8)


@pytest.mark.parametrize("kind", ["boundary", "shard", "file", "hardlink", "fifo", "directory"])
def test_cross_boundary_links_and_nonregular_targets_hold(tmp_path, kind):
    store = m.LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b"invented personal bytes"
    digest = m.content_hash_of(raw)
    location = store.put(B.PERSONAL, digest, raw)
    source = store.root / B.PERSONAL.value / location
    boundary = store.root / B.BRAINSTORM.value
    shard = boundary / digest[:2]
    target = shard / source.name
    if kind == "boundary":
        boundary.symlink_to(source.parent.parent, target_is_directory=True)
    else:
        boundary.mkdir()
        if kind == "shard":
            shard.symlink_to(source.parent, target_is_directory=True)
        else:
            shard.mkdir()
            if kind == "file":
                target.symlink_to(source)
            elif kind == "hardlink":
                os.link(source, target)
            elif kind == "fifo":
                os.mkfifo(target)
            else:
                target.mkdir()
    with pytest.raises(OSError):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=100)
    if kind == "hardlink":
        assert source.read_bytes() == raw
        target.unlink()
    assert store.get(B.PERSONAL, location) == raw


def test_host_configured_root_alias_resolves_once(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "trusted-config-alias"
    alias.symlink_to(real, target_is_directory=True)
    store = m.LocalFilesystemArtifactStore(alias)
    raw = b"invented root alias"
    location = store.put(B.BRAINSTORM, m.content_hash_of(raw), raw)
    other = tmp_path / "other"
    other.mkdir()
    alias.unlink()
    alias.symlink_to(other, target_is_directory=True)
    assert store.get_bounded(B.BRAINSTORM, location, max_bytes=100) == raw
    assert not (other / B.BRAINSTORM.value).exists()


@pytest.mark.parametrize("fault", ["interrupt", "cancel"])
def test_read_baseexception_propagates_and_all_descriptors_close(tmp_path, monkeypatch, fault):
    store, location, _ = stored(tmp_path)
    opened = []
    real_open, real_fdopen = m.os.open, m.os.fdopen

    class Cancel(BaseException):
        pass

    error = KeyboardInterrupt if fault == "interrupt" else Cancel

    def track_open(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        opened.append(fd)
        return fd

    class Stream:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def read(self, count):
            raise error()

    monkeypatch.setattr(m.os, "open", track_open)
    monkeypatch.setattr(m.os, "fdopen", lambda *a, **k: Stream(real_fdopen(*a, **k)))
    with pytest.raises(error):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=100)
    for fd in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF


def test_empty_complete_artifact_still_requires_positive_limit(tmp_path):
    store, location, _ = stored(tmp_path, b"")
    assert store.get_bounded(B.BRAINSTORM, location, max_bytes=1) == b""


def test_bounded_method_never_falls_back_to_unbounded_helper(tmp_path, monkeypatch):
    raw = b"invented no fallback"
    store, location, _ = stored(tmp_path, raw)
    calls = []
    monkeypatch.setattr(store, "_read_at", lambda *a, **k: calls.append(1))
    assert store.get_bounded(B.BRAINSTORM, location, max_bytes=len(raw)) == raw
    with pytest.raises(OSError, match="outside bounded capacity"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=1)
    assert calls == []


@pytest.mark.parametrize(
    "bad", ["../x", "/tmp/file", "aa/" + "b" * 64 + ".bin", "personal/file", None]
)
def test_bad_locations_hold_before_directory_open(tmp_path, monkeypatch, bad):
    store, _, _ = stored(tmp_path)
    calls = []
    monkeypatch.setattr(m.os, "open", lambda *a, **k: calls.append(1))
    with pytest.raises(ValueError):
        store.get_bounded(B.BRAINSTORM, bad, max_bytes=100)
    assert calls == []


def test_integer_subclass_cannot_supply_limit(tmp_path, monkeypatch):
    class Limit(int):
        pass

    store, location, _ = stored(tmp_path)
    calls = []
    monkeypatch.setattr(m.os, "open", lambda *a, **k: calls.append(1))
    with pytest.raises(ValueError, match="exact bounded artifact limit required"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=Limit(100))
    assert calls == []
