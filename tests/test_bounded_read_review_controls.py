"""Invented concrete files; size-bound allocation, not process memory proof."""

import os
import tracemalloc

import pytest

from tests.test_bounded_artifact_read import stored
from zacai.ingestion import artifact_store as m
from zacai.policy import TrustBoundary as B


def test_small_file_with_exact_ceiling_uses_small_observed_size_and_allocation(tmp_path):
    raw = b"invented"
    store, location, _ = stored(tmp_path, raw)
    if tracemalloc.is_tracing():
        pytest.skip("requires isolated tracing to measure only this read")
    tracemalloc.start()
    try:
        returned = store.get_bounded(B.BRAINSTORM, location, max_bytes=100_000_000)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert returned == raw
    assert peak < 1_000_000


@pytest.mark.parametrize("fault", ["unchanged", "growth", "growth_then_restore"])
def test_larger_limit_still_reads_only_observed_size_plus_one(tmp_path, monkeypatch, fault):
    raw = b"invented"
    store, location, target = stored(tmp_path, raw)
    fdopen = m.os.fdopen
    counts = []
    hashes = []
    original_hash = m.content_hash_of

    class Stream:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def read(self, count):
            counts.append(count)
            if fault != "unchanged":
                target.write_bytes(raw + b"x" * 20)
            data = self.inner.read(count)
            if fault == "growth_then_restore":
                target.write_bytes(raw)
            return data

    def hash_spy(data):
        hashes.append(len(data))
        return original_hash(data)

    monkeypatch.setattr(m.os, "fdopen", lambda *a, **k: Stream(fdopen(*a, **k)))
    monkeypatch.setattr(m, "content_hash_of", hash_spy)
    if fault == "unchanged":
        assert store.get_bounded(B.BRAINSTORM, location, max_bytes=100) == raw
        assert hashes == [len(raw)]
    else:
        with pytest.raises(OSError, match="bounded local artifact changed"):
            store.get_bounded(B.BRAINSTORM, location, max_bytes=100)
        assert hashes == []
    assert counts == [len(raw) + 1]


def test_preexisting_hardlink_holds_before_fdopen(tmp_path, monkeypatch):
    store, location, target = stored(tmp_path)
    os.link(target, tmp_path / "invented-hardlink")
    opened = []
    monkeypatch.setattr(m.os, "fdopen", lambda *a, **k: opened.append(1))
    with pytest.raises(OSError, match="regular singly linked local artifact required"):
        store.get_bounded(B.BRAINSTORM, location, max_bytes=100)
    assert opened == []


@pytest.mark.parametrize("boundary", ["BRAINSTORM", None, 1])
def test_invalid_boundary_is_zero_filesystem_io(tmp_path, monkeypatch, boundary):
    store, location, _ = stored(tmp_path)
    calls = []
    monkeypatch.setattr(m.os, "open", lambda *a, **k: calls.append(1))
    with pytest.raises(ValueError, match="exact local artifact boundary/location required"):
        store.get_bounded(boundary, location, max_bytes=100)
    assert calls == []
