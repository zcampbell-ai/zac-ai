"""Tests for zacai.ingestion.artifact_store (D030): atomicity,
permissions, content-addressed determinism, and the read-after-write
content-hash invariant. No database dependency - pure filesystem tests.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)


def test_canonical_bytes_is_deterministic() -> None:
    payload = {"b": 2, "a": 1, "nested": {"z": 1, "y": 2}}
    first = canonical_bytes(payload)
    second = canonical_bytes(dict(payload))
    assert first == second


def test_put_then_get_round_trips_exact_bytes(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b'{"hello": "world"}'
    location = store.put(content_hash_of(raw), raw)
    assert store.get(location) == raw


def test_content_hash_invariant_holds_after_write(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    payload = canonical_bytes({"transcript": "hello", "id": "abc123"})
    digest = content_hash_of(payload)
    location = store.put(digest, payload)
    assert content_hash_of(store.get(location)) == digest


def test_identical_bytes_produce_identical_path(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b"identical content"
    digest = content_hash_of(raw)
    first_location = store.put(digest, raw)
    second_location = store.put(digest, raw)
    assert first_location == second_location


def test_different_content_never_collides_at_same_path(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw_a = b"content a"
    raw_b = b"content b"
    location_a = store.put(content_hash_of(raw_a), raw_a)
    location_b = store.put(content_hash_of(raw_b), raw_b)
    assert location_a != location_b
    assert store.get(location_a) == raw_a
    assert store.get(location_b) == raw_b


def test_root_directory_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    LocalFilesystemArtifactStore(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_written_file_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = LocalFilesystemArtifactStore(root)
    raw = b"secret-shaped content"
    location = store.put(content_hash_of(raw), raw)
    full_path = root / location
    assert stat.S_IMODE(full_path.stat().st_mode) == 0o600


def test_shard_directory_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = LocalFilesystemArtifactStore(root)
    raw = b"some content"
    location = store.put(content_hash_of(raw), raw)
    shard_dir = (root / location).parent
    assert stat.S_IMODE(shard_dir.stat().st_mode) == 0o700


def test_put_leaves_no_partial_file_on_write_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulates an interrupted write: `os.replace` never runs, so the
    final content-addressed path must never exist, and no temp file is
    left behind either."""
    root = tmp_path / "artifacts"
    store = LocalFilesystemArtifactStore(root)
    raw = b"content that fails to finish writing"
    digest = content_hash_of(raw)

    def _failing_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated crash before rename completes")

    monkeypatch.setattr(os, "replace", _failing_replace)
    with pytest.raises(OSError, match="simulated crash"):
        store.put(digest, raw)

    final_path = root / store.location_for(digest)
    assert not final_path.exists()
    shard_dir = final_path.parent
    remaining = list(shard_dir.iterdir()) if shard_dir.exists() else []
    assert remaining == [], f"unexpected leftover file(s): {remaining}"
