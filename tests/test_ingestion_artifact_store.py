"""Tests for zacai.ingestion.artifact_store (D030/D031A): atomicity,
permissions, content-addressed determinism, the read-after-write
content-hash invariant, and PERSONAL/BRAINSTORM/SHARED boundary
partitioning/isolation. No database dependency - pure filesystem tests.
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
from zacai.policy import TrustBoundary

_BOUNDARY = TrustBoundary.BRAINSTORM


def test_canonical_bytes_is_deterministic() -> None:
    payload = {"b": 2, "a": 1, "nested": {"z": 1, "y": 2}}
    first = canonical_bytes(payload)
    second = canonical_bytes(dict(payload))
    assert first == second


def test_put_then_get_round_trips_exact_bytes(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b'{"hello": "world"}'
    location = store.put(_BOUNDARY, content_hash_of(raw), raw)
    assert store.get(_BOUNDARY, location) == raw


def test_content_hash_invariant_holds_after_write(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    payload = canonical_bytes({"transcript": "hello", "id": "abc123"})
    digest = content_hash_of(payload)
    location = store.put(_BOUNDARY, digest, payload)
    assert content_hash_of(store.get(_BOUNDARY, location)) == digest


def test_identical_bytes_produce_identical_path(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b"identical content"
    digest = content_hash_of(raw)
    first_location = store.put(_BOUNDARY, digest, raw)
    second_location = store.put(_BOUNDARY, digest, raw)
    assert first_location == second_location


def test_different_content_never_collides_at_same_path(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw_a = b"content a"
    raw_b = b"content b"
    location_a = store.put(_BOUNDARY, content_hash_of(raw_a), raw_a)
    location_b = store.put(_BOUNDARY, content_hash_of(raw_b), raw_b)
    assert location_a != location_b
    assert store.get(_BOUNDARY, location_a) == raw_a
    assert store.get(_BOUNDARY, location_b) == raw_b


def test_root_directory_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    LocalFilesystemArtifactStore(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_written_file_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = LocalFilesystemArtifactStore(root)
    raw = b"secret-shaped content"
    location = store.put(_BOUNDARY, content_hash_of(raw), raw)
    full_path = root / _BOUNDARY.value / location
    assert stat.S_IMODE(full_path.stat().st_mode) == 0o600


def test_boundary_directory_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = LocalFilesystemArtifactStore(root)
    raw = b"some content"
    store.put(_BOUNDARY, content_hash_of(raw), raw)
    boundary_dir = root / _BOUNDARY.value
    assert stat.S_IMODE(boundary_dir.stat().st_mode) == 0o700


def test_shard_directory_has_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = LocalFilesystemArtifactStore(root)
    raw = b"some content"
    location = store.put(_BOUNDARY, content_hash_of(raw), raw)
    shard_dir = (root / _BOUNDARY.value / location).parent
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
        store.put(_BOUNDARY, digest, raw)

    final_path = root / _BOUNDARY.value / store.location_for(digest)
    assert not final_path.exists()
    shard_dir = final_path.parent
    remaining = list(shard_dir.iterdir()) if shard_dir.exists() else []
    assert remaining == [], f"unexpected leftover file(s): {remaining}"


# --- D031A: boundary partitioning / isolation -------------------------------


def test_location_for_is_boundary_agnostic(tmp_path: Path) -> None:
    """`content_location` never encodes a boundary - the same suffix is
    predicted regardless of which boundary will eventually use it."""
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    digest = content_hash_of(b"some bytes")
    assert store.location_for(digest) == store.location_for(digest)


@pytest.mark.parametrize(
    "boundary_a,boundary_b",
    [
        (TrustBoundary.PERSONAL, TrustBoundary.BRAINSTORM),
        (TrustBoundary.PERSONAL, TrustBoundary.SHARED),
        (TrustBoundary.BRAINSTORM, TrustBoundary.SHARED),
    ],
)
def test_identical_content_hash_in_different_boundaries_creates_distinct_files(
    tmp_path: Path, boundary_a: TrustBoundary, boundary_b: TrustBoundary
) -> None:
    """The same bytes (and therefore the same content_hash and the same
    boundary-agnostic content_location) written under two different
    boundaries must land in two distinct physical files, each
    independently readable and isolated from the other (D031A)."""
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b"identical bytes, different boundaries"
    digest = content_hash_of(raw)

    location_a = store.put(boundary_a, digest, raw)
    location_b = store.put(boundary_b, digest, raw)

    # Same boundary-agnostic content_location string...
    assert location_a == location_b
    # ...but two distinct physical files, both intact and independently readable.
    path_a = tmp_path / "artifacts" / boundary_a.value / location_a
    path_b = tmp_path / "artifacts" / boundary_b.value / location_b
    assert path_a != path_b
    assert path_a.exists()
    assert path_b.exists()
    assert store.get(boundary_a, location_a) == raw
    assert store.get(boundary_b, location_b) == raw


def test_get_never_falls_back_across_boundaries(tmp_path: Path) -> None:
    """Writing under BRAINSTORM only must never be readable via PERSONAL,
    even though `content_location` is identical either way - no
    cross-boundary fallback (D031A)."""
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b"brainstorm-only content"
    digest = content_hash_of(raw)
    location = store.put(TrustBoundary.BRAINSTORM, digest, raw)

    assert store.get(TrustBoundary.BRAINSTORM, location) == raw
    with pytest.raises(FileNotFoundError):
        store.get(TrustBoundary.PERSONAL, location)
    with pytest.raises(FileNotFoundError):
        store.get(TrustBoundary.SHARED, location)


def test_deterministic_lookup_per_boundary(tmp_path: Path) -> None:
    """The same `(trust_boundary, content_hash)` always resolves to the
    identical path, independent of call order or repetition."""
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    raw = b"deterministic content"
    digest = content_hash_of(raw)

    first = store.put(TrustBoundary.SHARED, digest, raw)
    second = store.put(TrustBoundary.SHARED, digest, raw)
    assert first == second
    assert store.get(TrustBoundary.SHARED, first) == raw
