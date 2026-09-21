"""Content-addressed raw-artifact storage (D030).

`Source.content_location` is opaque from the database's point of view -
its meaning belongs entirely to whichever `ArtifactStore` implementation
wrote it. `LocalFilesystemArtifactStore` is the only implementation this
milestone builds; swapping in a future encrypted/object-storage backend
requires only a new class satisfying the same protocol, never a change
to `Source`'s schema or semantics (SECURITY.md "Vendor Independence").

This module has no PostgreSQL dependency and performs no database I/O.
See `zacai.ingestion.pipeline` for how a write here is sequenced against
a `Source` row - the artifact write always happens fully outside the
database transaction, and an artifact left with no referencing `Source`
row (an "orphan artifact") is an accepted, named failure mode, never
cleaned up automatically (D030).

**Real-ingestion hard gate (D030)**: no real Fireflies content may be
ingested until raw artifact backup/recovery - encrypted, off-device,
per-boundary-separated, hash-verified on restore - has been designed,
implemented, and restore-drill tested. This module and this milestone
only ever write synthetic fixture bytes.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Protocol

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """The one function that produces the bytes both hashed and stored
    for a JSON-shaped raw payload (D030). Hashing and storage must always
    consume this exact output - never call `json.dumps` independently a
    second time for either purpose, or the content-hash invariant
    (`sha256(store.get(content_location)) == content_hash`) can silently
    break. Deterministic: the same logical payload always serializes to
    bit-identical bytes (sorted keys, fixed separators)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_hash_of(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


class ArtifactStore(Protocol):
    """A minimal put/get interface. Never transactional with PostgreSQL -
    see the module docstring."""

    def put(self, content_hash: str, raw_bytes: bytes) -> str:
        """Writes `raw_bytes`, addressed by `content_hash`. Returns the
        opaque `content_location` to store on the `Source` row. Writing
        the same `content_hash` twice is always a safe no-op - identical
        hash means identical bytes are already stored."""
        ...

    def get(self, content_location: str) -> bytes:
        """Reads back exactly the bytes written for this location."""
        ...


class LocalFilesystemArtifactStore:
    """v1 `ArtifactStore` (D030): local disk, content-addressed,
    atomic writes, restrictive permissions. No S3/cloud/object storage in
    this milestone - see DECISIONS.md D030."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(self._root, _DIR_MODE)

    def _path_for(self, content_hash: str) -> Path:
        """Content-addressed, deterministic: identical bytes always
        resolve to the identical path - free storage-level deduplication
        in addition to `Source`'s own DB-level idempotency key. Sharded
        by hash prefix so one connector's artifacts never sit in one
        huge flat directory."""
        shard = content_hash[:2]
        return self._root / shard / f"{content_hash}.bin"

    def location_for(self, content_hash: str) -> str:
        """The `content_location` `put(content_hash, ...)` would produce,
        without writing anything - lets a caller (or a test) predict a
        path deterministically."""
        return str(self._path_for(content_hash).relative_to(self._root))

    def put(self, content_hash: str, raw_bytes: bytes) -> str:
        target = self._path_for(content_hash)
        target.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(target.parent, _DIR_MODE)

        if target.exists():
            return str(target.relative_to(self._root))

        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as tmp_file:
                tmp_file.write(raw_bytes)
            os.chmod(tmp_name, _FILE_MODE)
            os.replace(tmp_name, target)  # atomic rename on the same filesystem
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise
        return str(target.relative_to(self._root))

    def get(self, content_location: str) -> bytes:
        path = self._root / content_location
        return path.read_bytes()
