"""Content-addressed raw-artifact storage (D030/D031A).

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

**D031A boundary partitioning**: `put`/`get` require an explicit
`trust_boundary` parameter and store artifacts under
`<root>/<trust_boundary>/<hash[:2]>/<hash>.bin`. This corrects D030's
originally shipped flat layout (`<root>/<hash[:2]>/<hash>.bin`, no
boundary segmentation at all) - found during D031 design review, fixed
before any real artifact ever existed under the old layout, so this is a
pure code change with nothing to migrate. `content_location` itself
(and `location_for`) stays boundary-agnostic - a pure function of
`content_hash` - so the boundary is never inferred from a path string or
by scanning the filesystem; it must always be supplied explicitly by the
caller (who already holds it, from the `Source` row's own
`trust_boundary` column or the ingestion run's own configured boundary).
There is no cross-boundary fallback: `get` resolves strictly within the
supplied boundary's subtree and raises if the file isn't there, even if
an identical `content_location` string happens to exist under a
different boundary (a rare content-hash coincidence, now correctly
isolated rather than accidentally shared).

**Real-ingestion hard gate (D030/D031)**: no real Fireflies content may
be ingested until raw artifact backup/recovery - encrypted, genuinely
off-device, per-boundary-separated, hash-verified on restore - has been
designed, implemented, and restore-drill tested (D031A/D031B). This
module and this milestone only ever write synthetic fixture bytes.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from zacai.policy import TrustBoundary

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
    see the module docstring. `trust_boundary` is required and explicit
    on every call (D031A) - an implementation must never infer it from
    `content_location` or by scanning the filesystem."""

    def put(self, trust_boundary: TrustBoundary, content_hash: str, raw_bytes: bytes) -> str:
        """Writes `raw_bytes`, addressed by `content_hash` within
        `trust_boundary`. Returns the opaque `content_location` to store
        on the `Source` row - boundary-agnostic; the boundary must be
        supplied again on every `get`. Writing the same
        `(trust_boundary, content_hash)` twice is always a safe no-op -
        identical hash means identical bytes are already stored."""
        ...

    def get(self, trust_boundary: TrustBoundary, content_location: str) -> bytes:
        """Reads back exactly the bytes written for this location within
        `trust_boundary`. Never falls back to another boundary, even if
        an identical `content_location` string happens to exist there."""
        ...


class LocalFilesystemArtifactStore:
    """v1 `ArtifactStore` (D030/D031A): local disk, boundary-partitioned,
    content-addressed within each boundary, atomic writes, restrictive
    permissions. No S3/cloud/object storage in this milestone - see
    DECISIONS.md D030/D031."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(self._root, _DIR_MODE)

    @property
    def root(self) -> Path:
        """The local filesystem root this store is backed by - exposed
        so restore-target safety checks (D031B) can inspect it without
        reaching into a private attribute."""
        return self._root

    def _path_for(self, trust_boundary: TrustBoundary, content_hash: str) -> Path:
        """Content-addressed within a boundary, deterministic: the same
        `(trust_boundary, content_hash)` always resolves to the identical
        path - free storage-level deduplication in addition to `Source`'s
        own DB-level idempotency key. Sharded by hash prefix within each
        boundary directory so one connector's artifacts never sit in one
        huge flat directory. `trust_boundary` is never derived from
        anything other than this explicit parameter."""
        shard = content_hash[:2]
        return self._root / trust_boundary.value / shard / f"{content_hash}.bin"

    def location_for(self, content_hash: str) -> str:
        """The boundary-agnostic `content_location` suffix `put(...)`
        would produce for `content_hash`, without writing anything - lets
        a caller (or a test) predict it deterministically. Does not take
        a boundary: `content_location` itself never encodes one (D031A) -
        the boundary is applied only when resolving to an actual path."""
        shard = content_hash[:2]
        return str(Path(shard) / f"{content_hash}.bin")

    def put(self, trust_boundary: TrustBoundary, content_hash: str, raw_bytes: bytes) -> str:
        target = self._path_for(trust_boundary, content_hash)
        target.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(target.parent, _DIR_MODE)
        os.chmod(target.parent.parent, _DIR_MODE)  # the boundary directory itself

        if target.exists():
            return self.location_for(content_hash)

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
        return self.location_for(content_hash)

    def get(self, trust_boundary: TrustBoundary, content_location: str) -> bytes:
        path = self._root / trust_boundary.value / content_location
        return path.read_bytes()
