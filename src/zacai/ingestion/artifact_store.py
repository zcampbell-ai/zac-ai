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
import re
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

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
        `(trust_boundary, content_hash)` twice is a safe no-op when the
        existing artifact is intact. A local corrupt or linked target holds
        rather than being silently repaired or declared successful."""
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
        # Root is trusted host configuration, not an artifact location. Resolve
        # only this once so macOS /tmp and /var aliases remain compatible. Never
        # resolve boundary/shard or caller-supplied content_location components.
        self._root = root.resolve(strict=False)
        with self._directory_fd((), create=True) as fd:
            os.fchmod(fd, _DIR_MODE)

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
        if type(trust_boundary) is not TrustBoundary:
            raise ValueError("exact artifact boundary required")
        self.location_for(content_hash)
        shard = content_hash[:2]
        return self._root / trust_boundary.value / shard / f"{content_hash}.bin"

    def location_for(self, content_hash: str) -> str:
        """The boundary-agnostic `content_location` suffix `put(...)`
        would produce for `content_hash`, without writing anything - lets
        a caller (or a test) predict it deterministically. Does not take
        a boundary: `content_location` itself never encodes one (D031A) -
        the boundary is applied only when resolving to an actual path."""
        if type(content_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", content_hash) is None:
            raise ValueError("canonical artifact hash required")
        shard = content_hash[:2]
        return str(Path(shard) / f"{content_hash}.bin")

    @contextlib.contextmanager
    def _directory_fd(self, suffix: tuple[str, ...], *, create: bool = False) -> Iterator[int]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        with contextlib.ExitStack() as descriptors:
            current = os.open("/", flags)
            descriptors.callback(os.close, current)
            root_parts = self._root.parts[1:]
            for index, part in enumerate((*root_parts, *suffix)):
                if part in (".", ".."):
                    raise ValueError("canonical local artifact root required")
                try:
                    opened = os.open(part, flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, _DIR_MODE, dir_fd=current)
                    opened = os.open(part, flags, dir_fd=current)
                current = opened
                descriptors.callback(os.close, current)
                if create and index >= len(root_parts):
                    os.fchmod(current, _DIR_MODE)
            yield current

    def _read_at(self, directory: int, digest: str) -> bytes:
        fd = os.open(digest + ".bin", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("regular singly linked local artifact required")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read()
            if content_hash_of(raw) != digest:
                raise OSError("local artifact content hash differs")
            return raw
        finally:
            os.close(fd)

    def put(self, trust_boundary: TrustBoundary, content_hash: str, raw_bytes: bytes) -> str:
        self._path_for(trust_boundary, content_hash)  # Closed validation, no I/O.
        if type(raw_bytes) is not bytes or content_hash_of(raw_bytes) != content_hash:
            raise ValueError("exact content-addressed artifact bytes required")
        with self._directory_fd((trust_boundary.value, content_hash[:2]), create=True) as directory:
            try:
                previous = self._read_at(directory, content_hash)
            except FileNotFoundError:
                previous = None
            if previous is not None:
                if previous != raw_bytes:
                    raise OSError("existing artifact bytes differ")
                return self.location_for(content_hash)
            temporary = ".tmp-" + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         _FILE_MODE, dir_fd=directory)
            try:
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        os.fchmod(stream.fileno(), _FILE_MODE)
                        stream.write(raw_bytes)
                finally:
                    os.close(fd)
                os.replace(temporary, content_hash + ".bin",
                           src_dir_fd=directory, dst_dir_fd=directory)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=directory)
                raise
        return self.location_for(content_hash)

    def get(self, trust_boundary: TrustBoundary, content_location: str) -> bytes:
        if type(trust_boundary) is not TrustBoundary or type(content_location) is not str:
            raise ValueError("exact local artifact boundary/location required")
        match = re.fullmatch(r"([0-9a-f]{2})/([0-9a-f]{64})\.bin", content_location)
        if match is None or match[1] != match[2][:2]:
            raise ValueError("canonical local artifact location required")
        digest = match[2]
        with self._directory_fd((trust_boundary.value, match[1])) as directory:
            return self._read_at(directory, digest)
