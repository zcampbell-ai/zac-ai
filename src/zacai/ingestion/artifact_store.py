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

# Separate explicit preparation ceiling; unchanged get/put impose no new cap.
MAX_BOUNDED_ARTIFACT_BYTES = 100_000_000


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
        fd = os.open(digest + ".bin", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
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
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                _FILE_MODE,
                dir_fd=directory,
            )
            try:
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        os.fchmod(stream.fileno(), _FILE_MODE)
                        stream.write(raw_bytes)
                finally:
                    os.close(fd)
                os.replace(
                    temporary, content_hash + ".bin", src_dir_fd=directory, dst_dir_fd=directory
                )
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

    def _read_bounded_at(self, directory: int, digest: str, max_bytes: int) -> bytes:
        fd = os.open(digest + ".bin", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("regular singly linked local artifact required")
            if not 0 <= metadata.st_size <= max_bytes:
                raise OSError("local artifact outside bounded capacity")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(metadata.st_size + 1)
            after = os.fstat(fd)
            if (
                len(raw) > max_bytes
                or len(raw) != metadata.st_size
                or after.st_size != metadata.st_size
                or not stat.S_ISREG(after.st_mode)
                or after.st_nlink != 1
            ):
                raise OSError("bounded local artifact changed")
            if content_hash_of(raw) != digest:
                raise OSError("local artifact content hash differs")
            return raw
        finally:
            os.close(fd)

    def get_bounded(
        self, trust_boundary: TrustBoundary, content_location: str, *, max_bytes: int
    ) -> bytes:
        """Read one complete hash-verified artifact within an explicit byte limit.

        Separate preparation API: no Source ACL, custody, capture permission or
        encrypted recovery is verified. The 100MB ceiling is an input-byte bound,
        not a total memory guarantee. No fallback to unbounded get is performed.
        Host configuration/root alias and descriptor confinement match get.
        """
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BOUNDED_ARTIFACT_BYTES:
            raise ValueError("exact bounded artifact limit required")
        if type(trust_boundary) is not TrustBoundary or type(content_location) is not str:
            raise ValueError("exact local artifact boundary/location required")
        match = re.fullmatch(r"([0-9a-f]{2})/([0-9a-f]{64})\.bin", content_location)
        if match is None or match[1] != match[2][:2]:
            raise ValueError("canonical local artifact location required")
        digest = match[2]
        with self._directory_fd((trust_boundary.value, match[1])) as directory:
            return self._read_bounded_at(directory, digest, max_bytes)

    @contextlib.contextmanager
    def _durable_directories(
        self, boundary: TrustBoundary, shard: str
    ) -> Iterator[tuple[list[tuple[int, str | None, int, tuple[int, int]]], int]]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        with contextlib.ExitStack() as descriptors:
            fd = os.open("/", flags)
            descriptors.callback(os.close, fd)
            info = os.fstat(fd)
            chain: list[tuple[int, str | None, int, tuple[int, int]]] = [
                (fd, None, fd, (info.st_dev, info.st_ino))
            ]
            root_index = len(self._root.parts) - 1
            for index, part in enumerate((*self._root.parts[1:], boundary.value, shard), 1):
                if part in (".", ".."):
                    raise ValueError("canonical durable root required")
                parent = fd
                try:
                    fd = os.open(part, flags, dir_fd=parent)
                except FileNotFoundError:
                    if index <= root_index:
                        raise
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, _DIR_MODE, dir_fd=parent)
                    fd = os.open(part, flags, dir_fd=parent)
                descriptors.callback(os.close, fd)
                info = os.fstat(fd)
                chain.append((parent, part, fd, (info.st_dev, info.st_ino)))
                # Pin/check root before creating any boundary/shard directory.
                if index == root_index:
                    self._assert_durable_directories(chain, root_index)
            self._assert_durable_directories(chain, root_index)
            yield chain, root_index

    def _assert_durable_directories(
        self, chain: list[tuple[int, str | None, int, tuple[int, int]]], root_index: int
    ) -> None:
        for index, (parent, name, fd, identity) in enumerate(chain):
            opened = os.fstat(fd)
            current = os.stat("/" if name is None else name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(current.st_mode)
                or (opened.st_dev, opened.st_ino) != identity
                or (current.st_dev, current.st_ino) != identity
                or (
                    index >= root_index
                    and (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != _DIR_MODE)
                )
            ):
                raise OSError("durable artifact directory changed or unsafe")

    def _durable_file(self, fd: int, digest: str, max_bytes: int) -> bytes:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != _FILE_MODE
            or not 0 <= before.st_size <= max_bytes
        ):
            raise OSError("bounded durable artifact file unsafe")
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        after = os.fstat(fd)
        if (
            len(raw) != before.st_size
            or after.st_size != before.st_size
            or after.st_uid != before.st_uid
            or after.st_mode != before.st_mode
            or after.st_nlink != 1
            or content_hash_of(raw) != digest
        ):
            raise OSError("durable artifact bytes changed")
        return raw

    def _assert_durable_file_path(self, directory: int, digest: str, fd: int) -> None:
        current = os.stat(digest + ".bin", dir_fd=directory, follow_symlinks=False)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != _FILE_MODE
            or current.st_nlink != 1
        ):
            raise OSError("durable artifact path changed")

    def put_durable(
        self,
        trust_boundary: TrustBoundary,
        content_hash: str,
        raw_bytes: bytes,
        *,
        max_bytes: int,
    ) -> str:
        """Optional concrete atomic write/reuse with local fsync acknowledgment.

        Entire verified file and shard/boundary/root/ancestor directories are
        fsynced, including exact reuse. The observed root inode is stability,
        not authority: the trusted host must independently pin configured root
        identity before/after this call. No Protocol or legacy put/get changes.
        No F_FULLFSYNC, power-loss, encrypted/off-device recovery or Source ACL
        guarantee. On any hold, a new unreferenced artifact may remain; caller
        must not acknowledge/commit its Source from a failed call. A failed
        sync poisons the capture acknowledgment until operator verification or
        replacement; later successful reuse is not proof the prior write survived
        a one-shot writeback error. No retry-until-success or automatic repair.
        Host contract: exclusive durable writer, no concurrent legacy put and
        trusted same-UID/ACL custody. SIGKILL between final link and temp unlink
        can leave a double-linked orphan; operator must verify both names refer
        to the same inode before removing the temp. This method holds, not repairs.
        """
        self._path_for(trust_boundary, content_hash)
        if (
            type(max_bytes) is not int
            or not 0 < max_bytes <= MAX_BOUNDED_ARTIFACT_BYTES
            or type(raw_bytes) is not bytes
            or len(raw_bytes) > max_bytes
            or content_hash_of(raw_bytes) != content_hash
        ):
            raise ValueError("exact bounded durable artifact bytes required")
        starting_root = self._root
        with self._durable_directories(trust_boundary, content_hash[:2]) as (chain, root_index):
            directory = chain[-1][2]
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            temporary = None
            try:
                fd = os.open(content_hash + ".bin", flags, dir_fd=directory)
            except FileNotFoundError:
                temporary = ".tmp-" + secrets.token_hex(16)
                fd = os.open(
                    temporary,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    _FILE_MODE,
                    dir_fd=directory,
                )
            try:
                if temporary is not None:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        os.fchmod(fd, _FILE_MODE)
                        stream.write(raw_bytes)
                    self._assert_durable_directories(chain, root_index)
                    if self._durable_file(fd, content_hash, max_bytes) != raw_bytes:
                        raise OSError("durable temporary artifact bytes differ")
                    # A complete buffered write is not a durable inode. Sync it
                    # before exposing the final name, then sync again afterward.
                    os.fsync(fd)
                    # Install the complete inode without replacing a target
                    # concurrently created after the first bounded lookup.
                    os.link(
                        temporary,
                        content_hash + ".bin",
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                        follow_symlinks=False,
                    )
                    os.unlink(temporary, dir_fd=directory)
                    temporary = None
                if self._durable_file(fd, content_hash, max_bytes) != raw_bytes:
                    raise OSError("durable artifact reuse bytes differ")
                self._assert_durable_file_path(directory, content_hash, fd)
                self._assert_durable_directories(chain, root_index)
                os.fsync(fd)
                for _, _, opened, _ in reversed(chain):
                    os.fsync(opened)
                # Last fsync can span legitimate host changes; no acknowledgment
                # until complete bytes and every anchored path are rechecked.
                self._assert_durable_directories(chain, root_index)
                self._assert_durable_file_path(directory, content_hash, fd)
                if self._durable_file(fd, content_hash, max_bytes) != raw_bytes:
                    raise OSError("durable artifact final bytes differ")
                self._assert_durable_directories(chain, root_index)
                self._assert_durable_file_path(directory, content_hash, fd)
            finally:
                os.close(fd)
                if temporary is not None:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(temporary, dir_fd=directory)
        if self._root != starting_root:
            raise OSError("durable artifact configured root changed")
        return self.location_for(content_hash)
