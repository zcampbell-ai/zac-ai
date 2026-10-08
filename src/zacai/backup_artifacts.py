"""D031A: encrypted raw-artifact backup, restore, and reconciliation.

Extends Lane B (D028) to cover the raw artifacts D030's `ArtifactStore`
writes, which D028's PostgreSQL-only backup never touches. Reuses D028's
exact three per-boundary `age` identities/recipients unchanged - no new
key system, no key generation, no key exposure. See DECISIONS.md D031A
for the full architecture review.

**This module never lifts the real-ingestion hard gate by itself.**
`LocalDirectoryBackupStore` is a synthetic-drill-only backend proving the
cryptographic/procedural pipeline - a second directory on the same Mac
Studio is not off-device durability. Only a real off-device backend and
a real drill (D031B, not built here) may lift the gate.

Backup is driven entirely by `Source` rows, never by scanning the
filesystem - an artifact with no `Source` reference (an "orphan", D030)
is never backed up, since it cannot be assigned a trust boundary for
encryption purposes.

**Backup only ever uses the public `age` recipient** - the private
identity is never required, read, or referenced during a backup run.
Only `restore_boundary_artifacts` takes a private identity, supplied
out-of-band by the caller (never embedded, never logged).

**Local manifest cache**: the four-part "already protected" check (see
`backup_boundary`) needs a durable baseline (expected ciphertext size and
hash) to compare each run against, without ever decrypting the
off-device manifest (which would require the private identity). This
module therefore keeps a small local, plaintext JSON cache of the same
shape as the manifest, at a caller-supplied path. This cache is never
uploaded and is never treated as the durable backup representation -
only the *encrypted* manifest object written to the `BackupObjectStore`
is. Losing the local cache is always safe: the next run simply finds no
prior baseline for each hash and re-verifies/re-uploads everything,
which is safe given content-addressed idempotency - it only costs extra
work, never correctness.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import select as _process_events
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import UUID, DateTime, Enum, Text, case, func, select, true
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql import ColumnElement, SQLColumnExpression

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import ArtifactBackupRun, Source, SourceClassificationElevation
from zacai.state_repository import (
    complete_artifact_backup_run,
    fail_artifact_backup_run,
    source_classification_elevation_strength,
    start_artifact_backup_run,
)

_DIR_MODE = 0o700
_FILE_MODE = 0o600
MANIFEST_VERSION = 1

# A naming convention for a dedicated, non-production restore-drill
# directory - not itself an enforcement mechanism (see
# `assert_safe_restore_target`, which is the actual fail-closed guard).
ARTIFACT_RESTORE_TEST_DIRNAME = "artifact_restore_test"


class BackupArtifactsError(RuntimeError):
    """Base class for D031A backup/restore errors."""


class EncryptionError(BackupArtifactsError):
    """Raised when the `age` encryption subprocess fails."""


class DecryptionError(BackupArtifactsError):
    """Raised when the `age` decryption subprocess fails - including a
    wrong identity, which `age` itself rejects outright via its own
    authenticated-encryption scheme."""


class ManifestError(BackupArtifactsError):
    """Raised when a manifest is malformed, wrong-version, or its
    declared boundary doesn't match the one requested."""


class LocalArtifactCorruptionError(BackupArtifactsError):
    """Raised when a local artifact's bytes no longer match
    `Source.content_hash` - never backed up in this state."""


class MissingLocalArtifactError(BackupArtifactsError):
    """Raised when a `Source`-referenced artifact cannot be read from the
    local `ArtifactStore` at all - a hard per-item failure, logged and
    reported, never allowed to silently abort the rest of the run."""


class RestoreIntegrityError(BackupArtifactsError):
    """Raised when a restored artifact fails ciphertext or plaintext hash
    verification."""


class RestoreTargetUnsafeError(BackupArtifactsError):
    """Raised when a restore target's safety cannot be verified at all -
    e.g. an `ArtifactStore` implementation with no inspectable `root`
    (D031B). Never silently skipped - restore refuses to proceed rather
    than assume safety."""


# --- age subprocess wrappers (public-key-only for backup) -------------------


def age_encrypt(plaintext: bytes, recipient: str) -> bytes:
    """Encrypts with only the public recipient - backup never needs a
    private identity (D031A)."""
    proc = subprocess.run(
        ["age", "-r", recipient], input=plaintext, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise EncryptionError(
            f"age encryption failed: {proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout


def age_decrypt(ciphertext: bytes, identity_path: Path) -> bytes:
    """Decrypts with a private identity, supplied out-of-band by the
    caller (never embedded, never logged). Fails outright for a
    non-matching identity - `age`'s own AEAD scheme, not custom logic."""
    proc = subprocess.run(
        ["age", "-d", "-i", str(identity_path)], input=ciphertext, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise DecryptionError(
            f"age decryption failed: {proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout


# --- backup object store -----------------------------------------------------


@dataclass(frozen=True)
class ObjectStat:
    size: int


class BackupObjectStore(Protocol):
    """A minimal backup-object interface, mirroring `ArtifactStore`'s
    shape. Never coupled to one vendor - `LocalDirectoryBackupStore` is
    the only v1 implementation, synthetic-drill-only; a real off-device
    backend (D031B) satisfies the same protocol."""

    def exists(self, key: str) -> bool: ...
    def stat(self, key: str) -> ObjectStat: ...
    def get_object(self, key: str) -> bytes: ...
    def put_object(self, key: str, data: bytes) -> None: ...


class LocalDirectoryBackupStore:
    """v1 `BackupObjectStore` (D031A): a second local directory - used
    only to prove the cryptographic/procedural pipeline. **Never
    off-device** - never claimed to satisfy the real-ingestion gate."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(self._root, _DIR_MODE)

    def _path(self, key: str) -> Path:
        return self._root / key

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def stat(self, key: str) -> ObjectStat:
        return ObjectStat(size=self._path(key).stat().st_size)

    def get_object(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def get_object_bounded(self, key: str, *, max_bytes: int) -> bytes:
        """Read one confined object under an explicit host ciphertext bound.

        No Source permission, plaintext-size policy, hash proof or recovery
        acknowledgment. No fallback to the unbounded protocol method. The
        descriptor walk requires directory read permission on root ancestors,
        including resolved host root aliases; search-only ancestors may hold.
        """
        result = None
        try:
            if (
                type(max_bytes) is not int
                or not 0 < max_bytes < sys.maxsize
                or type(key) is not str
                or not key
                or "\x00" in key
                or "\\" in key
                or key.startswith("/")
                or any(part in ("", ".", "..") for part in key.split("/"))
            ):
                raise ValueError("bounded object contract required")
            parts = key.split("/")
            # Host root aliases resolve once here; object descendants never do.
            root = self._root.resolve(strict=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            with contextlib.ExitStack() as descriptors:
                directory = os.open("/", flags)
                descriptors.callback(os.close, directory)
                for part in (*root.parts[1:], *parts[:-1]):
                    directory = os.open(part, flags, dir_fd=directory)
                    descriptors.callback(os.close, directory)
                fd = os.open(
                    parts[-1],
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                descriptors.callback(os.close, fd)
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or not 0 <= before.st_size <= max_bytes
                ):
                    raise ValueError("bounded object metadata required")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(before.st_size + 1)
                after = os.fstat(fd)
                if (
                    len(raw) != before.st_size
                    or after.st_size != before.st_size
                    or not stat.S_ISREG(after.st_mode)
                    or after.st_nlink != 1
                    or after.st_mtime_ns != before.st_mtime_ns
                    or after.st_ctime_ns != before.st_ctime_ns
                ):
                    raise ValueError("bounded object changed")
                result = raw
        except Exception:  # noqa: BLE001,S110 - fixed message outside exception context
            pass
        if result is None:
            raise BackupArtifactsError("bounded local backup object unavailable")
        return result

    def put_object(self, key: str, data: bytes) -> None:
        target = self._path(key)
        target.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(target.parent, _DIR_MODE)
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as tmp_file:
                tmp_file.write(data)
            os.chmod(tmp_name, _FILE_MODE)
            os.replace(tmp_name, target)  # atomic rename on the same filesystem
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise


def backup_object_key_for(trust_boundary: TrustBoundary, content_hash: str) -> str:
    """Deterministic, content-addressed backup object key - the same
    `(trust_boundary, content_hash)` always resolves to the identical
    key, mirroring `ArtifactStore`'s own addressing scheme."""
    return f"{trust_boundary.value}/{content_hash[:2]}/{content_hash}.age"


def manifest_key_for(trust_boundary: TrustBoundary) -> str:
    return f"{trust_boundary.value}/manifest.age"


# --- manifest -----------------------------------------------------------


@dataclass(frozen=True)
class ManifestEntry:
    content_hash: str
    content_location: str
    backup_object_key: str
    size_bytes: int
    ciphertext_sha256: str
    backed_up_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "content_hash": self.content_hash,
            "content_location": self.content_location,
            "backup_object_key": self.backup_object_key,
            "size_bytes": self.size_bytes,
            "ciphertext_sha256": self.ciphertext_sha256,
            "backed_up_at": self.backed_up_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> ManifestEntry:
        if not isinstance(data, dict):
            raise ManifestError("malformed manifest entry: not an object")
        try:
            return cls(
                content_hash=str(data["content_hash"]),
                content_location=str(data["content_location"]),
                backup_object_key=str(data["backup_object_key"]),
                size_bytes=int(data["size_bytes"]),
                ciphertext_sha256=str(data["ciphertext_sha256"]),
                backed_up_at=str(data["backed_up_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"malformed manifest entry: {exc}") from exc


@dataclass
class Manifest:
    boundary: str
    generated_at: str
    entries: dict[str, ManifestEntry] = field(default_factory=dict)
    manifest_version: int = MANIFEST_VERSION

    def to_json_bytes(self) -> bytes:
        payload = {
            "manifest_version": self.manifest_version,
            "boundary": self.boundary,
            "generated_at": self.generated_at,
            "entries": [entry.to_dict() for entry in self.entries.values()],
        }
        return json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> Manifest:
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ManifestError("manifest root must be an object")
        try:
            version = int(payload["manifest_version"])
            boundary = str(payload["boundary"])
            generated_at = str(payload["generated_at"])
            raw_entries = payload["entries"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"manifest is missing required fields: {exc}") from exc
        if version != MANIFEST_VERSION:
            raise ManifestError(
                f"unsupported manifest_version {version} (expected {MANIFEST_VERSION})"
            )
        if not isinstance(raw_entries, list):
            raise ManifestError("manifest 'entries' must be a list")
        entries = {}
        for raw_entry in raw_entries:
            entry = ManifestEntry.from_dict(raw_entry)
            entries[entry.content_hash] = entry
        return cls(
            boundary=boundary, generated_at=generated_at, entries=entries, manifest_version=version
        )

    @classmethod
    def empty(cls, trust_boundary: TrustBoundary) -> Manifest:
        return cls(boundary=trust_boundary.value, generated_at=datetime.now(UTC).isoformat())


def _load_local_manifest_cache(path: Path, trust_boundary: TrustBoundary) -> Manifest:
    """Local-only, plaintext, never uploaded, never the durable backup
    representation (see module docstring). A missing or corrupted cache
    safely degrades to "nothing known yet" - every artifact is then
    re-verified/re-uploaded this run, which is always safe."""
    if not path.exists():
        return Manifest.empty(trust_boundary)
    try:
        return Manifest.from_json_bytes(path.read_bytes())
    except ManifestError:
        return Manifest.empty(trust_boundary)


def _save_local_manifest_cache(path: Path, manifest: Manifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    os.chmod(path.parent, _DIR_MODE)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as tmp_file:
            tmp_file.write(manifest.to_json_bytes())
        os.chmod(tmp_name, _FILE_MODE)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


# --- backup algorithm ---------------------------------------------------


@dataclass(frozen=True)
class BackupItemFailure:
    content_hash: str
    error: str


@dataclass(frozen=True)
class BackupSummary:
    trust_boundary: TrustBoundary
    checked: int
    already_protected: int
    backed_up: int
    repaired: int
    failures: list[BackupItemFailure]

    @property
    def failed(self) -> int:
        return len(self.failures)


def _source_rows_for_boundary(
    session: Session, *, trust_boundary: TrustBoundary
) -> list[tuple[str, str]]:
    rows = session.execute(
        select(Source.content_hash, Source.content_location)
        .where(Source.trust_boundary == trust_boundary, Source.content_hash.is_not(None))
        .distinct()
    ).all()
    return [(str(content_hash), str(content_location)) for content_hash, content_location in rows]


def source_hashes_for_boundary(session: Session, *, trust_boundary: TrustBoundary) -> set[str]:
    """The set of `Source.content_hash` values currently committed for
    this boundary - the authoritative "what should exist" list used both
    by backup (indirectly, via `_source_rows_for_boundary`) and by
    restore reconciliation."""
    return {
        content_hash
        for content_hash, _ in _source_rows_for_boundary(session, trust_boundary=trust_boundary)
    }


def _verify_or_repair(
    prior_entry: ManifestEntry | None,
    *,
    trust_boundary: TrustBoundary,
    content_hash: str,
    content_location: str,
    key: str,
    artifact_store: ArtifactStore,
    backup_store: BackupObjectStore,
    recipient: str,
) -> tuple[ManifestEntry, str]:
    """The four-part "already protected" check (D031A), never decrypting
    during routine backup: (A) a prior manifest-cache entry exists, (B)
    the backup object exists, (C) its size matches, (D) its ciphertext
    SHA-256 matches. If any check fails, the artifact is (re-)backed up
    from the verified local plaintext."""
    if prior_entry is not None and backup_store.exists(key):
        try:
            stat = backup_store.stat(key)
        except OSError:
            stat = None
        if stat is not None and stat.size == prior_entry.size_bytes:
            ciphertext = backup_store.get_object(key)
            if (
                len(ciphertext) == prior_entry.size_bytes
                and hashlib.sha256(ciphertext).hexdigest() == prior_entry.ciphertext_sha256
            ):
                return prior_entry, "already_protected"

    # Not protected (no prior record, object missing, size mismatch, or
    # ciphertext-hash mismatch) - repair from verified local plaintext.
    try:
        local_bytes = artifact_store.get(trust_boundary, content_location)
    except OSError as exc:
        raise MissingLocalArtifactError(
            f"local artifact at {content_location!r} could not be read for {content_hash!r}: {exc}"
        ) from exc
    if content_hash_of(local_bytes) != content_hash:
        raise LocalArtifactCorruptionError(
            f"local artifact at {content_location!r} does not hash to {content_hash!r} - "
            "refusing to (re)create a backup object from corrupted bytes"
        )

    ciphertext = age_encrypt(local_bytes, recipient)
    backup_store.put_object(key, ciphertext)
    confirmed = backup_store.get_object(key)
    confirmed_hash = hashlib.sha256(confirmed).hexdigest()
    if (
        len(confirmed) != len(ciphertext)
        or confirmed_hash != hashlib.sha256(ciphertext).hexdigest()
    ):
        raise BackupArtifactsError(f"post-upload verification failed for {content_hash}")

    entry = ManifestEntry(
        content_hash=content_hash,
        content_location=content_location,
        backup_object_key=key,
        size_bytes=len(confirmed),
        ciphertext_sha256=confirmed_hash,
        backed_up_at=datetime.now(UTC).isoformat(),
    )
    outcome = "repaired" if prior_entry is not None else "backed_up"
    return entry, outcome


def backup_boundary(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    artifact_store: ArtifactStore,
    backup_store: BackupObjectStore,
    recipient: str,
    local_manifest_cache_path: Path,
    personal_plan: PersonalFullOriginalBackupPlan | None = None,
) -> BackupSummary:
    """The D031A incremental/idempotent backup algorithm: driven entirely
    by `Source` rows, never by scanning the filesystem. Orphan artifacts
    (no `Source` reference) are never backed up - they cannot be
    assigned a trust boundary for encryption without guessing."""
    if personal_plan is not None:
        return _backup_personal_full_original(
            session,
            trust_boundary=trust_boundary,
            artifact_store=artifact_store,
            backup_store=backup_store,
            recipient=recipient,
            local_manifest_cache_path=local_manifest_cache_path,
            plan=personal_plan,
        )
    previous = _load_local_manifest_cache(local_manifest_cache_path, trust_boundary)

    rows = _source_rows_for_boundary(session, trust_boundary=trust_boundary)
    new_entries: dict[str, ManifestEntry] = {}
    already_protected = backed_up = repaired = 0
    failures: list[BackupItemFailure] = []

    for content_hash, content_location in rows:
        key = backup_object_key_for(trust_boundary, content_hash)
        try:
            entry, outcome = _verify_or_repair(
                previous.entries.get(content_hash),
                trust_boundary=trust_boundary,
                content_hash=content_hash,
                content_location=content_location,
                key=key,
                artifact_store=artifact_store,
                backup_store=backup_store,
                recipient=recipient,
            )
        except BackupArtifactsError as exc:
            failures.append(BackupItemFailure(content_hash=content_hash, error=str(exc)))
            continue

        new_entries[content_hash] = entry
        if outcome == "already_protected":
            already_protected += 1
        elif outcome == "backed_up":
            backed_up += 1
        else:
            repaired += 1

    new_manifest = Manifest(
        boundary=trust_boundary.value,
        generated_at=datetime.now(UTC).isoformat(),
        entries=new_entries,
    )
    _save_local_manifest_cache(local_manifest_cache_path, new_manifest)
    encrypted_manifest = age_encrypt(new_manifest.to_json_bytes(), recipient)
    backup_store.put_object(manifest_key_for(trust_boundary), encrypted_manifest)

    return BackupSummary(
        trust_boundary=trust_boundary,
        checked=len(rows),
        already_protected=already_protected,
        backed_up=backed_up,
        repaired=repaired,
        failures=failures,
    )


def run_artifact_backup(
    session_factory: sessionmaker[Session],
    *,
    trust_boundary: TrustBoundary,
    artifact_store: ArtifactStore,
    backup_store: BackupObjectStore,
    recipient: str,
    local_manifest_cache_path: Path,
    personal_plan: PersonalFullOriginalBackupPlan | None = None,
) -> ArtifactBackupRun:
    """Wraps `backup_boundary` with the `artifact_backup_run` audit
    lifecycle (D031A) - `STARTED` committed immediately, a fresh
    transaction for the terminal `SUCCEEDED`/`FAILED` update, mirroring
    D030's `ingest_fireflies_batch` three-transaction shape. The run is
    marked `FAILED` (not `SUCCEEDED`) if any artifact failed, even though
    the manifest still durably protects whatever *did* succeed - success
    requires zero unresolved errors."""
    with session_factory() as run_session:
        run = start_artifact_backup_run(run_session, trust_boundary=trust_boundary)
        run_id = run.id
        run_session.commit()

    try:
        with session_factory() as data_session:
            options = {} if personal_plan is None else {"personal_plan": personal_plan}
            summary = backup_boundary(
                data_session,
                trust_boundary=trust_boundary,
                artifact_store=artifact_store,
                backup_store=backup_store,
                recipient=recipient,
                local_manifest_cache_path=local_manifest_cache_path,
                **options,
            )
    except Exception as exc:
        with session_factory() as fail_session:
            fail_artifact_backup_run(fail_session, run_id=run_id, error=str(exc))
            fail_session.commit()
        raise

    with session_factory() as complete_session:
        if summary.failures:
            error_text = "; ".join(f"{f.content_hash}: {f.error}" for f in summary.failures)
            fail_artifact_backup_run(complete_session, run_id=run_id, error=error_text)
        else:
            complete_artifact_backup_run(
                complete_session,
                run_id=run_id,
                artifacts_checked=summary.checked,
                artifacts_backed_up=summary.backed_up,
                artifacts_already_protected=summary.already_protected,
                artifacts_repaired=summary.repaired,
                artifacts_failed=summary.failed,
            )
        complete_session.commit()
        finished_run = complete_session.get(ArtifactBackupRun, run_id)
        if finished_run is None:
            raise RuntimeError(f"artifact_backup_run {run_id} vanished after completion")
        complete_session.expunge(finished_run)
        return finished_run


# --- restore + reconciliation --------------------------------------------


def assert_safe_restore_target(restore_root: Path, live_artifact_root: Path) -> None:
    """Fail closed unless the restore target is clearly distinct from
    the live production `ArtifactStore` root - adapted for a filesystem
    target from D027/D028's fixed-target guard pattern (a database
    connection string there; a directory path here)."""
    resolved_restore = restore_root.resolve()
    resolved_live = live_artifact_root.resolve()
    if resolved_restore == resolved_live:
        raise RuntimeError(
            f"refusing to restore into the live artifact store root {resolved_live} - "
            "restore must target a dedicated, non-production location (D031A)"
        )


def _assert_restore_target_is_safe(restore_target: ArtifactStore, live_artifact_root: Path) -> None:
    """The internal, unconditional call site for `assert_safe_restore_
    target` (D031B) - `restore_boundary_artifacts` calls this itself,
    before any decryption or restore work, so the safety property is
    structural rather than dependent on a caller remembering to invoke
    it separately. Fails closed (never silently skips the check) if
    `restore_target` doesn't expose an inspectable filesystem root at
    all - a backend this function cannot verify is treated as unsafe,
    not assumed safe."""
    root = getattr(restore_target, "root", None)
    if not isinstance(root, Path):
        raise RestoreTargetUnsafeError(
            "restore_target does not expose an inspectable 'root' path - "
            "cannot verify it is distinct from the live artifact store; refusing to proceed"
        )
    assert_safe_restore_target(root, live_artifact_root)


@dataclass(frozen=True)
class RestoreFailure:
    content_hash: str
    reason: str


@dataclass(frozen=True)
class ReconciliationResult:
    verified: frozenset[str]
    missing: frozenset[str]
    unexpected: frozenset[str]


@dataclass(frozen=True)
class RestoreOutcome:
    manifest: Manifest
    reconciliation: ReconciliationResult
    failures: list[RestoreFailure]

    @property
    def successful(self) -> bool:
        """A restore is successful only if every expected
        Source-referenced artifact was restored and hash-verified -
        `missing` is empty and no verification failure occurred. A
        non-empty `unexpected` set is always surfaced in the result but
        does not by itself flip this to False - it is a regression
        signal to investigate, not automatically a hard failure."""
        return not self.reconciliation.missing and not self.failures


def restore_boundary_artifacts(
    *,
    trust_boundary: TrustBoundary,
    backup_store: BackupObjectStore,
    identity_path: Path,
    restore_target: ArtifactStore,
    live_artifact_root: Path,
    expected_source_hashes: set[str],
) -> RestoreOutcome:
    """Restores one boundary's artifacts from `backup_store` into
    `restore_target`, using only `identity_path` (the matching private
    `age` identity, supplied out-of-band). Two-layer wrong-boundary
    rejection: (1) `age -d` fails outright for a non-matching identity;
    (2) the decrypted manifest's own `boundary` field is independently
    checked against `trust_boundary`. Never silently accepts a partial
    restore, a hash mismatch, or a missing artifact - see
    `RestoreOutcome.successful`.

    **Fails closed on an unsafe restore target before any other work**
    (D031B): `live_artifact_root` is required, not optional, and is
    checked internally via `_assert_restore_target_is_safe` - this is
    what makes the restore-target protection structural rather than
    dependent on a caller remembering to call `assert_safe_restore_
    target` separately."""
    _assert_restore_target_is_safe(restore_target, live_artifact_root)

    encrypted_manifest = backup_store.get_object(manifest_key_for(trust_boundary))
    manifest_bytes = age_decrypt(
        encrypted_manifest, identity_path
    )  # raises DecryptionError on wrong identity
    manifest = Manifest.from_json_bytes(manifest_bytes)
    if manifest.boundary != trust_boundary.value:
        raise ManifestError(
            f"manifest declares boundary {manifest.boundary!r}, expected {trust_boundary.value!r} - "
            "refusing to restore (D031A independent boundary check)"
        )

    restored_hashes: set[str] = set()
    failures: list[RestoreFailure] = []
    for content_hash, entry in manifest.entries.items():
        try:
            ciphertext = backup_store.get_object(entry.backup_object_key)
            if hashlib.sha256(ciphertext).hexdigest() != entry.ciphertext_sha256:
                raise RestoreIntegrityError(f"ciphertext hash mismatch restoring {content_hash}")
            plaintext = age_decrypt(ciphertext, identity_path)
            if content_hash_of(plaintext) != content_hash:
                raise RestoreIntegrityError(
                    f"restored artifact {content_hash} failed plaintext hash verification"
                )
            restore_target.put(trust_boundary, content_hash, plaintext)
            restored_hashes.add(content_hash)
        except BackupArtifactsError as exc:
            failures.append(RestoreFailure(content_hash=content_hash, reason=str(exc)))

    verified = restored_hashes & expected_source_hashes
    missing = expected_source_hashes - restored_hashes
    unexpected = restored_hashes - expected_source_hashes

    return RestoreOutcome(
        manifest=manifest,
        reconciliation=ReconciliationResult(
            verified=frozenset(verified),
            missing=frozenset(missing),
            unexpected=frozenset(unexpected),
        ),
        failures=failures,
    )


# Separate explicit resource-bounded variants; legacy helpers remain unchanged.
def _validate_bounded_age_input(
    raw: bytes,
    max_input_bytes: int,
    max_output_bytes: int,
    max_stderr_bytes: int,
    timeout_seconds: float,
) -> None:
    if (
        type(raw) is not bytes
        or any(
            type(n) is not int or n <= 0
            for n in (max_input_bytes, max_output_bytes, max_stderr_bytes)
        )
        or len(raw) > max_input_bytes
        or type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("bounded age resource contract required")


def _darwin_exited_group_is_only_leader(pid: int) -> bool:
    """Prove the unreaped, exit-observed leader is the group's only member.

    Darwin excludes zombies from killpg's signal candidates and returns EPERM
    for an otherwise empty zombie group. A fixed two-slot libproc inventory
    distinguishes that case from a real permission failure with descendants.
    The caller must still own the unreaped leader and have observed its exit.
    """
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_pids = library.proc_listpids
        list_pids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        list_pids.restype = ctypes.c_int
        members = (ctypes.c_int * 2)()
        ctypes.set_errno(0)
        count = list_pids(2, pid, members, ctypes.sizeof(members))
        return (
            ctypes.get_errno() == 0
            and count == ctypes.sizeof(ctypes.c_int)
            and members[0] == pid
            and members[1] == 0
        )
    except Exception:  # noqa: BLE001 - unavailable host inventory fails closed
        return False


def _run_bounded_age(
    argv: list[str],
    raw: bytes,
    *,
    max_output_bytes: int,
    max_stderr_bytes: int,
    timeout_seconds: float,
) -> bytes:
    started = time.monotonic()
    deadline = started + timeout_seconds
    if not math.isfinite(deadline):
        raise ValueError("finite age deadline required")
    process: subprocess.Popen[bytes] | None = None
    selection = selectors.DefaultSelector()
    exit_watch: _process_events.kqueue | None = None
    output = bytearray()
    stderr_size = 0
    sent = 0
    view = memoryview(raw)
    completed = False
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            shell=False,
            start_new_session=True,
        )
        # Register before writing stdin: age waits for input, so the native
        # child's normal completion cannot outrun observer registration.
        if hasattr(_process_events, "kqueue"):
            exit_watch = _process_events.kqueue()
            exit_watch.control(
                [
                    _process_events.kevent(
                        process.pid,
                        filter=_process_events.KQ_FILTER_PROC,
                        flags=_process_events.KQ_EV_ADD | _process_events.KQ_EV_ONESHOT,
                        fflags=_process_events.KQ_NOTE_EXIT,
                    )
                ],
                0,
                0,
            )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise ValueError("bounded age pipes required")
        for name, stream in (
            ("input", process.stdin),
            ("output", process.stdout),
            ("error", process.stderr),
        ):
            os.set_blocking(stream.fileno(), False)
            if name == "input" and not raw:
                stream.close()
            else:
                selection.register(
                    stream.fileno(),
                    selectors.EVENT_WRITE if name == "input" else selectors.EVENT_READ,
                    name,
                )
        while selection.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("bounded age deadline elapsed")
            for key, _ in selection.select(remaining):
                if time.monotonic() >= deadline:
                    raise ValueError("bounded age deadline elapsed")
                if key.data == "input":
                    try:
                        count = os.write(key.fd, view[sent : sent + 65_536])
                    except BlockingIOError:
                        continue
                    if count <= 0:
                        raise ValueError("bounded age input incomplete")
                    sent += count
                    if sent == len(raw):
                        selection.unregister(key.fd)
                        process.stdin.close()
                    continue
                remaining_bytes = (
                    max_output_bytes - len(output)
                    if key.data == "output"
                    else max_stderr_bytes - stderr_size
                )
                try:
                    chunk = os.read(key.fd, min(65_536, remaining_bytes + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selection.unregister(key.fd)
                    (process.stdout if key.data == "output" else process.stderr).close()
                    continue
                if len(chunk) > remaining_bytes:
                    raise ValueError("bounded age output exceeded")
                if key.data == "output":
                    output.extend(chunk)
                else:
                    stderr_size += len(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or sent != len(raw):
            raise ValueError("bounded age completion unavailable")
        # Observe exit without reaping: the live/zombie PID pins our group.
        # Darwin Python has kqueue but no os.waitid. Both observers leave reaping
        # to cleanup, after the last signal to the owned process group.
        if exit_watch is not None:
            events = exit_watch.control(None, 1, remaining)
            if (
                len(events) != 1
                or events[0].ident != process.pid
                or events[0].filter != _process_events.KQ_FILTER_PROC
                or events[0].flags & _process_events.KQ_EV_ERROR
                or not events[0].fflags & _process_events.KQ_NOTE_EXIT
            ):
                raise ValueError("bounded age exit unavailable")
        elif hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("bounded age deadline elapsed")
                time.sleep(min(0.005, remaining))
        else:
            raise ValueError("non-reaping age exit observation unavailable")
        if time.monotonic() >= deadline:
            raise ValueError("bounded age deadline elapsed")
        result = bytes(output)
        completed = True
        return result
    finally:
        cleanup_failed = False
        try:
            selection.close()
        except OSError:
            cleanup_failed = True
        if exit_watch is not None:
            try:
                exit_watch.close()
            except OSError:
                cleanup_failed = True
        if process is not None:
            # No poll/wait has reaped the direct child: its live/zombie PID pins
            # the owned group while we kill descendants. Trusted children must
            # not escape the group. Only now may we reap the direct child.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                if not (
                    completed
                    and exit_watch is not None
                    and sys.platform == "darwin"
                    and exc.errno == errno.EPERM
                    and _darwin_exited_group_is_only_leader(process.pid)
                ):
                    cleanup_failed = True
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        cleanup_failed = True
            try:
                status = process.wait(timeout=5)
                if completed and (status != 0 or time.monotonic() >= deadline):
                    cleanup_failed = True
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
        try:
            view.release()
        except Exception:  # noqa: BLE001 - cleanup must not skip child reaping
            cleanup_failed = True
        if cleanup_failed and completed:
            raise ValueError("bounded age cleanup unavailable")


def age_encrypt_bounded(
    plaintext: bytes,
    recipient: str,
    *,
    max_input_bytes: int,
    max_output_bytes: int,
    max_stderr_bytes: int,
    timeout_seconds: float,
) -> bytes:
    """Resource-bounded age IO only; caller bounds are not permission/profile.

    No inferred cipher overhead, Source/custody proof or legacy-cap change.
    Process start/OS cleanup cannot promise hard realtime or total RAM bounds.
    Hosts must disable traceback-local capture and arbitrary-child reapers
    (SIGCHLD handlers or waitpid(-1)). Trusted age/plugins must not escape the
    group, change credentials, or leave background descendants. This is cleanup,
    not process containment. No stderr/key diagnostics escape.
    """
    result = None
    try:
        _validate_bounded_age_input(
            plaintext, max_input_bytes, max_output_bytes, max_stderr_bytes, timeout_seconds
        )
        if (
            type(recipient) is not str
            or re.fullmatch(r"age1[02-9ac-hj-np-z]{58}", recipient) is None
        ):
            raise ValueError("host age recipient required")
        result = _run_bounded_age(
            ["age", "-r", recipient],
            plaintext,
            max_output_bytes=max_output_bytes,
            max_stderr_bytes=max_stderr_bytes,
            timeout_seconds=timeout_seconds,
        )
    except Exception:  # noqa: BLE001,S110 - fixed public message outside exception context
        pass
    if result is None:
        raise EncryptionError("bounded age encryption unavailable")
    return result


def age_decrypt_bounded(
    ciphertext: bytes,
    identity_path: Path,
    *,
    max_input_bytes: int,
    max_output_bytes: int,
    max_stderr_bytes: int,
    timeout_seconds: float,
) -> bytes:
    """Same bounded IO contract; identity configuration is host-trusted.

    This function does not inspect identity contents. An age plugin identity can
    execute host code; process-group isolation is not a sandbox or an allowlist.
    Hosts must validate their declared native identity profile independently.
    """
    result = None
    try:
        _validate_bounded_age_input(
            ciphertext, max_input_bytes, max_output_bytes, max_stderr_bytes, timeout_seconds
        )
        if not isinstance(identity_path, Path) or "\x00" in str(identity_path):
            raise ValueError("host age identity required")
        result = _run_bounded_age(
            ["age", "-d", "-i", str(identity_path)],
            ciphertext,
            max_output_bytes=max_output_bytes,
            max_stderr_bytes=max_stderr_bytes,
            timeout_seconds=timeout_seconds,
        )
    except Exception:  # noqa: BLE001,S110 - fixed public message outside exception context
        pass
    if result is None:
        raise DecryptionError("bounded age decryption unavailable")
    return result


# Closed, dormant engineering profile. It never establishes owner/key permission.
_PERSONAL_PLAIN_LIMIT = 100_000_000
_PERSONAL_CIPHER_LIMIT = 101_000_000
_PERSONAL_ARTIFACT_LIMIT = 4096
_PERSONAL_AGGREGATE_LIMIT = 512_000_000
_PERSONAL_METADATA_LIMIT = 8_000_000


@dataclass(frozen=True)
class PersonalFullOriginalBackupPlan:
    """Complete canonical PERSONAL selection, not authority or a receipt.

    Closed profiles hold above4096 Source rows as well as4096 unique artifacts.
    Explicit v2 admits HR for encrypted PERSONAL custody, never model processing.
    Host owner/access and reviewed recipient custody remain caller prerequisites.
    """

    engine: Engine = field(repr=False, compare=False)
    rows: bytes = field(repr=False)
    artifacts: tuple[tuple[str, str], ...] = field(repr=False)
    profile: str = "personal-full-original-backup-v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.engine, Engine)
            or type(self.rows) is not bytes
            or not 0 < len(self.rows) <= _PERSONAL_METADATA_LIMIT
            or type(self.profile) is not str
            or self.profile
            not in (
                "personal-full-original-backup-v1",
                "personal-encrypted-custody-backup-v2",
            )
            or type(self.artifacts) is not tuple
            or not 0 < len(self.artifacts) <= _PERSONAL_ARTIFACT_LIMIT
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", item[0]) is None
                or type(item[1]) is not str
                or item[1] != f"{item[0][:2]}/{item[0]}.bin"
                for item in self.artifacts
            )
            or tuple(sorted(set(self.artifacts))) != self.artifacts
        ):
            raise ValueError("exact closed PERSONAL backup plan required")


def _personal_backup_rows(
    session: Session, *, profile: str = "personal-full-original-backup-v1"
) -> tuple[bytes, tuple[tuple[str, str], ...]]:
    if type(profile) is not str or profile not in (
        "personal-full-original-backup-v1",
        "personal-encrypted-custody-backup-v2",
    ):
        raise ValueError("closed encrypted PERSONAL backup profile required")
    admitted_labels: tuple[DataClassification, ...] = (
        DataClassification.PUBLIC,
        DataClassification.INTERNAL,
        DataClassification.CONFIDENTIAL,
    )
    if profile == "personal-encrypted-custody-backup-v2":
        admitted_labels += (DataClassification.HIGHLY_RESTRICTED,)
    if not isinstance(session, Session) or session.new or session.dirty or session.deleted:
        raise ValueError("clean actual canonical Session required")
    _assert_personal_backup_backend(session)
    if tuple(Source.__table__.columns.keys()) != (
        "id",
        "trust_boundary",
        "data_classification",
        "system",
        "external_ref",
        "captured_at",
        "excerpt",
        "content_hash",
        "content_location",
        "supersedes_source_id",
    ):
        raise ValueError("reviewed bounded canonical Source columns required")
    expected_types = (UUID, Enum, Enum, Enum, Text, DateTime, Text, Text, Text, UUID)
    if tuple(type(column.type) for column in Source.__table__.columns) != expected_types:
        raise ValueError("reviewed bounded canonical Source types required")
    date_type = Source.__table__.c.captured_at.type
    if not isinstance(date_type, DateTime) or date_type.timezone is not True:
        raise ValueError("reviewed canonical UTC Source date required")
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(
            source_classification_elevation_strength().desc(),
            SourceClassificationElevation.elevated_at.desc(),
        )
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    labels = (
        DataClassification.PUBLIC,
        DataClassification.INTERNAL,
        DataClassification.CONFIDENTIAL,
        DataClassification.HIGHLY_RESTRICTED,
    )
    if set(labels) != set(DataClassification):
        raise ValueError("reviewed classification policy required")

    def strength(expression: SQLColumnExpression[DataClassification]) -> ColumnElement[int]:
        return case(*((expression == label, rank) for rank, label in enumerate(labels)), else_=4)

    observed_elevation = func.coalesce(latest, Source.data_classification)
    effective = case(
        (strength(observed_elevation) > strength(Source.data_classification), observed_elevation),
        else_=Source.data_classification,
    )
    # One statement: the server computes complete-boundary text widths and
    # refuses ALL result rows before materializing any unbounded text in Python.
    # Never select a permitted subset or fetch text before checking the cap.
    candidates = (
        select(Source.external_ref, Source.excerpt, Source.content_hash, Source.content_location)
        .where(Source.trust_boundary == TrustBoundary.PERSONAL)
        .limit(_PERSONAL_ARTIFACT_LIMIT + 1)
        .cte("personal_backup_candidates")
    )
    width = sum(
        func.octet_length(func.coalesce(column, ""))
        for column in (
            candidates.c.external_ref,
            candidates.c.excerpt,
            candidates.c.content_hash,
            candidates.c.content_location,
        )
    )
    sizes = (
        select(
            func.count().label("row_count"),
            func.coalesce(func.sum(width), 0).label("text_bytes"),
            func.coalesce(func.max(width), 0).label("max_text_bytes"),
        )
        .select_from(candidates)
        .cte("personal_backup_sizes")
    )
    rows = list(
        session.execute(
            select(
                *Source.__table__.columns,
                effective.label("effective"),
            )
            .select_from(Source)
            .join(sizes, true())
            .where(
                Source.trust_boundary == TrustBoundary.PERSONAL,
                sizes.c.row_count > 0,
                sizes.c.row_count <= _PERSONAL_ARTIFACT_LIMIT,
                sizes.c.text_bytes <= _PERSONAL_METADATA_LIMIT,
                sizes.c.max_text_bytes <= _PERSONAL_METADATA_LIMIT,
            )
            .order_by(Source.id)
            .limit(_PERSONAL_ARTIFACT_LIMIT + 1)
        ).mappings()
    )
    if not rows or len(rows) > _PERSONAL_ARTIFACT_LIMIT:
        raise ValueError("bounded complete PERSONAL Source selection required")
    items: dict[str, str] = {}
    for row in rows:
        digest, location = row["content_hash"], row["content_location"]
        if (
            type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(location) is not str
            or location != f"{digest[:2]}/{digest}.bin"
            or row["effective"] not in admitted_labels
            or row["data_classification"] not in admitted_labels
            or (digest in items and items[digest] != location)
        ):
            raise ValueError("closed PERSONAL artifact and classification profile required")
        items[digest] = location
    # Exact complete scalar metadata, including effective classification. No text
    # is exposed in repr or uploaded by the plan; no cached permission is inferred.
    raw = json.dumps(
        [dict(row) for row in rows], sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    if len(raw) > _PERSONAL_METADATA_LIMIT:
        raise ValueError("PERSONAL metadata plan capacity exceeded")
    return raw, tuple(sorted(items.items()))


def prepare_personal_full_original_backup_plan(session: Session) -> PersonalFullOriginalBackupPlan:
    """Snapshot exact whole boundary rows; never authorizes processing or backup."""
    result = None
    try:
        rows, artifacts = _personal_backup_rows(session)
        engine = session.get_bind()
        if not isinstance(engine, Engine):
            raise TypeError("actual canonical Engine required")
        result = PersonalFullOriginalBackupPlan(engine, rows, artifacts)
    except Exception:  # noqa: BLE001,S110 - fixed private-safe boundary
        pass
    if result is None:
        raise BackupArtifactsError("PERSONAL full-original backup plan unavailable")
    return result


def prepare_personal_encrypted_custody_backup_plan(
    session: Session,
) -> PersonalFullOriginalBackupPlan:
    """Explicit v2 HR-capable encrypted custody; no access or processing grant.

    This closed profile changes backup classification admission only. It never
    changes Source labels, model policy, owner approval or independent key proof.
    """
    result = None
    try:
        rows, artifacts = _personal_backup_rows(
            session, profile="personal-encrypted-custody-backup-v2"
        )
        engine = session.get_bind()
        if not isinstance(engine, Engine):
            raise TypeError("actual canonical Engine required")
        result = PersonalFullOriginalBackupPlan(
            engine, rows, artifacts, profile="personal-encrypted-custody-backup-v2"
        )
    except Exception:  # noqa: BLE001,S110 - fixed private-safe boundary
        pass
    if result is None:
        raise BackupArtifactsError("PERSONAL encrypted-custody backup plan unavailable")
    return result


def _backup_personal_full_original(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    artifact_store: ArtifactStore,
    backup_store: BackupObjectStore,
    recipient: str,
    local_manifest_cache_path: Path,
    plan: PersonalFullOriginalBackupPlan,
) -> BackupSummary:
    # No unbounded fallback or cache-as-proof. All new path failures are fixed;
    # uploaded objects or a manifest may remain after a late hold. They never
    # constitute success/current access without subsequent independent checks.
    result = None
    try:
        if (
            type(plan) is not PersonalFullOriginalBackupPlan
            or plan.profile
            not in ("personal-full-original-backup-v1", "personal-encrypted-custody-backup-v2")
            or trust_boundary is not TrustBoundary.PERSONAL
            or session.get_bind() is not plan.engine
        ):
            raise ValueError("exact explicit PERSONAL plan required")
        plan.__post_init__()
        transaction = None

        def current() -> None:
            nonlocal transaction
            if plan.profile == "personal-encrypted-custody-backup-v2":
                rows, artifacts = _personal_backup_rows(session, profile=plan.profile)
            else:
                rows, artifacts = _personal_backup_rows(session)
            actual = session.get_transaction()
            if transaction is None:
                transaction = actual
            if (
                actual is None
                or actual is not transaction
                or rows != plan.rows
                or artifacts != plan.artifacts
            ):
                raise ValueError("PERSONAL Source plan or transaction changed")

        current()
        local_read = getattr(artifact_store, "get_bounded", None)
        object_read = getattr(backup_store, "get_object_bounded", None)
        if not callable(local_read) or not callable(object_read):
            raise TypeError("actual bounded IO required without fallback")
        entries: dict[str, ManifestEntry] = {}
        total = 0
        for digest, location in plan.artifacts:
            current()
            raw = local_read(trust_boundary, location, max_bytes=_PERSONAL_PLAIN_LIMIT)
            current()
            if (
                type(raw) is not bytes
                or not 0 < len(raw) <= _PERSONAL_PLAIN_LIMIT
                or content_hash_of(raw) != digest
            ):
                raise ValueError("complete bounded plaintext hash required")
            total += len(raw)
            if total > _PERSONAL_AGGREGATE_LIMIT:
                raise ValueError("PERSONAL aggregate capacity exceeded")
            cipher = age_encrypt_bounded(
                raw,
                recipient,
                max_input_bytes=_PERSONAL_PLAIN_LIMIT,
                max_output_bytes=_PERSONAL_CIPHER_LIMIT,
                max_stderr_bytes=65_536,
                timeout_seconds=30.0,
            )
            current()
            if type(cipher) is not bytes or not 0 < len(cipher) <= _PERSONAL_CIPHER_LIMIT:
                raise ValueError("bounded complete ciphertext required")
            total += len(cipher)
            if total > _PERSONAL_AGGREGATE_LIMIT:
                raise ValueError("PERSONAL aggregate capacity exceeded")
            # Explicit PERSONAL objects are immutable by ciphertext identity. A failed rerun
            # must not replace ciphertext referenced by an earlier manifest.
            cipher_hash = hashlib.sha256(cipher).hexdigest()
            key = f"{trust_boundary.value}/{digest[:2]}/{digest}/{cipher_hash}.age"
            backup_store.put_object(key, cipher)
            current()
            confirmed = object_read(key, max_bytes=_PERSONAL_CIPHER_LIMIT)
            current()
            if type(confirmed) is not bytes or confirmed != cipher:
                raise ValueError("complete uploaded ciphertext readback differs")
            entries[digest] = ManifestEntry(
                digest,
                location,
                key,
                len(cipher),
                cipher_hash,
                datetime.now(UTC).isoformat(),
            )
        manifest = Manifest(trust_boundary.value, datetime.now(UTC).isoformat(), entries)
        body = manifest.to_json_bytes()
        total += len(body)
        if total > _PERSONAL_AGGREGATE_LIMIT or len(body) > 4_000_000:
            raise ValueError("bounded manifest capacity exceeded")
        current()
        encrypted = age_encrypt_bounded(
            body,
            recipient,
            max_input_bytes=4_000_000,
            max_output_bytes=4_100_000,
            max_stderr_bytes=65_536,
            timeout_seconds=30.0,
        )
        current()
        if type(encrypted) is not bytes or not 0 < len(encrypted) <= 4_100_000:
            raise ValueError("bounded manifest ciphertext required")
        total += len(encrypted)
        if total > _PERSONAL_AGGREGATE_LIMIT:
            raise ValueError("PERSONAL aggregate capacity exceeded")
        key = manifest_key_for(trust_boundary)
        backup_store.put_object(key, encrypted)
        current()
        confirmed = object_read(key, max_bytes=4_100_000)
        current()
        if type(confirmed) is not bytes or confirmed != encrypted:
            raise ValueError("bounded manifest readback differs")
        # Local cache is convenience only and never consulted as proof here.
        _save_local_manifest_cache(local_manifest_cache_path, manifest)
        current()
        result = BackupSummary(trust_boundary, len(entries), 0, len(entries), 0, [])
    except Exception:  # noqa: BLE001,S110 - never expose private SQL/object/process diagnostics
        pass
    if result is None:
        raise BackupArtifactsError("PERSONAL full-original bounded backup unavailable")
    return result


def _assert_personal_backup_backend(session: Session) -> None:
    from zacai.review_authorization import _assert_ledger_isolation

    if session.get_bind().dialect.name != "postgresql":
        raise ValueError("canonical PostgreSQL metadata bounds required")
    _assert_ledger_isolation(session)


def _assert_personal_custody_append_capacity(session: Session, reserved_sources: int) -> None:
    """Bound complete custody before a one-use burn, never reserve permission.

    Caller holds the existing parent lock. Unrelated concurrent appends still
    require complete later reconciliation; this check is not a boundary lock.
    """
    if type(reserved_sources) is not int or not 1 <= reserved_sources <= 8:
        raise ValueError("exact bounded custody append count required")
    raw, _ = _personal_backup_rows(session, profile="personal-encrypted-custody-backup-v2")
    if len(json.loads(raw)) + reserved_sources > _PERSONAL_ARTIFACT_LIMIT:
        raise ValueError("complete PERSONAL recovery capacity exhausted before burn")
