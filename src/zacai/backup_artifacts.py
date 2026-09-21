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
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.policy import TrustBoundary
from zacai.state import ArtifactBackupRun, Source
from zacai.state_repository import (
    complete_artifact_backup_run,
    fail_artifact_backup_run,
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


# --- age subprocess wrappers (public-key-only for backup) -------------------


def age_encrypt(plaintext: bytes, recipient: str) -> bytes:
    """Encrypts with only the public recipient - backup never needs a
    private identity (D031A)."""
    proc = subprocess.run(["age", "-r", recipient], input=plaintext, capture_output=True, check=False)
    if proc.returncode != 0:
        raise EncryptionError(f"age encryption failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def age_decrypt(ciphertext: bytes, identity_path: Path) -> bytes:
    """Decrypts with a private identity, supplied out-of-band by the
    caller (never embedded, never logged). Fails outright for a
    non-matching identity - `age`'s own AEAD scheme, not custom logic."""
    proc = subprocess.run(
        ["age", "-d", "-i", str(identity_path)], input=ciphertext, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise DecryptionError(f"age decryption failed: {proc.stderr.decode(errors='replace').strip()}")
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
            raise ManifestError(f"unsupported manifest_version {version} (expected {MANIFEST_VERSION})")
        if not isinstance(raw_entries, list):
            raise ManifestError("manifest 'entries' must be a list")
        entries = {}
        for raw_entry in raw_entries:
            entry = ManifestEntry.from_dict(raw_entry)
            entries[entry.content_hash] = entry
        return cls(boundary=boundary, generated_at=generated_at, entries=entries, manifest_version=version)

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


def _source_rows_for_boundary(session: Session, *, trust_boundary: TrustBoundary) -> list[tuple[str, str]]:
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
    return {content_hash for content_hash, _ in _source_rows_for_boundary(session, trust_boundary=trust_boundary)}


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
    if len(confirmed) != len(ciphertext) or confirmed_hash != hashlib.sha256(ciphertext).hexdigest():
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
) -> BackupSummary:
    """The D031A incremental/idempotent backup algorithm: driven entirely
    by `Source` rows, never by scanning the filesystem. Orphan artifacts
    (no `Source` reference) are never backed up - they cannot be
    assigned a trust boundary for encryption without guessing."""
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
        boundary=trust_boundary.value, generated_at=datetime.now(UTC).isoformat(), entries=new_entries
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
            summary = backup_boundary(
                data_session,
                trust_boundary=trust_boundary,
                artifact_store=artifact_store,
                backup_store=backup_store,
                recipient=recipient,
                local_manifest_cache_path=local_manifest_cache_path,
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
    expected_source_hashes: set[str],
) -> RestoreOutcome:
    """Restores one boundary's artifacts from `backup_store` into
    `restore_target`, using only `identity_path` (the matching private
    `age` identity, supplied out-of-band). Two-layer wrong-boundary
    rejection: (1) `age -d` fails outright for a non-matching identity;
    (2) the decrypted manifest's own `boundary` field is independently
    checked against `trust_boundary`. Never silently accepts a partial
    restore, a hash mismatch, or a missing artifact - see
    `RestoreOutcome.successful`."""
    encrypted_manifest = backup_store.get_object(manifest_key_for(trust_boundary))
    manifest_bytes = age_decrypt(encrypted_manifest, identity_path)  # raises DecryptionError on wrong identity
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
                raise RestoreIntegrityError(f"restored artifact {content_hash} failed plaintext hash verification")
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
            verified=frozenset(verified), missing=frozenset(missing), unexpected=frozenset(unexpected)
        ),
        failures=failures,
    )
