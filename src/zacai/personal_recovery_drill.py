"""PERSONAL invented-fixture recovery seam; never ingestion readiness authority.

Uses existing encryption/manifest/restore abstractions, with a fresh namespace
and independently supplied writer/reader. No credential/client construction,
production database, key generation or destination discovery. Concrete guarded
SQL seeding and real off-device/escrow verification are intentionally not wired.
The caller owns exclusive restore windows and cleanup of disposable local roots.
Partial ciphertext stays retained on failure; there is no retry/delete operation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol
from uuid import UUID

from zacai.backup_artifacts import (
    BackupObjectStore,
    DecryptionError,
    Manifest,
    ManifestEntry,
    ObjectStat,
    age_decrypt,
    age_encrypt,
    assert_safe_restore_target,
    backup_object_key_for,
    manifest_key_for,
    restore_boundary_artifacts,
)
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.policy import TrustBoundary

_BOUNDARY = TrustBoundary.PERSONAL
_FIXTURES = (b"invented personal drill evidence one", b"invented personal drill evidence two\x00")


class PersonalDrillError(RuntimeError):
    """Closed diagnostic with no key, data, adapter exception or path content."""


class SyntheticStateAdapter(Protocol):
    """Offline injectable seam only, not a production SQL adapter.

    Implementations retain the exact module-owned fixture snapshot, then restore
    and independently read back all bytes. A future SQL adapter must use guarded
    disposable DBs and existing backup.py frame comparison; this protocol alone
    cannot attest real database restore. Nothing accepts a caller's own snapshot.
    """

    def seed_and_export(self, expected_fixture: bytes) -> bytes: ...
    def restore_and_export(self, expected_fixture: bytes) -> bytes: ...


@dataclass(frozen=True)
class PersonalDrillReceipt:
    run_id: UUID
    object_keys: tuple[str, ...]
    artifact_hashes: tuple[str, ...]
    synthetic_state_hash: str

    @property
    def synthetic_round_trip_verified(self) -> Literal[True]:
        return True

    @property
    def real_off_device_verified(self) -> Literal[False]:
        return False

    @property
    def database_restore_verified(self) -> Literal[False]:
        return False

    @property
    def key_escrow_verified(self) -> Literal[False]:
        return False

    @property
    def real_ingestion_authorized(self) -> Literal[False]:
        return False


class _RunStore:
    """Map existing PERSONAL keys inside one run; no fallback or deletion."""

    def __init__(self, store: BackupObjectStore, run_id: UUID) -> None:
        self._store = store
        self._prefix = f"PERSONAL/recovery-drills/{run_id}/"

    def key(self, key: str) -> str:
        if (
            key == "PERSONAL/manifest.age"
            or re.fullmatch(r"PERSONAL/[0-9a-f]{2}/[0-9a-f]{64}\.age", key)
            or re.fullmatch(r"PERSONAL/state/[0-9a-f]{64}\.age", key)
        ):
            return self._prefix + key.removeprefix("PERSONAL/")
        raise PersonalDrillError("personal drill scope rejected")

    def exists(self, key: str) -> bool:
        return self._store.exists(self.key(key))

    def stat(self, key: str) -> ObjectStat:
        return self._store.stat(self.key(key))

    def get_object(self, key: str) -> bytes:
        return self._store.get_object(self.key(key))

    def put_object(self, key: str, data: bytes) -> None:
        self._store.put_object(self.key(key), data)


def _snapshot(run_id: UUID) -> bytes:
    # Fixed invented fixture inventory; never a replacement canonical state.
    return canonical_bytes(
        {
            "synthetic_personal_drill": str(run_id),
            "boundary": "PERSONAL",
            "sources": [
                {"fixture_index": index, "content_hash": content_hash_of(raw)}
                for index, raw in enumerate(_FIXTURES)
            ],
        }
    )


def run_synthetic_personal_drill(
    *,
    run_id: UUID,
    writer: BackupObjectStore,
    independent_reader: BackupObjectStore,
    state: SyntheticStateAdapter,
    original_artifacts: LocalFilesystemArtifactStore,
    restore_artifacts: LocalFilesystemArtifactStore,
    recipient: str,
    identity_path: Path,
    wrong_identity_path: Path,
) -> PersonalDrillReceipt:
    """Explicit offline seam: synthetic checks cannot lift the PERSONAL gate.

    Stores/artifact paths must be new disposable targets provided by a trusted
    host. Actual store roots are checked for separation before writes; a future
    concrete operator owns authority, fresh-target creation and cleanup.
    Hash/byte equality cannot prove a supplied reader is independently remote.
    No source imports, account access, live SQL, deletion or automatic retry.
    """
    try:
        if type(run_id) is not UUID or writer is independent_reader:
            raise ValueError("scope")
        if (
            not isinstance(original_artifacts, LocalFilesystemArtifactStore)
            or not isinstance(restore_artifacts, LocalFilesystemArtifactStore)
            or identity_path.resolve() == wrong_identity_path.resolve()
            or not identity_path.is_file()
            or not wrong_identity_path.is_file()
        ):
            raise ValueError("fixture targets")
        assert_safe_restore_target(restore_artifacts.root, original_artifacts.root)
        write = _RunStore(writer, run_id)
        read = _RunStore(independent_reader, run_id)
        expected_state = _snapshot(run_id)
        state_hash = content_hash_of(expected_state)
        state_key = f"PERSONAL/state/{state_hash}.age"
        hashes = tuple(content_hash_of(raw) for raw in _FIXTURES)
        keys = tuple(backup_object_key_for(_BOUNDARY, digest) for digest in hashes) + (
            manifest_key_for(_BOUNDARY),
            state_key,
        )
        # Refuse namespace reuse before any local writes or adapter action.
        if any(write.exists(key) or read.exists(key) for key in keys):
            raise ValueError("run already exists")
        if state.seed_and_export(expected_state) != expected_state:
            raise ValueError("synthetic state mismatch")
        timestamp = datetime.now(UTC).isoformat()
        entries: dict[str, ManifestEntry] = {}
        ciphertexts: dict[str, bytes] = {}
        for raw, digest in zip(_FIXTURES, hashes, strict=True):
            location = original_artifacts.put(_BOUNDARY, digest, raw)
            if original_artifacts.get(_BOUNDARY, location) != raw:
                raise ValueError("artifact mismatch")
            key = backup_object_key_for(_BOUNDARY, digest)
            cipher = age_encrypt(raw, recipient)
            ciphertexts[key] = cipher
            entries[digest] = ManifestEntry(
                digest, location, key, len(raw), content_hash_of(cipher), timestamp
            )
        manifest = Manifest("PERSONAL", timestamp, entries)
        ciphertexts[manifest_key_for(_BOUNDARY)] = age_encrypt(manifest.to_json_bytes(), recipient)
        ciphertexts[state_key] = age_encrypt(expected_state, recipient)
        for key in keys:
            write.put_object(key, ciphertexts[key])
        # Fresh reader bytes/length must exactly match uploaded ciphertext.
        for key in keys:
            retrieved = read.get_object(key)
            if read.stat(key).size != len(ciphertexts[key]) or retrieved != ciphertexts[key]:
                raise ValueError("remote ciphertext mismatch")
        encrypted_manifest = read.get_object(manifest_key_for(_BOUNDARY))
        try:
            age_decrypt(encrypted_manifest, wrong_identity_path)
        except DecryptionError:
            pass
        else:
            raise ValueError("wrong identity accepted")
        outcome = restore_boundary_artifacts(
            trust_boundary=_BOUNDARY,
            backup_store=read,
            identity_path=identity_path,
            restore_target=restore_artifacts,
            live_artifact_root=original_artifacts.root,
            expected_source_hashes=set(hashes),
        )
        if not outcome.successful or outcome.reconciliation.unexpected:
            raise ValueError("reconciliation failed")
        for raw, digest in zip(_FIXTURES, hashes, strict=True):
            restored = restore_artifacts.get(_BOUNDARY, entries[digest].content_location)
            if restored != raw or content_hash_of(restored) != digest:
                raise ValueError("restored artifact mismatch")
        retrieved_state = age_decrypt(read.get_object(state_key), identity_path)
        if (
            retrieved_state != expected_state
            or state.restore_and_export(retrieved_state) != expected_state
        ):
            raise ValueError("restored state mismatch")
        return PersonalDrillReceipt(
            run_id, tuple(write.key(key) for key in keys), hashes, state_hash
        )
    except Exception:  # noqa: BLE001, S110 - no raw adapter/private diagnostics
        pass
    raise PersonalDrillError("synthetic personal recovery drill rejected; no readiness claim")
