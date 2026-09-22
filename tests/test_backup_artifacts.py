"""Tests for zacai.backup_artifacts (D031A): encrypted per-artifact
backup, the four-part "already protected" check with repair-on-failure,
encrypted per-boundary manifests, restore, and reconciliation.

Uses the disposable `zacai_test` database only (D027), synthetic data
only, rolled back via the `db_session` fixture. Every `age` identity used
here is a throwaway keypair generated fresh per test via `age-keygen` -
never a real escrowed identity. `LocalDirectoryBackupStore` stands in
for "off-device" storage - these tests prove cryptographic/procedural
correctness only, never off-device durability (D031A does not lift the
real-ingestion gate).
"""

from __future__ import annotations

import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import (
    BackupArtifactsError,
    DecryptionError,
    LocalArtifactCorruptionError,
    LocalDirectoryBackupStore,
    Manifest,
    ManifestError,
    RestoreTargetUnsafeError,
    age_decrypt,
    age_encrypt,
    assert_safe_restore_target,
    backup_boundary,
    backup_object_key_for,
    manifest_key_for,
    restore_boundary_artifacts,
    run_artifact_backup,
    source_hashes_for_boundary,
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, SourceSystem
from zacai.state_repository import record_source, start_artifact_backup_run

# backup_boundary() deliberately backs up every Source-referenced hash
# for a boundary, with no per-test scoping (correct for production).
# SHARED is used here - rather than BRAINSTORM/PERSONAL - specifically
# because no other test file in this suite leaves committed, content-
# hash-bearing Source rows under SHARED via test_session_factory; using
# a boundary other files also populate would let leftover rows (whose
# content_location points at a now-vanished tmp_path from another test)
# surface as spurious MissingLocalArtifactError failures here.
_BOUNDARY = TrustBoundary.SHARED


@dataclass(frozen=True)
class AgeKeypair:
    recipient: str
    identity_path: Path


def _generate_age_keypair(tmp_path: Path, name: str) -> AgeKeypair:
    identity_path = tmp_path / f"{name}.key"
    proc = subprocess.run(
        ["age-keygen", "-o", str(identity_path)], capture_output=True, text=True, check=True
    )
    output = proc.stdout + proc.stderr
    for line in output.splitlines():
        if line.startswith("Public key:"):
            return AgeKeypair(recipient=line.split(":", 1)[1].strip(), identity_path=identity_path)
    raise RuntimeError(f"could not parse age-keygen output: {output!r}")


@pytest.fixture
def brainstorm_key(tmp_path: Path) -> AgeKeypair:
    return _generate_age_keypair(tmp_path, "brainstorm")


@pytest.fixture
def personal_key(tmp_path: Path) -> AgeKeypair:
    return _generate_age_keypair(tmp_path, "personal")


def _make_backed_source(
    session: Session,
    *,
    artifact_store: LocalFilesystemArtifactStore,
    trust_boundary: TrustBoundary = _BOUNDARY,
    raw_bytes: bytes,
    external_ref: str,
) -> str:
    """Creates a real local artifact plus a matching `Source` row -
    exactly the shape D030's ingestion pipeline produces."""
    digest = content_hash_of(raw_bytes)
    location = artifact_store.put(trust_boundary, digest, raw_bytes)
    record_source(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash=digest,
        content_location=location,
        external_ref=external_ref,
    )
    return digest


# --- backup: first run / idempotency / new items ----------------------------


def test_first_backup_encrypts_and_uploads(db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"hello world", external_ref="a1")

    summary = backup_boundary(
        db_session,
        trust_boundary=_BOUNDARY,
        artifact_store=artifact_store,
        backup_store=backup_store,
        recipient=brainstorm_key.recipient,
        local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert summary.checked == 1
    assert summary.backed_up == 1
    assert summary.already_protected == 0
    assert summary.repaired == 0
    assert summary.failed == 0
    assert backup_store.exists(manifest_key_for(_BOUNDARY))


def test_second_unchanged_backup_skips_reencryption(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"unchanged content", external_ref="a2")
    cache_path = tmp_path / "cache.json"

    first = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert first.backed_up == 1

    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert second.backed_up == 0
    assert second.repaired == 0
    assert second.already_protected == 1
    assert second.failed == 0


def test_newly_added_artifact_is_picked_up(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"first artifact", external_ref="a3")

    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"second artifact", external_ref="a4")

    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert second.checked == 2
    assert second.backed_up == 1
    assert second.already_protected == 1


# --- backup: repair paths ----------------------------------------------------


def test_missing_encrypted_object_is_repaired(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"will go missing", external_ref="a5"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    key = backup_object_key_for(_BOUNDARY, digest)
    (tmp_path / "backup" / key).unlink()

    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert second.repaired == 1
    assert second.already_protected == 0
    assert backup_store.exists(key)


def test_size_mismatch_is_repaired(db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"size will be corrupted", external_ref="a6"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    key = backup_object_key_for(_BOUNDARY, digest)
    object_path = tmp_path / "backup" / key
    object_path.write_bytes(object_path.read_bytes()[:-5])  # truncate - changes size

    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert second.repaired == 1


def test_ciphertext_hash_mismatch_is_repaired(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"ciphertext will be corrupted", external_ref="a7"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    key = backup_object_key_for(_BOUNDARY, digest)
    object_path = tmp_path / "backup" / key
    original = object_path.read_bytes()
    corrupted = bytes([b ^ 0xFF for b in original])  # same length, different bytes
    assert len(corrupted) == len(original)
    object_path.write_bytes(corrupted)

    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert second.repaired == 1


def test_corrupted_local_plaintext_causes_hard_failure(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    raw = b"will be corrupted locally before any backup"
    digest = _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=raw, external_ref="a8")

    local_path = tmp_path / "artifacts" / _BOUNDARY.value / artifact_store.location_for(digest)
    local_path.write_bytes(b"corrupted bytes, wrong hash entirely")

    summary = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert summary.failed == 1
    assert summary.backed_up == 0
    assert not backup_store.exists(backup_object_key_for(_BOUNDARY, digest))


def test_missing_local_artifact_is_a_per_item_failure_not_a_crash(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """A Source row whose local artifact file is entirely absent (e.g.
    deleted, or - as found during D031A testing - referencing a
    different `ArtifactStore` root than the one this run was given) must
    be recorded as a per-item failure, never crash the whole backup
    run."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"will be deleted", external_ref="a8b"
    )
    local_path = tmp_path / "artifacts" / _BOUNDARY.value / artifact_store.location_for(digest)
    local_path.unlink()

    summary = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert summary.failed == 1
    assert summary.failures[0].content_hash == digest
    assert not backup_store.exists(backup_object_key_for(_BOUNDARY, digest))


def test_failed_post_upload_verification_does_not_update_manifest(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"post-upload check will fail", external_ref="a9"
    )

    call_count = {"n": 0}
    original_get_object = LocalDirectoryBackupStore.get_object

    def _flaky_get_object(self: LocalDirectoryBackupStore, key: str) -> bytes:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return b"this does not match what was just uploaded"
        return original_get_object(self, key)

    monkeypatch.setattr(LocalDirectoryBackupStore, "get_object", _flaky_get_object)

    summary = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert summary.failed == 1
    assert summary.failures[0].content_hash == digest


# --- manifest / crypto -------------------------------------------------------


def test_manifest_object_is_actually_encrypted(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"manifest crypto check", external_ref="b1")
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    raw = backup_store.get_object(manifest_key_for(_BOUNDARY))
    with pytest.raises(ManifestError):
        Manifest.from_json_bytes(raw)


def test_manifest_decrypts_with_correct_identity(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"correct identity works", external_ref="b2")
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    raw = backup_store.get_object(manifest_key_for(_BOUNDARY))
    plaintext = age_decrypt(raw, brainstorm_key.identity_path)
    manifest = Manifest.from_json_bytes(plaintext)
    assert manifest.boundary == _BOUNDARY.value
    assert len(manifest.entries) == 1


def test_manifest_fails_to_decrypt_with_wrong_identity(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair, personal_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"wrong identity fails", external_ref="b3")
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    raw = backup_store.get_object(manifest_key_for(_BOUNDARY))
    with pytest.raises(DecryptionError):
        age_decrypt(raw, personal_key.identity_path)


def test_manifest_boundary_field_mismatch_rejected_independently_of_key(
    tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """Even when the CORRECT identity decrypts successfully, a manifest
    whose own declared boundary doesn't match the requested one must be
    rejected - the second, independent D031A defense layer."""
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    wrong_boundary_manifest = Manifest.empty(TrustBoundary.PERSONAL)
    encrypted = age_encrypt(wrong_boundary_manifest.to_json_bytes(), brainstorm_key.recipient)
    backup_store.put_object(manifest_key_for(_BOUNDARY), encrypted)

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    with pytest.raises(ManifestError, match="declares boundary"):
        restore_boundary_artifacts(
            trust_boundary=_BOUNDARY,
            backup_store=backup_store,
            identity_path=brainstorm_key.identity_path,
            restore_target=restore_target,
            live_artifact_root=tmp_path / "artifacts",
            expected_source_hashes=set(),
        )


def test_malformed_manifest_json_rejected() -> None:
    with pytest.raises(ManifestError):
        Manifest.from_json_bytes(b"not json at all {{{")


def test_truncated_encrypted_manifest_fails_to_decrypt(
    tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    manifest = Manifest.empty(_BOUNDARY)
    encrypted = age_encrypt(manifest.to_json_bytes(), brainstorm_key.recipient)
    truncated = encrypted[:-10]
    with pytest.raises(DecryptionError):
        age_decrypt(truncated, brainstorm_key.identity_path)


# --- restore / reconciliation -------------------------------------------------


def test_full_synthetic_round_trip_drill(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """The D031A proving drill. `Source` is append-only and `zacai_test`
    is a shared, session-lifetime database (D027) - it can accumulate
    committed rows from other tests under the same boundary (e.g.
    `test_run_artifact_backup_lifecycle` below, or a future test), and
    those rows can never be deleted to "clean up" for this drill. This
    drill's own expected set is therefore scoped to exactly the digests
    *this drill itself created* - deterministic and isolated regardless
    of test execution order or any other accumulated synthetic state -
    while still exercising the real `source_hashes_for_boundary` query
    (via the subset assertion below) and the real, unmodified
    reconciliation logic in `restore_boundary_artifacts`. This does not
    filter or weaken reconciliation's result in any way - it only fixes
    what this test asserts is *expected*, which is what a real disaster
    recovery would also know precisely (the set of artifacts a given
    backup was actually run over)."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digests = {
        _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=payload, external_ref=f"c{i}")
        for i, payload in enumerate([b"drill artifact one", b"drill artifact two", b"drill artifact three"])
    }

    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    # Still genuinely exercises the real Source query - this drill's own
    # digests must be a subset of whatever that query returns.
    all_boundary_hashes = source_hashes_for_boundary(db_session, trust_boundary=_BOUNDARY)
    assert digests <= all_boundary_hashes

    # Simulate loss of the Mac Studio: wipe the local artifact store.
    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")

    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=artifact_store.root,
        expected_source_hashes=digests,
    )
    assert outcome.successful
    assert outcome.reconciliation.missing == frozenset()
    assert outcome.reconciliation.unexpected == frozenset()
    assert outcome.reconciliation.verified == frozenset(digests)
    for digest in digests:
        location = restore_target.location_for(digest)
        assert content_hash_of(restore_target.get(_BOUNDARY, location)) == digest
    for digest in digests:
        location = restore_target.location_for(digest)
        assert content_hash_of(restore_target.get(_BOUNDARY, location)) == digest


def test_corrupted_ciphertext_object_fails_restore(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"will be corrupted before restore", external_ref="c9"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    key = backup_object_key_for(_BOUNDARY, digest)
    object_path = tmp_path / "backup" / key
    original = object_path.read_bytes()
    object_path.write_bytes(bytes([b ^ 0xFF for b in original]))

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=artifact_store.root,
        expected_source_hashes={digest},
    )
    assert not outcome.successful
    assert digest in outcome.reconciliation.missing
    assert any(f.content_hash == digest for f in outcome.failures)


def test_missing_source_referenced_artifact_detected(
    tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    empty_manifest = Manifest.empty(_BOUNDARY)
    backup_store.put_object(manifest_key_for(_BOUNDARY), age_encrypt(empty_manifest.to_json_bytes(), brainstorm_key.recipient))

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=tmp_path / "artifacts",
        expected_source_hashes={"a-hash-that-was-never-backed-up"},
    )
    assert not outcome.successful
    assert "a-hash-that-was-never-backed-up" in outcome.reconciliation.missing


def test_unexpected_restored_artifact_detected_without_forcing_failure(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"backed up but not expected", external_ref="c10"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=artifact_store.root,
        expected_source_hashes=set(),  # deliberately doesn't expect this hash
    )
    assert digest in outcome.reconciliation.unexpected
    assert outcome.reconciliation.missing == frozenset()
    assert outcome.successful  # unexpected alone never forces failure


def test_interrupted_restore_cannot_report_success(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unhandled, non-`BackupArtifactsError` failure mid-restore (a
    stand-in for a genuine interruption/crash) must propagate rather than
    ever producing a falsely-successful `RestoreOutcome`."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"interrupted restore", external_ref="c11")
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )

    def _raise_os_error(self: LocalDirectoryBackupStore, key: str) -> bytes:
        raise OSError("simulated interruption")

    monkeypatch.setattr(LocalDirectoryBackupStore, "get_object", _raise_os_error)

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    with pytest.raises(OSError, match="simulated interruption"):
        restore_boundary_artifacts(
            trust_boundary=_BOUNDARY,
            backup_store=backup_store,
            identity_path=brainstorm_key.identity_path,
            restore_target=restore_target,
            live_artifact_root=artifact_store.root,
            expected_source_hashes=set(),
        )


def test_assert_safe_restore_target_rejects_the_live_root(tmp_path: Path) -> None:
    live_root = tmp_path / "artifacts"
    with pytest.raises(RuntimeError, match="live artifact store root"):
        assert_safe_restore_target(live_root, live_root)


def test_assert_safe_restore_target_allows_a_distinct_root(tmp_path: Path) -> None:
    assert_safe_restore_target(tmp_path / "artifact_restore_test", tmp_path / "artifacts")


# --- D031B: restore_boundary_artifacts fails closed structurally -----------
#
# assert_safe_restore_target (above) is a plain function anyone could
# forget to call. These tests prove the equivalent guarantee is now
# unconditional and internal to restore_boundary_artifacts itself - it
# is called before any decryption or restore work happens, for every
# caller, with no way to opt out.


def test_restore_boundary_artifacts_rejects_the_live_artifact_root(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"must not restore over itself", external_ref="g1"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )

    with pytest.raises(RuntimeError, match="live artifact store root"):
        restore_boundary_artifacts(
            trust_boundary=_BOUNDARY,
            backup_store=backup_store,
            identity_path=brainstorm_key.identity_path,
            restore_target=LocalFilesystemArtifactStore(tmp_path / "artifacts"),  # same root as artifact_store
            live_artifact_root=artifact_store.root,
            expected_source_hashes={digest},
        )


def test_restore_boundary_artifacts_succeeds_with_a_distinct_fresh_root(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"distinct root is fine", external_ref="g2"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")  # distinct root
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=artifact_store.root,
        expected_source_hashes={digest},
    )
    assert outcome.successful


def test_restore_boundary_artifacts_rejects_a_target_with_no_inspectable_root(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """A `restore_target` implementation with no `.root` property is
    refused outright - the safety check never silently no-ops for a
    backend it cannot verify."""

    class _RootlessArtifactStore:
        def put(self, trust_boundary: TrustBoundary, content_hash: str, raw_bytes: bytes) -> str:
            raise NotImplementedError

        def get(self, trust_boundary: TrustBoundary, content_location: str) -> bytes:
            raise NotImplementedError

    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"rootless target rejected", external_ref="g3"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )

    with pytest.raises(RestoreTargetUnsafeError):
        restore_boundary_artifacts(
            trust_boundary=_BOUNDARY,
            backup_store=backup_store,
            identity_path=brainstorm_key.identity_path,
            restore_target=_RootlessArtifactStore(),
            live_artifact_root=artifact_store.root,
            expected_source_hashes={digest},
        )


# --- crash / audit ------------------------------------------------------------


def test_manifest_save_failure_is_repaired_on_next_run(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zacai.backup_artifacts as backup_artifacts_module

    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"manifest save will fail once", external_ref="d1"
    )

    original_save = backup_artifacts_module._save_local_manifest_cache
    call_count = {"n": 0}

    def _flaky_save(path: Path, manifest: Manifest) -> None:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OSError("simulated local manifest cache write failure")
        original_save(path, manifest)

    monkeypatch.setattr(backup_artifacts_module, "_save_local_manifest_cache", _flaky_save)

    with pytest.raises(OSError, match="simulated local manifest cache write failure"):
        backup_boundary(
            db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
            recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
        )

    monkeypatch.undo()
    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert second.failed == 0
    assert backup_store.exists(backup_object_key_for(_BOUNDARY, digest))
    assert backup_store.exists(manifest_key_for(_BOUNDARY))


def test_stray_started_run_does_not_affect_protection_truth(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"stray run test", external_ref="d2")

    stray = start_artifact_backup_run(db_session, trust_boundary=_BOUNDARY)

    summary = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert summary.backed_up == 1
    assert summary.failed == 0

    stray_row = db_session.execute(
        select(ArtifactBackupRun).where(ArtifactBackupRun.id == stray.id)
    ).scalar_one()
    assert stray_row.status == ArtifactBackupRunStatus.STARTED


def test_run_artifact_backup_lifecycle(
    test_session_factory: sessionmaker[Session], tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")

    with test_session_factory() as session:
        _make_backed_source(
            session, artifact_store=artifact_store, raw_bytes=b"run_artifact_backup lifecycle", external_ref="d3"
        )
        session.commit()

    run = run_artifact_backup(
        test_session_factory,
        trust_boundary=_BOUNDARY,
        artifact_store=artifact_store,
        backup_store=backup_store,
        recipient=brainstorm_key.recipient,
        local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert run.status == ArtifactBackupRunStatus.SUCCEEDED
    assert run.artifacts_backed_up == 1


# --- local plaintext manifest cache safety (D031A deviation verification) --
#
# backup_artifacts.py keeps a small local, plaintext JSON cache (never
# uploaded) purely as a same-run-to-run comparison baseline for the
# four-part "already protected" check - a deliberate, disclosed
# deviation from the original design (see DECISIONS.md D031A). These
# tests verify, explicitly, that this cache can never substitute for or
# weaken the actual durable, encrypted backup.


def test_local_manifest_cache_contains_metadata_only_never_plaintext(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    secret_payload = b"THE-ACTUAL-CONFIDENTIAL-ARTIFACT-BYTES-12345"
    cache_path = tmp_path / "cache.json"
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=secret_payload, external_ref="f1")

    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    cache_bytes = cache_path.read_bytes()
    assert secret_payload not in cache_bytes
    # It is metadata-shaped: it parses as a Manifest with hash/size/etc.
    # fields, not as arbitrary artifact content.
    parsed = Manifest.from_json_bytes(cache_bytes)
    assert len(parsed.entries) == 1


def test_local_manifest_cache_permissions(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache_dir" / "cache.json"
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"permissions check", external_ref="f2")

    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    assert stat.S_IMODE(cache_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(cache_path.parent.stat().st_mode) == 0o700


def test_local_manifest_cache_is_never_uploaded(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=b"never uploaded", external_ref="f3")

    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    cache_bytes = cache_path.read_bytes()
    # The backup store (the stand-in "off-device" destination) contains
    # only the encrypted manifest and encrypted artifact objects - never
    # the local cache's own bytes, and it lives entirely outside the
    # backup store's own root directory.
    assert not cache_path.is_relative_to(tmp_path / "backup")
    for key_path in (tmp_path / "backup").rglob("*"):
        if key_path.is_file():
            assert key_path.read_bytes() != cache_bytes


def test_local_manifest_cache_is_not_authoritative_for_protection(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """Deleting the cache never makes previously-backed-up data
    unrecoverable - restore reads only from `backup_store`, never from
    any local cache (the restore functions don't even accept one)."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"recoverable without the cache", external_ref="f4"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )

    cache_path.unlink()
    assert not cache_path.exists()

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=artifact_store.root,
        expected_source_hashes={digest},
    )
    assert outcome.successful
    assert digest in outcome.reconciliation.verified
    location = restore_target.location_for(digest)
    assert content_hash_of(restore_target.get(_BOUNDARY, location)) == digest


def test_deleting_local_manifest_cache_causes_safe_reverification_not_false_protection(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """A missing cache must never be read as "everything is already
    protected" - it must degrade to "nothing known yet," forcing a full,
    safe re-verification/re-backup rather than any false-positive skip."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    cache_path = tmp_path / "cache.json"
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"cache loss forces recheck", external_ref="f5"
    )
    first = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    assert first.backed_up == 1
    original_object_bytes = (tmp_path / "backup" / backup_object_key_for(_BOUNDARY, digest)).read_bytes()

    cache_path.unlink()

    second = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=cache_path,
    )
    # With the entire cache lost, this hash has no prior local record at
    # all - it is treated as newly encountered ("backed_up" again, a
    # fresh full re-verify-and-upload), never silently as
    # "already_protected". This is still always safe: content-addressed
    # re-upload, never a false-positive skip.
    assert second.already_protected == 0
    assert second.backed_up == 1
    new_object_bytes = (tmp_path / "backup" / backup_object_key_for(_BOUNDARY, digest)).read_bytes()
    # A fresh, independently-verified encrypted object (age is
    # non-deterministic - re-encryption is expected to differ bit-for-bit
    # from the original, but must still decrypt to the same plaintext).
    assert age_decrypt(new_object_bytes, brainstorm_key.identity_path) == age_decrypt(
        original_object_bytes, brainstorm_key.identity_path
    )


def test_encrypted_manifest_alone_is_sufficient_for_restore(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    """The encrypted manifest in `backup_store` is the durable backup
    representation - restore succeeds using only it and the backup
    objects, with no local cache involved at any point (the restore
    functions have no local-cache parameter at all)."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"manifest alone suffices", external_ref="f6"
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    (tmp_path / "cache.json").unlink()  # remove any local trace entirely

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY,
        backup_store=backup_store,
        identity_path=brainstorm_key.identity_path,
        restore_target=restore_target,
        live_artifact_root=artifact_store.root,
        expected_source_hashes={digest},
    )
    assert outcome.successful
    assert outcome.manifest.entries[digest].content_hash == digest


def test_backup_success_requires_both_objects_and_manifest_finalized(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the encrypted manifest itself fails to upload (even though
    every individual artifact object succeeded), the run must not report
    success - encrypted objects alone, without a consistent finalized
    manifest, are not a complete, restorable backup."""
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    digest = _make_backed_source(
        db_session, artifact_store=artifact_store, raw_bytes=b"manifest upload will fail", external_ref="f7"
    )

    original_put_object = LocalDirectoryBackupStore.put_object

    def _fail_manifest_put(self: LocalDirectoryBackupStore, key: str, data: bytes) -> None:
        if key == manifest_key_for(_BOUNDARY):
            raise OSError("simulated manifest upload failure")
        original_put_object(self, key, data)

    monkeypatch.setattr(LocalDirectoryBackupStore, "put_object", _fail_manifest_put)

    with pytest.raises(OSError, match="simulated manifest upload failure"):
        backup_boundary(
            db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
            recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
        )

    # The artifact object itself may have been written, but with no
    # finalized manifest, this must never be treated as a completed,
    # restorable backup.
    assert not backup_store.exists(manifest_key_for(_BOUNDARY))
    assert backup_object_key_for(_BOUNDARY, digest)  # sanity: key is well-formed

    monkeypatch.undo()
    retry = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    assert not any(f.content_hash == digest for f in retry.failures)
    assert backup_store.exists(manifest_key_for(_BOUNDARY))


# --- security -----------------------------------------------------------


def test_backup_artifacts_never_touches_gateway_or_action_type() -> None:
    contents = Path("src/zacai/backup_artifacts.py").read_text()
    assert "zacai.gateway" not in contents
    assert "ActionType" not in contents


def test_failure_error_text_never_contains_private_key_material(
    db_session: Session, tmp_path: Path, brainstorm_key: AgeKeypair
) -> None:
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = LocalDirectoryBackupStore(tmp_path / "backup")
    raw = b"corrupted before backup for security test"
    digest = _make_backed_source(db_session, artifact_store=artifact_store, raw_bytes=raw, external_ref="e1")
    local_path = tmp_path / "artifacts" / _BOUNDARY.value / artifact_store.location_for(digest)
    local_path.write_bytes(b"deliberately wrong bytes")

    summary = backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    secret_key_text = brainstorm_key.identity_path.read_text()
    assert summary.failures[0].error
    assert secret_key_text not in summary.failures[0].error


def test_local_artifact_corruption_error_is_a_backup_artifacts_error() -> None:
    assert issubclass(LocalArtifactCorruptionError, BackupArtifactsError)
