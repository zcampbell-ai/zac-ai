"""Real age crypto with throwaway keys and two local synthetic object clients.

No B2/network/real identity. Inventory is restricted in the fixture to this
capture's four sources because other tests retain unrelated committed sources
under zacai_test with different ephemeral artifact roots. Production has no
such filter: run_artifact_backup covers the entire BRAINSTORM inventory.
"""

import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from tests.test_fireflies_trial import NOW, FakeProtector, FakeTransport, register, scope
from zacai import backup_artifacts
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt
from zacai.connectors.fireflies_protection import BrainstormTrialProtector
from zacai.connectors.fireflies_trial import TrialError, execute_trial
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.policy import TrustBoundary
from zacai.state import Source


def keypair(path: Path) -> str:
    generated = subprocess.run(
        ["age-keygen", "-o", str(path)], capture_output=True, check=True, text=True
    )
    return next(
        line.split(": ", 1)[1]
        for line in generated.stderr.splitlines()
        if line.startswith("Public key:")
    )


def test_actual_protector_reads_back_decrypts_and_binds_committed_state(
    test_session_factory: sessionmaker[Session], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pydantic import SecretStr

    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    approval = scope()
    approval_id = register(test_session_factory, artifact_store, approval)
    capture, synthetic = execute_trial(
        test_session_factory,
        store=artifact_store,
        approval_source_id=approval_id,
        transport=FakeTransport(),
        protector=FakeProtector(test_session_factory),
        credential=lambda _: SecretStr("synthetic-test-only-credential"),
        clock=lambda: NOW,
    )
    source_ids = {
        approval_id,
        capture.account_source_id,
        capture.raw_source_id,
        capture.normalized_source_id,
    }

    def rows(session: Session, *, trust_boundary: TrustBoundary) -> list[tuple[str, str]]:
        selected = session.execute(
            select(Source.content_hash, Source.content_location).where(
                Source.id.in_(source_ids), Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(row[0], row[1]) for row in selected]

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    identity = tmp_path / "throwaway.key"
    recipient = keypair(identity)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    engine = test_session_factory.kw["bind"]
    assert isinstance(engine, Engine)
    protector = BrainstormTrialProtector(
        factory=test_session_factory,
        engine=engine,
        artifacts=artifact_store,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest.cache",
        credential_recovery_reference=approval.credential_recovery_reference,
        artifact_recovery_reference=approval.artifact_recovery_reference,
    )
    protector.preflight(approval)
    evidence = protector.protect(approval_id, synthetic.run_id, capture)
    assert evidence.artifact_hashes == synthetic.artifact_hashes
    encrypted_files = list((tmp_path / "objects" / "BRAINSTORM" / "state").rglob("*.age"))
    assert len(encrypted_files) == 1
    encrypted = encrypted_files[0].read_bytes()
    assert str(capture.meeting_id).encode() not in encrypted
    plaintext = age_decrypt(encrypted, identity)
    assert str(capture.meeting_id).encode() in plaintext
    assert str(approval_id).encode() in plaintext
    assert str(synthetic.run_id).encode() in plaintext
    assert b"SUCCEEDED" in plaintext
    assert not list(tmp_path.rglob("*.csv"))
    # The separately constructed verifier must detect a corrupted remote state
    # even if the writer's own upload returned successfully.
    original_get = reader.get_object

    def corrupt_state(key: str) -> bytes:
        return b"corrupted synthetic ciphertext" if "/state/" in key else original_get(key)

    monkeypatch.setattr(reader, "get_object", corrupt_state)
    with pytest.raises(TrialError, match="state recovery"):
        protector.protect(approval_id, synthetic.run_id, capture)


def test_protector_refuses_same_client_or_mismatched_engine(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    engine = test_session_factory.kw["bind"]
    with pytest.raises(TrialError, match="independent"):
        BrainstormTrialProtector(
            factory=test_session_factory,
            engine=engine,
            artifacts=LocalFilesystemArtifactStore(tmp_path / "artifacts"),
            objects=objects,
            verification_objects=objects,
            recipient="synthetic-placeholder",
            identity_path=tmp_path / "none.key",
            manifest_cache=tmp_path / "cache",
            credential_recovery_reference="synthetic",
            artifact_recovery_reference="synthetic",
        )


def test_snapshot_buffer_fails_closed_at_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    from zacai.connectors import fireflies_protection as module

    monkeypatch.setattr(module, "_MAX_STATE_BYTES", 8)
    with module._BoundedBuffer() as buffer:
        assert buffer.write(b"12345678") == 8
        with pytest.raises(TrialError, match="memory limit"):
            buffer.write(b"9")
        assert buffer.getvalue() == b"12345678"


def test_preflight_wrong_identity_and_unverified_references(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    from zacai.backup_artifacts import DecryptionError

    approval = scope()
    recipient = keypair(tmp_path / "one.key")
    wrong_identity = tmp_path / "two.key"
    keypair(wrong_identity)
    protector = BrainstormTrialProtector(
        factory=test_session_factory,
        engine=test_session_factory.kw["bind"],
        artifacts=LocalFilesystemArtifactStore(tmp_path / "artifacts"),
        objects=LocalDirectoryBackupStore(tmp_path / "objects"),
        verification_objects=LocalDirectoryBackupStore(tmp_path / "objects"),
        recipient=recipient,
        identity_path=wrong_identity,
        manifest_cache=tmp_path / "cache",
        credential_recovery_reference=approval.credential_recovery_reference,
        artifact_recovery_reference=approval.artifact_recovery_reference,
    )
    with pytest.raises(DecryptionError):
        protector.preflight(approval)
    with pytest.raises(TrialError, match="prerequisites"):
        protector.preflight(
            approval.model_copy(update={"credential_recovery_reference": "unverified"})
        )
