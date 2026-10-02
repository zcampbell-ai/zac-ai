"""BRAINSTORM state + artifact recovery verification for the operator trial.

Uses D028 export framing, D031 artifact backup and age encryption unchanged.
State snapshots are encrypted before upload under a separate BRAINSTORM/state
prefix in the same configured object store. No plaintext file is written.
This module does not select/create infrastructure or load credentials. Real use
requires the independently approved existing B2 backend and escrowed identity.
"""

from __future__ import annotations

import io
import uuid
from collections.abc import Buffer
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup import export_boundary_stream
from zacai.backup_artifacts import (
    BackupObjectStore,
    age_decrypt,
    age_encrypt,
    backup_object_key_for,
    run_artifact_backup,
)
from zacai.connectors.fireflies_trial import ProtectionEvidence, TrialApproval, TrialError
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.ingestion.fireflies_capture import CaptureReceipt
from zacai.policy import TrustBoundary
from zacai.state import ArtifactBackupRunStatus, IngestionRun, IngestionRunStatus, Source

_MAX_STATE_BYTES = 64_000_000
_BOUNDARY = TrustBoundary.BRAINSTORM


class _BoundedBuffer(io.BytesIO):
    def write(self, data: Buffer, /) -> int:
        if self.tell() + memoryview(data).nbytes > _MAX_STATE_BYTES:
            raise TrialError("state snapshot exceeds trial memory limit")
        return super().write(data)


class BrainstormTrialProtector:
    """Trusted backup adapter, not a user-supplied success declaration.

    Recovery references are operator attestations to independently performed
    drills/escrow; reference matching does not itself verify a password manager.
    Preflight additionally proves recipient/identity match via encryption round
    trip. protect performs actual remote readback and decryption/hash checks.
    The existing off-device S3 backend must be supplied by approved host wiring;
    the protocol can also accept a local synthetic store in tests, which never
    proves off-device durability. No permissive default exists.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        engine: Engine,
        artifacts: ArtifactStore,
        objects: BackupObjectStore,
        verification_objects: BackupObjectStore,
        recipient: str,
        identity_path: Path,
        manifest_cache: Path,
        credential_recovery_reference: str,
        artifact_recovery_reference: str,
    ) -> None:
        if factory.kw.get("bind") is not engine:
            raise TrialError("state export and capture must use the same engine")
        if objects is verification_objects:
            raise TrialError("independent backup verification client required")
        self._factory = factory
        self._engine = engine
        self._artifacts = artifacts
        self._objects = objects
        self._verification_objects = verification_objects
        self._recipient = recipient
        self._identity = identity_path
        self._cache = manifest_cache
        self._credential_reference = credential_recovery_reference
        self._artifact_reference = artifact_recovery_reference

    def preflight(self, scope: TrialApproval) -> None:
        if (
            scope.credential_recovery_reference != self._credential_reference
            or scope.artifact_recovery_reference != self._artifact_reference
            or not self._identity.is_file()
        ):
            raise TrialError("recovery prerequisites not verified")
        challenge = b"zacai BRAINSTORM recipient-identity readiness"
        if age_decrypt(age_encrypt(challenge, self._recipient), self._identity) != challenge:
            raise TrialError("backup encryption identity mismatch")

    def protect(
        self, approval_source_id: uuid.UUID, run_id: uuid.UUID, capture: CaptureReceipt
    ) -> ProtectionEvidence:
        backup_run = run_artifact_backup(
            self._factory,
            trust_boundary=_BOUNDARY,
            artifact_store=self._artifacts,
            backup_store=self._objects,
            recipient=self._recipient,
            local_manifest_cache_path=self._cache,
        )
        if backup_run.status != ArtifactBackupRunStatus.SUCCEEDED:
            raise TrialError("artifact backup incomplete")
        with self._factory() as session:
            run = session.get(IngestionRun, run_id)
            rows = list(
                session.scalars(
                    select(Source).where(
                        Source.id.in_(
                            [
                                approval_source_id,
                                capture.account_source_id,
                                capture.raw_source_id,
                                capture.normalized_source_id,
                            ]
                        ),
                        Source.trust_boundary == _BOUNDARY,
                    )
                )
            )
            if (
                run is None
                or run.trust_boundary != _BOUNDARY
                or run.status != IngestionRunStatus.SUCCEEDED
                or len(rows) != 4
            ):
                raise TrialError("committed capture audit or evidence unavailable")
            hashes = {source.content_hash for source in rows}
        if None in hashes or len(hashes) != 4:
            raise TrialError("capture hash inventory invalid")
        for digest in hashes:
            assert digest is not None
            ciphertext = self._verification_objects.get_object(
                backup_object_key_for(_BOUNDARY, digest)
            )
            if content_hash_of(age_decrypt(ciphertext, self._identity)) != digest:
                raise TrialError("remote artifact recovery verification failed")
        # Repeatable-read fixes a possible torn view under READ COMMITTED: every
        # framed table sees one snapshot, after capture and audit have committed.
        with _BoundedBuffer() as buffer:
            export_boundary_stream(
                self._engine.execution_options(isolation_level="REPEATABLE READ"), _BOUNDARY, buffer
            )
            plaintext = buffer.getvalue()
        encrypted = age_encrypt(plaintext, self._recipient)
        digest = content_hash_of(encrypted)
        state_key = f"BRAINSTORM/state/{run_id}/{digest}.age"
        self._objects.put_object(state_key, encrypted)
        returned = self._verification_objects.get_object(state_key)
        if content_hash_of(returned) != digest or content_hash_of(
            age_decrypt(returned, self._identity)
        ) != content_hash_of(plaintext):
            raise TrialError("remote state recovery verification failed")
        return ProtectionEvidence(
            approval_source_id=approval_source_id,
            run_id=run_id,
            artifact_hashes=hashes,
            state_export_hash=digest,
            verification_reference=f"state:{state_key};artifact-run:{backup_run.id}",
        )
