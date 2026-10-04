"""Explicit BRAINSTORM packet recovery adapter; no service or approval issuer.

Real use requires separate approved host wiring. Synthetic local object clients
prove mechanics, never actual off-device availability. No generated prose is
returned; a future host must gate release on this verification and fresh access.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai import backup
from zacai.backup_artifacts import (
    BackupObjectStore,
    age_decrypt,
    age_encrypt,
    backup_object_key_for,
    run_artifact_backup,
)
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import BoundedStateBuffer, DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRunStatus


def _snapshot_artifact_hashes(conn: Connection) -> set[str]:
    return set(
        conn.execute(
            text(
                "SELECT content_hash FROM source WHERE trust_boundary='BRAINSTORM' AND content_hash IS NOT NULL"
            )
        ).scalars()
    )


class ContextualProtectionError(RuntimeError):
    """Fixed diagnostics; hosts must disable traceback-local capture."""


class BrainstormContextualProtector:
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
        restoration: DisposableStateRestoreVerifier,
    ) -> None:
        try:
            url = engine.url
            if (
                url.drivername != "postgresql+psycopg"
                or url.host != "127.0.0.1"
                or url.port != 5432
                or url.database not in ("zacai_dev", "zacai_test")
                or url.password
                or url.query
                or factory.kw.get("bind") is not engine
                or factory.kw.get("binds")
                or factory.class_.__bases__ != (Session,)
                or objects is verification_objects
                or not isinstance(restoration, DisposableStateRestoreVerifier)
            ):
                raise ValueError("controlled configuration required")
            self._factory, self._engine, self._artifacts = factory, engine, artifacts
            self._objects, self._reader = objects, verification_objects
            self._recipient, self._identity, self._cache = recipient, identity_path, manifest_cache
            self._restoration = restoration
            return
        except Exception:  # noqa: BLE001, S110 - no private configuration diagnostics
            pass
        raise ContextualProtectionError("contextual protection configuration rejected")

    def protect(self, source_id: UUID, expected_digest: str) -> None:
        """Verify committed packet/evidence crypto recovery and full state restore.

        Does not authorize inference, verify semantic judgments or authenticate
        the caller. No ephemeral caller-supplied scope can override source checks.
        """
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SET TRANSACTION READ ONLY"))
                actual = conn.execute(
                    text(
                        "SELECT current_database(), inet_server_port(), host(inet_server_addr()), current_schema()"
                    )
                ).one()
                if tuple(actual) != (self._engine.url.database, 5432, "127.0.0.1", "public"):
                    raise ValueError("connected target mismatch")
                if conn.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalars().all() != ["0005"]:
                    raise ValueError("protected schema required")
            hashes = {source_id: expected_digest}
            with self._factory() as session:
                if session.scalar(text("SELECT current_database()")) != self._engine.url.database:
                    raise ValueError("session target mismatch")
                packet = load_contextual_packet(
                    session,
                    artifacts=self._artifacts,
                    source_id=source_id,
                    expected_digest=expected_digest,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                )
                hashes.update(
                    {
                        item.reference.source_id: item.reference.content_hash
                        for item in packet.task.context
                    }
                )
            challenge = b"zacai contextual packet recovery identity readiness"
            if age_decrypt(age_encrypt(challenge, self._recipient), self._identity) != challenge:
                raise ValueError("identity mismatch")
            result = run_artifact_backup(
                self._factory,
                trust_boundary=B.BRAINSTORM,
                artifact_store=self._artifacts,
                backup_store=self._objects,
                recipient=self._recipient,
                local_manifest_cache_path=self._cache,
            )
            if result.status != ArtifactBackupRunStatus.SUCCEEDED:
                raise ValueError("artifact protection incomplete")
            for digest in hashes.values():
                returned = self._reader.get_object(backup_object_key_for(B.BRAINSTORM, digest))
                if content_hash_of(age_decrypt(returned, self._identity)) != digest:
                    raise ValueError("artifact recovery mismatch")
            with BoundedStateBuffer() as buffer, self._engine.connect() as conn:
                conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                if conn.scalar(text("SELECT current_database()")) != self._engine.url.database:
                    raise ValueError("snapshot target mismatch")
                backup._export_boundary_connection(conn, B.BRAINSTORM, buffer)
                snapshot_hashes = _snapshot_artifact_hashes(conn)
                journal = backup._export_table_csv(
                    backup._raw_connection(conn), "artifact_backup_run", B.BRAINSTORM.value
                )
                if not 0 < len(journal) <= 4_000_000:
                    raise ValueError("operational journal outside capacity")
                snapshot = buffer.getvalue()
            # Catch Sources committed after artifact backup but before the snapshot.
            for artifact_hash in snapshot_hashes:
                returned = self._reader.get_object(
                    backup_object_key_for(B.BRAINSTORM, artifact_hash)
                )
                if content_hash_of(age_decrypt(returned, self._identity)) != artifact_hash:
                    raise ValueError("snapshot artifact coverage incomplete")
            ciphertext = age_encrypt(snapshot, self._recipient)
            digest = content_hash_of(ciphertext)
            key = f"BRAINSTORM/state/contextual-packet-{source_id}/{digest}.age"
            self._objects.put_object(key, ciphertext)
            returned = self._reader.get_object(key)
            if content_hash_of(returned) != digest:
                raise ValueError("state ciphertext mismatch")
            recovered = age_decrypt(returned, self._identity)
            if content_hash_of(recovered) != content_hash_of(snapshot):
                raise ValueError("state recovery mismatch")
            journal_ciphertext = age_encrypt(journal, self._recipient)
            journal_digest = content_hash_of(journal_ciphertext)
            journal_key = (
                f"BRAINSTORM/state/contextual-packet-{source_id}/journal-{journal_digest}.age"
            )
            self._objects.put_object(journal_key, journal_ciphertext)
            returned_journal = self._reader.get_object(journal_key)
            if content_hash_of(returned_journal) != journal_digest:
                raise ValueError("journal ciphertext mismatch")
            recovered_journal = age_decrypt(returned_journal, self._identity)
            if recovered_journal != journal:
                raise ValueError("journal recovery mismatch")
            self._restoration.verify(
                recovered,
                hashes,
                current_business_state=self._engine,
                operational_journal=recovered_journal,
            )
            with self._factory() as session:
                load_contextual_packet(
                    session,
                    artifacts=self._artifacts,
                    source_id=source_id,
                    expected_digest=expected_digest,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                )
            return
        except Exception:  # noqa: BLE001, S110 - no private backend diagnostics
            pass
        raise ContextualProtectionError("contextual recovery verification failed")
