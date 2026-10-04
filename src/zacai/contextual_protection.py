"""Explicit BRAINSTORM packet recovery adapter; no service or approval issuer.

Real use requires separate approved host wiring. Synthetic local object clients
prove mechanics, never actual off-device availability. No generated prose is
returned. The host must gate release on verified receipts and fresh access.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

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
from zacai.contextual_recovery_record import (
    ContextualRecoveryReceipt,
    RecoveryLocator,
    encode_recovery_receipt,
    load_contextual_recovery_receipt,
)
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.review_audit import ContextualAuditEvent, ContextualAuditStage
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _bytes, _write
from zacai.review_protection import BoundedStateBuffer, DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRunStatus, Source, SourceSystem


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

    def _read(self, key: str, limit: int) -> bytes:
        size = self._reader.stat(key).size
        if not 0 < size <= limit:
            raise ValueError("recovery object outside capacity")
        raw = self._reader.get_object(key)
        if len(raw) != size:
            raise ValueError("recovery object changed")
        return raw

    def protect(
        self,
        source_id: UUID,
        expected_digest: str,
        audit_source_ids: tuple[UUID, ...] = (),
    ) -> ContextualRecoveryReceipt:
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
            if len(audit_source_ids) > 16 or len(set(audit_source_ids)) != len(audit_source_ids):
                raise ValueError("invalid audit inventory")
            if audit_source_ids:
                with self._factory() as session:
                    from zacai.intelligence.contextual_generation import prepare_contextual_request
                    from zacai.intelligence.contextual_host import contextual_request_digest

                    expected_request_hash = contextual_request_digest(
                        prepare_contextual_request(packet.context())
                    )
                    run_ids = set()
                    route_pins = set()
                    stages = set()
                    for sid in audit_source_ids:
                        source = session.get(Source, sid)
                        if (
                            source is None
                            or source.trust_boundary != B.BRAINSTORM
                            or source.system != SourceSystem.MANUAL
                        ):
                            raise ValueError("audit outside scope")
                        raw = _bytes(session, self._artifacts, source)
                        event = ContextualAuditEvent.model_validate_json(raw)
                        if (
                            raw != canonical_bytes(event.model_dump(mode="json"))
                            or source.external_ref != f"contextual-run-audit/{event.audit_event_id}"
                            or source.captured_at != event.recorded_at
                            or event.request_digest != expected_request_hash
                            or event.task_id != packet.task.task_id
                            or event.builder_id != packet.builder_id
                            or event.context_digest != packet.context_digest
                            or event.trust_boundary != B.BRAINSTORM
                            or event.data_classification != C.CONFIDENTIAL
                            or (
                                event.stage == ContextualAuditStage.PACKET_CAPTURED
                                and (
                                    event.packet_source_id != source_id
                                    or event.packet_digest != expected_digest
                                )
                            )
                        ):
                            raise ValueError("audit binding mismatch")
                        run_ids.add(event.run_id)
                        route_pins.add((event.route, event.model_digest))
                        stages.add(event.stage)
                        if source.content_hash is None:
                            raise ValueError("audit hash unavailable")
                        hashes[sid] = source.content_hash
                    if len(run_ids) != 1 or stages != {
                        ContextualAuditStage.REQUEST_PREPARED,
                        ContextualAuditStage.DISPATCH_PREPARED,
                        ContextualAuditStage.PACKET_CAPTURED,
                    }:
                        raise ValueError("incomplete host audit")
            locator = RecoveryLocator(
                locator_id=uuid4(),
                packet_source_id=source_id,
                packet_digest=expected_digest,
                task_id=packet.task.task_id,
                builder_id=packet.builder_id,
                created_at=datetime.now(UTC),
            )
            locator_raw = canonical_bytes(locator.model_dump(mode="json"))
            locator_hash = content_hash_of(locator_raw)
            with self._factory() as session:
                locator_sid = _write(
                    session,
                    self._artifacts,
                    f"contextual-recovery-locator/{source_id}/{locator.locator_id}",
                    SourceSystem.MANUAL,
                    locator_raw,
                    locator.created_at,
                )
                session.commit()
            hashes[locator_sid] = locator_hash
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
                returned = self._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
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
                returned = self._read(backup_object_key_for(B.BRAINSTORM, artifact_hash), 8_500_000)
                if content_hash_of(age_decrypt(returned, self._identity)) != artifact_hash:
                    raise ValueError("snapshot artifact coverage incomplete")
            ciphertext = age_encrypt(snapshot, self._recipient)
            digest = content_hash_of(ciphertext)
            key = f"BRAINSTORM/state/contextual-packet-{source_id}/{digest}.age"
            self._objects.put_object(key, ciphertext)
            returned = self._read(key, 65_000_000)
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
            returned_journal = self._read(journal_key, 4_100_000)
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
            receipt = ContextualRecoveryReceipt(
                locator=locator,
                locator_source_id=locator_sid,
                locator_digest=locator_hash,
                verified_at=datetime.now(UTC),
                artifact_backup_run_id=result.id,
                audit_source_ids=audit_source_ids,
                state_object=key,
                state_ciphertext_hash=digest,
                state_plaintext_hash=content_hash_of(snapshot),
                journal_object=journal_key,
                journal_ciphertext_hash=journal_digest,
                journal_plaintext_hash=content_hash_of(journal),
            )
            receipt_raw = encode_recovery_receipt(receipt)
            receipt_ciphertext = age_encrypt(receipt_raw, self._recipient)
            # New UUID locator is append-only; existing objects must never be overwritten.
            if self._objects.exists(locator.receipt_object):
                raise ValueError("receipt object already exists")
            self._objects.put_object(locator.receipt_object, receipt_ciphertext)
            recovered_receipt = self._read(locator.receipt_object, 64_000)
            if (
                recovered_receipt != receipt_ciphertext
                or age_decrypt(recovered_receipt, self._identity) != receipt_raw
            ):
                raise ValueError("receipt recovery mismatch")
            with self._factory() as session:
                loaded = load_contextual_recovery_receipt(
                    session,
                    locator_source_id=locator_sid,
                    expected_locator_digest=locator_hash,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                    verification_objects=self._reader,
                    identity_path=self._identity,
                )
            if loaded != receipt:
                raise ValueError("receipt canonical recovery mismatch")
            return receipt
        except Exception:  # noqa: BLE001, S110 - no private backend diagnostics
            pass
        raise ContextualProtectionError("contextual recovery verification failed")
