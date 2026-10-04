"""D034L explicit Brainstorm review backup and full disposable state restore.

No credential loading, infrastructure selection or enabled service. Real calls
require approved host wiring; local synthetic object stores prove mechanics only.
"""

from __future__ import annotations

import io
import json
from collections.abc import Buffer
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai import backup
from zacai.backup_artifacts import (
    BackupObjectStore,
    age_decrypt,
    age_encrypt,
    backup_object_key_for,
    run_artifact_backup,
)
from zacai.backup_safety import (
    assert_connected_to_safe_restore_database,
    assert_safe_restore_target_url,
)
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.review_audit import ReviewAuditEvent, ReviewAuditStage
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import ReviewConsent
from zacai.state import ArtifactBackupRunStatus, Source, SourceSystem
from zacai.state_repository import get_effective_source_classification

_MAX_STATE_BYTES = 64_000_000
_DRILL_LOCK = 73403412


class ReviewProtectionError(RuntimeError):
    """Fixed errors; never expose state, credentials or provider diagnostics."""


class BoundedStateBuffer(io.BytesIO):
    def write(self, data: Buffer, /) -> int:
        if self.tell() + memoryview(data).nbytes > _MAX_STATE_BYTES:
            raise ReviewProtectionError("state snapshot outside review capacity")
        return super().write(data)


class DisposableStateRestoreVerifier:
    """Restore only zacai_restore_test, verify every field, then drop it.

    Use in an exclusive operator recovery window; the advisory lease serializes
    this verifier's calls, not arbitrary third-party administrative SQL. Never run
    alongside independent legacy restore drills. No plaintext export file exists;
    PostgreSQL holds the temporary recovered state during this explicit drill.
    """

    def verify(
        self,
        snapshot: bytes,
        expected_sources: dict[UUID, str],
        *,
        current_business_state: Engine | None = None,
        operational_journal: bytes | None = None,
    ) -> None:
        try:
            if not snapshot or len(snapshot) > _MAX_STATE_BYTES or not expected_sources:
                raise ValueError("invalid recovery inventory")
            with backup._admin_connection() as admin:
                if not admin.execute(
                    text("SELECT pg_try_advisory_lock(:key)"), {"key": _DRILL_LOCK}
                ).scalar_one():
                    raise ValueError("another recovery verifier is active")
                created = False
                try:
                    active = admin.execute(
                        text("SELECT count(*) FROM pg_stat_activity WHERE datname=:db"),
                        {"db": backup.RESTORE_TEST_DATABASE},
                    ).scalar_one()
                    if active:
                        raise ValueError("restore target in use")
                    admin.execute(text(f"DROP DATABASE IF EXISTS {backup.RESTORE_TEST_DATABASE}"))
                    admin.execute(text(f"CREATE DATABASE {backup.RESTORE_TEST_DATABASE}"))
                    created = True
                    backup.upgrade_restore_test_schema()
                    engine = create_engine(backup.RESTORE_TEST_URL, future=True)
                    try:
                        backup.restore_boundary_stream(engine, io.BytesIO(snapshot))
                        backup.verify_restored_boundary_stream(
                            engine, io.BytesIO(snapshot), boundary=B.BRAINSTORM
                        )
                        if operational_journal is not None:
                            if not 0 < len(operational_journal) <= 4_000_000:
                                raise ValueError("operational journal outside capacity")
                            with engine.begin() as conn:
                                raw = backup._raw_connection(conn)
                                backup._restore_table_csv(
                                    raw, "artifact_backup_run", operational_journal
                                )
                                backup._verify_table_csv(
                                    raw, "artifact_backup_run", operational_journal
                                )
                                if set(
                                    conn.execute(
                                        text(
                                            "SELECT DISTINCT trust_boundary FROM artifact_backup_run"
                                        )
                                    ).scalars()
                                ) - {B.BRAINSTORM.value}:
                                    raise ValueError("operational journal boundary mismatch")
                        if current_business_state is not None:
                            _verify_current_business_state(engine, current_business_state)
                        with Session(engine) as session:
                            for sid, digest in expected_sources.items():
                                source = session.get(Source, sid)
                                if (
                                    source is None
                                    or source.trust_boundary != B.BRAINSTORM
                                    or source.content_hash != digest
                                ):
                                    raise ValueError("required recovery source missing")
                    finally:
                        engine.dispose()
                finally:
                    try:
                        if created:
                            admin.execute(text(f"DROP DATABASE {backup.RESTORE_TEST_DATABASE}"))
                    finally:
                        admin.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _DRILL_LOCK})
        except Exception:  # noqa: BLE001 - private state/admin diagnostics
            raise ReviewProtectionError("state restore verification failed") from None


def assert_local_review_state_engine(engine: Engine) -> None:
    """Only existing Mac Studio dev state or the guarded synthetic test DB."""
    url = engine.url
    if (
        url.drivername != "postgresql+psycopg"
        or url.host != "127.0.0.1"
        or url.port not in (None, 5432)
        or url.database not in ("zacai_dev", "zacai_test")
        or url.password
        or url.query
    ):
        raise ReviewProtectionError("local review state target required")


def _verify_current_business_state(restored: Engine, current: Engine) -> None:
    """Conservative checkpoint freshness without the authority/audit cycle.

    Compare every non-Source canonical table in the current revision, and every
    original checkpoint Source field. Additional Sources alone are permitted;
    the caller separately requires selected/dependency Sources in the checkpoint.
    This permits new consent/claim/audit records, never ignores business rows,
    classifications, retractions, project versions or original Source changes.
    An unrelated business change can also require a new protected checkpoint.
    """
    assert_local_review_state_engine(current)
    assert_safe_restore_target_url(restored.url.render_as_string(hide_password=False))
    with current.connect() as live, restored.connect() as recovered:
        for conn in (live, recovered):
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        if live.scalar(text("SELECT current_database()")) != current.url.database:
            raise ValueError("current state target mismatch")
        assert_connected_to_safe_restore_database(
            recovered.scalar(text("SELECT current_database()"))
        )
        revisions = live.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        if len(revisions) != 1 or revisions[0] not in ("0004", "0005"):
            raise ValueError("unsupported current review schema")
        live_raw, recovered_raw = backup._raw_connection(live), backup._raw_connection(recovered)
        for table in backup._SCHEMA_TABLES[revisions[0]][1:]:
            if backup._export_table_csv(live_raw, table, B.BRAINSTORM.value) != (
                backup._export_table_csv(recovered_raw, table, B.BRAINSTORM.value)
            ):
                raise ValueError("business state changed since recovery checkpoint")
        for table in set(backup.TABLE_ORDER) - set(backup._SCHEMA_TABLES[revisions[0]]):
            if recovered.scalar(text(f"SELECT EXISTS (SELECT 1 FROM {table})")):
                raise ValueError("current schema omitted recovered business evidence")
        ids = (
            recovered.execute(
                text("SELECT id FROM source WHERE trust_boundary='BRAINSTORM' ORDER BY id")
            )
            .scalars()
            .all()
        )
        query = (
            "COPY (SELECT * FROM source WHERE trust_boundary = %s AND id = ANY(%s) "
            "ORDER BY id) TO STDOUT WITH (FORMAT csv, HEADER true)"
        )
        with live_raw.cursor() as cur, cur.copy(query, (B.BRAINSTORM.value, ids)) as copy:
            expected = backup._export_table_csv(recovered_raw, "source", B.BRAINSTORM.value)
            offset = 0
            for chunk in copy:
                data = bytes(chunk)
                if expected[offset : offset + len(data)] != data:
                    raise ValueError("checkpoint Source changed")
                offset += len(data)
            if offset != len(expected):
                raise ValueError("checkpoint Source changed")


class BrainstormReviewProtector:
    """Verify committed audit/authority and encrypted off-device recovery.

    Host supplies approved independent object clients, recipient and identity.
    The actual disposable verifier is mandatory; strings/success flags cannot
    substitute for restoration. No live invocation or recovery permission exists
    merely because this class is constructed.
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
        approval_id: UUID,
        restoration: DisposableStateRestoreVerifier,
    ) -> None:
        if factory.kw.get("bind") is not engine or objects is verification_objects:
            raise ReviewProtectionError("invalid review protection wiring")
        self._factory, self._engine, self._artifacts = factory, engine, artifacts
        self._objects, self._reader = objects, verification_objects
        self._recipient, self._identity, self._cache = recipient, identity_path, manifest_cache
        self._approval, self._restoration = approval_id, restoration

    def _read(self, session: Session, sid: UUID, system: SourceSystem) -> tuple[Source, bytes]:
        source = session.get(Source, sid)
        if (
            source is None
            or source.system != system
            or source.trust_boundary != B.BRAINSTORM
            or not source.content_hash
            or not source.content_location
            or get_effective_source_classification(session, source_id=sid) != C.CONFIDENTIAL
        ):
            raise ValueError("invalid committed review source")
        raw = self._artifacts.get(B.BRAINSTORM, source.content_location)
        if len(raw) > 64_000 or content_hash_of(raw) != source.content_hash:
            raise ValueError("review artifact integrity failed")
        return source, raw

    def protect(self, run_id: UUID, audit_source_ids: tuple[UUID, ...]) -> None:
        try:
            if len(audit_source_ids) != 3 or len(set(audit_source_ids)) != 3:
                raise ValueError("incomplete review audit")
            hashes: dict[UUID, str] = {}
            with self._factory() as session:
                approval, raw = self._read(session, self._approval, SourceSystem.USER_INSTRUCTION)
                consent = ReviewConsent.model_validate_json(raw)
                if approval.external_ref != f"review-consent/{consent.id}":
                    raise ValueError("invalid consent")
                assert approval.content_hash is not None
                hashes[approval.id] = approval.content_hash
                claim_id = session.execute(
                    select(Source.id).where(
                        Source.trust_boundary == B.BRAINSTORM,
                        Source.system == SourceSystem.MANUAL,
                        Source.external_ref == f"review-claim/{self._approval}",
                    )
                ).scalar_one()
                claim, raw = self._read(session, claim_id, SourceSystem.MANUAL)
                consumed = json.loads(raw)
                if (
                    set(consumed)
                    != {"format", "approval_id", "run_id", "context_digest", "prepared_digest"}
                    or consumed["format"] != "zac-review-claim-v1"
                    or consumed["approval_id"] != str(self._approval)
                    or consumed["run_id"] != str(run_id)
                    or consumed["prepared_digest"] != consent.prepared_digest
                ):
                    raise ValueError("claim mismatch")
                assert claim.content_hash is not None
                hashes[claim.id] = claim.content_hash
                task_id = None
                for sid, stage in zip(
                    audit_source_ids,
                    (
                        ReviewAuditStage.REQUEST_PREPARED,
                        ReviewAuditStage.DISPATCH_STARTED,
                        ReviewAuditStage.DRAFT_VALIDATED,
                    ),
                    strict=True,
                ):
                    source, raw = self._read(session, sid, SourceSystem.MANUAL)
                    event = ReviewAuditEvent.model_validate_json(raw)
                    if (
                        event.run_id != run_id
                        or event.stage != stage
                        or event.trust_boundary != B.BRAINSTORM
                        or event.data_classification != C.CONFIDENTIAL
                        or event.context_digest != consumed["context_digest"]
                        or event.route != consent.route.identity
                        or source.external_ref != f"meeting-review-audit/{event.audit_event_id}"
                        or task_id is not None
                        and event.task_id != task_id
                    ):
                        raise ValueError("audit binding mismatch")
                    task_id = event.task_id
                    assert source.content_hash is not None
                    hashes[sid] = source.content_hash
            challenge = b"zacai BRAINSTORM review recipient-identity readiness"
            if age_decrypt(age_encrypt(challenge, self._recipient), self._identity) != challenge:
                raise ValueError("backup identity mismatch")
            result = run_artifact_backup(
                self._factory,
                trust_boundary=B.BRAINSTORM,
                artifact_store=self._artifacts,
                backup_store=self._objects,
                recipient=self._recipient,
                local_manifest_cache_path=self._cache,
            )
            if result.status != ArtifactBackupRunStatus.SUCCEEDED:
                raise ValueError("artifact backup incomplete")
            for digest in hashes.values():
                returned = self._reader.get_object(backup_object_key_for(B.BRAINSTORM, digest))
                if content_hash_of(age_decrypt(returned, self._identity)) != digest:
                    raise ValueError("remote artifact recovery failed")
            with BoundedStateBuffer() as buffer:
                backup.export_boundary_stream(self._engine, B.BRAINSTORM, buffer)
                snapshot = buffer.getvalue()
            encrypted = age_encrypt(snapshot, self._recipient)
            digest = content_hash_of(encrypted)
            key = f"BRAINSTORM/state/review-{run_id}/{digest}.age"
            self._objects.put_object(key, encrypted)
            returned = self._reader.get_object(key)
            if content_hash_of(returned) != digest:
                raise ValueError("remote state ciphertext mismatch")
            recovered = age_decrypt(returned, self._identity)
            if content_hash_of(recovered) != content_hash_of(snapshot):
                raise ValueError("remote state mismatch")
            self._restoration.verify(recovered, hashes)
        except Exception:  # noqa: BLE001
            raise ReviewProtectionError("review protection verification failed") from None
