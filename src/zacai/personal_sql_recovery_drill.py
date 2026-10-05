"""Guarded PERSONAL invented-state SQL preparation and restore adapter.

No URL, SQL, fixture text or private snapshot is caller supplied. Constructor has
no I/O. Calls require the host's exclusive restore window; this adapter's advisory
lock plus backup shared administrative lease serialize cooperating operators.
Non-cooperating direct SQL/admin actors still require the exclusive host window.
No credentials,
crypto, cloud clients, ingestion authority or automatic retry are implemented.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from typing import Literal, Self
from uuid import UUID, uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from zacai import backup
from zacai.backup_safety import (
    assert_connected_to_safe_restore_database,
    assert_safe_restore_target_url,
)
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import CommitmentStatus, EvidenceStance, SourceSystem
from zacai.state_repository import EvidenceInput, create_commitment, create_person, record_source

_FIXTURES = (b"invented PERSONAL SQL drill evidence v1", b"invented PERSONAL SQL drill evidence v2")
_LOCK = 0x50455253
_MAX_SNAPSHOT = 2_000_000


class PersonalSqlDrillError(RuntimeError):
    """Closed diagnostic; never includes SQL, paths, source values or DB errors."""


def _closed[**P, R](operation: Callable[P, R]) -> Callable[P, R]:
    @wraps(operation)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return operation(*args, **kwargs)
        except Exception:  # noqa: BLE001, S110 - strip exception context
            pass
        raise PersonalSqlDrillError("personal synthetic SQL drill rejected")

    return wrapped


@dataclass(frozen=True)
class PreparedPersonalSqlSnapshot:
    run_id: UUID
    snapshot_hash: str
    snapshot_bytes: bytes
    artifact_hashes: tuple[str, ...]

    @property
    def ingestion_authorized(self) -> Literal[False]:
        return False

    @property
    def off_device_verified(self) -> Literal[False]:
        return False


class PersonalSqlDrill:
    """One exclusive lifecycle: prepare -> retrieve -> restore_exact -> cleanup.

    The host supplies a disposable artifact store. Only fixed invented bytes are
    written there. The fixed restore DB must initially be absent; creation uses
    CREATE without DROP, so a concurrently appearing target is never destroyed.
    Database OID ownership is checked before each destructive cleanup/rebuild.
    The retained backup admin lease covers cooperating helpers and the existing
    review verifier, including nested helpers. The parent must still exclude
    non-cooperating/direct administrative actors throughout this lifecycle.
    """

    def __init__(self, *, run_id: UUID, artifacts: ArtifactStore) -> None:
        if type(run_id) is not UUID:
            raise PersonalSqlDrillError("personal synthetic SQL drill rejected")
        self._run_id = run_id
        self._artifacts = artifacts
        self._stack = ExitStack()
        self._admin: Connection | None = None
        self._engine: Engine | None = None
        self._owned_oid: int | None = None
        self._prepared: PreparedPersonalSqlSnapshot | None = None
        self._restored = False
        self._prepare_attempted = False
        self._restore_attempted = False
        self._entered = False

    @_closed
    def __enter__(self) -> Self:
        if self._entered:
            raise ValueError("one lifecycle only")
        self._entered = True
        try:
            assert_safe_restore_target_url(backup.RESTORE_TEST_URL)
            self._admin = self._stack.enter_context(backup._admin_connection())
            if not self._admin.scalar(text("SELECT pg_try_advisory_lock(:lock)"), {"lock": _LOCK}):
                raise ValueError("exclusive window unavailable")
            self._create_empty()
            return self
        except BaseException:
            self._cleanup()
            raise

    def _current_oid(self) -> int | None:
        if self._admin is None:
            raise ValueError("no owned window")
        value = self._admin.scalar(
            text("SELECT oid FROM pg_database WHERE datname=:name"),
            {"name": backup.RESTORE_TEST_DATABASE},
        )
        return None if value is None else int(value)

    def _assert_owned(self) -> None:
        if self._owned_oid is None or self._current_oid() != self._owned_oid:
            raise ValueError("restore database not owned")

    def _create_empty(self) -> None:
        if self._current_oid() is not None or self._admin is None:
            raise ValueError("target occupied")
        self._admin.execute(text(f"CREATE DATABASE {backup.RESTORE_TEST_DATABASE}"))
        self._owned_oid = self._current_oid()
        if self._owned_oid is None:
            raise ValueError("target creation unconfirmed")
        backup.upgrade_restore_test_schema()
        self._engine = create_engine(backup.RESTORE_TEST_URL, future=True)
        with self._engine.connect() as conn:
            assert_connected_to_safe_restore_database(
                conn.scalar(text("SELECT current_database()"))
            )
        self._assert_owned()

    def _export(self) -> bytes:
        if self._engine is None:
            raise ValueError("no owned engine")
        self._assert_owned()
        stream = io.BytesIO()
        backup.export_boundary_stream(self._engine, B.PERSONAL, stream)
        value = stream.getvalue()
        if not 0 < len(value) <= _MAX_SNAPSHOT:
            raise ValueError("snapshot outside bound")
        return value

    @_closed
    def prepare(self) -> PreparedPersonalSqlSnapshot:
        if self._prepare_attempted or self._engine is None:
            raise ValueError("one preparation only")
        self._prepare_attempted = True
        self._assert_owned()
        hashes = tuple(content_hash_of(raw) for raw in _FIXTURES)
        sources = []
        with Session(self._engine) as session, session.begin():
            for raw, digest in zip(_FIXTURES, hashes, strict=True):
                location = self._artifacts.put(B.PERSONAL, digest, raw)
                if self._artifacts.get(B.PERSONAL, location) != raw:
                    raise ValueError("artifact integrity")
                source, _ = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    content_hash=digest,
                    content_location=location,
                    external_ref=f"synthetic-personal-sql-drill/{self._run_id}/revision",
                    captured_at=datetime(2026, 1, 1, tzinfo=UTC),
                )
                sources.append(source)
            person_id, commitment_id = uuid4(), uuid4()
            for index, source in enumerate(sources):
                evidence = [EvidenceInput(source.id, EvidenceStance.SUPPORTS, 1.0)]
                create_person(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.CONFIDENTIAL,
                    display_name=f"Invented drill person version {index + 1}",
                    entity_id=person_id,
                    evidence=evidence,
                )
                create_commitment(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.CONFIDENTIAL,
                    owner_person_id=person_id,
                    description=f"Invented drill commitment version {index + 1}",
                    entity_id=commitment_id,
                    evidence=evidence,
                    status=CommitmentStatus.OPEN if index == 0 else CommitmentStatus.DONE,
                )
        snapshot = self._export()
        self._prepared = PreparedPersonalSqlSnapshot(
            self._run_id, content_hash_of(snapshot), snapshot, hashes
        )
        return self._prepared

    @_closed
    def restore_exact(self, retrieved_snapshot: bytes) -> str:
        if (
            self._prepared is None
            or self._restore_attempted
            or type(retrieved_snapshot) is not bytes
            or retrieved_snapshot != self._prepared.snapshot_bytes
        ):
            raise ValueError("not the prepared original snapshot")
        self._restore_attempted = True
        self._assert_owned()
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
        backup.drop_restore_test_database()
        self._owned_oid = None
        self._create_empty()
        assert self._engine is not None
        backup.restore_boundary_stream(self._engine, io.BytesIO(retrieved_snapshot))
        backup.verify_restored_boundary_stream(
            self._engine, io.BytesIO(retrieved_snapshot), boundary=B.PERSONAL
        )
        if self._export() != retrieved_snapshot:
            raise ValueError("full state readback differs")
        self._restored = True
        return content_hash_of(retrieved_snapshot)

    def _cleanup(self) -> None:
        try:
            if self._engine is not None:
                self._engine.dispose()
                self._engine = None
            if self._owned_oid is not None:
                self._assert_owned()
                backup.drop_restore_test_database()
                self._owned_oid = None
        finally:
            self._stack.close()
            self._admin = None

    @_closed
    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self._cleanup()
