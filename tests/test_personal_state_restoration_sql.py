"""Root-only invented full PERSONAL State and journal; no escrow/owner/crypto claim."""

import csv
import io
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text

from tests.conftest import assert_connected_to_safe_test_database, assert_safe_test_database_url
from zacai import backup
from zacai import review_protection as module
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionError
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, SourceSystem
from zacai.state_repository import record_source


@pytest.mark.parametrize(
    "fault", [None, "missing", "snapshot_boundary", "journal_boundary", "metadata", "occupied"]
)
def test_actual_personal_full_state_journal_and_selected_copy(
    test_session_factory, fault, monkeypatch
):
    stages = []

    def observe(name, function):
        def run(*args, **kwargs):
            try:
                result = function(*args, **kwargs)
            except Exception:
                stages.append((name, "raised"))
                raise
            stages.append((name, "passed"))
            return result

        return run

    monkeypatch.setattr(
        backup,
        "verify_restored_boundary_stream",
        observe("state_boundary", backup.verify_restored_boundary_stream),
    )
    monkeypatch.setattr(
        module, "_verify_personal_journal", observe("journal", module._verify_personal_journal)
    )
    monkeypatch.setattr(
        module,
        "_verify_personal_selected_source_rows",
        observe("selected", module._verify_personal_selected_source_rows),
    )
    engine = test_session_factory.kw["bind"]
    assert_safe_test_database_url(engine.url.render_as_string(hide_password=False))
    with engine.connect() as connection:
        assert_connected_to_safe_test_database(connection.scalar(text("SELECT current_database()")))
    now = datetime.now(UTC)
    sources = []
    # These invented rows represent selected original+companion mechanics only.
    # No actual Claude bytes, custody approval or recovered-key provenance exists.
    with test_session_factory() as session, session.begin():
        for label in ("original", "companion"):
            sid, _ = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.MANUAL,
                content_hash=("a" if label == "original" else "b") * 64,
                content_location=f"{label}-invented-private-location",
                external_ref=f"invented-personal-restore/{uuid4()}/{label}",
                captured_at=now,
                excerpt=f"Invented {label}",
            )
            sources.append((sid.id, sid.content_hash))
        session.add(
            ArtifactBackupRun(
                id=uuid4(),
                trust_boundary=B.PERSONAL,
                status=ArtifactBackupRunStatus.SUCCEEDED,
                started_at=now,
                finished_at=now,
                artifacts_checked=2,
                artifacts_backed_up=2,
                artifacts_already_protected=0,
                artifacts_repaired=0,
                artifacts_failed=0,
            )
        )
        if fault == "journal_boundary":
            session.add(
                ArtifactBackupRun(
                    id=uuid4(),
                    trust_boundary=B.BRAINSTORM,
                    status=ArtifactBackupRunStatus.SUCCEEDED,
                    started_at=now,
                    finished_at=now,
                )
            )
    state = io.BytesIO()
    backup.export_boundary_stream(
        engine, B.BRAINSTORM if fault == "snapshot_boundary" else B.PERSONAL, state
    )
    with engine.connect() as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        journal = backup._export_table_csv(
            backup._raw_connection(connection),
            "artifact_backup_run",
            (B.BRAINSTORM if fault == "journal_boundary" else B.PERSONAL).value,
        )
    expected = dict(sources)
    if fault == "missing":
        expected[uuid4()] = "c" * 64
    if fault == "metadata":
        # Corrupt only the invented snapshot's selected Source metadata. The
        # canonical live ledger stays append-only; its mutation trigger remains.
        original = io.BytesIO(state.getvalue())
        altered = io.BytesIO()
        for _ in range(3):
            altered.write(original.readline())
        changed = 0
        while table_line := original.readline():
            table = table_line.decode("ascii").rstrip("\n")
            size = int(original.readline())
            frame = original.read(size)
            assert len(frame) == size
            if table == "source":
                reader = csv.DictReader(io.StringIO(frame.decode("utf-8")))
                rows = list(reader)
                assert reader.fieldnames is not None
                for row in rows:
                    if row["id"] == str(sources[0][0]):
                        assert row["excerpt"] == "Invented original"
                        row["excerpt"] = "Invented altered excerpt"
                        changed += 1
                text_frame = io.StringIO(newline="")
                writer = csv.DictWriter(
                    text_frame, fieldnames=reader.fieldnames, lineterminator="\n"
                )
                writer.writeheader()
                writer.writerows(rows)
                frame = text_frame.getvalue().encode("utf-8")
            backup._write_frame(altered, table, frame)
        assert changed == 1
        state = altered
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT oid FROM pg_roles WHERE rolname='zacai_personal_restore_pending_v1'")
            )
            is None
        )
    with backup._admin_connection() as admin:
        assert (
            admin.scalar(
                text("SELECT oid FROM pg_database WHERE datname=:name"),
                {"name": backup.RESTORE_TEST_DATABASE},
            )
            is None
        )
    if fault == "occupied":
        with backup._admin_connection() as admin:
            admin.execute(text("CREATE DATABASE zacai_restore_test"))
            owned = admin.scalar(
                text("SELECT oid FROM pg_database WHERE datname='zacai_restore_test'")
            )
    try:
        if fault is None:
            assert (
                DisposableStateRestoreVerifier().verify_personal(
                    state.getvalue(),
                    expected,
                    current_selected_sources=engine,
                    operational_journal=journal,
                )
                is None
            )
        else:
            with pytest.raises(ReviewProtectionError) as error:
                DisposableStateRestoreVerifier().verify_personal(
                    state.getvalue(),
                    expected,
                    current_selected_sources=engine,
                    operational_journal=journal,
                )
            assert type(error.value) is ReviewProtectionError
            assert error.value.__context__ is None
        if fault is None:
            assert stages == [
                ("state_boundary", "passed"),
                ("journal", "passed"),
                ("selected", "passed"),
            ]
        elif fault == "snapshot_boundary":
            assert stages == [("state_boundary", "raised")]
        elif fault == "journal_boundary":
            assert stages == [("state_boundary", "passed"), ("journal", "raised")]
        elif fault in {"missing", "metadata"}:
            assert stages == [
                ("state_boundary", "passed"),
                ("journal", "passed"),
                ("selected", "raised"),
            ]
        else:
            assert fault == "occupied" and stages == []
        with backup._admin_connection() as admin:
            oid = admin.scalar(
                text("SELECT oid FROM pg_database WHERE datname='zacai_restore_test'")
            )
            assert oid == (owned if fault == "occupied" else None)
    finally:
        if fault == "occupied":
            with backup._admin_connection() as admin:
                assert (
                    admin.scalar(
                        text("SELECT oid FROM pg_database WHERE datname='zacai_restore_test'")
                    )
                    == owned
                )
                admin.execute(text("DROP DATABASE zacai_restore_test"))
