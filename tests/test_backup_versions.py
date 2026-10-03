"""D034I versioned backups on invented state in guarded test/drill databases."""

import io
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from tests.test_backup import _make_source, _parse_frames
from zacai import backup
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Base
from zacai.state_repository import EvidenceInput, EvidenceStance, create_person


@pytest.fixture
def drill_engine():
    backup.recreate_restore_test_database()
    backup.upgrade_restore_test_schema()
    engine = create_engine(backup.RESTORE_TEST_URL)
    try:
        yield engine
    finally:
        engine.dispose()
        backup.drop_restore_test_database()


def export(engine, boundary=B.BRAINSTORM):
    out = io.BytesIO()
    backup.export_boundary_stream(engine, boundary, out)
    return out.getvalue()


def test_association_and_retraction_roundtrip(test_session_factory, _test_engine, drill_engine):
    from tests.test_meeting_project_association import _add, _fixture
    from zacai.state_repository import retract_meeting_project_association

    with test_session_factory() as session:
        project, meeting, confirmation = _fixture(session)
        link = _add(session, project, meeting, confirmation)
        withdrawal = retract_meeting_project_association(
            session,
            association_id=link.id,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
            confirmation_source_id=confirmation.id,
        )
        ids = link.id, withdrawal.id, project.entity_id, meeting.id
        session.commit()
    backup.restore_boundary_stream(drill_engine, io.BytesIO(export(_test_engine)))
    with drill_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT project_id, meeting_id, reviewed_project_version FROM "
                "meeting_project_association WHERE id=:id"
            ),
            {"id": ids[0]},
        ).one()
        assert (row.project_id, row.meeting_id, row.reviewed_project_version) == (*ids[2:], 1)
        assert (
            conn.scalar(
                text(
                    "SELECT association_id FROM meeting_project_association_retraction WHERE id=:id"
                ),
                {"id": ids[1]},
            )
            == ids[0]
        )
        assert (
            conn.scalar(text("SELECT project_id FROM meeting WHERE id=:id"), {"id": ids[3]}) is None
        )


def test_repeatable_read_snapshot_excludes_concurrent_later_rows(
    test_session_factory, _test_engine, monkeypatch
):
    original = backup._export_table_csv
    marker = f"snapshot-after-source-{uuid4()}"
    calls = []

    def wrapped(raw, table, boundary):
        if not calls:
            with raw.cursor() as cur:
                cur.execute("SHOW transaction_isolation")
                assert cur.fetchone()[0] == "repeatable read"
                cur.execute("SHOW transaction_read_only")
                assert cur.fetchone()[0] == "on"
        result = original(raw, table, boundary)
        calls.append(table)
        if table == "source":
            with test_session_factory() as session:
                sid = _make_source(session, trust_boundary=B.BRAINSTORM)
                create_person(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.INTERNAL,
                    display_name=marker,
                    evidence=[
                        EvidenceInput(source_id=sid, stance=EvidenceStance.SUPPORTS, confidence=0.9)
                    ],
                )
                session.commit()
        return result

    monkeypatch.setattr(backup, "_export_table_csv", wrapped)
    frames = _parse_frames(io.BytesIO(export(_test_engine)))
    assert marker.encode() not in frames["person"]
    with _test_engine.connect() as conn:
        assert (
            conn.scalar(
                text("SELECT count(*) FROM person WHERE display_name=:name"), {"name": marker}
            )
            == 1
        )


def test_schema_0004_export_and_restore_into_0005(drill_engine):
    from alembic import command
    from alembic.config import Config

    config = Config(str(Path(backup.__file__).resolve().parents[2] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", backup.RESTORE_TEST_URL)
    command.downgrade(config, "0004")
    sid = uuid4()
    with drill_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO source(id,trust_boundary,data_classification,system) "
                "VALUES(:id,'BRAINSTORM','INTERNAL','MANUAL')"
            ),
            {"id": sid},
        )
    raw = export(drill_engine)
    assert raw.startswith(b"zacai-state-backup-v2\n0004\nBRAINSTORM\n")
    assert b"meeting_project_association\n" not in raw
    # Recreate only the disposable drill DB; preserve serialized bytes in memory.
    drill_engine.dispose()
    backup.recreate_restore_test_database()
    backup.upgrade_restore_test_schema()
    backup.restore_boundary_stream(drill_engine, io.BytesIO(raw))
    with drill_engine.connect() as conn:
        assert conn.scalar(text("SELECT id FROM source WHERE id=:id"), {"id": sid}) == sid
        assert conn.scalar(text("SELECT count(*) FROM meeting_project_association")) == 0


@pytest.mark.parametrize("revision", ["0001", "0002", "0003"])
def test_actual_historical_schema_legacy_stream_restores(drill_engine, revision):
    from alembic import command
    from alembic.config import Config

    config = Config(str(Path(backup.__file__).resolve().parents[2] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", backup.RESTORE_TEST_URL)
    command.downgrade(config, revision)
    sid = uuid4()
    with drill_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO source(id,trust_boundary,data_classification,system) "
                "VALUES(:id,'BRAINSTORM','INTERNAL','MANUAL')"
            ),
            {"id": sid},
        )
    owner_id, commitment_id = uuid4(), uuid4()
    with drill_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO person_head(entity_id,trust_boundary,current_version) "
                "VALUES(:id,'BRAINSTORM',1)"
            ),
            {"id": owner_id},
        )
        conn.execute(
            text(
                "INSERT INTO person(entity_id,version,trust_boundary,data_classification,"
                "status,display_name) VALUES(:id,1,'BRAINSTORM','INTERNAL','ACTIVE',"
                "'Invented historical owner')"
            ),
            {"id": owner_id},
        )
        conn.execute(
            text(
                "INSERT INTO commitment_head(entity_id,trust_boundary,current_version) "
                "VALUES(:id,'BRAINSTORM',1)"
            ),
            {"id": commitment_id},
        )
        conn.execute(
            text(
                "INSERT INTO commitment(entity_id,version,trust_boundary,data_classification,"
                "status,owner_person_id,description) VALUES(:id,1,'BRAINSTORM','INTERNAL',"
                "'OPEN',:owner,'Invented historical commitment')"
            ),
            {"id": commitment_id, "owner": owner_id},
        )
    versioned = io.BytesIO(export(drill_engine))
    for _ in range(3):
        backup._read_line(versioned)
    legacy = versioned.read()
    drill_engine.dispose()
    backup.recreate_restore_test_database()
    backup.upgrade_restore_test_schema()
    backup.restore_boundary_stream(drill_engine, io.BytesIO(legacy))
    with drill_engine.connect() as conn:
        assert conn.scalar(text("SELECT id FROM source WHERE id=:id"), {"id": sid}) == sid
        row = conn.execute(
            text("SELECT owner_person_id, project_id FROM commitment WHERE entity_id=:id"),
            {"id": commitment_id},
        ).one()
        assert row.owner_person_id == owner_id
        assert row.project_id is None


@pytest.mark.parametrize(
    "bad",
    [
        b"zacai-state-backup-v2\n0006\nBRAINSTORM\n",
        b"zacai-state-backup-v2\n0005\nunknown\n",
        b"source\n-1\n",
        b"source\n9999999999\n",
        b"source\n2\nx",
        b"x" * 257 + b"\n",
        b"person\n0\n",
    ],
)
def test_invalid_stream_rejected(_test_engine, bad):
    with pytest.raises((RuntimeError, ValueError)):
        backup.restore_boundary_stream(_test_engine, io.BytesIO(bad))


def test_trailing_or_missing_data_rolls_back(drill_engine, _test_engine):
    raw = export(_test_engine)
    for invalid in (raw + b"unexpected\n0\n", raw[:-1]):
        with pytest.raises(RuntimeError):
            backup.restore_boundary_stream(drill_engine, io.BytesIO(invalid))
        with drill_engine.connect() as conn:
            assert conn.scalar(text("SELECT count(*) FROM source")) == 0


def test_failed_decryption_never_commits(_test_engine, drill_engine, tmp_path):
    artifact = tmp_path / "invented.bin"
    artifact.write_bytes(export(_test_engine))
    # Emit a complete valid stream, then fail: DB must still remain empty.
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes()); "
            "sys.stdout.flush(); sys.exit(7)"
        ),
    ]
    with pytest.raises(RuntimeError, match="before commit"):
        backup.restore_boundary(artifact, backup.RESTORE_TEST_URL, command)
    with drill_engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM source")) == 0


def test_inventory_covers_business_tables():
    assert set(backup.TABLE_ORDER) == set(Base.metadata.tables) - {"artifact_backup_run"}


def test_manifest_boundary_mismatch_rolls_back(_test_engine, drill_engine):
    raw = export(_test_engine)
    wrong = raw.replace(b"0005\nBRAINSTORM\n", b"0005\nPERSONAL\n", 1)
    with pytest.raises(RuntimeError, match="boundary mismatch"):
        backup.restore_boundary_stream(drill_engine, io.BytesIO(wrong))
    with drill_engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM source")) == 0


def test_unknown_export_revision_writes_no_stream(drill_engine):
    with drill_engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num='0006'"))
    out = io.BytesIO()
    with pytest.raises(RuntimeError, match="unsupported"):
        backup.export_boundary_stream(drill_engine, B.BRAINSTORM, out)
    assert out.getvalue() == b""


def test_0005_stream_missing_exact_new_tables_rolls_back(_test_engine, drill_engine):
    frames = _parse_frames(io.BytesIO(export(_test_engine)))
    incomplete = io.BytesIO(b"zacai-state-backup-v2\n0005\nBRAINSTORM\n")
    incomplete.seek(0, io.SEEK_END)
    for table in backup.TABLE_ORDER[:-2]:
        backup._write_frame(incomplete, table, frames[table])
    incomplete.seek(0)
    with pytest.raises(RuntimeError, match="incomplete"):
        backup.restore_boundary_stream(drill_engine, incomplete)
    with drill_engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM source")) == 0


def test_mixed_boundary_legacy_stream_rejected(test_session_factory, _test_engine, drill_engine):
    with test_session_factory() as session:
        _make_source(session, trust_boundary=B.PERSONAL)
        session.commit()
    brain = _parse_frames(io.BytesIO(export(_test_engine)))
    personal = _parse_frames(io.BytesIO(export(_test_engine, B.PERSONAL)))
    brain["source"] += personal["source"].split(b"\n", 1)[1]
    legacy = io.BytesIO()
    for table in backup.TABLE_ORDER[:-2]:
        backup._write_frame(legacy, table, brain[table])
    legacy.seek(0)
    with pytest.raises(RuntimeError, match="boundary mismatch"):
        backup.restore_boundary_stream(drill_engine, legacy)
    with drill_engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM source")) == 0
