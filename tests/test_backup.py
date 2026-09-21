"""Tests for the D028 backup/restore pipeline in zacai.backup.

Uses `zacai_test` (D027) as the export source and `zacai_restore_test`
(D028's own disposable drill database, recreated/dropped only through the
fixed-constant, guarded functions under test) as the restore target.
`zacai_dev` is never connected to by any test in this file - that is
verified separately, manually, exactly as D027 itself was.

Encryption is exercised with `cat` (a no-op passthrough) rather than
`age`, so these tests prove the framing/streaming/FK-order logic
independent of whether `age` is installed - `age`'s own encrypt/decrypt
correctness is a separate, external-tool concern this module does not
need to re-test.

Tests that need the export/restore machinery (which opens its own,
separate database connections) to see data use `test_session_factory`
(D027) and a real `.commit()` - never the rollback/SAVEPOINT-based
`db_session` fixture, whose data is never visible outside its own
connection. Synthetic rows these tests commit are left in `zacai_test`
until the next session's D027 reset, exactly like the D026 concurrency
tests.
"""

from __future__ import annotations

import csv
import inspect
import io
import stat
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup import (
    TABLE_ORDER,
    _read_exact,
    _read_line,
    _write_frame,
    drop_restore_test_database,
    export_boundary,
    export_boundary_stream,
    recreate_restore_test_database,
    restore_boundary,
    restore_boundary_stream,
    upgrade_restore_test_schema,
)
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import (
    CompanyRelationshipKind,
    MeetingSourceRole,
    PersonCompanyRelationshipKind,
    Source,
    SourceSystem,
)
from zacai.state_repository import (
    EvidenceInput,
    EvidenceStance,
    MeetingSourceInput,
    create_commitment,
    create_company,
    create_decision,
    create_meeting,
    create_person,
    create_project,
    record_person_company_relationship,
)

RESTORE_TEST_URL = "postgresql+psycopg://127.0.0.1:5432/zacai_restore_test"
_TEST_DB_URL = "postgresql+psycopg://127.0.0.1:5432/zacai_test"


def _make_source(session: Session, *, trust_boundary: TrustBoundary) -> uuid.UUID:
    source = Source(
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
        excerpt="D028 backup test fixture",
    )
    session.add(source)
    session.flush()
    return source.id


def _parse_frames(stream: io.BytesIO) -> dict[str, bytes]:
    stream.seek(0)
    frames: dict[str, bytes] = {}
    for expected_table in TABLE_ORDER:
        table = _read_line(stream)
        assert table == expected_table
        length = int(_read_line(stream))
        frames[table] = _read_exact(stream, length)
    return frames


# --- export framing: boundary purity ----------------------------------------


def test_export_boundary_stream_excludes_other_boundaries(
    test_session_factory: sessionmaker[Session], _test_engine: Engine
) -> None:
    personal_marker = f"D028-personal-{uuid.uuid4()}"
    brainstorm_marker = f"D028-brainstorm-{uuid.uuid4()}"

    with test_session_factory() as session:
        personal_source = _make_source(session, trust_boundary=TrustBoundary.PERSONAL)
        create_person(
            session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            display_name=personal_marker,
            evidence=[EvidenceInput(source_id=personal_source, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
        )
        brainstorm_source = _make_source(session, trust_boundary=TrustBoundary.BRAINSTORM)
        create_person(
            session,
            trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.INTERNAL,
            display_name=brainstorm_marker,
            evidence=[EvidenceInput(source_id=brainstorm_source, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
        )
        session.commit()

    out = io.BytesIO()
    export_boundary_stream(_test_engine, TrustBoundary.PERSONAL, out)
    frames = _parse_frames(out)

    person_csv = frames["person"].decode()
    assert personal_marker in person_csv
    assert brainstorm_marker not in person_csv


# --- restore ordering --------------------------------------------------------


def test_restore_boundary_stream_rejects_out_of_order_frames(_test_engine: Engine) -> None:
    bad_stream = io.BytesIO()
    bad_stream.write(b"person\n0\n")  # "person" is not TABLE_ORDER[0] ("source")
    bad_stream.seek(0)

    with pytest.raises(RuntimeError, match="frame order mismatch"):
        restore_boundary_stream(_test_engine, bad_stream)


# --- export_boundary: filesystem safety -------------------------------------


def test_export_boundary_creates_artifact_with_restrictive_permissions(tmp_path: Path) -> None:
    output = tmp_path / "artifact.bin"
    export_boundary(_TEST_DB_URL, TrustBoundary.PERSONAL, output, ["cat"])

    mode = stat.S_IMODE(output.stat().st_mode)
    assert oct(mode) == "0o600"


def test_export_boundary_leaves_no_other_file_behind(tmp_path: Path) -> None:
    output = tmp_path / "artifact.bin"
    export_boundary(_TEST_DB_URL, TrustBoundary.PERSONAL, output, ["cat"])

    assert list(tmp_path.iterdir()) == [output]


def test_export_boundary_removes_partial_file_on_encryption_failure(tmp_path: Path) -> None:
    output = tmp_path / "artifact.bin"

    with pytest.raises(RuntimeError, match="exited with status"):
        export_boundary(_TEST_DB_URL, TrustBoundary.PERSONAL, output, ["false"])

    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


# --- fixed-constant proof for destructive operations ------------------------


def test_recreate_restore_test_database_has_no_target_parameter() -> None:
    assert inspect.signature(recreate_restore_test_database).parameters == {}


def test_drop_restore_test_database_has_no_target_parameter() -> None:
    assert inspect.signature(drop_restore_test_database).parameters == {}


# --- restore-target guard used by restore_boundary --------------------------


def test_restore_boundary_refuses_unsafe_target(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"irrelevant - guard must reject before reading this")

    with pytest.raises(RuntimeError, match="zacai_restore_test"):
        restore_boundary(artifact, "postgresql+psycopg://127.0.0.1:5432/zacai_dev", ["cat"])


# --- full drill: export from zacai_test, restore into zacai_restore_test ---


def test_full_export_restore_drill_round_trip(test_session_factory: sessionmaker[Session]) -> None:
    marker = f"D028-drill-{uuid.uuid4()}"

    with test_session_factory() as session:
        source_id = _make_source(session, trust_boundary=TrustBoundary.PERSONAL)
        owner = create_person(
            session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            display_name=marker,
            evidence=[EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
        )
        create_commitment(
            session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            owner_person_id=owner.entity_id,
            description=marker,
            evidence=[EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
        )
        session.commit()

    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "personal.bin"
        export_boundary(_TEST_DB_URL, TrustBoundary.PERSONAL, artifact, ["cat"])

        recreate_restore_test_database()
        try:
            upgrade_restore_test_schema()
            restore_boundary(artifact, RESTORE_TEST_URL, ["cat"])

            restore_engine = create_engine(RESTORE_TEST_URL, future=True)
            try:
                with restore_engine.connect() as conn:
                    person_row = conn.execute(
                        text("SELECT trust_boundary FROM person WHERE display_name = :name"),
                        {"name": marker},
                    ).one()
                    assert person_row.trust_boundary == "PERSONAL"

                    commitment_row = conn.execute(
                        text("SELECT trust_boundary FROM commitment WHERE description = :desc"),
                        {"desc": marker},
                    ).one()
                    assert commitment_row.trust_boundary == "PERSONAL"

                    all_boundaries = (
                        conn.execute(
                            text(
                                "SELECT DISTINCT trust_boundary FROM person "
                                "UNION SELECT DISTINCT trust_boundary FROM commitment"
                            )
                        )
                        .scalars()
                        .all()
                    )
                    assert set(all_boundaries) <= {"PERSONAL"}

                    # Append-only trigger must survive a fresh Alembic-built
                    # schema in the restore-test database, not just zacai_dev.
                    with pytest.raises(Exception, match="append-only"):
                        conn.execute(
                            text("UPDATE person SET display_name = 'x' WHERE display_name = :name"),
                            {"name": marker},
                        )
                        conn.commit()
                    conn.rollback()
            finally:
                restore_engine.dispose()
        finally:
            drop_restore_test_database()


# --- D029: extended round-trip and the reversed-order Decision drill -------


def _reverse_decision_rows(decision_csv: bytes, first_marker: str, second_marker: str) -> bytes:
    """Reorders exactly the two rows whose `description` matches
    `first_marker`/`second_marker` so `second_marker` (the superseding
    decision) appears BEFORE `first_marker` (the superseded one) in the
    CSV - the opposite of natural insertion order. Used to prove
    `decision.supersedes_decision_id`'s DEFERRABLE INITIALLY DEFERRED
    foreign key, not row order, is what makes restore safe (D029)."""
    reader = csv.DictReader(io.StringIO(decision_csv.decode()))
    fieldnames = reader.fieldnames
    assert fieldnames is not None
    rows = list(reader)

    first = next(row for row in rows if row["description"] == first_marker)
    second = next(row for row in rows if row["description"] == second_marker)
    others = [row for row in rows if row["description"] not in (first_marker, second_marker)]

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows([*others, second, first])
    return out.getvalue().encode()


def test_decision_supersession_restores_with_reversed_row_order(
    test_session_factory: sessionmaker[Session],
) -> None:
    boundary = TrustBoundary.BRAINSTORM
    marker_a = f"D029-reversed-A-{uuid.uuid4()}"
    marker_b = f"D029-reversed-B-{uuid.uuid4()}"

    with test_session_factory() as session:
        source_id = _make_source(session, trust_boundary=boundary)
        evidence = [EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)]
        decision_a = create_decision(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            description=marker_a,
            evidence=evidence,
        )
        create_decision(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            description=marker_b,
            evidence=evidence,
            supersedes_decision_id=decision_a.id,
        )
        session.commit()
        decision_a_id = decision_a.id

    engine = create_engine(_TEST_DB_URL, future=True)
    try:
        raw_stream = io.BytesIO()
        export_boundary_stream(engine, boundary, raw_stream)
    finally:
        engine.dispose()

    frames = _parse_frames(raw_stream)
    frames["decision"] = _reverse_decision_rows(frames["decision"], marker_a, marker_b)

    rebuilt = io.BytesIO()
    for table in TABLE_ORDER:
        _write_frame(rebuilt, table, frames[table])

    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "reversed.bin"
        artifact.write_bytes(rebuilt.getvalue())

        recreate_restore_test_database()
        try:
            upgrade_restore_test_schema()
            # Must not raise - the deferred FK is what makes this safe,
            # not the (here, deliberately wrong) row order.
            restore_boundary(artifact, RESTORE_TEST_URL, ["cat"])

            verify_engine = create_engine(RESTORE_TEST_URL, future=True)
            try:
                with verify_engine.connect() as conn:
                    row_b = conn.execute(
                        text("SELECT supersedes_decision_id FROM decision WHERE description = :d"),
                        {"d": marker_b},
                    ).one()
                    assert row_b.supersedes_decision_id == decision_a_id
            finally:
                verify_engine.dispose()
        finally:
            drop_restore_test_database()


def test_extended_d029_backup_restore_round_trip(test_session_factory: sessionmaker[Session]) -> None:
    """Proves the D029 tables (Company, Project, Decision, Meeting,
    PersonCompanyRelationship, and their typed link/evidence/retraction
    tables) restore correctly via the same generic D028 pipeline - no
    pipeline code change was needed, only extending TABLE_ORDER."""
    boundary = TrustBoundary.BRAINSTORM
    marker = f"D029-extended-{uuid.uuid4()}"

    with test_session_factory() as session:
        source_id = _make_source(session, trust_boundary=boundary)
        evidence = [EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)]

        company = create_company(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            name=marker,
            relationship_kind=CompanyRelationshipKind.CLIENT,
            evidence=evidence,
        )
        project = create_project(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            name=marker,
            company_id=company.entity_id,
            evidence=evidence,
        )
        owner = create_person(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            display_name=marker,
            evidence=evidence,
        )
        record_person_company_relationship(
            session,
            person_id=owner.entity_id,
            company_id=company.entity_id,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            relationship_kind=PersonCompanyRelationshipKind.EMPLOYEE,
            source_id=source_id,
        )
        create_commitment(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            owner_person_id=owner.entity_id,
            description=marker,
            project_id=project.entity_id,
            evidence=evidence,
        )
        meeting = create_meeting(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            title=marker,
            occurred_at=datetime.now(UTC),
            sources=[MeetingSourceInput(source_id=source_id, source_role=MeetingSourceRole.TRANSCRIPT)],
            project_id=project.entity_id,
            attendees=[owner.entity_id],
        )
        create_decision(
            session,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            description=marker,
            evidence=evidence,
            project_id=project.entity_id,
            meeting_id=meeting.id,
        )
        session.commit()

    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "extended.bin"
        export_boundary(_TEST_DB_URL, boundary, artifact, ["cat"])

        recreate_restore_test_database()
        try:
            upgrade_restore_test_schema()
            restore_boundary(artifact, RESTORE_TEST_URL, ["cat"])

            engine = create_engine(RESTORE_TEST_URL, future=True)
            try:
                with engine.connect() as conn:
                    for table in (
                        "company",
                        "project",
                        "person_company_relationship",
                        "meeting",
                        "meeting_source",
                        "meeting_attendee",
                        "decision",
                    ):
                        count = conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
                        assert count >= 1, f"{table} has no restored rows"

                    # Append-only still active on a D029 table in the
                    # freshly Alembic-built restore-test schema.
                    with pytest.raises(Exception, match="append-only"):
                        conn.execute(text("UPDATE company SET name = 'x' WHERE name = :n"), {"n": marker})
                        conn.commit()
                    conn.rollback()
            finally:
                engine.dispose()
        finally:
            drop_restore_test_database()
