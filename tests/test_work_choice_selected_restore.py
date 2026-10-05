"""Historical recovery regression; guarded invented zacai_test/restore_test only.

No production database, source, external object store or credential is used.
"""

import csv
import io
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from zacai import backup
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionError
from zacai.state import EvidenceStance, SourceSystem
from zacai.state_repository import EvidenceInput, create_person, record_source


def test_historical_snapshot_remains_exact_after_unrelated_business_growth(test_session_factory):
    engine = test_session_factory.kw["bind"]
    original_excerpt = f"invented original provenance {uuid4()}"
    with test_session_factory() as session:
        source, _ = record_source(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.USER_INSTRUCTION,
            content_hash="a" * 64,
            content_location="invented-source-location",
            external_ref=f"invented-history-{uuid4()}",
            excerpt=original_excerpt,
        )
        sid = source.id
        session.commit()
    snapshot = io.BytesIO()
    backup.export_boundary_stream(engine, B.BRAINSTORM, snapshot)
    with test_session_factory() as session:
        create_person(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            display_name="Invented later business entity",
            evidence=[EvidenceInput(source_id=sid, stance=EvidenceStance.SUPPORTS, confidence=1)],
        )
        session.commit()
    verifier = DisposableStateRestoreVerifier()
    # All old rows/fields restore, exact selected Source stays unchanged; new
    # business rows do not retroactively invalidate historical recovery proof.
    verifier.verify(snapshot.getvalue(), {sid: "a" * 64}, current_selected_sources=engine)
    # Existing full-current mode remains conservative and unchanged.
    with pytest.raises(ReviewProtectionError):
        verifier.verify(snapshot.getvalue(), {sid: "a" * 64}, current_business_state=engine)
    # Mutate only invented snapshot bytes, preserving append-only live Source.
    # Rebuild every byte-length frame with the existing parser/serializer.
    stream, altered = io.BytesIO(snapshot.getvalue()), io.BytesIO()
    assert backup._read_line(stream) == backup._BACKUP_MAGIC
    revision, boundary = backup._read_line(stream), backup._read_line(stream)
    altered.write(f"{backup._BACKUP_MAGIC}\n{revision}\n{boundary}\n".encode())
    changed = False
    for table in backup._SCHEMA_TABLES[revision]:
        assert backup._read_line(stream) == table
        data = backup._read_exact(stream, int(backup._read_line(stream)))
        if table == "source":
            backup._csv_columns(table, data)
            rows = list(csv.DictReader(io.StringIO(data.decode())))
            selected = [row for row in rows if row["id"] == str(sid)]
            assert len(selected) == 1 and selected[0]["content_hash"] == "a" * 64
            assert selected[0]["excerpt"] == original_excerpt
            assert data.count(original_excerpt.encode()) == 1
            # This unique ASCII field needs no CSV quoting; all other original
            # bytes/NULL quoting stay untouched.
            data = data.replace(original_excerpt.encode(), b"invented changed snapshot provenance")
            changed = True
        backup._write_frame(altered, table, data)
    assert changed and stream.read() == b""
    # A changed historical row still has the same UUID/hash and full frames can
    # restore correctly, but exact comparison to current provenance rejects it.
    verifier.verify(altered.getvalue(), {sid: "a" * 64})
    with pytest.raises(ReviewProtectionError):
        verifier.verify(altered.getvalue(), {sid: "a" * 64}, current_selected_sources=engine)


@pytest.mark.parametrize("inventory", [{"not-a-uuid": "a" * 64}, {uuid4(): "not-a-digest"}])
def test_invalid_selected_inventory_refused_before_restore_target(monkeypatch, inventory):
    def forbidden():
        pytest.fail("invalid selected inventory must fail before target acquisition")

    monkeypatch.setattr(backup, "_admin_connection", forbidden)
    engine = create_engine("postgresql+psycopg://127.0.0.1:5432/zacai_test")
    try:
        with pytest.raises(ReviewProtectionError):
            DisposableStateRestoreVerifier().verify(
                b"invented", inventory, current_selected_sources=engine
            )
    finally:
        engine.dispose()
