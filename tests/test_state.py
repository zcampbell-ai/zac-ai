"""Tests for the D026 Zac State schema itself: fail-closed CHECK
constraints and the append-only triggers, independent of the
`state_repository` layer that normally sits in front of them.

Uses the disposable `zacai_test` database only (D027), synthetic data
only, rolled back via the `db_session` fixture (tests/conftest.py) -
nothing here is left behind.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from zacai.policy import DataClassification, TrustBoundary
from zacai.state import PersonHead, Source, SourceSystem


def _insert_source_raw(session: Session, trust_boundary: str, data_classification: str = "INTERNAL") -> None:
    """Bypasses the ORM's own client-side enum validation (which would
    otherwise reject an invalid literal in Python before any SQL is sent)
    so the database's own CHECK constraint is what's actually exercised."""
    session.execute(
        text(
            "INSERT INTO source (id, trust_boundary, data_classification, system, captured_at) "
            "VALUES (gen_random_uuid(), :boundary, :classification, 'MANUAL', now())"
        ),
        {"boundary": trust_boundary, "classification": data_classification},
    )
    session.flush()


# --- fail-closed enum CHECK constraints -------------------------------------


def test_source_rejects_invalid_trust_boundary(db_session: Session) -> None:
    with pytest.raises(DBAPIError):
        _insert_source_raw(db_session, trust_boundary="NOT_A_BOUNDARY")


def test_source_rejects_invalid_data_classification(db_session: Session) -> None:
    with pytest.raises(DBAPIError):
        _insert_source_raw(db_session, trust_boundary="PERSONAL", data_classification="NOT_A_LEVEL")


def test_person_evidence_confidence_out_of_range_rejected(db_session: Session) -> None:
    entity_id = uuid.uuid4()
    db_session.execute(
        text("INSERT INTO person_head (entity_id, trust_boundary, current_version) VALUES (:id, 'PERSONAL', 0)"),
        {"id": entity_id},
    )
    db_session.execute(
        text(
            "INSERT INTO person (entity_id, version, trust_boundary, data_classification, status, "
            "display_name, valid_from) "
            "VALUES (:id, 1, 'PERSONAL', 'INTERNAL', 'ACTIVE', 'Test Person', now())"
        ),
        {"id": entity_id},
    )
    source = Source(
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
        excerpt="synthetic",
    )
    db_session.add(source)
    db_session.flush()

    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO person_evidence "
                "(id, person_entity_id, person_version, trust_boundary, source_id, stance, confidence, noted_at) "
                "VALUES (gen_random_uuid(), :pid, 1, 'PERSONAL', :sid, 'SUPPORTS', 1.5, now())"
            ),
            {"pid": entity_id, "sid": source.id},
        )
        db_session.flush()


# --- append-only enforcement (triggers) -------------------------------------


def test_source_update_is_rejected(db_session: Session) -> None:
    source = Source(
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
        excerpt="original",
    )
    db_session.add(source)
    db_session.flush()

    with pytest.raises(DBAPIError, match="append-only"):
        db_session.execute(text("UPDATE source SET excerpt = 'changed' WHERE id = :id"), {"id": source.id})
        db_session.flush()


def test_source_delete_is_rejected(db_session: Session) -> None:
    source = Source(
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
        excerpt="original",
    )
    db_session.add(source)
    db_session.flush()

    with pytest.raises(DBAPIError, match="append-only"):
        db_session.execute(text("DELETE FROM source WHERE id = :id"), {"id": source.id})
        db_session.flush()


def test_person_head_can_be_updated(db_session: Session) -> None:
    """The one deliberate, named exception to append-only: head rows are
    mutable pointers holding no content."""
    entity_id = uuid.uuid4()
    head = PersonHead(entity_id=entity_id, trust_boundary=TrustBoundary.PERSONAL, current_version=0)
    db_session.add(head)
    db_session.flush()

    db_session.execute(
        text("UPDATE person_head SET current_version = 1 WHERE entity_id = :id"), {"id": entity_id}
    )
    db_session.flush()
    db_session.expire_all()  # the raw UPDATE above bypassed the ORM, so the
    # identity map's cached copy of `head` must be forced to reload from
    # the database rather than returning its stale in-memory value.

    refreshed = db_session.get(PersonHead, entity_id)
    assert refreshed is not None
    assert refreshed.current_version == 1
