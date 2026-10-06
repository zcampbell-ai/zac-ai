from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from zacai.ingestion.native_batch_inventory import _effective
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import (
    ClassificationNotElevatedError,
    elevate_source_classification,
    get_effective_source_classification,
)


@pytest.mark.parametrize("ordering", ["same_timestamp", "reverse_timestamp"])
def test_strongest_elevation_is_preserved_in_repository_and_correlated_reader(ordering):
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    instant = datetime(2026, 10, 6, 12, tzinfo=UTC)
    with Session(engine) as session:
        source = Source(
            id=uuid4(),
            trust_boundary=B.PERSONAL,
            data_classification=C.PUBLIC,
            system=SourceSystem.MANUAL,
            captured_at=instant,
        )
        untouched = Source(
            id=uuid4(),
            trust_boundary=B.BRAINSTORM,
            data_classification=C.INTERNAL,
            system=SourceSystem.MANUAL,
            captured_at=instant,
        )
        session.add_all([source, untouched])
        session.flush()
        for previous, current, offset in [
            (C.PUBLIC, C.CONFIDENTIAL, 1),
            (C.CONFIDENTIAL, C.HIGHLY_RESTRICTED, 0),
        ]:
            session.add(
                SourceClassificationElevation(
                    source_id=source.id,
                    trust_boundary=B.PERSONAL,
                    previous_classification=previous,
                    new_classification=current,
                    reason="invented timestamp control",
                    elevated_by="invented operator",
                    elevated_at=instant
                    + timedelta(seconds=offset if ordering == "reverse_timestamp" else 0),
                )
            )
            session.flush()
        assert (
            get_effective_source_classification(session, source_id=source.id) is C.HIGHLY_RESTRICTED
        )
        assert (
            session.scalar(select(_effective()).select_from(Source).where(Source.id == source.id))
            is C.HIGHLY_RESTRICTED
        )
        assert get_effective_source_classification(session, source_id=untouched.id) is C.INTERNAL
        assert (
            session.scalar(
                select(_effective()).select_from(Source).where(Source.id == untouched.id)
            )
            is C.INTERNAL
        )
        assert session.get(Source, source.id).data_classification is C.PUBLIC
        with pytest.raises(ClassificationNotElevatedError):
            elevate_source_classification(
                session,
                source_id=source.id,
                trust_boundary=B.PERSONAL,
                new_classification=C.CONFIDENTIAL,
                reason="invented downgrade",
                elevated_by="invented operator",
            )
    engine.dispose()


def test_missing_source_still_holds():
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    with Session(engine) as session, pytest.raises(ValueError):
        get_effective_source_classification(session, source_id=uuid4())
    engine.dispose()


def test_incomplete_future_policy_rank_holds_before_query(monkeypatch):
    from zacai import state_repository as repository

    monkeypatch.delitem(repository._CLASSIFICATION_ORDER, C.HIGHLY_RESTRICTED)
    with pytest.raises(RuntimeError, match="classification policy order requires review"):
        repository.source_classification_elevation_strength()


def test_unrecognized_database_label_cannot_hide_behind_known_weaker_label():
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    instant = datetime(2026, 10, 6, 12, tzinfo=UTC)
    with Session(engine) as session:
        sid = uuid4()
        session.add(
            Source(
                id=sid,
                trust_boundary=B.PERSONAL,
                data_classification=C.PUBLIC,
                system=SourceSystem.MANUAL,
                captured_at=instant,
            )
        )
        session.flush()
        # Only this invented SQLite fixture disables its enum CHECK and bind
        # validation to simulate schema drift. Production constraints stay exact.
        session.execute(text("PRAGMA ignore_check_constraints=ON"))
        for label in (C.CONFIDENTIAL.value, "UNREVIEWED_FUTURE_LABEL"):
            session.execute(
                text(
                    "INSERT INTO source_classification_elevation "
                    "(id, source_id, trust_boundary, previous_classification, "
                    "new_classification, reason, elevated_by, elevated_at) "
                    "VALUES (:id,:source,'PERSONAL','PUBLIC',:label,"
                    "'invented future-schema control','invented operator',:instant)"
                ),
                {
                    "id": uuid4().hex,
                    "source": sid.hex,
                    "label": label,
                    "instant": instant.isoformat(),
                },
            )
        with pytest.raises(LookupError):
            get_effective_source_classification(session, source_id=sid)
        with pytest.raises(LookupError):
            session.scalar(select(_effective()).select_from(Source).where(Source.id == sid))
    engine.dispose()
