"""D034C synthetic canonical association tests, guarded zacai_test only."""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from tests.test_state_d029 import (
    _make_company,
    _make_meeting,
    _make_project,
    _make_source,
    _supports,
)
from zacai.policy import DataClassification as DC
from zacai.policy import TrustBoundary as TB
from zacai.state import MeetingProjectAssociation, ProjectEvidence, SourceSystem
from zacai.state_repository import (
    ClassificationTooWeakError,
    associate_meeting_project,
    create_project,
    elevate_source_classification,
    get_meeting_project_context,
    retract_meeting,
    retract_meeting_project_association,
    retract_project,
)

B = frozenset({TB.BRAINSTORM})
ALL_LABELS = frozenset(DC)


def _fixture(session):
    company = _make_company(session)
    project = _make_project(session, company=company)
    meeting = _make_meeting(session)
    confirmation = _make_source(session, trust_boundary=TB.BRAINSTORM)
    return project, meeting, confirmation


def _add(session, project, meeting, confirmation, **kwargs):
    values = {
        "project_id": project.entity_id,
        "meeting_id": meeting.id,
        "reviewed_project_version": project.version,
        "confirmation_source_id": confirmation.id,
        "data_classification": DC.INTERNAL,
        "requestor_boundaries": B,
    }
    values.update(kwargs)
    return associate_meeting_project(session, **values)


def _get(session, meeting, **kwargs):
    values = {
        "meeting_id": meeting.id,
        "requestor_boundaries": B,
        "allowed_classifications": ALL_LABELS,
    }
    values.update(kwargs)
    return get_meeting_project_context(session, **values)


def _elevate(session, source_id):
    return elevate_source_classification(
        session,
        source_id=source_id,
        trust_boundary=TB.BRAINSTORM,
        elevated_by="synthetic-human",
        new_classification=DC.CONFIDENTIAL,
        reason="Synthetic sensitivity correction",
    )


def test_association_leaves_original_meeting_untouched(db_session):
    project, meeting, confirmation = _fixture(db_session)
    association = _add(db_session, project, meeting, confirmation)
    db_session.expire(meeting)
    assert meeting.project_id is None
    (context,) = _get(db_session, meeting)
    assert context.association_id == association.id
    assert context.project_id == project.entity_id
    assert context.reviewed_project_version == context.current_project_version == 1
    assert context.confirmation_source_id == confirmation.id
    assert context.effective_classification == DC.INTERNAL


def test_two_distinct_projects_can_share_a_meeting(db_session):
    project, meeting, confirmation = _fixture(db_session)
    other = _make_project(db_session, company=_make_company(db_session), name="Different project")
    _add(db_session, project, meeting, confirmation)
    _add(db_session, other, meeting, confirmation)
    assert {c.project_id for c in _get(db_session, meeting)} == {project.entity_id, other.entity_id}


def test_changed_contract_keeps_identity_and_exposes_version_change(db_session):
    project, meeting, confirmation = _fixture(db_session)
    _add(db_session, project, meeting, confirmation)
    next_source = _make_source(db_session, trust_boundary=TB.BRAINSTORM)
    next_version = create_project(
        db_session,
        entity_id=project.entity_id,
        company_id=project.company_id,
        trust_boundary=TB.BRAINSTORM,
        data_classification=DC.INTERNAL,
        name="Continuing work with updated contract",
        evidence=[_supports(next_source)],
    )
    (context,) = _get(db_session, meeting)
    assert context.project_id == next_version.entity_id
    assert context.reviewed_project_version == 1
    assert context.current_project_version == 2
    with pytest.raises(ValueError, match="changed since review"):
        _add(db_session, project, meeting, confirmation)


def test_duplicate_link_rejected_and_withdrawal_allows_new_assertion(db_session):
    project, meeting, confirmation = _fixture(db_session)
    first = _add(db_session, project, meeting, confirmation)
    with pytest.raises(ValueError, match="already exists"):
        _add(db_session, project, meeting, confirmation)
    retract_meeting_project_association(
        db_session,
        association_id=first.id,
        confirmation_source_id=confirmation.id,
        requestor_boundaries=B,
    )
    assert _get(db_session, meeting) == ()
    second = _add(db_session, project, meeting, confirmation)
    assert second.id != first.id
    assert db_session.get(MeetingProjectAssociation, first.id) is not None
    assert _get(db_session, meeting)[0].association_id == second.id


@pytest.mark.parametrize("endpoint", ["meeting", "project"])
def test_retracted_endpoint_hides_link_and_blocks_new_assertion(db_session, endpoint):
    project, meeting, confirmation = _fixture(db_session)
    link = _add(db_session, project, meeting, confirmation)
    if endpoint == "meeting":
        retract_meeting(
            db_session, meeting_id=meeting.id, requestor_boundaries=B, source_id=confirmation.id
        )
    else:
        retract_project(
            db_session,
            entity_id=project.entity_id,
            requestor_boundaries=B,
            evidence=[_supports(confirmation)],
        )
    assert _get(db_session, meeting) == ()
    with pytest.raises(ValueError, match="active same-boundary"):
        _add(db_session, project, meeting, confirmation)
    # Corrections must remain possible even after an endpoint is withdrawn.
    retract_meeting_project_association(
        db_session,
        association_id=link.id,
        confirmation_source_id=confirmation.id,
        requestor_boundaries=B,
    )


@pytest.mark.parametrize("role", ["meeting", "project", "confirmation"])
def test_cross_boundary_endpoint_or_confirmation_rejected(db_session, role):
    project, meeting, confirmation = _fixture(db_session)
    if role == "meeting":
        meeting = _make_meeting(db_session, trust_boundary=TB.PERSONAL)
    elif role == "project":
        company = _make_company(db_session, trust_boundary=TB.PERSONAL)
        project = _make_project(db_session, company=company, trust_boundary=TB.PERSONAL)
    else:
        confirmation = _make_source(db_session, trust_boundary=TB.PERSONAL)
    with pytest.raises(ValueError):
        _add(
            db_session,
            project,
            meeting,
            confirmation,
            requestor_boundaries=frozenset({TB.PERSONAL, TB.BRAINSTORM}),
        )


def test_unauthorized_and_unknown_read_are_empty(db_session):
    project, meeting, confirmation = _fixture(db_session)
    _add(db_session, project, meeting, confirmation)
    assert _get(db_session, meeting, requestor_boundaries=frozenset({TB.PERSONAL})) == ()
    assert (
        get_meeting_project_context(
            db_session,
            meeting_id=uuid.uuid4(),
            requestor_boundaries=B,
            allowed_classifications=ALL_LABELS,
        )
        == ()
    )


def test_nonmanual_source_cannot_stand_for_confirmation(db_session):
    project, meeting, _ = _fixture(db_session)
    from zacai.state import Source

    source = Source(
        trust_boundary=TB.BRAINSTORM,
        data_classification=DC.INTERNAL,
        system=SourceSystem.FIREFLIES,
        excerpt="Synthetic model/source proposal",
    )
    db_session.add(source)
    db_session.flush()
    with pytest.raises(ValueError, match="manual confirmation"):
        _add(db_session, project, meeting, source)


@pytest.mark.parametrize("role", ["meeting", "project", "confirmation"])
def test_elevation_refreshes_effective_label_and_prevents_weak_write(db_session, role):
    project, meeting, confirmation = _fixture(db_session)
    link = _add(db_session, project, meeting, confirmation)
    if role == "confirmation":
        source_id = confirmation.id
    elif role == "project":
        source_id = db_session.execute(
            select(ProjectEvidence.source_id).where(
                ProjectEvidence.project_entity_id == project.entity_id,
            )
        ).scalar_one()
    else:
        from zacai.state import MeetingSource

        source_id = db_session.execute(
            select(MeetingSource.source_id).where(
                MeetingSource.meeting_id == meeting.id,
            )
        ).scalar_one()
    _elevate(db_session, source_id)
    assert _get(db_session, meeting)[0].effective_classification == DC.CONFIDENTIAL
    assert _get(db_session, meeting, allowed_classifications=frozenset({DC.INTERNAL})) == ()
    retract_meeting_project_association(
        db_session,
        association_id=link.id,
        confirmation_source_id=confirmation.id,
        requestor_boundaries=B,
    )
    with pytest.raises(ClassificationTooWeakError):
        _add(db_session, project, meeting, confirmation)
    _add(db_session, project, meeting, confirmation, data_classification=DC.CONFIDENTIAL)


def test_previous_project_evidence_remains_sensitive_after_new_version(db_session):
    project, meeting, confirmation = _fixture(db_session)
    _add(db_session, project, meeting, confirmation)
    old_source = db_session.execute(
        select(ProjectEvidence.source_id).where(
            ProjectEvidence.project_entity_id == project.entity_id,
        )
    ).scalar_one()
    create_project(
        db_session,
        entity_id=project.entity_id,
        company_id=project.company_id,
        trust_boundary=TB.BRAINSTORM,
        data_classification=DC.INTERNAL,
        name="Renamed contract",
        evidence=[_supports(confirmation)],
    )
    _elevate(db_session, old_source)
    assert _get(db_session, meeting, allowed_classifications=frozenset({DC.INTERNAL})) == ()
    assert _get(db_session, meeting)[0].effective_classification == DC.CONFIDENTIAL


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
@pytest.mark.parametrize(
    "table", ["meeting_project_association", "meeting_project_association_retraction"]
)
def test_database_blocks_mutation_of_assertions_and_corrections(db_session, operation, table):
    project, meeting, confirmation = _fixture(db_session)
    link = _add(db_session, project, meeting, confirmation)
    correction = retract_meeting_project_association(
        db_session,
        association_id=link.id,
        confirmation_source_id=confirmation.id,
        requestor_boundaries=B,
    )
    row_id = link.id if table == "meeting_project_association" else correction.id
    sql = (
        f"UPDATE {table} SET id=id WHERE id=:id"
        if operation == "UPDATE"
        else f"DELETE FROM {table} WHERE id=:id"
    )
    with pytest.raises(DBAPIError, match="append-only"):
        db_session.execute(text(sql), {"id": row_id})
    db_session.rollback()


def test_raw_database_write_cannot_cross_boundary(db_session):
    project, _meeting, confirmation = _fixture(db_session)
    other = _make_meeting(db_session, trust_boundary=TB.PERSONAL)
    forged = MeetingProjectAssociation(
        meeting_id=other.id,
        project_id=project.entity_id,
        reviewed_project_version=1,
        confirmation_source_id=confirmation.id,
        trust_boundary=TB.BRAINSTORM,
        data_classification=DC.INTERNAL,
    )
    db_session.add(forged)
    with pytest.raises(DBAPIError):
        db_session.flush()
    db_session.rollback()


def test_unauthorized_correction_and_duplicate_withdrawal_rejected(db_session):
    project, meeting, confirmation = _fixture(db_session)
    link = _add(db_session, project, meeting, confirmation)
    with pytest.raises(ValueError, match="not found or not authorized"):
        retract_meeting_project_association(
            db_session,
            association_id=link.id,
            confirmation_source_id=confirmation.id,
            requestor_boundaries=frozenset({TB.PERSONAL}),
        )
    retract_meeting_project_association(
        db_session,
        association_id=link.id,
        confirmation_source_id=confirmation.id,
        requestor_boundaries=B,
    )
    with pytest.raises(ValueError, match="already withdrawn"):
        retract_meeting_project_association(
            db_session,
            association_id=link.id,
            confirmation_source_id=confirmation.id,
            requestor_boundaries=B,
        )


def test_original_anchor_is_preserved_when_supplemental_context_added(db_session):
    project, _, confirmation = _fixture(db_session)
    meeting = _make_meeting(db_session, project_id=project.entity_id)
    other = _make_project(db_session, company=_make_company(db_session))
    _add(db_session, other, meeting, confirmation)
    db_session.expire(meeting)
    assert meeting.project_id == project.entity_id
    assert _get(db_session, meeting)[0].project_id == other.entity_id


def test_concurrent_duplicate_assertions_serialize(test_session_factory):
    with test_session_factory() as session:
        project, meeting, confirmation = _fixture(session)
        project_id, meeting_id, source_id = project.entity_id, meeting.id, confirmation.id
        session.commit()

    ready = Barrier(2)

    def write():
        ready.wait(timeout=10)
        with test_session_factory() as session:
            try:
                associate_meeting_project(
                    session,
                    project_id=project_id,
                    meeting_id=meeting_id,
                    reviewed_project_version=1,
                    confirmation_source_id=source_id,
                    data_classification=DC.INTERNAL,
                    requestor_boundaries=B,
                )
                session.commit()
                return "created"
            except ValueError as exc:
                session.rollback()
                assert str(exc) == "an active association already exists"
                return "duplicate"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write) for _ in range(2)]
        assert sorted(f.result(timeout=10) for f in futures) == ["created", "duplicate"]
    with test_session_factory() as session:
        assert (
            len(
                get_meeting_project_context(
                    session,
                    meeting_id=meeting_id,
                    requestor_boundaries=B,
                    allowed_classifications=ALL_LABELS,
                )
            )
            == 1
        )


@pytest.mark.parametrize("version", [0, True, 2])
def test_invalid_reviewed_version_cannot_create_link(db_session, version):
    project, meeting, confirmation = _fixture(db_session)
    with pytest.raises(ValueError, match="changed since review"):
        _add(db_session, project, meeting, confirmation, reviewed_project_version=version)
    assert _get(db_session, meeting) == ()


def test_migration_matches_association_metadata(db_session):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from zacai.state import Base

    names = {"meeting_project_association", "meeting_project_association_retraction"}
    context = MigrationContext.configure(
        db_session.connection(),
        opts={
            "include_object": lambda obj, name, kind, reflected, compare_to: (
                name in names
                if kind == "table"
                else getattr(obj, "table", None) is not None and obj.table.name in names
            ),
        },
    )
    assert compare_metadata(context, Base.metadata) == []
