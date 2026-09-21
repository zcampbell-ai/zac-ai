"""Tests for the D029 entity model expansion: Company, Project,
Decision, Meeting, PersonCompanyRelationship, and the two retraction
tables.

Uses the disposable `zacai_test` database only (D027), synthetic data
only, rolled back via the `db_session` fixture (tests/conftest.py) unless
noted otherwise.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from zacai.policy import DataClassification, TrustBoundary
from zacai.state import (
    Company,
    CompanyRelationshipKind,
    CompanyStatus,
    EvidenceStance,
    Meeting,
    MeetingSourceRole,
    PersonCompanyRelationshipKind,
    Project,
    ProjectStatus,
    Source,
    SourceSystem,
)
from zacai.state_repository import (
    EvidenceInput,
    MeetingSourceInput,
    MissingSupportingEvidenceError,
    RelatedEntityBoundaryMismatchError,
    add_meeting_source,
    create_commitment,
    create_company,
    create_decision,
    create_meeting,
    create_person,
    create_project,
    get_company,
    get_current_company_relationships,
    get_decision,
    get_meeting,
    get_project,
    record_person_company_relationship,
    retract_company,
    retract_decision,
    retract_meeting,
    retract_project,
)


def _make_source(
    session: Session,
    *,
    trust_boundary: TrustBoundary = TrustBoundary.PERSONAL,
    data_classification: DataClassification = DataClassification.INTERNAL,
) -> Source:
    source = Source(
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        system=SourceSystem.MANUAL,
        excerpt="D029 test fixture",
    )
    session.add(source)
    session.flush()
    return source


def _supports(source: Source, confidence: float = 0.9) -> EvidenceInput:
    return EvidenceInput(source_id=source.id, stance=EvidenceStance.SUPPORTS, confidence=confidence)


def _make_person(session: Session, *, trust_boundary: TrustBoundary = TrustBoundary.PERSONAL, name: str = "Person"):
    source = _make_source(session, trust_boundary=trust_boundary)
    return create_person(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        display_name=name,
        evidence=[_supports(source)],
    )


def _make_company(
    session: Session,
    *,
    trust_boundary: TrustBoundary = TrustBoundary.BRAINSTORM,
    name: str = "Acme",
    relationship_kind: CompanyRelationshipKind = CompanyRelationshipKind.CLIENT,
) -> Company:
    source = _make_source(session, trust_boundary=trust_boundary)
    return create_company(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        name=name,
        relationship_kind=relationship_kind,
        evidence=[_supports(source)],
    )


def _make_project(
    session: Session, *, company: Company, trust_boundary: TrustBoundary = TrustBoundary.BRAINSTORM, name: str = "Website"
) -> Project:
    source = _make_source(session, trust_boundary=trust_boundary)
    return create_project(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        name=name,
        company_id=company.entity_id,
        evidence=[_supports(source)],
    )


def _make_meeting(
    session: Session, *, trust_boundary: TrustBoundary = TrustBoundary.BRAINSTORM, project_id: uuid.UUID | None = None
) -> Meeting:
    source = _make_source(session, trust_boundary=trust_boundary)
    return create_meeting(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        title="Kickoff",
        occurred_at=datetime.now(UTC),
        sources=[MeetingSourceInput(source_id=source.id, source_role=MeetingSourceRole.TRANSCRIPT)],
        project_id=project_id,
    )


# --- Company: versioning and tombstones -------------------------------------


def test_create_and_get_company(db_session: Session) -> None:
    company = _make_company(db_session)
    fetched = get_company(db_session, entity_id=company.entity_id, requestor_boundaries=frozenset({company.trust_boundary}))
    assert fetched is not None
    assert fetched.name == "Acme"
    assert fetched.version == 1


def test_retract_company_creates_tombstone(db_session: Session) -> None:
    company = _make_company(db_session)
    retraction_source = _make_source(db_session, trust_boundary=company.trust_boundary)
    retracted = retract_company(
        db_session,
        entity_id=company.entity_id,
        requestor_boundaries=frozenset({company.trust_boundary}),
        evidence=[_supports(retraction_source)],
    )
    assert retracted.version == 2
    assert retracted.status is CompanyStatus.RETRACTED
    assert get_company(db_session, entity_id=company.entity_id, requestor_boundaries=frozenset({company.trust_boundary})) is None


# --- Project: requires Company, versioning and tombstones -------------------


def test_create_project_requires_company_in_same_boundary(db_session: Session) -> None:
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_project(
            db_session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            name="Mismatched",
            company_id=company.entity_id,
            evidence=[_supports(source)],
        )


def test_project_company_fk_backstop_rejects_mismatched_boundary_raw_insert(db_session: Session) -> None:
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    project = _make_project(db_session, company=company, trust_boundary=TrustBoundary.BRAINSTORM)
    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO project (entity_id, version, trust_boundary, data_classification, status, "
                "name, company_id, valid_from) "
                "VALUES (:id, 99, 'PERSONAL', 'INTERNAL', 'ACTIVE', 'bypass', :company_id, now())"
            ),
            {"id": project.entity_id, "company_id": company.entity_id},
        )
        db_session.flush()


def test_retract_project_creates_tombstone(db_session: Session) -> None:
    company = _make_company(db_session)
    project = _make_project(db_session, company=company)
    retraction_source = _make_source(db_session, trust_boundary=project.trust_boundary)
    retracted = retract_project(
        db_session,
        entity_id=project.entity_id,
        requestor_boundaries=frozenset({project.trust_boundary}),
        evidence=[_supports(retraction_source)],
    )
    assert retracted.status is ProjectStatus.RETRACTED
    assert get_project(db_session, entity_id=project.entity_id, requestor_boundaries=frozenset({project.trust_boundary})) is None


# --- Commitment -> Project (additive, optional) ------------------------------


def test_commitment_optional_project_reference(db_session: Session) -> None:
    company = _make_company(db_session, trust_boundary=TrustBoundary.PERSONAL, relationship_kind=CompanyRelationshipKind.INTERNAL)
    project = _make_project(db_session, company=company, trust_boundary=TrustBoundary.PERSONAL)
    owner = _make_person(db_session, trust_boundary=TrustBoundary.PERSONAL)
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    commitment = create_commitment(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        owner_person_id=owner.entity_id,
        description="Ship the thing",
        project_id=project.entity_id,
        evidence=[_supports(source)],
    )
    assert commitment.project_id == project.entity_id


def test_commitment_project_boundary_mismatch_rejected(db_session: Session) -> None:
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    project = _make_project(db_session, company=company, trust_boundary=TrustBoundary.BRAINSTORM)
    owner = _make_person(db_session, trust_boundary=TrustBoundary.PERSONAL)
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_commitment(
            db_session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            owner_person_id=owner.entity_id,
            description="Should fail",
            project_id=project.entity_id,
            evidence=[_supports(source)],
        )


# --- PersonCompanyRelationship ------------------------------------------


def test_record_and_get_current_company_relationship(db_session: Session) -> None:
    person = _make_person(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    record_person_company_relationship(
        db_session,
        person_id=person.entity_id,
        company_id=company.entity_id,
        trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.INTERNAL,
        relationship_kind=PersonCompanyRelationshipKind.EMPLOYEE,
        source_id=source.id,
    )
    current = get_current_company_relationships(
        db_session, person_id=person.entity_id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM})
    )
    assert len(current) == 1
    assert current[0].relationship_kind is PersonCompanyRelationshipKind.EMPLOYEE


def test_person_company_relationship_allows_multiple_concurrent_and_historical(db_session: Session) -> None:
    person = _make_person(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    company_a = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM, name="A")
    company_b = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM, name="B")
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)

    # Two concurrent relationships (different companies).
    record_person_company_relationship(
        db_session, person_id=person.entity_id, company_id=company_a.entity_id,
        trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        relationship_kind=PersonCompanyRelationshipKind.EMPLOYEE, source_id=source.id,
    )
    record_person_company_relationship(
        db_session, person_id=person.entity_id, company_id=company_b.entity_id,
        trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        relationship_kind=PersonCompanyRelationshipKind.CONTACT, source_id=source.id,
    )
    # Two historical rows for the SAME pair (company_a): ended, then a new one.
    record_person_company_relationship(
        db_session, person_id=person.entity_id, company_id=company_a.entity_id,
        trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        relationship_kind=PersonCompanyRelationshipKind.CONTACT, source_id=source.id,
        started_at=datetime.now(UTC), ended_at=datetime.now(UTC),
    )

    current = get_current_company_relationships(
        db_session, person_id=person.entity_id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM})
    )
    # Only the two rows with ended_at IS NULL count as "current".
    assert len(current) == 2


def test_person_company_relationship_person_boundary_mismatch_rejected(db_session: Session) -> None:
    person = _make_person(db_session, trust_boundary=TrustBoundary.PERSONAL)
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        record_person_company_relationship(
            db_session, person_id=person.entity_id, company_id=company.entity_id,
            trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
            relationship_kind=PersonCompanyRelationshipKind.EMPLOYEE, source_id=source.id,
        )


def test_person_company_relationship_source_boundary_mismatch_db_rejected(db_session: Session) -> None:
    person = _make_person(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    wrong_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises((DBAPIError, RelatedEntityBoundaryMismatchError, Exception)):
        record_person_company_relationship(
            db_session, person_id=person.entity_id, company_id=company.entity_id,
            trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
            relationship_kind=PersonCompanyRelationshipKind.EMPLOYEE, source_id=wrong_source.id,
        )


# --- Meeting: multi-source ----------------------------------------------


def test_create_meeting_requires_at_least_one_source(db_session: Session) -> None:
    with pytest.raises(MissingSupportingEvidenceError):
        create_meeting(
            db_session,
            trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.INTERNAL,
            title="No sources",
            occurred_at=datetime.now(UTC),
            sources=[],
        )


def test_add_meeting_source_appends_additional_source(db_session: Session) -> None:
    meeting = _make_meeting(db_session)
    summary_source = _make_source(db_session, trust_boundary=meeting.trust_boundary)
    add_meeting_source(
        db_session,
        meeting_id=meeting.id,
        requestor_boundaries=frozenset({meeting.trust_boundary}),
        source_id=summary_source.id,
        source_role=MeetingSourceRole.SUMMARY,
    )
    rows = db_session.execute(
        text("SELECT source_role FROM meeting_source WHERE meeting_id = :id ORDER BY source_role"),
        {"id": meeting.id},
    ).scalars().all()
    assert set(rows) == {"SUMMARY", "TRANSCRIPT"}


def test_meeting_source_boundary_mismatch_db_rejected(db_session: Session) -> None:
    meeting = _make_meeting(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    wrong_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(Exception):  # noqa: B017 - repository or DB error, both prove rejection
        add_meeting_source(
            db_session,
            meeting_id=meeting.id,
            requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
            source_id=wrong_source.id,
            source_role=MeetingSourceRole.NOTES,
        )


def test_meeting_optional_project_boundary_mismatch_rejected(db_session: Session) -> None:
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    project = _make_project(db_session, company=company, trust_boundary=TrustBoundary.BRAINSTORM)
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_meeting(
            db_session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            title="Mismatched",
            occurred_at=datetime.now(UTC),
            sources=[MeetingSourceInput(source_id=source.id, source_role=MeetingSourceRole.NOTES)],
            project_id=project.entity_id,
        )


def test_meeting_attendee_boundary_mismatch_db_rejected(db_session: Session) -> None:
    wrong_person = _make_person(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_meeting(
            db_session,
            trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.INTERNAL,
            title="Attendee mismatch",
            occurred_at=datetime.now(UTC),
            sources=[MeetingSourceInput(
                source_id=_make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM).id,
                source_role=MeetingSourceRole.CALENDAR_EVENT,
            )],
            attendees=[wrong_person.entity_id],
        )


# --- Meeting retraction ---------------------------------------------------


def test_retract_meeting_leaves_original_row_unchanged(db_session: Session) -> None:
    meeting = _make_meeting(db_session)
    original_title = meeting.title
    retraction_source = _make_source(db_session, trust_boundary=meeting.trust_boundary)
    retract_meeting(
        db_session,
        meeting_id=meeting.id,
        requestor_boundaries=frozenset({meeting.trust_boundary}),
        source_id=retraction_source.id,
        reason="duplicate",
    )
    row = db_session.execute(text("SELECT title FROM meeting WHERE id = :id"), {"id": meeting.id}).scalar_one()
    assert row == original_title
    assert get_meeting(db_session, meeting_id=meeting.id, requestor_boundaries=frozenset({meeting.trust_boundary})) is None
    assert get_meeting(
        db_session, meeting_id=meeting.id, requestor_boundaries=frozenset({meeting.trust_boundary}), include_retracted=True
    ) is not None


def test_duplicate_meeting_retraction_rejected(db_session: Session) -> None:
    meeting = _make_meeting(db_session)
    source = _make_source(db_session, trust_boundary=meeting.trust_boundary)
    retract_meeting(db_session, meeting_id=meeting.id, requestor_boundaries=frozenset({meeting.trust_boundary}), source_id=source.id)
    with pytest.raises(ValueError, match="already been retracted"):
        retract_meeting(db_session, meeting_id=meeting.id, requestor_boundaries=frozenset({meeting.trust_boundary}), source_id=source.id)


def test_meeting_retraction_source_boundary_mismatch_db_rejected(db_session: Session) -> None:
    meeting = _make_meeting(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    wrong_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(Exception):  # noqa: B017
        retract_meeting(
            db_session, meeting_id=meeting.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
            source_id=wrong_source.id,
        )


def test_meeting_retraction_requires_source(db_session: Session) -> None:
    meeting = _make_meeting(db_session)
    with pytest.raises(Exception):  # noqa: B017 - _load_sources raises ValueError for an unknown id
        retract_meeting(
            db_session, meeting_id=meeting.id, requestor_boundaries=frozenset({meeting.trust_boundary}),
            source_id=uuid.uuid4(),
        )


def test_meeting_retraction_column_not_null_db_rejected(db_session: Session) -> None:
    meeting = _make_meeting(db_session)
    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO meeting_retraction (id, meeting_id, trust_boundary, source_id, retracted_at) "
                "VALUES (gen_random_uuid(), :meeting_id, :boundary, NULL, now())"
            ),
            {"meeting_id": meeting.id, "boundary": meeting.trust_boundary.value},
        )
        db_session.flush()


# --- Decision: supersession vs retraction ------------------------------


def test_decision_supersession_preserves_both_rows(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    original = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Use Postgres", evidence=[_supports(source)],
    )
    newer = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Use SQLite instead", evidence=[_supports(source)],
        supersedes_decision_id=original.id,
    )
    assert newer.supersedes_decision_id == original.id
    # Both remain independently fetchable - supersession never hides the original.
    assert get_decision(db_session, decision_id=original.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM})) is not None
    assert get_decision(db_session, decision_id=newer.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM})) is not None


def test_decision_supersedes_boundary_mismatch_rejected(db_session: Session) -> None:
    source_a = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    source_b = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    original = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Brainstorm decision", evidence=[_supports(source_a)],
    )
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_decision(
            db_session, trust_boundary=TrustBoundary.PERSONAL, data_classification=DataClassification.INTERNAL,
            description="Should fail", evidence=[_supports(source_b)],
            supersedes_decision_id=original.id,
        )


def test_retract_decision_leaves_original_row_unchanged_and_distinct_from_supersession(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    decision = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Extraction error", evidence=[_supports(source)],
    )
    original_description = decision.description

    retraction_source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    retract_decision(
        db_session, decision_id=decision.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
        source_id=retraction_source.id, reason="never actually decided",
    )

    row = db_session.execute(text("SELECT description FROM decision WHERE id = :id"), {"id": decision.id}).scalar_one()
    assert row == original_description
    assert get_decision(db_session, decision_id=decision.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM})) is None
    with_retracted = get_decision(
        db_session, decision_id=decision.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}), include_retracted=True
    )
    assert with_retracted is not None
    # Retraction leaves supersedes_decision_id untouched (still None here) -
    # structurally distinct from supersession, which is a *different* row.
    assert with_retracted.supersedes_decision_id is None


def test_duplicate_decision_retraction_rejected(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    decision = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Retract me", evidence=[_supports(source)],
    )
    retract_decision(db_session, decision_id=decision.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}), source_id=source.id)
    with pytest.raises(ValueError, match="already been retracted"):
        retract_decision(db_session, decision_id=decision.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}), source_id=source.id)


def test_decision_retraction_source_boundary_mismatch_db_rejected(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    decision = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Test", evidence=[_supports(source)],
    )
    wrong_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    with pytest.raises(Exception):  # noqa: B017
        retract_decision(
            db_session, decision_id=decision.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
            source_id=wrong_source.id,
        )


def test_decision_retraction_column_not_null_db_rejected(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    decision = create_decision(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM, data_classification=DataClassification.INTERNAL,
        description="Test", evidence=[_supports(source)],
    )
    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO decision_retraction (id, decision_id, trust_boundary, source_id, retracted_at) "
                "VALUES (gen_random_uuid(), :decision_id, :boundary, NULL, now())"
            ),
            {"decision_id": decision.id, "boundary": decision.trust_boundary.value},
        )
        db_session.flush()


def test_decision_project_and_meeting_boundary_mismatch_rejected(db_session: Session) -> None:
    company = _make_company(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    project = _make_project(db_session, company=company, trust_boundary=TrustBoundary.BRAINSTORM)
    meeting = _make_meeting(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)

    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_decision(
            db_session, trust_boundary=TrustBoundary.PERSONAL, data_classification=DataClassification.INTERNAL,
            description="Bad project ref", evidence=[_supports(source)], project_id=project.entity_id,
        )
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        create_decision(
            db_session, trust_boundary=TrustBoundary.PERSONAL, data_classification=DataClassification.INTERNAL,
            description="Bad meeting ref", evidence=[_supports(source)], meeting_id=meeting.id,
        )
