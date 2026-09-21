"""Boundary-enforcing, concurrency-safe access to Zac State (D026).

This is the only module callers should use to read or write `zacai.state`
tables - there is no query path here that returns a row outside a
caller's declared `requestor_boundaries`, mirroring
`zacai.gateway.evaluate_gateway`'s "no parameter or code path that skips
the check" pattern.

Version allocation (`_allocate_version`) is concurrency-safe using only
ordinary PostgreSQL-native mechanisms - `INSERT ... ON CONFLICT DO
NOTHING` followed by `SELECT ... FOR UPDATE` - never an unguarded
`SELECT max(version) + 1`. The same algorithm handles a brand-new entity
and an existing one identically: for two concurrent callers targeting the
same not-yet-existing `entity_id`, Postgres blocks the second's `INSERT
... ON CONFLICT` on the first's uncommitted row until it commits or rolls
back, after which the second's insert resolves as a no-op and it proceeds
to lock the now-existing row - fully serializing both the first-version
and next-version cases with nothing but row-level locking. No advisory
lock, no external lock service.

An entity's trust boundary is fixed at first creation and can never
change: `_allocate_version` checks this explicitly (`BoundaryImmutableError`),
and `person`/`commitment`'s foreign key to `person_head`/`commitment_head`
on `(entity_id, trust_boundary)` makes it structurally impossible even if
this check were ever bypassed.

`create_person`/`create_commitment` require at least one `SUPPORTS`
evidence row per version and enforce the classification non-weakening
invariant (D026): a version's `data_classification` may never be less
restrictive than any `SUPPORTS` evidence backing it. No code here
automatically computes a classification from evidence - only rejects a
supplied value the evidence doesn't justify.

Logical deletion is a tombstone version (`status="RETRACTED"`), never a
physical `DELETE` - `retract_person`/`retract_commitment` are ordinary
calls through the same version-creation path as any other change.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import cast

from sqlalchemy import Table, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from zacai.policy import DataClassification, TrustBoundary
from zacai.state import (
    ArtifactBackupRun,
    ArtifactBackupRunStatus,
    Base,
    Commitment,
    CommitmentEvidence,
    CommitmentHead,
    CommitmentStatus,
    Company,
    CompanyEvidence,
    CompanyHead,
    CompanyRelationshipKind,
    CompanyStatus,
    Decision,
    DecisionEvidence,
    DecisionRetraction,
    EvidenceStance,
    ExtractionCandidate,
    ExtractionCandidateReview,
    ExtractionCandidateType,
    ExtractionRecord,
    ExtractionRecordStatus,
    ExtractionReviewOutcome,
    IngestionCursor,
    IngestionRun,
    IngestionRunStatus,
    Meeting,
    MeetingAttendee,
    MeetingRetraction,
    MeetingSource,
    MeetingSourceRole,
    Person,
    PersonCompanyRelationship,
    PersonCompanyRelationshipKind,
    PersonEvidence,
    PersonHead,
    PersonStatus,
    Project,
    ProjectEvidence,
    ProjectHead,
    ProjectStatus,
    Source,
    SourceClassificationElevation,
    SourceSystem,
    UnresolvedIdentity,
)

_CLASSIFICATION_ORDER: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.HIGHLY_RESTRICTED: 3,
}


class BoundaryImmutableError(ValueError):
    """Raised when a write would change an existing entity's trust boundary."""


class OwnerBoundaryMismatchError(ValueError):
    """Raised when a Commitment's boundary does not match its owner Person's."""


class RelatedEntityBoundaryMismatchError(ValueError):
    """Raised when an optional cross-entity reference (D029: Project's
    Company, Meeting's/Decision's Project, Decision's Meeting or
    superseded Decision, a PersonCompanyRelationship's Person/Company)
    does not share the referencing entity's exact trust boundary."""


class EvidenceBoundaryMismatchError(ValueError):
    """Raised when cited evidence does not share the entity version's boundary."""


class ClassificationTooWeakError(ValueError):
    """Raised when a version's classification is less restrictive than its evidence."""


class MissingSupportingEvidenceError(ValueError):
    """Raised when a version is submitted with no SUPPORTS evidence at all."""


class ClassificationNotElevatedError(ValueError):
    """Raised when a Source classification 'elevation' would not
    strictly increase its effective classification (D030) - elevation is
    monotonic upward-only, never a way to weaken it."""


@dataclass(frozen=True)
class EvidenceInput:
    """One caller-supplied evidence citation for a version being created."""

    source_id: uuid.UUID
    stance: EvidenceStance
    confidence: float


def _allocate_version(
    session: Session,
    head_model: type[Base],
    entity_id: uuid.UUID,
    trust_boundary: TrustBoundary,
) -> int:
    """Ensure a head row exists for `entity_id`, lock it, and return the
    next version number. Must run inside the same transaction as the
    version-row insert it guards - see module docstring.

    `head_model` is typed as `type[Base]` rather than a growing union of
    specific head models (`PersonHead | CommitmentHead | ...`): this
    function only ever touches `head_model.__table__` generically (it
    never constructs an ORM instance of the model), so it works unchanged
    for any head-shaped table - `CompanyHead`/`ProjectHead` (D029) needed
    no change here at all, and neither will a future entity's head table.
    """
    table = cast(Table, head_model.__table__)

    session.execute(
        pg_insert(table)
        .values(entity_id=entity_id, trust_boundary=trust_boundary, current_version=0)
        .on_conflict_do_nothing(index_elements=["entity_id"])
    )

    row = session.execute(
        select(table.c.current_version, table.c.trust_boundary)
        .where(table.c.entity_id == entity_id)
        .with_for_update()
    ).one()

    if row.trust_boundary != trust_boundary:
        raise BoundaryImmutableError(
            f"entity {entity_id} was created in the {row.trust_boundary} boundary; "
            f"cannot write a {trust_boundary} version of it"
        )

    return int(row.current_version) + 1


def _advance_head(
    session: Session,
    head_model: type[Base],
    entity_id: uuid.UUID,
    new_version: int,
) -> None:
    table = cast(Table, head_model.__table__)
    session.execute(update(table).where(table.c.entity_id == entity_id).values(current_version=new_version))


def _load_sources(session: Session, source_ids: set[uuid.UUID]) -> dict[uuid.UUID, Source]:
    if not source_ids:
        return {}
    sources = session.execute(select(Source).where(Source.id.in_(source_ids))).scalars().all()
    found = {source.id: source for source in sources}
    missing = source_ids - found.keys()
    if missing:
        raise ValueError(f"unknown source id(s): {missing}")
    return found


def _assert_evidence_matches_boundary(
    sources_by_id: dict[uuid.UUID, Source], trust_boundary: TrustBoundary
) -> None:
    for source in sources_by_id.values():
        if source.trust_boundary != trust_boundary:
            raise EvidenceBoundaryMismatchError(
                f"source {source.id} is in the {source.trust_boundary} boundary, "
                f"which does not match the {trust_boundary} boundary of the entity it would support"
            )


def get_effective_source_classification(session: Session, *, source_id: uuid.UUID) -> DataClassification:
    """The Source's own classification, elevated by its most recent
    `source_classification_elevation` row if one exists (D030). Elevation
    is enforced strictly upward-only (`elevate_source_classification`),
    so "most recent" and "maximum" always agree. This is the only correct
    way to ask how sensitive a Source currently is anywhere downstream -
    never read `Source.data_classification` directly for a policy/access
    decision."""
    latest = session.execute(
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == source_id)
        .order_by(SourceClassificationElevation.elevated_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if latest is not None:
        return latest

    stored = session.execute(select(Source.data_classification).where(Source.id == source_id)).scalar_one_or_none()
    if stored is None:
        raise ValueError(f"source {source_id} does not exist")
    return stored


def _assert_classification_not_weaker_than_evidence(
    session: Session, data_classification: DataClassification, supporting_sources: Sequence[Source]
) -> None:
    for source in supporting_sources:
        effective = get_effective_source_classification(session, source_id=source.id)
        if _CLASSIFICATION_ORDER[data_classification] < _CLASSIFICATION_ORDER[effective]:
            raise ClassificationTooWeakError(
                f"classification {data_classification} is less restrictive than "
                f"supporting source {source.id}'s effective classification {effective}"
            )


def _assert_has_supporting_evidence(evidence: Sequence[EvidenceInput]) -> None:
    if not any(item.stance == EvidenceStance.SUPPORTS for item in evidence):
        raise MissingSupportingEvidenceError("a version requires at least one SUPPORTS evidence row")


def _assert_head_boundary(
    session: Session,
    head_model: type[Base],
    related_id: uuid.UUID,
    trust_boundary: TrustBoundary,
    label: str,
) -> None:
    """Confirms `related_id` exists in a versioned entity's head table
    (D029: `CompanyHead`/`ProjectHead`, or `PersonHead`) and shares
    `trust_boundary` - for optional/required references to a versioned
    entity, mirroring `create_commitment`'s existing owner-Person check."""
    table = cast(Table, head_model.__table__)
    row = session.execute(select(table.c.trust_boundary).where(table.c.entity_id == related_id)).one_or_none()
    if row is None:
        raise ValueError(f"{label} {related_id} does not exist")
    if row.trust_boundary != trust_boundary:
        raise RelatedEntityBoundaryMismatchError(
            f"boundary {trust_boundary} does not match {label} boundary {row.trust_boundary}"
        )


def _assert_direct_boundary(
    session: Session,
    model: type[Base],
    id_column: str,
    related_id: uuid.UUID,
    trust_boundary: TrustBoundary,
    label: str,
) -> None:
    """Same as `_assert_head_boundary`, for immutable/event-like entities
    (D029: `Meeting`, `Decision`) that have no head table - looked up
    directly by their own `id`/`trust_boundary` columns."""
    table = cast(Table, model.__table__)
    row = session.execute(
        select(table.c.trust_boundary).where(table.c[id_column] == related_id)
    ).one_or_none()
    if row is None:
        raise ValueError(f"{label} {related_id} does not exist")
    if row.trust_boundary != trust_boundary:
        raise RelatedEntityBoundaryMismatchError(
            f"boundary {trust_boundary} does not match {label} boundary {row.trust_boundary}"
        )


def create_person(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    display_name: str,
    evidence: Sequence[EvidenceInput],
    entity_id: uuid.UUID | None = None,
    primary_email: str | None = None,
    status: PersonStatus = PersonStatus.ACTIVE,
) -> Person:
    """Create the next version of a Person (a brand-new one if `entity_id`
    is omitted or not yet known)."""
    _assert_has_supporting_evidence(evidence)

    entity_id = entity_id if entity_id is not None else uuid.uuid4()
    sources_by_id = _load_sources(session, {item.source_id for item in evidence})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)
    supporting = [sources_by_id[item.source_id] for item in evidence if item.stance == EvidenceStance.SUPPORTS]
    _assert_classification_not_weaker_than_evidence(session, data_classification, supporting)

    version = _allocate_version(session, PersonHead, entity_id, trust_boundary)

    person = Person(
        entity_id=entity_id,
        version=version,
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        status=status,
        display_name=display_name,
        primary_email=primary_email,
    )
    session.add(person)
    session.flush()

    for item in evidence:
        session.add(
            PersonEvidence(
                person_entity_id=entity_id,
                person_version=version,
                trust_boundary=trust_boundary,
                source_id=item.source_id,
                stance=item.stance,
                confidence=item.confidence,
            )
        )

    _advance_head(session, PersonHead, entity_id, version)
    session.flush()
    return person


def get_person(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    include_retracted: bool = False,
) -> Person | None:
    """Return the current version of a Person, or None if it doesn't
    exist, isn't within `requestor_boundaries`, or (unless
    `include_retracted`) is retracted."""
    stmt = (
        select(Person)
        .join(
            PersonHead,
            (PersonHead.entity_id == Person.entity_id) & (PersonHead.trust_boundary == Person.trust_boundary),
        )
        .where(
            Person.entity_id == entity_id,
            Person.version == PersonHead.current_version,
            Person.trust_boundary.in_(requestor_boundaries),
        )
    )
    person = session.execute(stmt).scalar_one_or_none()
    if person is None:
        return None
    if not include_retracted and person.status == PersonStatus.RETRACTED:
        return None
    return person


def retract_person(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    evidence: Sequence[EvidenceInput],
) -> Person:
    """Logically delete a Person: a new, tombstoned version - never a
    physical DELETE (which the schema's trigger forbids outright)."""
    current = get_person(
        session, entity_id=entity_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if current is None:
        raise ValueError(f"person {entity_id} not found or not authorized for {requestor_boundaries}")
    return create_person(
        session,
        entity_id=entity_id,
        trust_boundary=current.trust_boundary,
        data_classification=current.data_classification,
        display_name=current.display_name,
        primary_email=current.primary_email,
        evidence=evidence,
        status=PersonStatus.RETRACTED,
    )


def create_commitment(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    owner_person_id: uuid.UUID,
    description: str,
    evidence: Sequence[EvidenceInput],
    entity_id: uuid.UUID | None = None,
    due_date: date | None = None,
    project_id: uuid.UUID | None = None,
    status: CommitmentStatus = CommitmentStatus.OPEN,
) -> Commitment:
    """Create the next version of a Commitment (a brand-new one if
    `entity_id` is omitted). `owner_person_id` must be a Person already in
    the same `trust_boundary` - enforced here for a clear error, and by a
    database foreign key regardless. `project_id` (D029) is optional but,
    if given, must be a Project in the same `trust_boundary` too."""
    _assert_has_supporting_evidence(evidence)

    owner_head = session.execute(select(PersonHead).where(PersonHead.entity_id == owner_person_id)).scalar_one_or_none()
    if owner_head is None:
        raise ValueError(f"owner person {owner_person_id} does not exist")
    if owner_head.trust_boundary != trust_boundary:
        raise OwnerBoundaryMismatchError(
            f"commitment boundary {trust_boundary} does not match "
            f"owner person boundary {owner_head.trust_boundary}"
        )
    if project_id is not None:
        _assert_head_boundary(session, ProjectHead, project_id, trust_boundary, "project")

    entity_id = entity_id if entity_id is not None else uuid.uuid4()
    sources_by_id = _load_sources(session, {item.source_id for item in evidence})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)
    supporting = [sources_by_id[item.source_id] for item in evidence if item.stance == EvidenceStance.SUPPORTS]
    _assert_classification_not_weaker_than_evidence(session, data_classification, supporting)

    version = _allocate_version(session, CommitmentHead, entity_id, trust_boundary)

    commitment = Commitment(
        entity_id=entity_id,
        version=version,
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        status=status,
        owner_person_id=owner_person_id,
        description=description,
        due_date=due_date,
        project_id=project_id,
    )
    session.add(commitment)
    session.flush()

    for item in evidence:
        session.add(
            CommitmentEvidence(
                commitment_entity_id=entity_id,
                commitment_version=version,
                trust_boundary=trust_boundary,
                source_id=item.source_id,
                stance=item.stance,
                confidence=item.confidence,
            )
        )

    _advance_head(session, CommitmentHead, entity_id, version)
    session.flush()
    return commitment


def get_commitment(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    include_retracted: bool = False,
) -> Commitment | None:
    stmt = (
        select(Commitment)
        .join(
            CommitmentHead,
            (CommitmentHead.entity_id == Commitment.entity_id)
            & (CommitmentHead.trust_boundary == Commitment.trust_boundary),
        )
        .where(
            Commitment.entity_id == entity_id,
            Commitment.version == CommitmentHead.current_version,
            Commitment.trust_boundary.in_(requestor_boundaries),
        )
    )
    commitment = session.execute(stmt).scalar_one_or_none()
    if commitment is None:
        return None
    if not include_retracted and commitment.status == CommitmentStatus.RETRACTED:
        return None
    return commitment


def retract_commitment(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    evidence: Sequence[EvidenceInput],
) -> Commitment:
    current = get_commitment(
        session, entity_id=entity_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if current is None:
        raise ValueError(f"commitment {entity_id} not found or not authorized for {requestor_boundaries}")
    return create_commitment(
        session,
        entity_id=entity_id,
        trust_boundary=current.trust_boundary,
        data_classification=current.data_classification,
        owner_person_id=current.owner_person_id,
        description=current.description,
        due_date=current.due_date,
        project_id=current.project_id,
        evidence=evidence,
        status=CommitmentStatus.RETRACTED,
    )


# --- D029: Company -----------------------------------------------------------


def create_company(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    name: str,
    relationship_kind: CompanyRelationshipKind,
    evidence: Sequence[EvidenceInput],
    entity_id: uuid.UUID | None = None,
    status: CompanyStatus = CompanyStatus.ACTIVE,
) -> Company:
    """Create the next version of a Company (a brand-new one if
    `entity_id` is omitted or not yet known). Same shape as `create_person`."""
    _assert_has_supporting_evidence(evidence)

    entity_id = entity_id if entity_id is not None else uuid.uuid4()
    sources_by_id = _load_sources(session, {item.source_id for item in evidence})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)
    supporting = [sources_by_id[item.source_id] for item in evidence if item.stance == EvidenceStance.SUPPORTS]
    _assert_classification_not_weaker_than_evidence(session, data_classification, supporting)

    version = _allocate_version(session, CompanyHead, entity_id, trust_boundary)

    company = Company(
        entity_id=entity_id,
        version=version,
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        status=status,
        name=name,
        relationship_kind=relationship_kind,
    )
    session.add(company)
    session.flush()

    for item in evidence:
        session.add(
            CompanyEvidence(
                company_entity_id=entity_id,
                company_version=version,
                trust_boundary=trust_boundary,
                source_id=item.source_id,
                stance=item.stance,
                confidence=item.confidence,
            )
        )

    _advance_head(session, CompanyHead, entity_id, version)
    session.flush()
    return company


def get_company(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    include_retracted: bool = False,
) -> Company | None:
    stmt = (
        select(Company)
        .join(
            CompanyHead,
            (CompanyHead.entity_id == Company.entity_id) & (CompanyHead.trust_boundary == Company.trust_boundary),
        )
        .where(
            Company.entity_id == entity_id,
            Company.version == CompanyHead.current_version,
            Company.trust_boundary.in_(requestor_boundaries),
        )
    )
    company = session.execute(stmt).scalar_one_or_none()
    if company is None:
        return None
    if not include_retracted and company.status == CompanyStatus.RETRACTED:
        return None
    return company


def retract_company(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    evidence: Sequence[EvidenceInput],
) -> Company:
    """Logically delete a Company: a new, tombstoned version - never a
    physical DELETE."""
    current = get_company(
        session, entity_id=entity_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if current is None:
        raise ValueError(f"company {entity_id} not found or not authorized for {requestor_boundaries}")
    return create_company(
        session,
        entity_id=entity_id,
        trust_boundary=current.trust_boundary,
        data_classification=current.data_classification,
        name=current.name,
        relationship_kind=current.relationship_kind,
        evidence=evidence,
        status=CompanyStatus.RETRACTED,
    )


# --- D029: Project -------------------------------------------------------


def create_project(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    name: str,
    company_id: uuid.UUID,
    evidence: Sequence[EvidenceInput],
    entity_id: uuid.UUID | None = None,
    status: ProjectStatus = ProjectStatus.ACTIVE,
) -> Project:
    """Create the next version of a Project. `company_id` is required (a
    Project always belongs to exactly one Company) and must be in the
    same `trust_boundary`."""
    _assert_has_supporting_evidence(evidence)
    _assert_head_boundary(session, CompanyHead, company_id, trust_boundary, "company")

    entity_id = entity_id if entity_id is not None else uuid.uuid4()
    sources_by_id = _load_sources(session, {item.source_id for item in evidence})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)
    supporting = [sources_by_id[item.source_id] for item in evidence if item.stance == EvidenceStance.SUPPORTS]
    _assert_classification_not_weaker_than_evidence(session, data_classification, supporting)

    version = _allocate_version(session, ProjectHead, entity_id, trust_boundary)

    project = Project(
        entity_id=entity_id,
        version=version,
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        status=status,
        name=name,
        company_id=company_id,
    )
    session.add(project)
    session.flush()

    for item in evidence:
        session.add(
            ProjectEvidence(
                project_entity_id=entity_id,
                project_version=version,
                trust_boundary=trust_boundary,
                source_id=item.source_id,
                stance=item.stance,
                confidence=item.confidence,
            )
        )

    _advance_head(session, ProjectHead, entity_id, version)
    session.flush()
    return project


def get_project(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    include_retracted: bool = False,
) -> Project | None:
    stmt = (
        select(Project)
        .join(
            ProjectHead,
            (ProjectHead.entity_id == Project.entity_id) & (ProjectHead.trust_boundary == Project.trust_boundary),
        )
        .where(
            Project.entity_id == entity_id,
            Project.version == ProjectHead.current_version,
            Project.trust_boundary.in_(requestor_boundaries),
        )
    )
    project = session.execute(stmt).scalar_one_or_none()
    if project is None:
        return None
    if not include_retracted and project.status == ProjectStatus.RETRACTED:
        return None
    return project


def retract_project(
    session: Session,
    *,
    entity_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    evidence: Sequence[EvidenceInput],
) -> Project:
    current = get_project(
        session, entity_id=entity_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if current is None:
        raise ValueError(f"project {entity_id} not found or not authorized for {requestor_boundaries}")
    return create_project(
        session,
        entity_id=entity_id,
        trust_boundary=current.trust_boundary,
        data_classification=current.data_classification,
        name=current.name,
        company_id=current.company_id,
        evidence=evidence,
        status=ProjectStatus.RETRACTED,
    )


# --- D029: PersonCompanyRelationship ------------------------------------


def record_person_company_relationship(
    session: Session,
    *,
    person_id: uuid.UUID,
    company_id: uuid.UUID,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    relationship_kind: PersonCompanyRelationshipKind,
    source_id: uuid.UUID,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
) -> PersonCompanyRelationship:
    """Records one relationship fact. Append-only: multiple rows for the
    same (person, company) pair are expected, both concurrently and over
    time - see `PersonCompanyRelationship`'s docstring. Not a generic
    Relationship framework - this function only ever creates
    `person_company_relationship` rows."""
    _assert_head_boundary(session, PersonHead, person_id, trust_boundary, "person")
    _assert_head_boundary(session, CompanyHead, company_id, trust_boundary, "company")

    sources_by_id = _load_sources(session, {source_id})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)

    relationship = PersonCompanyRelationship(
        person_id=person_id,
        company_id=company_id,
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        relationship_kind=relationship_kind,
        started_at=started_at,
        ended_at=ended_at,
        source_id=source_id,
    )
    session.add(relationship)
    session.flush()
    return relationship


def get_current_company_relationships(
    session: Session,
    *,
    person_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
) -> list[PersonCompanyRelationship]:
    """Relationships with no recorded end date, within the caller's
    authorized boundaries - the simplest useful notion of "current"; the
    full history remains queryable directly against the table for
    anything more than this."""
    stmt = (
        select(PersonCompanyRelationship)
        .where(
            PersonCompanyRelationship.person_id == person_id,
            PersonCompanyRelationship.ended_at.is_(None),
            PersonCompanyRelationship.trust_boundary.in_(requestor_boundaries),
        )
        .order_by(PersonCompanyRelationship.noted_at)
    )
    return list(session.execute(stmt).scalars().all())


# --- D029: Meeting -------------------------------------------------------


@dataclass(frozen=True)
class MeetingSourceInput:
    """One caller-supplied source citation for a meeting being created,
    or appended to an existing one via `add_meeting_source`."""

    source_id: uuid.UUID
    source_role: MeetingSourceRole


def create_meeting(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    title: str,
    occurred_at: datetime,
    sources: Sequence[MeetingSourceInput],
    project_id: uuid.UUID | None = None,
    attendees: Sequence[uuid.UUID] = (),
) -> Meeting:
    """Create a Meeting. Requires at least one `MeetingSourceInput` -
    more may be added later via `add_meeting_source`. Meetings are
    immutable/event-like: there is no `retract_meeting`-adjacent "update"
    path, only `add_meeting_source` (additive) and `retract_meeting`
    (marks it invalid without mutating this row)."""
    if not sources:
        raise MissingSupportingEvidenceError("a meeting requires at least one source")

    if project_id is not None:
        _assert_head_boundary(session, ProjectHead, project_id, trust_boundary, "project")

    sources_by_id = _load_sources(session, {item.source_id for item in sources})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)

    for attendee_id in attendees:
        _assert_head_boundary(session, PersonHead, attendee_id, trust_boundary, "attendee")

    meeting = Meeting(
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        title=title,
        occurred_at=occurred_at,
        project_id=project_id,
    )
    session.add(meeting)
    session.flush()

    for item in sources:
        session.add(
            MeetingSource(
                meeting_id=meeting.id,
                source_id=item.source_id,
                trust_boundary=trust_boundary,
                source_role=item.source_role,
            )
        )
    for attendee_id in attendees:
        session.add(
            MeetingAttendee(
                meeting_id=meeting.id,
                person_id=attendee_id,
                trust_boundary=trust_boundary,
            )
        )

    session.flush()
    return meeting


def add_meeting_source(
    session: Session,
    *,
    meeting_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    source_id: uuid.UUID,
    source_role: MeetingSourceRole,
) -> MeetingSource:
    """Appends one more source to an existing Meeting - the Meeting row
    itself is never mutated; this only adds a new `meeting_source` row."""
    meeting = get_meeting(
        session, meeting_id=meeting_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if meeting is None:
        raise ValueError(f"meeting {meeting_id} not found or not authorized for {requestor_boundaries}")

    sources_by_id = _load_sources(session, {source_id})
    _assert_evidence_matches_boundary(sources_by_id, meeting.trust_boundary)

    meeting_source = MeetingSource(
        meeting_id=meeting_id,
        source_id=source_id,
        trust_boundary=meeting.trust_boundary,
        source_role=source_role,
    )
    session.add(meeting_source)
    session.flush()
    return meeting_source


def get_meeting(
    session: Session,
    *,
    meeting_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    include_retracted: bool = False,
) -> Meeting | None:
    """Returns the Meeting, or None if it doesn't exist, isn't within
    `requestor_boundaries`, or (unless `include_retracted`) has an entry
    in `meeting_retraction`."""
    stmt = select(Meeting).where(
        Meeting.id == meeting_id,
        Meeting.trust_boundary.in_(requestor_boundaries),
    )
    meeting = session.execute(stmt).scalar_one_or_none()
    if meeting is None:
        return None
    if not include_retracted:
        retracted = session.execute(
            select(MeetingRetraction.id).where(MeetingRetraction.meeting_id == meeting_id)
        ).scalar_one_or_none()
        if retracted is not None:
            return None
    return meeting


def retract_meeting(
    session: Session,
    *,
    meeting_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    source_id: uuid.UUID,
    reason: str | None = None,
) -> MeetingRetraction:
    """Marks a Meeting invalid (duplicate/cancelled/incorrect) - the
    original `meeting` row is never touched. Distinct from Decision's
    supersession concept: a Meeting has no equivalent, since a meeting
    isn't "replaced" by a later meeting the way a decision can be."""
    meeting = get_meeting(
        session, meeting_id=meeting_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if meeting is None:
        raise ValueError(f"meeting {meeting_id} not found or not authorized for {requestor_boundaries}")

    existing = session.execute(
        select(MeetingRetraction.id).where(MeetingRetraction.meeting_id == meeting_id)
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"meeting {meeting_id} has already been retracted")

    sources_by_id = _load_sources(session, {source_id})
    _assert_evidence_matches_boundary(sources_by_id, meeting.trust_boundary)

    retraction = MeetingRetraction(
        meeting_id=meeting_id,
        trust_boundary=meeting.trust_boundary,
        source_id=source_id,
        reason=reason,
    )
    session.add(retraction)
    session.flush()
    return retraction


# --- D029: Decision ------------------------------------------------------


def create_decision(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    description: str,
    evidence: Sequence[EvidenceInput],
    project_id: uuid.UUID | None = None,
    meeting_id: uuid.UUID | None = None,
    supersedes_decision_id: uuid.UUID | None = None,
) -> Decision:
    """Create a Decision. Immutable/event-like: there is no
    `update`/`version` path - revisiting a decision means calling this
    again with `supersedes_decision_id` set to the earlier decision's id.
    That is distinct from `retract_decision`: supersession means the
    earlier decision was real; retraction means it should not be treated
    as valid at all."""
    _assert_has_supporting_evidence(evidence)

    if project_id is not None:
        _assert_head_boundary(session, ProjectHead, project_id, trust_boundary, "project")
    if meeting_id is not None:
        _assert_direct_boundary(session, Meeting, "id", meeting_id, trust_boundary, "meeting")
    if supersedes_decision_id is not None:
        _assert_direct_boundary(
            session, Decision, "id", supersedes_decision_id, trust_boundary, "superseded decision"
        )

    sources_by_id = _load_sources(session, {item.source_id for item in evidence})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)
    supporting = [sources_by_id[item.source_id] for item in evidence if item.stance == EvidenceStance.SUPPORTS]
    _assert_classification_not_weaker_than_evidence(session, data_classification, supporting)

    decision = Decision(
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        description=description,
        project_id=project_id,
        meeting_id=meeting_id,
        supersedes_decision_id=supersedes_decision_id,
    )
    session.add(decision)
    session.flush()

    for item in evidence:
        session.add(
            DecisionEvidence(
                decision_id=decision.id,
                trust_boundary=trust_boundary,
                source_id=item.source_id,
                stance=item.stance,
                confidence=item.confidence,
            )
        )

    session.flush()
    return decision


def get_decision(
    session: Session,
    *,
    decision_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    include_retracted: bool = False,
) -> Decision | None:
    """Returns the Decision, or None if it doesn't exist, isn't within
    `requestor_boundaries`, or (unless `include_retracted`) has an entry
    in `decision_retraction`. Does not follow `supersedes_decision_id` -
    a superseded decision is still returned (it remains valid history);
    only retraction hides a decision by default."""
    stmt = select(Decision).where(
        Decision.id == decision_id,
        Decision.trust_boundary.in_(requestor_boundaries),
    )
    decision = session.execute(stmt).scalar_one_or_none()
    if decision is None:
        return None
    if not include_retracted:
        retracted = session.execute(
            select(DecisionRetraction.id).where(DecisionRetraction.decision_id == decision_id)
        ).scalar_one_or_none()
        if retracted is not None:
            return None
    return decision


def retract_decision(
    session: Session,
    *,
    decision_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    source_id: uuid.UUID,
    reason: str | None = None,
) -> DecisionRetraction:
    """Marks a Decision invalid ("should not have been asserted") - the
    original `decision` row is never touched. Distinct from supersession
    (`Decision.supersedes_decision_id`): use supersession when the
    original decision was real but circumstances changed; use retraction
    when the original record was wrong."""
    decision = get_decision(
        session, decision_id=decision_id, requestor_boundaries=requestor_boundaries, include_retracted=True
    )
    if decision is None:
        raise ValueError(f"decision {decision_id} not found or not authorized for {requestor_boundaries}")

    existing = session.execute(
        select(DecisionRetraction.id).where(DecisionRetraction.decision_id == decision_id)
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"decision {decision_id} has already been retracted")

    sources_by_id = _load_sources(session, {source_id})
    _assert_evidence_matches_boundary(sources_by_id, decision.trust_boundary)

    retraction = DecisionRetraction(
        decision_id=decision_id,
        trust_boundary=decision.trust_boundary,
        source_id=source_id,
        reason=reason,
    )
    session.add(retraction)
    session.flush()
    return retraction


# --- D030: Source lineage/idempotency ---------------------------------------


def get_current_source_revision(
    session: Session,
    *,
    system: SourceSystem,
    external_ref: str,
    trust_boundary: TrustBoundary,
    lock: bool = False,
) -> Source | None:
    """The tip of a `(system, external_ref, trust_boundary)` lineage
    chain - the one row nothing else's `supersedes_source_id` points to.
    Structural, not timestamp-based (D030). `lock=True` row-locks the tip
    (if any) via `SELECT ... FOR UPDATE` for use inside `record_source`."""
    superseded_ids = select(Source.supersedes_source_id).where(Source.supersedes_source_id.is_not(None))
    stmt = select(Source).where(
        Source.system == system,
        Source.external_ref == external_ref,
        Source.trust_boundary == trust_boundary,
        Source.id.not_in(superseded_ids),
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.execute(stmt).scalar_one_or_none()


def record_source(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    system: SourceSystem,
    content_hash: str,
    content_location: str,
    external_ref: str | None = None,
    captured_at: datetime | None = None,
    excerpt: str | None = None,
) -> tuple[Source, bool]:
    """Idempotently records one Source. Returns `(source, was_new)`.

    Idempotency key: `(system, external_ref, trust_boundary,
    content_hash)` - a second call with identical values is a no-op
    returning the existing row. A call with the same
    `(system, external_ref, trust_boundary)` but a *different*
    `content_hash` is a legitimate content revision (D030 Source
    lineage): a new, immutable row is inserted with
    `supersedes_source_id` set to the current (row-locked) tip of that
    chain - the prior row is never mutated. `content_hash`/
    `content_location` must already reference bytes an `ArtifactStore`
    has durably written before this is called - this function performs
    no filesystem I/O itself (see `zacai.ingestion.artifact_store`,
    `zacai.ingestion.pipeline`).

    Concurrency note: the tip lookup below is row-locked when an existing
    chain is found, serializing concurrent revisions of the same
    `external_ref`. Two fully concurrent *first-ever* inserts of
    different content for a never-before-seen `external_ref` are not
    fully serialized by this function alone - acceptable for this
    milestone's single-writer, no-scheduler synthetic pipeline (D030);
    closing that gap for a multi-writer future is separate, later work.
    """
    existing = None
    if external_ref is not None:
        existing = session.execute(
            select(Source).where(
                Source.system == system,
                Source.external_ref == external_ref,
                Source.trust_boundary == trust_boundary,
                Source.content_hash == content_hash,
            )
        ).scalar_one_or_none()
    if existing is not None:
        return existing, False

    supersedes_source_id: uuid.UUID | None = None
    if external_ref is not None:
        current_tip = get_current_source_revision(
            session, system=system, external_ref=external_ref, trust_boundary=trust_boundary, lock=True
        )
        if current_tip is not None:
            supersedes_source_id = current_tip.id

    source_kwargs: dict[str, object] = {
        "trust_boundary": trust_boundary,
        "data_classification": data_classification,
        "system": system,
        "external_ref": external_ref,
        "excerpt": excerpt,
        "content_hash": content_hash,
        "content_location": content_location,
        "supersedes_source_id": supersedes_source_id,
    }
    if captured_at is not None:
        source_kwargs["captured_at"] = captured_at

    source = Source(**source_kwargs)
    session.add(source)
    session.flush()
    return source, True


def is_artifact_referenced(session: Session, *, content_location: str) -> bool:
    """True if any `Source` row references this artifact location - the
    observability primitive a future, separate, not-yet-built
    orphan-artifact reconciliation process would use (D030). Never
    deletes anything itself."""
    existing = session.execute(
        select(Source.id).where(Source.content_location == content_location)
    ).scalar_one_or_none()
    return existing is not None


# --- D030: identity resolution (minimal, "unresolved rather than guessed") -


def find_person_by_email(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    email: str,
) -> Person | None:
    """Exact, case-insensitive match against the CURRENT version's
    `primary_email`, within one trust boundary only - never cross-
    boundary, never fuzzy (D030). Returns `None` - never guesses - if
    zero or more than one active Person matches."""
    stmt = (
        select(Person)
        .join(
            PersonHead,
            (PersonHead.entity_id == Person.entity_id) & (PersonHead.trust_boundary == Person.trust_boundary),
        )
        .where(
            Person.version == PersonHead.current_version,
            Person.trust_boundary == trust_boundary,
            Person.status == PersonStatus.ACTIVE,
            func.lower(Person.primary_email) == email.lower(),
        )
    )
    matches = session.execute(stmt).scalars().all()
    if len(matches) != 1:
        return None
    return matches[0]


def record_unresolved_identity(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    source_id: uuid.UUID,
    context: str,
    meeting_id: uuid.UUID | None = None,
    raw_name: str | None = None,
    raw_email: str | None = None,
) -> UnresolvedIdentity:
    """Records a reference that could not be confidently matched to an
    existing Person - never a merge, never a guess (D030). No 'resolved'
    status here; a future, separate identity-resolution workflow is what
    would eventually consume this table."""
    record = UnresolvedIdentity(
        trust_boundary=trust_boundary,
        source_id=source_id,
        meeting_id=meeting_id,
        raw_name=raw_name,
        raw_email=raw_email,
        context=context,
    )
    session.add(record)
    session.flush()
    return record


# --- D030: ingestion cursor/run lifecycle -----------------------------------


def get_ingestion_cursor(session: Session, *, connector: str, trust_boundary: TrustBoundary) -> str | None:
    return session.execute(
        select(IngestionCursor.cursor_value).where(
            IngestionCursor.connector == connector, IngestionCursor.trust_boundary == trust_boundary
        )
    ).scalar_one_or_none()


def advance_ingestion_cursor(
    session: Session, *, connector: str, trust_boundary: TrustBoundary, cursor_value: str
) -> None:
    """Upserts the single `(connector, trust_boundary)` cursor row - a
    mutable pointer (D030), not an append-only fact history. Must run in
    the same transaction as the data batch it checkpoints - see
    `zacai.ingestion.pipeline`'s three-transaction lifecycle."""
    table = cast(Table, IngestionCursor.__table__)
    session.execute(
        pg_insert(table)
        .values(connector=connector, trust_boundary=trust_boundary, cursor_value=cursor_value)
        .on_conflict_do_update(
            index_elements=["connector", "trust_boundary"],
            set_={"cursor_value": cursor_value, "updated_at": func.now()},
        )
    )


def start_ingestion_run(session: Session, *, connector: str, trust_boundary: TrustBoundary) -> IngestionRun:
    """Step 1 of the D030 three-transaction ingestion-run lifecycle:
    caller must commit the session containing this call immediately,
    before any risky work begins - see `zacai.ingestion.pipeline`."""
    run = IngestionRun(connector=connector, trust_boundary=trust_boundary, status=IngestionRunStatus.STARTED)
    session.add(run)
    session.flush()
    return run


def complete_ingestion_run(
    session: Session,
    *,
    run_id: uuid.UUID,
    items_fetched: int,
    items_ingested: int,
    items_skipped: int,
    items_failed: int,
) -> None:
    """Step 3, success case: must run in a fresh transaction opened after
    the data batch's own transaction has already committed (D030)."""
    table = cast(Table, IngestionRun.__table__)
    session.execute(
        update(table)
        .where(table.c.id == run_id)
        .values(
            status=IngestionRunStatus.SUCCEEDED,
            finished_at=func.now(),
            items_fetched=items_fetched,
            items_ingested=items_ingested,
            items_skipped=items_skipped,
            items_failed=items_failed,
        )
    )


def fail_ingestion_run(session: Session, *, run_id: uuid.UUID, error: str) -> None:
    """Step 3, failure case: must run in a fresh transaction opened after
    the data batch's own transaction has been rolled back - this is what
    lets the failure audit record survive the data rollback (D030)."""
    table = cast(Table, IngestionRun.__table__)
    session.execute(
        update(table).where(table.c.id == run_id).values(status=IngestionRunStatus.FAILED, finished_at=func.now(), error=error)
    )


# --- D030: extraction candidates (never canonical facts until approved) ----


def record_extraction_attempt(
    session: Session,
    *,
    source_id: uuid.UUID,
    trust_boundary: TrustBoundary,
    model_name: str,
    prompt_version: str,
    status: ExtractionRecordStatus,
    candidate_count: int = 0,
    error: str | None = None,
) -> ExtractionRecord:
    """Append-only: one row per extraction attempt. No uniqueness
    constraint - a deliberate re-run is expected and always retained."""
    record = ExtractionRecord(
        source_id=source_id,
        trust_boundary=trust_boundary,
        model_name=model_name,
        prompt_version=prompt_version,
        status=status,
        candidate_count=candidate_count,
        error=error,
    )
    session.add(record)
    session.flush()
    return record


def has_succeeded_extraction(
    session: Session, *, source_id: uuid.UUID, model_name: str, prompt_version: str
) -> bool:
    """True if a `SUCCEEDED` extraction_record already exists for this
    exact `(source, model, prompt)` key - the reprocessing idempotency
    check (D030): a caller checks this before running extraction again."""
    existing = session.execute(
        select(ExtractionRecord.id).where(
            ExtractionRecord.source_id == source_id,
            ExtractionRecord.model_name == model_name,
            ExtractionRecord.prompt_version == prompt_version,
            ExtractionRecord.status == ExtractionRecordStatus.SUCCEEDED,
        )
    ).scalar_one_or_none()
    return existing is not None


def create_extraction_candidate(
    session: Session,
    *,
    trust_boundary: TrustBoundary,
    extraction_record_id: uuid.UUID,
    candidate_type: ExtractionCandidateType,
    source_id: uuid.UUID,
    description: str,
    proposed_classification: DataClassification,
    confidence: float,
    meeting_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    owner_person_id: uuid.UUID | None = None,
    due_date: date | None = None,
) -> ExtractionCandidate:
    """Writes one immutable candidate - never a canonical Decision/
    Commitment (D030). `owner_person_id` is required for `COMMITMENT`
    candidates (checked here, not only by the DB, since the column
    itself is nullable to accommodate `DECISION` candidates, which have
    no owner). `proposed_classification` must already be at least as
    restrictive as the cited Source's *effective* classification (D030
    classification elevation) - checked here using the same
    `_CLASSIFICATION_ORDER` the rest of this module uses."""
    if candidate_type == ExtractionCandidateType.COMMITMENT and owner_person_id is None:
        raise ValueError("a COMMITMENT candidate requires owner_person_id")

    effective = get_effective_source_classification(session, source_id=source_id)
    if _CLASSIFICATION_ORDER[proposed_classification] < _CLASSIFICATION_ORDER[effective]:
        raise ClassificationTooWeakError(
            f"candidate classification {proposed_classification} is less restrictive than "
            f"source {source_id}'s effective classification {effective}"
        )

    candidate = ExtractionCandidate(
        trust_boundary=trust_boundary,
        extraction_record_id=extraction_record_id,
        candidate_type=candidate_type,
        source_id=source_id,
        meeting_id=meeting_id,
        project_id=project_id,
        description=description,
        owner_person_id=owner_person_id,
        due_date=due_date,
        proposed_classification=proposed_classification,
        confidence=confidence,
    )
    session.add(candidate)
    session.flush()
    return candidate


def get_candidate_review(session: Session, *, candidate_id: uuid.UUID) -> ExtractionCandidateReview | None:
    return session.execute(
        select(ExtractionCandidateReview).where(ExtractionCandidateReview.candidate_id == candidate_id)
    ).scalar_one_or_none()


def approve_extraction_candidate(
    session: Session,
    *,
    candidate_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    reviewed_by: str,
) -> ExtractionCandidateReview:
    """The only path a candidate may become canonical state (D030):
    promotes it through the normal, existing `create_decision`/
    `create_commitment` functions - never a shortcut write. Canonical
    evidence cites the candidate's original `source_id`, never the
    candidate row itself."""
    candidate = session.execute(
        select(ExtractionCandidate).where(
            ExtractionCandidate.id == candidate_id,
            ExtractionCandidate.trust_boundary.in_(requestor_boundaries),
        )
    ).scalar_one_or_none()
    if candidate is None:
        raise ValueError(f"candidate {candidate_id} not found or not authorized for {requestor_boundaries}")
    if get_candidate_review(session, candidate_id=candidate_id) is not None:
        raise ValueError(f"candidate {candidate_id} has already been reviewed")

    evidence = [
        EvidenceInput(source_id=candidate.source_id, stance=EvidenceStance.SUPPORTS, confidence=candidate.confidence)
    ]

    promoted_entity_id: uuid.UUID
    if candidate.candidate_type == ExtractionCandidateType.DECISION:
        decision = create_decision(
            session,
            trust_boundary=candidate.trust_boundary,
            data_classification=candidate.proposed_classification,
            description=candidate.description,
            evidence=evidence,
            project_id=candidate.project_id,
            meeting_id=candidate.meeting_id,
        )
        promoted_entity_id = decision.id
    else:
        if candidate.owner_person_id is None:
            raise ValueError(f"candidate {candidate_id} is a COMMITMENT candidate with no owner_person_id")
        commitment = create_commitment(
            session,
            trust_boundary=candidate.trust_boundary,
            data_classification=candidate.proposed_classification,
            owner_person_id=candidate.owner_person_id,
            description=candidate.description,
            evidence=evidence,
            due_date=candidate.due_date,
            project_id=candidate.project_id,
        )
        promoted_entity_id = commitment.entity_id

    review = ExtractionCandidateReview(
        candidate_id=candidate_id,
        trust_boundary=candidate.trust_boundary,
        outcome=ExtractionReviewOutcome.APPROVED,
        reviewed_by=reviewed_by,
        promoted_entity_id=promoted_entity_id,
    )
    session.add(review)
    session.flush()
    return review


def reject_extraction_candidate(
    session: Session,
    *,
    candidate_id: uuid.UUID,
    requestor_boundaries: frozenset[TrustBoundary],
    reviewed_by: str,
    reason: str,
) -> ExtractionCandidateReview:
    """Records a rejection - creates no Decision/Commitment. `reason` is
    required (D030: "rejection must remain auditable")."""
    if not reason:
        raise ValueError("rejecting a candidate requires a reason")

    candidate = session.execute(
        select(ExtractionCandidate).where(
            ExtractionCandidate.id == candidate_id,
            ExtractionCandidate.trust_boundary.in_(requestor_boundaries),
        )
    ).scalar_one_or_none()
    if candidate is None:
        raise ValueError(f"candidate {candidate_id} not found or not authorized for {requestor_boundaries}")
    if get_candidate_review(session, candidate_id=candidate_id) is not None:
        raise ValueError(f"candidate {candidate_id} has already been reviewed")

    review = ExtractionCandidateReview(
        candidate_id=candidate_id,
        trust_boundary=candidate.trust_boundary,
        outcome=ExtractionReviewOutcome.REJECTED,
        reviewed_by=reviewed_by,
        reason=reason,
    )
    session.add(review)
    session.flush()
    return review


# --- D030: Source classification elevation ----------------------------------


def elevate_source_classification(
    session: Session,
    *,
    source_id: uuid.UUID,
    trust_boundary: TrustBoundary,
    new_classification: DataClassification,
    reason: str,
    elevated_by: str,
) -> SourceClassificationElevation:
    """Records that a Source is more sensitive than previously known -
    never mutates `Source.data_classification` itself (Source is
    immutable). `new_classification` must be strictly more restrictive
    than the Source's current effective classification - elevation is
    monotonic upward-only (D030), never a way to weaken it."""
    source_boundary = session.execute(
        select(Source.trust_boundary).where(Source.id == source_id)
    ).scalar_one_or_none()
    if source_boundary is None:
        raise ValueError(f"source {source_id} does not exist")
    if source_boundary != trust_boundary:
        raise RelatedEntityBoundaryMismatchError(
            f"boundary {trust_boundary} does not match source boundary {source_boundary}"
        )

    current = get_effective_source_classification(session, source_id=source_id)
    if _CLASSIFICATION_ORDER[new_classification] <= _CLASSIFICATION_ORDER[current]:
        raise ClassificationNotElevatedError(
            f"new classification {new_classification} is not strictly more restrictive "
            f"than the current effective classification {current}"
        )

    elevation = SourceClassificationElevation(
        source_id=source_id,
        trust_boundary=trust_boundary,
        previous_classification=current,
        new_classification=new_classification,
        reason=reason,
        elevated_by=elevated_by,
    )
    session.add(elevation)
    session.flush()
    return elevation


# --- D031A: artifact_backup_run (operational audit only) -------------------


def start_artifact_backup_run(session: Session, *, trust_boundary: TrustBoundary) -> ArtifactBackupRun:
    """Step 1 of the D031A backup-run lifecycle: caller must commit the
    session containing this call immediately, before any risky work
    begins - see `zacai.backup_artifacts`. Mirrors `start_ingestion_run`
    (D030) exactly."""
    run = ArtifactBackupRun(trust_boundary=trust_boundary, status=ArtifactBackupRunStatus.STARTED)
    session.add(run)
    session.flush()
    return run


def complete_artifact_backup_run(
    session: Session,
    *,
    run_id: uuid.UUID,
    artifacts_checked: int,
    artifacts_backed_up: int,
    artifacts_already_protected: int,
    artifacts_repaired: int,
    artifacts_failed: int,
) -> None:
    """Terminal success update - must run in a fresh transaction opened
    after the backup work has resolved (D030's `complete_ingestion_run`
    lifecycle pattern). Never consulted to decide protection status -
    see `ArtifactBackupRun`'s docstring."""
    table = cast(Table, ArtifactBackupRun.__table__)
    session.execute(
        update(table)
        .where(table.c.id == run_id)
        .values(
            status=ArtifactBackupRunStatus.SUCCEEDED,
            finished_at=func.now(),
            artifacts_checked=artifacts_checked,
            artifacts_backed_up=artifacts_backed_up,
            artifacts_already_protected=artifacts_already_protected,
            artifacts_repaired=artifacts_repaired,
            artifacts_failed=artifacts_failed,
        )
    )


def fail_artifact_backup_run(session: Session, *, run_id: uuid.UUID, error: str) -> None:
    """Terminal failure update - a crash before this ever runs leaves the
    row at `STARTED` (an accepted, honest audit gap - never a false
    "backed up" signal, since protection status is never read from this
    table)."""
    table = cast(Table, ArtifactBackupRun.__table__)
    session.execute(
        update(table)
        .where(table.c.id == run_id)
        .values(status=ArtifactBackupRunStatus.FAILED, finished_at=func.now(), error=error)
    )
