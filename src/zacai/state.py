"""Zac State v1 storage schema (D026): Source, Person, Commitment.

See DECISIONS.md D026 for the full architecture review this implements:
- `TrustBoundary`/`DataClassification` are reused unchanged from
  `zacai.policy` (D023) - this module never redefines or reinterprets
  them, only stores them, so a stored row carries enough information to
  reconstruct a D023 `AccessRequest` directly.
- `person`/`commitment` are append-only: every change is a new
  `(entity_id, version)` row, never an `UPDATE`. The initial Alembic
  migration installs a trigger on `source`/`person`/`commitment`/
  `person_evidence`/`commitment_evidence` that raises on any `UPDATE` or
  `DELETE`, so this is a database-enforced guarantee, not a convention -
  `person_head`/`commitment_head` are the one deliberate, named exception,
  holding nothing but a boundary and a version pointer.
- An entity's `trust_boundary` is fixed at first creation and can never
  change across its versions: `person`/`commitment` carry a composite
  foreign key to `person_head`/`commitment_head` on
  `(entity_id, trust_boundary)`, and a head row's `trust_boundary` is
  never updated after creation (only `current_version` is).
- `commitment.owner_person_id` carries a second composite foreign key,
  `(owner_person_id, trust_boundary) -> person_head(entity_id,
  trust_boundary)`, so a commitment can only ever reference a person in
  its own exact trust boundary - SHARED is not a bridge, matching D023.
- `person_evidence`/`commitment_evidence` are typed (not a generic
  polymorphic association table) and each carry a composite foreign key
  tying their own `trust_boundary` to both the entity version and the
  `source` they cite, so evidence cannot cross a boundary either.
- All boundary/classification enforcement here is schema-level (`CHECK`,
  foreign keys, triggers). `zacai.state_repository` adds the
  application-level checks (clear error messages, the classification
  non-weakening rule, concurrency-safe version allocation) that a caller
  actually interacts with - this module only defines the tables.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from enum import Enum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Integer,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from zacai.policy import DataClassification, TrustBoundary


class Base(DeclarativeBase):
    pass


class SourceSystem(str, Enum):
    """Where a piece of evidence came from (ARCHITECTURE.md Section 7)."""

    EMAIL = "EMAIL"
    SLACK = "SLACK"
    FIREFLIES = "FIREFLIES"
    SALESFORCE = "SALESFORCE"
    CLICKUP = "CLICKUP"
    DRIVE = "DRIVE"
    USER_INSTRUCTION = "USER_INSTRUCTION"
    MANUAL = "MANUAL"


class PersonStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RETRACTED = "RETRACTED"


class CommitmentStatus(str, Enum):
    OPEN = "OPEN"
    DONE = "DONE"
    CANCELLED = "CANCELLED"
    RETRACTED = "RETRACTED"


class EvidenceStance(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"


class CompanyRelationshipKind(str, Enum):
    """A Company's own relationship to Brainstorm - distinct from
    `PersonCompanyRelationshipKind`, which describes a Person's
    relationship to a Company."""

    CLIENT = "CLIENT"
    PROSPECT = "PROSPECT"
    PARTNER = "PARTNER"
    INTERNAL = "INTERNAL"


class CompanyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RETRACTED = "RETRACTED"


class ProjectStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ON_HOLD = "ON_HOLD"
    COMPLETE = "COMPLETE"
    RETRACTED = "RETRACTED"


class PersonCompanyRelationshipKind(str, Enum):
    """A Person's relationship to a Company (D029) - deliberately not an
    attempt to enumerate every professional relationship type; `OTHER` is
    the escape hatch, and this is additive to extend later."""

    EMPLOYEE = "EMPLOYEE"
    CONTACT = "CONTACT"
    OTHER = "OTHER"


class MeetingSourceRole(str, Enum):
    """What kind of material a Source is, with respect to a Meeting -
    orthogonal to `Source.system` (which connector produced it)."""

    CALENDAR_EVENT = "CALENDAR_EVENT"
    TRANSCRIPT = "TRANSCRIPT"
    SUMMARY = "SUMMARY"
    RECORDING = "RECORDING"
    NOTES = "NOTES"
    FOLLOW_UP = "FOLLOW_UP"


class IngestionRunStatus(str, Enum):
    """Lifecycle of one ingestion batch (D030) - see `IngestionRun`."""

    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ExtractionRecordStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ExtractionCandidateType(str, Enum):
    DECISION = "DECISION"
    COMMITMENT = "COMMITMENT"


class ExtractionReviewOutcome(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


def _enum_column(enum_cls: type[Enum], name: str) -> SAEnum:
    """A VARCHAR + CHECK-constraint enum, not a native Postgres ENUM type -
    simpler to extend later (an additive migration, not an `ALTER TYPE`),
    matching the fail-closed `str, Enum` pattern already used throughout
    `zacai.policy`/`zacai.config`.

    `create_constraint=True` is required explicitly: SQLAlchemy 2.0
    changed this default to False, so without it `native_enum=False`
    would only validate on the Python side and generate no database-level
    CHECK constraint at all - silently defeating the fail-closed guarantee
    for any write that bypasses the ORM (e.g. a raw SQL statement).
    """
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda cls: [member.value for member in cls],
    )


class Source(Base):
    """An immutable provenance record. Never versioned - a source does not
    change after capture; a corrected understanding of it is a new Source
    row, cited by a new entity version.

    D030 additions: `content_hash`/`content_location` point at the raw
    artifact bytes held by a separate `zacai.ingestion.artifact_store`
    implementation, never at a `JSONB` column here - `content_location`
    is opaque to this schema, owned entirely by whichever ArtifactStore
    wrote it. `supersedes_source_id` models a genuine content revision
    (same `(system, external_ref, trust_boundary)`, different
    `content_hash`) as a new, linked, immutable row - never a mutation.
    Its FK is DEFERRABLE INITIALLY DEFERRED for the same reason as
    `Decision.supersedes_decision_id` (D029): a self-reference within one
    table cannot be solved by row ordering alone during a bulk restore.
    The "current" revision of a lineage chain is the one row nothing
    else's `supersedes_source_id` points to - structural, not
    timestamp-based (see `state_repository.get_current_source_revision`).
    """

    __tablename__ = "source"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "source_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "source_data_classification"), nullable=False
    )
    system: Mapped[SourceSystem] = mapped_column(_enum_column(SourceSystem, "source_system"), nullable=False)
    external_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_location: Mapped[str | None] = mapped_column(Text, nullable=True)
    supersedes_source_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("id", "trust_boundary", name="uq_source_id_boundary"),
        UniqueConstraint(
            "system",
            "external_ref",
            "trust_boundary",
            "content_hash",
            name="uq_source_system_external_ref_hash_boundary",
        ),
        ForeignKeyConstraint(
            ["supersedes_source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_source_supersedes_boundary",
            deferrable=True,
            initially="DEFERRED",
        ),
    )


class PersonHead(Base):
    """Mutable-by-design pointer: current version number and the entity's
    permanently-fixed trust boundary. Holds no content. The only table
    besides `commitment_head` that this schema ever `UPDATE`s in place."""

    __tablename__ = "person_head"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "person_head_trust_boundary"), nullable=False
    )
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (UniqueConstraint("entity_id", "trust_boundary", name="uq_person_head_entity_boundary"),)


class CommitmentHead(Base):
    __tablename__ = "commitment_head"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "commitment_head_trust_boundary"), nullable=False
    )
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (UniqueConstraint("entity_id", "trust_boundary", name="uq_commitment_head_entity_boundary"),)


class CompanyHead(Base):
    """See `PersonHead` - identical shape, mutable-by-design pointer only."""

    __tablename__ = "company_head"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "company_head_trust_boundary"), nullable=False
    )
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (UniqueConstraint("entity_id", "trust_boundary", name="uq_company_head_entity_boundary"),)


class ProjectHead(Base):
    """See `PersonHead` - identical shape, mutable-by-design pointer only."""

    __tablename__ = "project_head"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "project_head_trust_boundary"), nullable=False
    )
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (UniqueConstraint("entity_id", "trust_boundary", name="uq_project_head_entity_boundary"),)


class Person(Base):
    """One immutable version of a Person. `(entity_id, version)` is the
    primary key; a new belief about a Person is always a new row, never an
    `UPDATE` to an existing one."""

    __tablename__ = "person"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "person_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "person_data_classification"), nullable=False
    )
    status: Mapped[PersonStatus] = mapped_column(
        _enum_column(PersonStatus, "person_status"), nullable=False, default=PersonStatus.ACTIVE
    )
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    primary_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("entity_id", "version", "trust_boundary", name="uq_person_entity_version_boundary"),
        ForeignKeyConstraint(
            ["entity_id", "trust_boundary"],
            ["person_head.entity_id", "person_head.trust_boundary"],
            name="fk_person_head_boundary",
        ),
    )


class Commitment(Base):
    """One immutable version of a Commitment. `owner_person_id` is a
    reference to a Person entity (not a specific version - a commitment's
    owner reference does not need re-versioning every time the owner's own
    Person record changes for unrelated reasons)."""

    __tablename__ = "commitment"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "commitment_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "commitment_data_classification"), nullable=False
    )
    status: Mapped[CommitmentStatus] = mapped_column(
        _enum_column(CommitmentStatus, "commitment_status"), nullable=False, default=CommitmentStatus.OPEN
    )
    owner_person_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    due_date: Mapped[date | None] = mapped_column(nullable=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("entity_id", "version", "trust_boundary", name="uq_commitment_entity_version_boundary"),
        ForeignKeyConstraint(
            ["entity_id", "trust_boundary"],
            ["commitment_head.entity_id", "commitment_head.trust_boundary"],
            name="fk_commitment_head_boundary",
        ),
        ForeignKeyConstraint(
            ["owner_person_id", "trust_boundary"],
            ["person_head.entity_id", "person_head.trust_boundary"],
            name="fk_commitment_owner_boundary",
        ),
        ForeignKeyConstraint(
            ["project_id", "trust_boundary"],
            ["project_head.entity_id", "project_head.trust_boundary"],
            name="fk_commitment_project_boundary",
        ),
    )


class PersonEvidence(Base):
    """A typed (non-polymorphic) link from one Person version to a Source
    that supports or contradicts it."""

    __tablename__ = "person_evidence"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    person_entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    person_version: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "person_evidence_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    stance: Mapped[EvidenceStance] = mapped_column(_enum_column(EvidenceStance, "person_evidence_stance"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_person_evidence_confidence_range"),
        ForeignKeyConstraint(
            ["person_entity_id", "person_version", "trust_boundary"],
            ["person.entity_id", "person.version", "person.trust_boundary"],
            name="fk_person_evidence_person",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_person_evidence_source",
        ),
    )


class CommitmentEvidence(Base):
    """A typed (non-polymorphic) link from one Commitment version to a
    Source that supports or contradicts it."""

    __tablename__ = "commitment_evidence"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    commitment_entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    commitment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "commitment_evidence_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    stance: Mapped[EvidenceStance] = mapped_column(
        _enum_column(EvidenceStance, "commitment_evidence_stance"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_commitment_evidence_confidence_range"),
        ForeignKeyConstraint(
            ["commitment_entity_id", "commitment_version", "trust_boundary"],
            ["commitment.entity_id", "commitment.version", "commitment.trust_boundary"],
            name="fk_commitment_evidence_commitment",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_commitment_evidence_source",
        ),
    )


# --- D029: Company, Project ------------------------------------------------


class Company(Base):
    """One immutable version of a Company. Same shape as `Person`."""

    __tablename__ = "company"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "company_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "company_data_classification"), nullable=False
    )
    status: Mapped[CompanyStatus] = mapped_column(
        _enum_column(CompanyStatus, "company_status"), nullable=False, default=CompanyStatus.ACTIVE
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    relationship_kind: Mapped[CompanyRelationshipKind] = mapped_column(
        _enum_column(CompanyRelationshipKind, "company_relationship_kind"), nullable=False
    )
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("entity_id", "version", "trust_boundary", name="uq_company_entity_version_boundary"),
        ForeignKeyConstraint(
            ["entity_id", "trust_boundary"],
            ["company_head.entity_id", "company_head.trust_boundary"],
            name="fk_company_head_boundary",
        ),
    )


class Project(Base):
    """One immutable version of a Project. Requires a Company in the same
    trust boundary."""

    __tablename__ = "project"

    entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "project_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "project_data_classification"), nullable=False
    )
    status: Mapped[ProjectStatus] = mapped_column(
        _enum_column(ProjectStatus, "project_status"), nullable=False, default=ProjectStatus.ACTIVE
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    company_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("entity_id", "version", "trust_boundary", name="uq_project_entity_version_boundary"),
        ForeignKeyConstraint(
            ["entity_id", "trust_boundary"],
            ["project_head.entity_id", "project_head.trust_boundary"],
            name="fk_project_head_boundary",
        ),
        ForeignKeyConstraint(
            ["company_id", "trust_boundary"],
            ["company_head.entity_id", "company_head.trust_boundary"],
            name="fk_project_company_boundary",
        ),
    )


class CompanyEvidence(Base):
    """A typed (non-polymorphic) link from one Company version to a
    Source that supports or contradicts it."""

    __tablename__ = "company_evidence"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    company_version: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "company_evidence_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    stance: Mapped[EvidenceStance] = mapped_column(
        _enum_column(EvidenceStance, "company_evidence_stance"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_company_evidence_confidence_range"),
        ForeignKeyConstraint(
            ["company_entity_id", "company_version", "trust_boundary"],
            ["company.entity_id", "company.version", "company.trust_boundary"],
            name="fk_company_evidence_company",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_company_evidence_source",
        ),
    )


class ProjectEvidence(Base):
    """A typed (non-polymorphic) link from one Project version to a
    Source that supports or contradicts it."""

    __tablename__ = "project_evidence"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_entity_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    project_version: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "project_evidence_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    stance: Mapped[EvidenceStance] = mapped_column(
        _enum_column(EvidenceStance, "project_evidence_stance"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_project_evidence_confidence_range"),
        ForeignKeyConstraint(
            ["project_entity_id", "project_version", "trust_boundary"],
            ["project.entity_id", "project.version", "project.trust_boundary"],
            name="fk_project_evidence_project",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_project_evidence_source",
        ),
    )


# --- D029: PersonCompanyRelationship ----------------------------------------


class PersonCompanyRelationship(Base):
    """An append-only, source-backed assertion that a Person has some
    relationship to a Company. Multiple rows for the same
    (person, company) pair are expected and meaningful, both concurrently
    (e.g. employee at one company, board member at another) and over time
    (e.g. employee 2020-2022, then contact 2023-present) - "current" is
    derived by the repository layer (e.g. `ended_at IS NULL`), never by
    mutating an earlier row. `data_classification` lives here rather than
    being inherited from Person/Company, since a relationship fact can be
    more or less sensitive than either endpoint's own record."""

    __tablename__ = "person_company_relationship"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    person_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    company_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "person_company_relationship_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "person_company_relationship_data_classification"), nullable=False
    )
    relationship_kind: Mapped[PersonCompanyRelationshipKind] = mapped_column(
        _enum_column(PersonCompanyRelationshipKind, "person_company_relationship_kind"), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["person_id", "trust_boundary"],
            ["person_head.entity_id", "person_head.trust_boundary"],
            name="fk_person_company_relationship_person",
        ),
        ForeignKeyConstraint(
            ["company_id", "trust_boundary"],
            ["company_head.entity_id", "company_head.trust_boundary"],
            name="fk_person_company_relationship_company",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_person_company_relationship_source",
        ),
    )


# --- D029: Meeting -----------------------------------------------------------


class Meeting(Base):
    """An immutable, event-like record - a meeting, once recorded, is a
    historical fact. Not versioned (no meeting_head/version machinery).
    Carries no direct `source_id`: see `MeetingSource` for its (one or
    more) typed, role-based provenance."""

    __tablename__ = "meeting"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "meeting_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "meeting_data_classification"), nullable=False
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    project_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("id", "trust_boundary", name="uq_meeting_id_boundary"),
        ForeignKeyConstraint(
            ["project_id", "trust_boundary"],
            ["project_head.entity_id", "project_head.trust_boundary"],
            name="fk_meeting_project_boundary",
        ),
    )


class MeetingSource(Base):
    """A typed, role-based link from a Meeting to a Source (calendar
    event, transcript, summary, recording, notes, follow-up material).
    Deliberately not an `EvidenceStance`-based table: these sources don't
    "support or contradict" that the meeting happened, they're each
    different material the meeting itself produced."""

    __tablename__ = "meeting_source"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    meeting_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "meeting_source_trust_boundary"), nullable=False
    )
    source_role: Mapped[MeetingSourceRole] = mapped_column(
        _enum_column(MeetingSourceRole, "meeting_source_role"), nullable=False
    )
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"],
            ["meeting.id", "meeting.trust_boundary"],
            name="fk_meeting_source_meeting",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_meeting_source_source",
        ),
    )


class MeetingAttendee(Base):
    """A typed (non-polymorphic) link from a Meeting to a Person who
    attended it. References the person entity generically via
    `person_head` (like `Commitment.owner_person_id` already does), not a
    pinned version."""

    __tablename__ = "meeting_attendee"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    meeting_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    person_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "meeting_attendee_trust_boundary"), nullable=False
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"],
            ["meeting.id", "meeting.trust_boundary"],
            name="fk_meeting_attendee_meeting",
        ),
        ForeignKeyConstraint(
            ["person_id", "trust_boundary"],
            ["person_head.entity_id", "person_head.trust_boundary"],
            name="fk_meeting_attendee_person",
        ),
    )


# --- D029: Decision ----------------------------------------------------------


class Decision(Base):
    """An immutable, event-like record. Not versioned. Revisiting a
    decision is a NEW row with `supersedes_decision_id` set - the old row
    is untouched and remains valid history. Distinct from retraction
    (`DecisionRetraction`): supersession means the old decision was real
    but a newer one now applies; retraction means the record should not
    be treated as valid at all.

    `supersedes_decision_id`'s foreign key is DEFERRABLE INITIALLY
    DEFERRED: it is the one self-referencing FK in this schema, and an
    ordinary (immediately-checked) FK would fail during a bulk restore if
    a superseding row happens to be written before the row it supersedes.
    Deferring the check to transaction commit removes any dependency on
    row order - `zacai.backup`'s restore already runs one boundary's
    entire table set inside a single transaction, committing once at the
    end, so this composes with it with no pipeline code change."""

    __tablename__ = "decision"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "decision_trust_boundary"), nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "decision_data_classification"), nullable=False
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    project_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    meeting_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    supersedes_decision_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("id", "trust_boundary", name="uq_decision_id_boundary"),
        ForeignKeyConstraint(
            ["project_id", "trust_boundary"],
            ["project_head.entity_id", "project_head.trust_boundary"],
            name="fk_decision_project_boundary",
        ),
        ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"],
            ["meeting.id", "meeting.trust_boundary"],
            name="fk_decision_meeting_boundary",
        ),
        ForeignKeyConstraint(
            ["supersedes_decision_id", "trust_boundary"],
            ["decision.id", "decision.trust_boundary"],
            name="fk_decision_supersedes_boundary",
            deferrable=True,
            initially="DEFERRED",
        ),
    )


class DecisionEvidence(Base):
    """A typed (non-polymorphic) link from a Decision to a Source that
    supports or contradicts it. No version component (unlike
    `PersonEvidence`/`CommitmentEvidence`): `Decision` rows are already
    immutable and individually unique, so there is no version to pin."""

    __tablename__ = "decision_evidence"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    decision_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "decision_evidence_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    stance: Mapped[EvidenceStance] = mapped_column(
        _enum_column(EvidenceStance, "decision_evidence_stance"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_decision_evidence_confidence_range"),
        ForeignKeyConstraint(
            ["decision_id", "trust_boundary"],
            ["decision.id", "decision.trust_boundary"],
            name="fk_decision_evidence_decision",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_decision_evidence_source",
        ),
    )


# --- D029: retraction (distinct from Decision supersession) ----------------


class DecisionRetraction(Base):
    """Marks a Decision as invalid ("should not have been asserted")
    without ever mutating the original row - presence of a row here, not
    an in-row status, is what makes a decision "retracted". At most one
    retraction per decision in v1 (`UNIQUE(decision_id)`). Distinct from
    supersession (`Decision.supersedes_decision_id`): supersession means
    the original decision was real; retraction means it should not be
    treated as valid state."""

    __tablename__ = "decision_retraction"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    decision_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "decision_retraction_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    retracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_decision_retraction_decision_id"),
        ForeignKeyConstraint(
            ["decision_id", "trust_boundary"],
            ["decision.id", "decision.trust_boundary"],
            name="fk_decision_retraction_decision",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_decision_retraction_source",
        ),
    )


class MeetingRetraction(Base):
    """Marks a Meeting as invalid (duplicate/cancelled/incorrect) without
    ever mutating the original row. See `DecisionRetraction` - identical
    shape and reasoning, one per immutable entity type, not a generic
    retraction framework."""

    __tablename__ = "meeting_retraction"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    meeting_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "meeting_retraction_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    retracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("meeting_id", name="uq_meeting_retraction_meeting_id"),
        ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"],
            ["meeting.id", "meeting.trust_boundary"],
            name="fk_meeting_retraction_meeting",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_meeting_retraction_source",
        ),
    )


# --- D030: ingestion cursor/run (mutable, operational bookkeeping) ----------


class IngestionCursor(Base):
    """The resume point for one (connector, trust_boundary) sync stream -
    a mutable pointer, the sixth deliberate exception to this schema's
    append-only rule (joining `person_head`/`commitment_head`/
    `company_head`/`project_head`), since a cursor is pure bookkeeping,
    not a content-bearing fact. `cursor_value` is opaque and
    connector-defined (D030)."""

    __tablename__ = "ingestion_cursor"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector: Mapped[str] = mapped_column(Text, nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "ingestion_cursor_trust_boundary"), nullable=False
    )
    cursor_value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("connector", "trust_boundary", name="uq_ingestion_cursor_connector_boundary"),
    )


class IngestionRun(Base):
    """One ingestion batch's lifecycle (D030): `STARTED` is written and
    committed before any risky work begins; `SUCCEEDED`/`FAILED` is
    written in a separate, later transaction so a rolled-back data batch
    can never erase the failure audit record. Mutable - a run's own
    lifecycle status is operational bookkeeping, not a fact whose full
    history must be preserved the way a Decision or Meeting is."""

    __tablename__ = "ingestion_run"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector: Mapped[str] = mapped_column(Text, nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "ingestion_run_trust_boundary"), nullable=False
    )
    status: Mapped[IngestionRunStatus] = mapped_column(
        _enum_column(IngestionRunStatus, "ingestion_run_status"),
        nullable=False,
        default=IngestionRunStatus.STARTED,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    items_fetched: Mapped[int | None] = mapped_column(Integer, nullable=True)
    items_ingested: Mapped[int | None] = mapped_column(Integer, nullable=True)
    items_skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    items_failed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


# --- D030: extraction (candidates, never canonical facts, until review) ----


class ExtractionRecord(Base):
    """One append-only row per extraction attempt over one Source. No
    uniqueness constraint - a deliberate re-run (bug fix, better model)
    is expected and always retained (D030), matching the reasoning
    already applied to `PersonCompanyRelationship`."""

    __tablename__ = "extraction_record"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "extraction_record_trust_boundary"), nullable=False
    )
    model_name: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_version: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ExtractionRecordStatus] = mapped_column(
        _enum_column(ExtractionRecordStatus, "extraction_record_status"), nullable=False
    )
    candidate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("id", "trust_boundary", name="uq_extraction_record_id_boundary"),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_extraction_record_source",
        ),
    )


class ExtractionCandidate(Base):
    """An LLM-proposed Decision or Commitment - never itself canonical
    state (D030). Immutable once written; review outcomes live in the
    separate `ExtractionCandidateReview` table, exactly mirroring why
    `Decision`/`Meeting` are immutable and their retractions live
    separately. Typed columns, not a generic JSON payload - the smallest
    shape that covers both candidate types without a polymorphic blob,
    consistent with this schema's typed-evidence precedent."""

    __tablename__ = "extraction_candidate"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "extraction_candidate_trust_boundary"), nullable=False
    )
    extraction_record_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    candidate_type: Mapped[ExtractionCandidateType] = mapped_column(
        _enum_column(ExtractionCandidateType, "extraction_candidate_type"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    meeting_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner_person_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    due_date: Mapped[date | None] = mapped_column(nullable=True)
    proposed_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "extraction_candidate_proposed_classification"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("id", "trust_boundary", name="uq_extraction_candidate_id_boundary"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_extraction_candidate_confidence_range"),
        ForeignKeyConstraint(
            ["extraction_record_id", "trust_boundary"],
            ["extraction_record.id", "extraction_record.trust_boundary"],
            name="fk_extraction_candidate_record",
        ),
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_extraction_candidate_source",
        ),
        ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"],
            ["meeting.id", "meeting.trust_boundary"],
            name="fk_extraction_candidate_meeting",
        ),
        ForeignKeyConstraint(
            ["project_id", "trust_boundary"],
            ["project_head.entity_id", "project_head.trust_boundary"],
            name="fk_extraction_candidate_project",
        ),
    )


class ExtractionCandidateReview(Base):
    """The only way a candidate's disposition is recorded - presence of a
    row here, not a mutable status column on `ExtractionCandidate`,
    mirrors `DecisionRetraction`/`MeetingRetraction` exactly. At most one
    review per candidate (`UNIQUE(candidate_id)`). `promoted_entity_id`
    is set only on `APPROVED`, pointing at the resulting
    `decision.id`/`commitment.entity_id` - traceable, but the canonical
    evidence for that promoted fact still cites the original `Source`,
    never this row."""

    __tablename__ = "extraction_candidate_review"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    candidate_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "extraction_candidate_review_trust_boundary"), nullable=False
    )
    outcome: Mapped[ExtractionReviewOutcome] = mapped_column(
        _enum_column(ExtractionReviewOutcome, "extraction_candidate_review_outcome"), nullable=False
    )
    reviewed_by: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    promoted_entity_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("candidate_id", name="uq_extraction_candidate_review_candidate_id"),
        ForeignKeyConstraint(
            ["candidate_id", "trust_boundary"],
            ["extraction_candidate.id", "extraction_candidate.trust_boundary"],
            name="fk_extraction_candidate_review_candidate",
        ),
    )


# --- D030: Source classification elevation ----------------------------------


class SourceClassificationElevation(Base):
    """Records that a Source is more sensitive than previously known -
    never mutates `Source.data_classification` itself (Source is
    immutable); presence-based, exactly like retraction. Multiple rows
    per Source are legitimate (each strictly more restrictive than the
    last) - see `state_repository.get_effective_source_classification`,
    the only correct way to ask how sensitive a Source currently is."""

    __tablename__ = "source_classification_elevation"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "source_classification_elevation_trust_boundary"), nullable=False
    )
    previous_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "source_classification_elevation_previous"), nullable=False
    )
    new_classification: Mapped[DataClassification] = mapped_column(
        _enum_column(DataClassification, "source_classification_elevation_new"), nullable=False
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    elevated_by: Mapped[str] = mapped_column(Text, nullable=False)
    elevated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_source_classification_elevation_source",
        ),
    )


# --- D030: unresolved identity ----------------------------------------------


class UnresolvedIdentity(Base):
    """A reference (meeting attendee, etc.) that could not be confidently
    matched to an existing Person - never a merge, never a guess (D030).
    No 'resolved' status: a future, separate identity-resolution
    workflow is what would eventually consume this table as its input
    queue."""

    __tablename__ = "unresolved_identity"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trust_boundary: Mapped[TrustBoundary] = mapped_column(
        _enum_column(TrustBoundary, "unresolved_identity_trust_boundary"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    meeting_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    raw_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    context: Mapped[str] = mapped_column(Text, nullable=False)
    noted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id", "trust_boundary"],
            ["source.id", "source.trust_boundary"],
            name="fk_unresolved_identity_source",
        ),
        ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"],
            ["meeting.id", "meeting.trust_boundary"],
            name="fk_unresolved_identity_meeting",
        ),
    )
