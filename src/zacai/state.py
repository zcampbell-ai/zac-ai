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
    row, cited by a new entity version."""

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

    __table_args__ = (UniqueConstraint("id", "trust_boundary", name="uq_source_id_boundary"),)


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
