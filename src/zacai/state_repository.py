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
from datetime import date
from typing import cast

from sqlalchemy import Table, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from zacai.policy import DataClassification, TrustBoundary
from zacai.state import (
    Commitment,
    CommitmentEvidence,
    CommitmentHead,
    CommitmentStatus,
    EvidenceStance,
    Person,
    PersonEvidence,
    PersonHead,
    PersonStatus,
    Source,
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


class EvidenceBoundaryMismatchError(ValueError):
    """Raised when cited evidence does not share the entity version's boundary."""


class ClassificationTooWeakError(ValueError):
    """Raised when a version's classification is less restrictive than its evidence."""


class MissingSupportingEvidenceError(ValueError):
    """Raised when a version is submitted with no SUPPORTS evidence at all."""


@dataclass(frozen=True)
class EvidenceInput:
    """One caller-supplied evidence citation for a version being created."""

    source_id: uuid.UUID
    stance: EvidenceStance
    confidence: float


def _allocate_version(
    session: Session,
    head_model: type[PersonHead | CommitmentHead],
    entity_id: uuid.UUID,
    trust_boundary: TrustBoundary,
) -> int:
    """Ensure a head row exists for `entity_id`, lock it, and return the
    next version number. Must run inside the same transaction as the
    version-row insert it guards - see module docstring."""
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
    head_model: type[PersonHead | CommitmentHead],
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


def _assert_classification_not_weaker_than_evidence(
    data_classification: DataClassification, supporting_sources: Sequence[Source]
) -> None:
    for source in supporting_sources:
        if _CLASSIFICATION_ORDER[data_classification] < _CLASSIFICATION_ORDER[source.data_classification]:
            raise ClassificationTooWeakError(
                f"classification {data_classification} is less restrictive than "
                f"supporting source {source.id} ({source.data_classification})"
            )


def _assert_has_supporting_evidence(evidence: Sequence[EvidenceInput]) -> None:
    if not any(item.stance == EvidenceStance.SUPPORTS for item in evidence):
        raise MissingSupportingEvidenceError("a version requires at least one SUPPORTS evidence row")


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
    _assert_classification_not_weaker_than_evidence(data_classification, supporting)

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
    status: CommitmentStatus = CommitmentStatus.OPEN,
) -> Commitment:
    """Create the next version of a Commitment (a brand-new one if
    `entity_id` is omitted). `owner_person_id` must be a Person already in
    the same `trust_boundary` - enforced here for a clear error, and by a
    database foreign key regardless."""
    _assert_has_supporting_evidence(evidence)

    owner_head = session.execute(select(PersonHead).where(PersonHead.entity_id == owner_person_id)).scalar_one_or_none()
    if owner_head is None:
        raise ValueError(f"owner person {owner_person_id} does not exist")
    if owner_head.trust_boundary != trust_boundary:
        raise OwnerBoundaryMismatchError(
            f"commitment boundary {trust_boundary} does not match "
            f"owner person boundary {owner_head.trust_boundary}"
        )

    entity_id = entity_id if entity_id is not None else uuid.uuid4()
    sources_by_id = _load_sources(session, {item.source_id for item in evidence})
    _assert_evidence_matches_boundary(sources_by_id, trust_boundary)
    supporting = [sources_by_id[item.source_id] for item in evidence if item.stance == EvidenceStance.SUPPORTS]
    _assert_classification_not_weaker_than_evidence(data_classification, supporting)

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
        evidence=evidence,
        status=CommitmentStatus.RETRACTED,
    )
