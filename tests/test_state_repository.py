"""Tests for zacai.state_repository (D026).

Uses `zacai_dev` only, synthetic data only. Most tests use the
`db_session` fixture (tests/conftest.py), which rolls back at teardown.

The concurrency tests are a deliberate, documented exception: they must
exercise genuinely separate, independently-committed transactions to mean
anything, so they use their own sessions via `get_session_factory()`
directly and commit for real. Because the schema is append-only by
design (tests/test_state.py proves DELETE is rejected even for test
cleanup), the synthetic rows these two tests create are left behind in
`zacai_dev` - an accepted, documented tradeoff for a local dev database,
each run using a fresh random `entity_id` so nothing collides.
"""

from __future__ import annotations

import itertools
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from zacai.db import get_session_factory
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import (
    Commitment,
    CommitmentStatus,
    EvidenceStance,
    Person,
    PersonHead,
    PersonStatus,
    Source,
    SourceSystem,
)
from zacai.state_repository import (
    BoundaryImmutableError,
    ClassificationTooWeakError,
    EvidenceBoundaryMismatchError,
    EvidenceInput,
    MissingSupportingEvidenceError,
    OwnerBoundaryMismatchError,
    create_commitment,
    create_person,
    get_commitment,
    get_person,
    retract_commitment,
    retract_person,
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
        excerpt="synthetic test source",
    )
    session.add(source)
    session.flush()
    return source


def _supports(source: Source, confidence: float = 0.9) -> EvidenceInput:
    return EvidenceInput(source_id=source.id, stance=EvidenceStance.SUPPORTS, confidence=confidence)


# --- create/get Person, create/get Commitment (happy path) -----------------


def test_create_and_get_person(db_session: Session) -> None:
    source = _make_source(db_session)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="Ada Lovelace",
        evidence=[_supports(source)],
    )
    fetched = get_person(db_session, entity_id=person.entity_id, requestor_boundaries=frozenset({TrustBoundary.PERSONAL}))
    assert fetched is not None
    assert fetched.display_name == "Ada Lovelace"
    assert fetched.version == 1


def test_create_and_get_commitment(db_session: Session) -> None:
    source = _make_source(db_session)
    owner = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="Owner",
        evidence=[_supports(source)],
    )
    commitment = create_commitment(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        owner_person_id=owner.entity_id,
        description="Send the proposal",
        evidence=[_supports(source)],
    )
    fetched = get_commitment(
        db_session, entity_id=commitment.entity_id, requestor_boundaries=frozenset({TrustBoundary.PERSONAL})
    )
    assert fetched is not None
    assert fetched.description == "Send the proposal"
    assert fetched.status is CommitmentStatus.OPEN


# --- boundary enforcement: get_person/get_commitment never leak ------------


@pytest.mark.parametrize(
    ("row_boundary", "requestor_boundaries"),
    [
        (TrustBoundary.PERSONAL, frozenset({TrustBoundary.BRAINSTORM})),
        (TrustBoundary.BRAINSTORM, frozenset({TrustBoundary.PERSONAL})),
        (TrustBoundary.SHARED, frozenset({TrustBoundary.PERSONAL})),
        (TrustBoundary.SHARED, frozenset({TrustBoundary.BRAINSTORM})),
        # SHARED must stay unreachable even to a requestor holding both of
        # the other two boundaries at once - combined authorization must
        # never imply SHARED (D023).
        (TrustBoundary.SHARED, frozenset({TrustBoundary.PERSONAL, TrustBoundary.BRAINSTORM})),
    ],
)
def test_get_person_never_returns_a_row_outside_requestor_boundaries(
    db_session: Session, row_boundary: TrustBoundary, requestor_boundaries: frozenset[TrustBoundary]
) -> None:
    source = _make_source(db_session, trust_boundary=row_boundary)
    person = create_person(
        db_session,
        trust_boundary=row_boundary,
        data_classification=DataClassification.INTERNAL,
        display_name="Boundary Test",
        evidence=[_supports(source)],
    )
    assert get_person(db_session, entity_id=person.entity_id, requestor_boundaries=requestor_boundaries) is None


def test_get_person_returns_row_within_its_own_boundary(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.SHARED)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.SHARED,
        data_classification=DataClassification.INTERNAL,
        display_name="Shared Person",
        evidence=[_supports(source)],
    )
    assert (
        get_person(db_session, entity_id=person.entity_id, requestor_boundaries=frozenset({TrustBoundary.SHARED}))
        is not None
    )


# --- evidence boundary consistency ------------------------------------------


def test_evidence_from_a_different_boundary_is_rejected(db_session: Session) -> None:
    other_boundary_source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    with pytest.raises(EvidenceBoundaryMismatchError):
        create_person(
            db_session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            display_name="Mismatched Evidence",
            evidence=[_supports(other_boundary_source)],
        )


def test_person_evidence_fk_rejects_mismatched_boundary_raw_insert(db_session: Session) -> None:
    """Proves the composite foreign key is a real, database-level backstop,
    not only a repository-layer convention."""
    personal_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="FK Backstop Test",
        evidence=[_supports(personal_source)],
    )
    brainstorm_source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)

    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO person_evidence "
                "(id, person_entity_id, person_version, trust_boundary, source_id, stance, confidence, noted_at) "
                "VALUES (gen_random_uuid(), :pid, :pver, 'BRAINSTORM', :sid, 'SUPPORTS', 0.9, now())"
            ),
            {"pid": person.entity_id, "pver": person.version, "sid": brainstorm_source.id},
        )
        db_session.flush()


def test_missing_supporting_evidence_is_rejected(db_session: Session) -> None:
    source = _make_source(db_session)
    with pytest.raises(MissingSupportingEvidenceError):
        create_person(
            db_session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.INTERNAL,
            display_name="No Support",
            evidence=[EvidenceInput(source_id=source.id, stance=EvidenceStance.CONTRADICTS, confidence=0.5)],
        )


# --- classification non-weakening invariant ---------------------------------


def test_classification_equal_to_evidence_is_allowed(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.CONFIDENTIAL)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.CONFIDENTIAL,
        display_name="Equal Classification",
        evidence=[_supports(source)],
    )
    assert person.data_classification is DataClassification.CONFIDENTIAL


def test_classification_more_restrictive_than_evidence_is_allowed(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.INTERNAL)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.HIGHLY_RESTRICTED,
        display_name="Stronger Classification",
        evidence=[_supports(source)],
    )
    assert person.data_classification is DataClassification.HIGHLY_RESTRICTED


def test_classification_weaker_than_evidence_is_rejected(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.CONFIDENTIAL)
    with pytest.raises(ClassificationTooWeakError):
        create_person(
            db_session,
            trust_boundary=TrustBoundary.PERSONAL,
            data_classification=DataClassification.PUBLIC,
            display_name="Too Weak",
            evidence=[_supports(source)],
        )


def test_classification_weaker_ignores_contradicting_evidence(db_session: Session) -> None:
    """The non-weakening rule only applies to SUPPORTS evidence - a
    CONTRADICTS citation of a highly-classified source should not itself
    force a stronger classification."""
    supporting = _make_source(db_session, data_classification=DataClassification.PUBLIC)
    contradicting = _make_source(db_session, data_classification=DataClassification.HIGHLY_RESTRICTED)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.PUBLIC,
        display_name="Contradicted",
        evidence=[
            _supports(supporting),
            EvidenceInput(source_id=contradicting.id, stance=EvidenceStance.CONTRADICTS, confidence=0.3),
        ],
    )
    assert person.data_classification is DataClassification.PUBLIC


# --- boundary immutability across versions ----------------------------------


def test_entity_boundary_is_immutable_across_versions(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="Immutable Boundary",
        evidence=[_supports(source)],
    )

    other_boundary_source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    with pytest.raises(BoundaryImmutableError):
        create_person(
            db_session,
            entity_id=person.entity_id,
            trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.INTERNAL,
            display_name="Changed Boundary",
            evidence=[_supports(other_boundary_source)],
        )


def test_entity_boundary_fk_backstop_rejects_mismatched_version_raw_insert(db_session: Session) -> None:
    """Proves boundary immutability is structural (a foreign key), not
    only the repository's own explicit check."""
    source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    person = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="Raw Insert Backstop",
        evidence=[_supports(source)],
    )

    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO person (entity_id, version, trust_boundary, data_classification, status, "
                "display_name, valid_from) "
                "VALUES (:id, :version, 'BRAINSTORM', 'INTERNAL', 'ACTIVE', 'bypass', now())"
            ),
            {"id": person.entity_id, "version": person.version + 1},
        )
        db_session.flush()


# --- owner boundary consistency ---------------------------------------------


@pytest.mark.parametrize(
    ("commitment_boundary", "owner_boundary"), list(itertools.product(TrustBoundary, TrustBoundary))
)
def test_commitment_owner_boundary_matrix(
    db_session: Session, commitment_boundary: TrustBoundary, owner_boundary: TrustBoundary
) -> None:
    owner_source = _make_source(db_session, trust_boundary=owner_boundary)
    owner = create_person(
        db_session,
        trust_boundary=owner_boundary,
        data_classification=DataClassification.INTERNAL,
        display_name="Owner",
        evidence=[_supports(owner_source)],
    )
    commitment_source = _make_source(db_session, trust_boundary=commitment_boundary)

    if commitment_boundary == owner_boundary:
        commitment = create_commitment(
            db_session,
            trust_boundary=commitment_boundary,
            data_classification=DataClassification.INTERNAL,
            owner_person_id=owner.entity_id,
            description="Matrix commitment",
            evidence=[_supports(commitment_source)],
        )
        assert commitment.owner_person_id == owner.entity_id
    else:
        with pytest.raises(OwnerBoundaryMismatchError):
            create_commitment(
                db_session,
                trust_boundary=commitment_boundary,
                data_classification=DataClassification.INTERNAL,
                owner_person_id=owner.entity_id,
                description="Should be rejected",
                evidence=[_supports(commitment_source)],
            )


def test_commitment_owner_fk_backstop_rejects_mismatched_boundary_raw_insert(db_session: Session) -> None:
    """Proves owner-boundary consistency is structural (a foreign key on
    (owner_person_id, trust_boundary)), not only a repository check."""
    owner_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL)
    owner = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="Owner",
        evidence=[_supports(owner_source)],
    )
    entity_id = uuid.uuid4()
    db_session.execute(
        text("INSERT INTO commitment_head (entity_id, trust_boundary, current_version) VALUES (:id, 'BRAINSTORM', 0)"),
        {"id": entity_id},
    )

    with pytest.raises(DBAPIError):
        db_session.execute(
            text(
                "INSERT INTO commitment (entity_id, version, trust_boundary, data_classification, status, "
                "owner_person_id, description, valid_from) "
                "VALUES (:id, 1, 'BRAINSTORM', 'INTERNAL', 'OPEN', :owner_id, 'bypass', now())"
            ),
            {"id": entity_id, "owner_id": owner.entity_id},
        )
        db_session.flush()


# --- tombstone / history behavior -------------------------------------------


def test_retract_person_creates_tombstone_version(db_session: Session) -> None:
    source = _make_source(db_session)
    original = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="To Be Retracted",
        primary_email="original@example.test",
        evidence=[_supports(source)],
    )

    retraction_source = _make_source(db_session, trust_boundary=TrustBoundary.PERSONAL, data_classification=DataClassification.PUBLIC)
    retracted = retract_person(
        db_session,
        entity_id=original.entity_id,
        requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
        evidence=[_supports(retraction_source)],
    )

    assert retracted.version == original.version + 1
    assert retracted.status is PersonStatus.RETRACTED
    assert retracted.display_name == original.display_name

    assert (
        get_person(db_session, entity_id=original.entity_id, requestor_boundaries=frozenset({TrustBoundary.PERSONAL}))
        is None
    )

    with_retracted = get_person(
        db_session,
        entity_id=original.entity_id,
        requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
        include_retracted=True,
    )
    assert with_retracted is not None
    assert with_retracted.status is PersonStatus.RETRACTED

    history = (
        db_session.execute(select(Person).where(Person.entity_id == original.entity_id).order_by(Person.version))
        .scalars()
        .all()
    )
    assert [row.version for row in history] == [1, 2]
    assert history[0].status is PersonStatus.ACTIVE
    assert history[0].display_name == original.display_name


def test_retract_commitment_creates_tombstone_version(db_session: Session) -> None:
    source = _make_source(db_session)
    owner = create_person(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        display_name="Owner",
        evidence=[_supports(source)],
    )
    original = create_commitment(
        db_session,
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        owner_person_id=owner.entity_id,
        description="Will be retracted",
        evidence=[_supports(source)],
    )

    retracted = retract_commitment(
        db_session,
        entity_id=original.entity_id,
        requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
        evidence=[_supports(source)],
    )

    assert retracted.status is CommitmentStatus.RETRACTED
    assert retracted.version == original.version + 1
    assert (
        get_commitment(
            db_session, entity_id=original.entity_id, requestor_boundaries=frozenset({TrustBoundary.PERSONAL})
        )
        is None
    )

    history = (
        db_session.execute(
            select(Commitment).where(Commitment.entity_id == original.entity_id).order_by(Commitment.version)
        )
        .scalars()
        .all()
    )
    assert [row.status for row in history] == [CommitmentStatus.OPEN, CommitmentStatus.RETRACTED]


# --- concurrency: real, separately-committed transactions -------------------
#
# These two tests deliberately do not use the `db_session` fixture - they
# need genuinely independent connections/transactions to exercise real
# PostgreSQL row-locking, and they commit for real. Synthetic rows they
# create are intentionally left in zacai_dev (see module docstring).


def test_concurrent_first_version_creation_same_entity() -> None:
    entity_id = uuid.uuid4()
    boundary = TrustBoundary.PERSONAL

    with get_session_factory()() as setup_session:
        source = _make_source(setup_session, trust_boundary=boundary)
        source_id = source.id
        setup_session.commit()

    def _create(display_name: str) -> None:
        session = get_session_factory()()
        try:
            create_person(
                session,
                entity_id=entity_id,
                trust_boundary=boundary,
                data_classification=DataClassification.INTERNAL,
                display_name=display_name,
                evidence=[EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
            )
            session.commit()
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create, "Concurrent A"), pool.submit(_create, "Concurrent B")]
        for future in futures:
            future.result()  # re-raises if either call failed

    with get_session_factory()() as verify_session:
        head = verify_session.get(PersonHead, entity_id)
        versions = (
            verify_session.execute(select(Person.version).where(Person.entity_id == entity_id).order_by(Person.version))
            .scalars()
            .all()
        )

    assert head is not None
    assert head.current_version == 2
    assert versions == [1, 2]


def test_concurrent_next_version_creation_existing_entity() -> None:
    entity_id = uuid.uuid4()
    boundary = TrustBoundary.PERSONAL

    with get_session_factory()() as setup_session:
        source = _make_source(setup_session, trust_boundary=boundary)
        source_id = source.id
        create_person(
            setup_session,
            entity_id=entity_id,
            trust_boundary=boundary,
            data_classification=DataClassification.INTERNAL,
            display_name="Initial version",
            evidence=[EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
        )
        setup_session.commit()

    def _create(display_name: str) -> None:
        session = get_session_factory()()
        try:
            create_person(
                session,
                entity_id=entity_id,
                trust_boundary=boundary,
                data_classification=DataClassification.INTERNAL,
                display_name=display_name,
                evidence=[EvidenceInput(source_id=source_id, stance=EvidenceStance.SUPPORTS, confidence=0.9)],
            )
            session.commit()
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create, "Concurrent Next A"), pool.submit(_create, "Concurrent Next B")]
        for future in futures:
            future.result()

    with get_session_factory()() as verify_session:
        head = verify_session.get(PersonHead, entity_id)
        versions = (
            verify_session.execute(select(Person.version).where(Person.entity_id == entity_id).order_by(Person.version))
            .scalars()
            .all()
        )

    assert head is not None
    assert head.current_version == 3
    assert versions == [1, 2, 3]
