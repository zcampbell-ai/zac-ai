"""Tests for D030 repository-layer behavior: Source lineage/idempotency,
`is_artifact_referenced`, minimal identity resolution, extraction
candidates/review, extraction reprocessing, classification elevation,
and isolation from D023/D024.

Uses the disposable `zacai_test` database only (D027), synthetic data
only, rolled back via the `db_session` fixture (tests/conftest.py).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from zacai.ingestion.extraction import CandidateProposal, run_extraction
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)
from zacai.state import (
    Decision,
    EvidenceStance,
    ExtractionCandidate,
    ExtractionCandidateType,
    ExtractionRecord,
    ExtractionRecordStatus,
    ExtractionReviewOutcome,
    Meeting,
    MeetingSourceRole,
    Source,
    SourceSystem,
)
from zacai.state_repository import (
    ClassificationNotElevatedError,
    ClassificationTooWeakError,
    EvidenceInput,
    MeetingSourceInput,
    RelatedEntityBoundaryMismatchError,
    approve_extraction_candidate,
    create_extraction_candidate,
    create_meeting,
    create_person,
    elevate_source_classification,
    find_person_by_email,
    get_commitment,
    get_current_source_revision,
    get_decision,
    get_effective_source_classification,
    is_artifact_referenced,
    record_extraction_attempt,
    record_source,
    record_unresolved_identity,
    reject_extraction_candidate,
)


def _make_source(
    session: Session,
    *,
    trust_boundary: TrustBoundary = TrustBoundary.BRAINSTORM,
    data_classification: DataClassification = DataClassification.INTERNAL,
) -> Source:
    source = Source(
        trust_boundary=trust_boundary,
        data_classification=data_classification,
        system=SourceSystem.MANUAL,
        excerpt="D030 test fixture",
    )
    session.add(source)
    session.flush()
    return source


def _supports(source: Source, confidence: float = 0.9) -> EvidenceInput:
    return EvidenceInput(source_id=source.id, stance=EvidenceStance.SUPPORTS, confidence=confidence)


def _make_person(
    session: Session,
    *,
    trust_boundary: TrustBoundary = TrustBoundary.BRAINSTORM,
    name: str = "Person",
    email: str | None = None,
):
    source = _make_source(session, trust_boundary=trust_boundary)
    return create_person(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        display_name=name,
        primary_email=email,
        evidence=[_supports(source)],
    )


def _make_meeting(session: Session, *, source: Source, trust_boundary: TrustBoundary = TrustBoundary.BRAINSTORM) -> Meeting:
    return create_meeting(
        session,
        trust_boundary=trust_boundary,
        data_classification=DataClassification.INTERNAL,
        title="Sync",
        occurred_at=datetime.now(UTC),
        sources=[MeetingSourceInput(source_id=source.id, source_role=MeetingSourceRole.TRANSCRIPT)],
    )


# --- Source lineage / idempotency -------------------------------------------


def test_record_source_is_idempotent_for_identical_content(db_session: Session) -> None:
    boundary = TrustBoundary.BRAINSTORM
    first, was_new_1 = record_source(
        db_session,
        trust_boundary=boundary,
        data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash="hash-idempotent",
        content_location="loc/idempotent.bin",
        external_ref="ext-idempotent",
    )
    assert was_new_1 is True
    second, was_new_2 = record_source(
        db_session,
        trust_boundary=boundary,
        data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash="hash-idempotent",
        content_location="loc/idempotent.bin",
        external_ref="ext-idempotent",
    )
    assert was_new_2 is False
    assert second.id == first.id


def test_different_hash_same_external_ref_creates_lineage(db_session: Session) -> None:
    boundary = TrustBoundary.BRAINSTORM
    first, _ = record_source(
        db_session,
        trust_boundary=boundary,
        data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash="hash-a",
        content_location="loc/a.bin",
        external_ref="ext-lineage",
    )
    second, was_new = record_source(
        db_session,
        trust_boundary=boundary,
        data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash="hash-b",
        content_location="loc/b.bin",
        external_ref="ext-lineage",
    )
    assert was_new is True
    assert second.supersedes_source_id == first.id
    assert first.supersedes_source_id is None


def test_get_current_source_revision_returns_the_tip(db_session: Session) -> None:
    boundary = TrustBoundary.BRAINSTORM
    record_source(
        db_session, trust_boundary=boundary, data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES, content_hash="hash-a2", content_location="loc/a2.bin", external_ref="ext-tip",
    )
    second, _ = record_source(
        db_session, trust_boundary=boundary, data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES, content_hash="hash-b2", content_location="loc/b2.bin", external_ref="ext-tip",
    )
    tip = get_current_source_revision(
        db_session, system=SourceSystem.FIREFLIES, external_ref="ext-tip", trust_boundary=boundary
    )
    assert tip is not None
    assert tip.id == second.id


def test_old_hash_reappearance_does_not_disturb_the_tip(db_session: Session) -> None:
    boundary = TrustBoundary.BRAINSTORM
    first, _ = record_source(
        db_session, trust_boundary=boundary, data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES, content_hash="hash-a3", content_location="loc/a3.bin", external_ref="ext-reversion",
    )
    second, _ = record_source(
        db_session, trust_boundary=boundary, data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES, content_hash="hash-b3", content_location="loc/b3.bin", external_ref="ext-reversion",
    )
    replay, was_new = record_source(
        db_session, trust_boundary=boundary, data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES, content_hash="hash-a3", content_location="loc/a3.bin", external_ref="ext-reversion",
    )
    assert was_new is False
    assert replay.id == first.id

    tip = get_current_source_revision(
        db_session, system=SourceSystem.FIREFLIES, external_ref="ext-reversion", trust_boundary=boundary
    )
    assert tip is not None
    assert tip.id == second.id


def test_is_artifact_referenced(db_session: Session) -> None:
    assert is_artifact_referenced(db_session, content_location="loc/never-used.bin") is False
    record_source(
        db_session,
        trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash="hash-referenced",
        content_location="loc/never-used.bin",
        external_ref="ext-referenced",
    )
    assert is_artifact_referenced(db_session, content_location="loc/never-used.bin") is True


# --- Minimal identity resolution ---------------------------------------------


def test_find_person_by_email_exact_case_insensitive_match(db_session: Session) -> None:
    person = _make_person(db_session, email="Alice@Example.com")
    found = find_person_by_email(db_session, trust_boundary=TrustBoundary.BRAINSTORM, email="alice@example.com")
    assert found is not None
    assert found.entity_id == person.entity_id


def test_find_person_by_email_no_match_returns_none(db_session: Session) -> None:
    assert find_person_by_email(db_session, trust_boundary=TrustBoundary.BRAINSTORM, email="nobody@example.com") is None


def test_find_person_by_email_never_crosses_boundary(db_session: Session) -> None:
    _make_person(db_session, trust_boundary=TrustBoundary.PERSONAL, email="bob@example.com")
    found = find_person_by_email(db_session, trust_boundary=TrustBoundary.BRAINSTORM, email="bob@example.com")
    assert found is None


def test_ambiguous_email_across_two_people_resolves_to_none(db_session: Session) -> None:
    _make_person(db_session, email="dup@example.com", name="Person A")
    _make_person(db_session, email="dup@example.com", name="Person B")
    assert find_person_by_email(db_session, trust_boundary=TrustBoundary.BRAINSTORM, email="dup@example.com") is None


def test_record_unresolved_identity(db_session: Session) -> None:
    source = _make_source(db_session)
    record = record_unresolved_identity(
        db_session,
        trust_boundary=TrustBoundary.BRAINSTORM,
        source_id=source.id,
        context="meeting_attendee",
        raw_name="Unknown Person",
    )
    assert record.raw_name == "Unknown Person"
    assert record.raw_email is None


# --- Extraction candidates / review ------------------------------------------


def test_candidate_creation_never_creates_canonical_decision(db_session: Session) -> None:
    source = _make_source(db_session)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    create_extraction_candidate(
        db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
        candidate_type=ExtractionCandidateType.DECISION, source_id=source.id,
        description="D030 candidate-only marker", proposed_classification=DataClassification.INTERNAL, confidence=0.8,
    )
    decisions = db_session.execute(
        select(Decision).where(Decision.description == "D030 candidate-only marker")
    ).scalars().all()
    assert decisions == []


def test_approve_decision_candidate_promotes_via_create_decision_with_provenance(db_session: Session) -> None:
    source = _make_source(db_session)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    candidate = create_extraction_candidate(
        db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
        candidate_type=ExtractionCandidateType.DECISION, source_id=source.id,
        description="Adopt Postgres", proposed_classification=DataClassification.INTERNAL, confidence=0.75,
    )
    review = approve_extraction_candidate(
        db_session, candidate_id=candidate.id, requestor_boundaries=frozenset({source.trust_boundary}), reviewed_by="zac"
    )
    assert review.outcome == ExtractionReviewOutcome.APPROVED
    assert review.promoted_entity_id is not None

    decision = get_decision(
        db_session, decision_id=review.promoted_entity_id, requestor_boundaries=frozenset({source.trust_boundary})
    )
    assert decision is not None
    assert decision.description == "Adopt Postgres"

    from zacai.state import DecisionEvidence

    evidence_rows = db_session.execute(
        select(DecisionEvidence).where(DecisionEvidence.decision_id == decision.id)
    ).scalars().all()
    assert len(evidence_rows) == 1
    assert evidence_rows[0].source_id == source.id
    assert evidence_rows[0].confidence == 0.75


def test_commitment_candidate_requires_owner_person_id(db_session: Session) -> None:
    source = _make_source(db_session)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    with pytest.raises(ValueError, match="owner_person_id"):
        create_extraction_candidate(
            db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
            candidate_type=ExtractionCandidateType.COMMITMENT, source_id=source.id,
            description="Follow up with client", proposed_classification=DataClassification.INTERNAL, confidence=0.6,
        )


def test_approve_commitment_candidate(db_session: Session) -> None:
    source = _make_source(db_session)
    person = _make_person(db_session)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    candidate = create_extraction_candidate(
        db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
        candidate_type=ExtractionCandidateType.COMMITMENT, source_id=source.id, owner_person_id=person.entity_id,
        description="Follow up with client", proposed_classification=DataClassification.INTERNAL, confidence=0.6,
    )
    review = approve_extraction_candidate(
        db_session, candidate_id=candidate.id, requestor_boundaries=frozenset({source.trust_boundary}), reviewed_by="zac"
    )
    assert review.promoted_entity_id is not None
    commitment = get_commitment(
        db_session, entity_id=review.promoted_entity_id, requestor_boundaries=frozenset({source.trust_boundary})
    )
    assert commitment is not None
    assert commitment.owner_person_id == person.entity_id


def test_reject_candidate_creates_no_canonical_fact_and_requires_reason(db_session: Session) -> None:
    source = _make_source(db_session)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    candidate = create_extraction_candidate(
        db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
        candidate_type=ExtractionCandidateType.DECISION, source_id=source.id,
        description="D030 hallucinated decision marker", proposed_classification=DataClassification.INTERNAL, confidence=0.3,
    )
    with pytest.raises(ValueError, match="reason"):
        reject_extraction_candidate(
            db_session, candidate_id=candidate.id, requestor_boundaries=frozenset({source.trust_boundary}),
            reviewed_by="zac", reason="",
        )
    review = reject_extraction_candidate(
        db_session, candidate_id=candidate.id, requestor_boundaries=frozenset({source.trust_boundary}),
        reviewed_by="zac", reason="not supported by the transcript",
    )
    assert review.outcome == ExtractionReviewOutcome.REJECTED
    decisions = db_session.execute(
        select(Decision).where(Decision.description == "D030 hallucinated decision marker")
    ).scalars().all()
    assert decisions == []


def test_duplicate_review_rejected(db_session: Session) -> None:
    source = _make_source(db_session)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    candidate = create_extraction_candidate(
        db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
        candidate_type=ExtractionCandidateType.DECISION, source_id=source.id,
        description="Duplicate review test", proposed_classification=DataClassification.INTERNAL, confidence=0.5,
    )
    approve_extraction_candidate(
        db_session, candidate_id=candidate.id, requestor_boundaries=frozenset({source.trust_boundary}), reviewed_by="zac"
    )
    with pytest.raises(ValueError, match="already been reviewed"):
        reject_extraction_candidate(
            db_session, candidate_id=candidate.id, requestor_boundaries=frozenset({source.trust_boundary}),
            reviewed_by="zac", reason="too late",
        )


def test_candidate_classification_cannot_be_weaker_than_effective_source(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.CONFIDENTIAL)
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="stub", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    with pytest.raises(ClassificationTooWeakError):
        create_extraction_candidate(
            db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
            candidate_type=ExtractionCandidateType.DECISION, source_id=source.id,
            description="Too weak", proposed_classification=DataClassification.INTERNAL, confidence=0.5,
        )


# --- Extraction reprocessing / run_extraction --------------------------------


def test_run_extraction_creates_candidates_from_stub(db_session: Session) -> None:
    source = _make_source(db_session)
    meeting = _make_meeting(db_session, source=source)

    def stub(_source: Source, _meeting: Meeting) -> list[CandidateProposal]:
        return [
            CandidateProposal(
                candidate_type=ExtractionCandidateType.DECISION,
                description="Extracted decision",
                confidence=0.6,
                proposed_classification=DataClassification.INTERNAL,
            )
        ]

    run_extraction(
        db_session, source=source, meeting=meeting, model_name="stub", prompt_version="v1", extraction_function=stub
    )
    candidates = db_session.execute(
        select(ExtractionCandidate).where(ExtractionCandidate.source_id == source.id)
    ).scalars().all()
    assert len(candidates) == 1
    assert candidates[0].description == "Extracted decision"


def test_run_extraction_is_a_noop_on_repeat_of_same_version(db_session: Session) -> None:
    source = _make_source(db_session)
    meeting = _make_meeting(db_session, source=source)
    calls = 0

    def stub(_source: Source, _meeting: Meeting) -> list[CandidateProposal]:
        nonlocal calls
        calls += 1
        return [
            CandidateProposal(
                candidate_type=ExtractionCandidateType.DECISION,
                description="Repeat decision",
                confidence=0.6,
                proposed_classification=DataClassification.INTERNAL,
            )
        ]

    run_extraction(db_session, source=source, meeting=meeting, model_name="m", prompt_version="v1", extraction_function=stub)
    run_extraction(db_session, source=source, meeting=meeting, model_name="m", prompt_version="v1", extraction_function=stub)

    assert calls == 1
    records = db_session.execute(select(ExtractionRecord).where(ExtractionRecord.source_id == source.id)).scalars().all()
    assert len(records) == 1
    candidates = db_session.execute(
        select(ExtractionCandidate).where(ExtractionCandidate.source_id == source.id)
    ).scalars().all()
    assert len(candidates) == 1


def test_run_extraction_new_prompt_version_coexists(db_session: Session) -> None:
    source = _make_source(db_session)
    meeting = _make_meeting(db_session, source=source)

    def stub(_source: Source, _meeting: Meeting) -> list[CandidateProposal]:
        return [
            CandidateProposal(
                candidate_type=ExtractionCandidateType.DECISION,
                description="Version test",
                confidence=0.6,
                proposed_classification=DataClassification.INTERNAL,
            )
        ]

    run_extraction(db_session, source=source, meeting=meeting, model_name="m", prompt_version="v1", extraction_function=stub)
    run_extraction(db_session, source=source, meeting=meeting, model_name="m", prompt_version="v2", extraction_function=stub)

    records = db_session.execute(select(ExtractionRecord).where(ExtractionRecord.source_id == source.id)).scalars().all()
    assert len(records) == 2
    candidates = db_session.execute(
        select(ExtractionCandidate).where(ExtractionCandidate.source_id == source.id)
    ).scalars().all()
    assert len(candidates) == 2


def test_run_extraction_records_failure_without_creating_candidates(db_session: Session) -> None:
    source = _make_source(db_session)
    meeting = _make_meeting(db_session, source=source)

    def failing(_source: Source, _meeting: Meeting) -> list[CandidateProposal]:
        raise RuntimeError("simulated extraction failure")

    run_extraction(
        db_session, source=source, meeting=meeting, model_name="m", prompt_version="v1", extraction_function=failing
    )
    record = db_session.execute(
        select(ExtractionRecord).where(ExtractionRecord.source_id == source.id)
    ).scalar_one()
    assert record.status == ExtractionRecordStatus.FAILED
    assert record.error is not None
    candidates = db_session.execute(
        select(ExtractionCandidate).where(ExtractionCandidate.source_id == source.id)
    ).scalars().all()
    assert candidates == []


# --- Classification elevation ------------------------------------------------


def test_elevate_increases_effective_classification(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.CONFIDENTIAL)
    assert get_effective_source_classification(db_session, source_id=source.id) == DataClassification.CONFIDENTIAL

    elevate_source_classification(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        new_classification=DataClassification.HIGHLY_RESTRICTED, reason="found a credential", elevated_by="stub-extraction",
    )
    assert get_effective_source_classification(db_session, source_id=source.id) == DataClassification.HIGHLY_RESTRICTED


def test_elevate_rejects_non_strict_increase(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.CONFIDENTIAL)
    with pytest.raises(ClassificationNotElevatedError):
        elevate_source_classification(
            db_session, source_id=source.id, trust_boundary=source.trust_boundary,
            new_classification=DataClassification.CONFIDENTIAL, reason="same", elevated_by="zac",
        )
    with pytest.raises(ClassificationNotElevatedError):
        elevate_source_classification(
            db_session, source_id=source.id, trust_boundary=source.trust_boundary,
            new_classification=DataClassification.INTERNAL, reason="weaker", elevated_by="zac",
        )


def test_elevate_boundary_mismatch_rejected(db_session: Session) -> None:
    source = _make_source(db_session, trust_boundary=TrustBoundary.BRAINSTORM)
    with pytest.raises(RelatedEntityBoundaryMismatchError):
        elevate_source_classification(
            db_session, source_id=source.id, trust_boundary=TrustBoundary.PERSONAL,
            new_classification=DataClassification.HIGHLY_RESTRICTED, reason="x", elevated_by="y",
        )


def test_source_row_itself_is_never_mutated_by_elevation(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.CONFIDENTIAL)
    elevate_source_classification(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        new_classification=DataClassification.HIGHLY_RESTRICTED, reason="x", elevated_by="y",
    )
    stored = db_session.execute(select(Source.data_classification).where(Source.id == source.id)).scalar_one()
    assert stored == DataClassification.CONFIDENTIAL


def test_candidate_checked_against_effective_not_stale_classification(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.INTERNAL)
    elevate_source_classification(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        new_classification=DataClassification.HIGHLY_RESTRICTED, reason="x", elevated_by="y",
    )
    record = record_extraction_attempt(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        model_name="m", prompt_version="v1", status=ExtractionRecordStatus.SUCCEEDED, candidate_count=1,
    )
    with pytest.raises(ClassificationTooWeakError):
        create_extraction_candidate(
            db_session, trust_boundary=source.trust_boundary, extraction_record_id=record.id,
            candidate_type=ExtractionCandidateType.DECISION, source_id=source.id,
            description="Stale classification check", proposed_classification=DataClassification.CONFIDENTIAL, confidence=0.5,
        )


def test_highly_restricted_effective_source_trips_external_hard_deny(db_session: Session) -> None:
    source = _make_source(db_session, data_classification=DataClassification.INTERNAL)
    elevate_source_classification(
        db_session, source_id=source.id, trust_boundary=source.trust_boundary,
        new_classification=DataClassification.HIGHLY_RESTRICTED, reason="x", elevated_by="y",
    )
    effective = get_effective_source_classification(db_session, source_id=source.id)
    decision = evaluate_access(
        AccessRequest(
            data_boundary=source.trust_boundary,
            data_classification=effective,
            requestor_boundaries=frozenset({source.trust_boundary}),
            destination=Destination.EXTERNAL,
        )
    )
    assert decision.allowed is False


# --- D023/D024 isolation ------------------------------------------------------


def test_ingestion_package_never_touches_gateway_or_action_type() -> None:
    ingestion_dir = Path(__file__).resolve().parent.parent / "src" / "zacai" / "ingestion"
    py_files = list(ingestion_dir.glob("*.py"))
    assert py_files, "expected ingestion package files to exist"
    for py_file in py_files:
        contents = py_file.read_text()
        assert "zacai.gateway" not in contents, f"{py_file} references zacai.gateway"
        assert "ActionType" not in contents, f"{py_file} references ActionType"
