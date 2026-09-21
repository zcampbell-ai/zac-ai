"""Integration tests for zacai.ingestion.pipeline.ingest_fireflies_batch
(D030): idempotency, cursor advancement, the three-transaction
ingestion-run lifecycle (including the "failure audit record survives a
rolled-back data transaction" invariant), and the orphan-artifact/retry
behavior.

Uses `test_session_factory` (D027) - real, independently-committed
sessions - never the rollback-scoped `db_session` fixture, since this
pipeline explicitly opens multiple separate transactions itself. All
data is synthetic and left in `zacai_test` until the next session's D027
reset, exactly like the D026/D028/D029 tests that need the same
independent-commit behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.extraction import CandidateProposal, run_extraction
from zacai.ingestion.fireflies import (
    InvalidFirefliesPayloadError,
    parse_transcript_payload,
    transcript_to_raw_payload,
)
from zacai.ingestion.pipeline import FIREFLIES_CONNECTOR, ingest_fireflies_batch
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import (
    Decision,
    ExtractionCandidateType,
    IngestionRun,
    IngestionRunStatus,
    Meeting,
    Source,
)
from zacai.state_repository import (
    approve_extraction_candidate,
    get_ingestion_cursor,
    is_artifact_referenced,
)


def _payload(
    external_id: str,
    *,
    title: str = "Weekly Sync",
    attendee_name: str = "Known Person",
    attendee_email: str | None = "known@example.com",
) -> dict[str, Any]:
    return {
        "id": external_id,
        "title": title,
        "date": "2026-09-21T10:00:00+00:00",
        "transcript_text": "We agreed to ship the thing by Friday.",
        "participants": [{"name": attendee_name, "email": attendee_email}],
    }


def test_ingest_creates_source_and_meeting(test_session_factory: sessionmaker[Session], tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    run = ingest_fireflies_batch(
        test_session_factory,
        trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL,
        artifact_store=store,
        payloads=[_payload("tx-create")],
    )
    assert run.status == IngestionRunStatus.SUCCEEDED
    assert run.items_ingested == 1
    assert run.items_skipped == 0

    with test_session_factory() as session:
        sources = session.execute(select(Source).where(Source.external_ref == "tx-create")).scalars().all()
        assert len(sources) == 1
        meetings = session.execute(select(Meeting).where(Meeting.title == "Weekly Sync")).scalars().all()
        assert any(m.id for m in meetings)


def test_ingest_same_payload_twice_is_idempotent(test_session_factory: sessionmaker[Session], tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    payload = _payload("tx-idempotent")

    first = ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store, payloads=[payload],
    )
    assert first.items_ingested == 1

    second = ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store, payloads=[payload],
    )
    assert second.items_ingested == 0
    assert second.items_skipped == 1

    with test_session_factory() as session:
        sources = session.execute(select(Source).where(Source.external_ref == "tx-idempotent")).scalars().all()
        assert len(sources) == 1


def test_ingest_advances_cursor_only_on_success(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store, payloads=[_payload("tx-cursor")],
    )
    with test_session_factory() as session:
        cursor = get_ingestion_cursor(session, connector=FIREFLIES_CONNECTOR, trust_boundary=TrustBoundary.PERSONAL)
        assert cursor == "1"


def test_ingestion_failure_leaves_no_partial_data_and_records_failed_run(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    """One malformed payload in a batch fails the whole batch's data
    transaction - proving the ingestion_run FAILED record survives that
    rollback, and that the cursor never advances and no rows from the
    otherwise-valid item in the same batch are left behind (D030)."""
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    good_payload = _payload("tx-fail-good")
    bad_payload = {"id": "tx-fail-bad"}  # missing required fields

    with test_session_factory() as session:
        cursor_before = get_ingestion_cursor(
            session, connector=FIREFLIES_CONNECTOR, trust_boundary=TrustBoundary.BRAINSTORM
        )

    try:
        ingest_fireflies_batch(
            test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.CONFIDENTIAL, artifact_store=store,
            payloads=[good_payload, bad_payload],
        )
        raised = False
    except InvalidFirefliesPayloadError:
        raised = True
    assert raised

    with test_session_factory() as session:
        sources = session.execute(select(Source).where(Source.external_ref == "tx-fail-good")).scalars().all()
        assert sources == [], "the batch's data transaction must have rolled back in full"

        cursor_after = get_ingestion_cursor(
            session, connector=FIREFLIES_CONNECTOR, trust_boundary=TrustBoundary.BRAINSTORM
        )
        assert cursor_after == cursor_before, "cursor must never advance on failure"

        latest_run = session.execute(
            select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(1)
        ).scalar_one()
        assert latest_run.status == IngestionRunStatus.FAILED
        assert latest_run.error is not None


def test_retry_after_failure_succeeds_without_duplication(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    good_payload = _payload("tx-retry")
    bad_payload = {"id": "tx-retry-bad"}

    try:
        ingest_fireflies_batch(
            test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.CONFIDENTIAL, artifact_store=store,
            payloads=[good_payload, bad_payload],
        )
    except InvalidFirefliesPayloadError:
        pass

    run = ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store, payloads=[good_payload],
    )
    assert run.items_ingested == 1

    with test_session_factory() as session:
        sources = session.execute(select(Source).where(Source.external_ref == "tx-retry")).scalars().all()
        assert len(sources) == 1


def test_orphan_artifact_from_failed_batch_is_safely_reused_on_retry(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    good_payload = _payload("tx-orphan")
    bad_payload = {"id": "tx-orphan-bad"}

    try:
        ingest_fireflies_batch(
            test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
            data_classification=DataClassification.CONFIDENTIAL, artifact_store=store,
            payloads=[good_payload, bad_payload],
        )
    except InvalidFirefliesPayloadError:
        pass

    transcript = parse_transcript_payload(good_payload)
    exact_bytes = canonical_bytes(transcript_to_raw_payload(transcript))
    digest = content_hash_of(exact_bytes)
    expected_location = store.location_for(digest)

    # The artifact exists on disk and is hash-valid - a genuine orphan.
    assert content_hash_of(store.get(expected_location)) == digest

    with test_session_factory() as session:
        assert is_artifact_referenced(session, content_location=expected_location) is False

    run = ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store, payloads=[good_payload],
    )
    assert run.items_ingested == 1

    with test_session_factory() as session:
        sources = session.execute(select(Source).where(Source.external_ref == "tx-orphan")).scalars().all()
        assert len(sources) == 1
        assert sources[0].content_location == expected_location
        assert is_artifact_referenced(session, content_location=expected_location) is True


def test_unknown_attendee_is_unresolved_not_merged(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store,
        payloads=[_payload("tx-unknown", attendee_email="nobody-yet@example.com", attendee_name="Nobody Yet")],
    )
    with test_session_factory() as session:
        from zacai.state import MeetingAttendee, UnresolvedIdentity

        unresolved = session.execute(
            select(UnresolvedIdentity).where(UnresolvedIdentity.raw_email == "nobody-yet@example.com")
        ).scalars().all()
        assert len(unresolved) == 1
        attendees = session.execute(select(MeetingAttendee)).scalars().all()
        # No attendee row was created for the unresolved person.
        assert all(a.person_id != unresolved[0].id for a in attendees)


def test_candidate_only_extraction_then_explicit_approval_end_to_end(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    """Ties ingestion + extraction + approval together: extraction never
    creates a canonical Decision directly, and approval promotes exactly
    one, citing the original transcript Source (D030)."""
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    ingest_fireflies_batch(
        test_session_factory, trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.CONFIDENTIAL, artifact_store=store,
        payloads=[_payload("tx-e2e")],
    )

    with test_session_factory() as session:
        source = session.execute(select(Source).where(Source.external_ref == "tx-e2e")).scalar_one()
        meeting = session.execute(select(Meeting).where(Meeting.title == "Weekly Sync")).scalars().first()
        assert meeting is not None

        def stub(_source: Source, _meeting: Meeting) -> list[CandidateProposal]:
            return [
                CandidateProposal(
                    candidate_type=ExtractionCandidateType.DECISION,
                    description="Ship the thing by Friday",
                    confidence=0.7,
                    proposed_classification=DataClassification.CONFIDENTIAL,
                )
            ]

        run_extraction(
            session, source=source, meeting=meeting, model_name="stub", prompt_version="v1", extraction_function=stub
        )
        session.commit()

        pre_approval_decisions = session.execute(
            select(Decision).where(Decision.description == "Ship the thing by Friday")
        ).scalars().all()
        assert pre_approval_decisions == []

        from zacai.state import ExtractionCandidate

        candidate = session.execute(
            select(ExtractionCandidate).where(ExtractionCandidate.source_id == source.id)
        ).scalar_one()
        review = approve_extraction_candidate(
            session, candidate_id=candidate.id, requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
            reviewed_by="zac",
        )
        session.commit()

        decisions = session.execute(
            select(Decision).where(Decision.description == "Ship the thing by Friday")
        ).scalars().all()
        assert len(decisions) == 1
        assert decisions[0].id == review.promoted_entity_id

        from zacai.state import DecisionEvidence

        evidence_rows = session.execute(
            select(DecisionEvidence).where(DecisionEvidence.decision_id == decisions[0].id)
        ).scalars().all()
        assert len(evidence_rows) == 1
        assert evidence_rows[0].source_id == source.id
