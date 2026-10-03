"""Closed canonical audit metadata tests; isolated zacai_test and temp artifacts."""

import json
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_review_evaluation import packet
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.review_audit import (
    ReviewAuditEvent,
    ReviewAuditStage,
    append_review_audit,
    append_review_evaluation,
)
from zacai.intelligence.review_evaluation import EvaluationOutcome, ReviewJudgment
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source


def audit_packet(judgment=ReviewJudgment.UNREVIEWED):
    context, review, evaluation = packet(judgment)
    outcome = {
        ReviewJudgment.PASS: EvaluationOutcome.REVIEWED_PASS,
        ReviewJudgment.FAIL: EvaluationOutcome.NEEDS_REVISION,
        ReviewJudgment.UNREVIEWED: EvaluationOutcome.NEEDS_REVIEW,
    }[judgment]
    event = ReviewAuditEvent(
        audit_event_id=uuid4(),
        run_id=uuid4(),
        task_id=review.task_id,
        recorded_at=evaluation.evaluated_at,
        trust_boundary=B.SHARED,
        data_classification=C.PUBLIC,
        stage=ReviewAuditStage.EVALUATION_RECORDED,
        context_digest=evaluation.context_digest,
        review_digest=evaluation.review_digest,
        evaluation=evaluation,
        evaluation_outcome=outcome,
    )
    return context, review, event


def append(session, store, event, **changes):
    # General stage storage must never bypass exact evaluation verification.
    data = event.model_dump()
    data.update(
        stage=ReviewAuditStage.DRAFT_VALIDATED,
        evaluation=None,
        evaluation_outcome=None,
        route={"provider_id": "synthetic", "model_id": "invented", "runtime_id": "test-only"},
    )
    event = ReviewAuditEvent.model_validate(data)
    values = {
        "artifacts": store,
        "event": event,
        "authorized_boundaries": frozenset({B.SHARED}),
    }
    values.update(changes)
    return append_review_audit(session, **values)


def test_evaluation_persists_exact_metadata_in_canonical_backup_inventory(db_session, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path)
    context, review, event = audit_packet()
    source_id = append_review_evaluation(
        db_session,
        artifacts=store,
        event=event,
        review=review,
        context=context,
        authorized_boundaries=frozenset({B.SHARED}),
    )
    source = db_session.get(Source, source_id)
    raw = store.get(B.SHARED, source.content_location)
    assert content_hash_of(raw) == source.content_hash
    assert source.trust_boundary == B.SHARED and source.data_classification == C.PUBLIC
    assert json.loads(raw)["evaluation_outcome"] == "NEEDS_REVIEW"
    assert b"Test the fix before release" not in raw
    assert b"Alex:" not in raw
    assert b"untrusted_text" not in raw
    assert json.loads(raw)["evaluation"]["review_digest"] == event.review_digest


def test_exact_retry_reuses_source_and_checks_artifact(db_session, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path)
    _, _, event = audit_packet()
    first = append(db_session, store, event)
    assert append(db_session, store, event) == first
    sources = db_session.scalars(
        select(Source).where(Source.external_ref == f"meeting-review-audit/{event.audit_event_id}")
    ).all()
    assert len(sources) == 1


def test_reused_audit_id_cannot_revise_history_before_artifact_write(db_session, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path)
    _, _, event = audit_packet()
    append(db_session, store, event)
    altered = event.model_copy(update={"run_id": uuid4()})

    class NoWrites:
        def put(self, *args):
            pytest.fail("revision must reject before writing an artifact")

    with pytest.raises(ValueError):
        append(db_session, NoWrites(), altered)


def test_unapproved_boundary_rejects_before_storage(db_session):
    _, _, event = audit_packet()

    class NoWrites:
        def put(self, *args):
            pytest.fail("denied boundary must not touch storage")

    with pytest.raises(ValueError):
        append(db_session, NoWrites(), event, authorized_boundaries=frozenset({B.BRAINSTORM}))


def test_corrupt_write_never_records_source_or_returns_success(db_session):
    _, _, event = audit_packet()

    class Corrupt:
        def put(self, *args):
            return "invented-location"

        def get(self, *args):
            return b"PRIVATE backend response"

    with pytest.raises(ValueError) as error:
        append(db_session, Corrupt(), event)
    assert str(error.value) == "meeting review audit unavailable or mismatched"
    assert (
        db_session.scalar(
            select(Source).where(
                Source.external_ref == f"meeting-review-audit/{event.audit_event_id}"
            )
        )
        is None
    )


@pytest.mark.parametrize(
    "change", ["notes", "missing_evaluation", "wrong_outcome", "wrong_task", "missing_digest"]
)
def test_closed_metadata_and_stage_consistency_rejects(change):
    _, _, event = audit_packet()
    data = event.model_dump()
    if change == "notes":
        data["notes"] = "PRIVATE exception/quote must not be logged"
    elif change == "missing_evaluation":
        data["evaluation"] = None
    elif change == "wrong_outcome":
        data["evaluation_outcome"] = EvaluationOutcome.REVIEWED_PASS
    elif change == "wrong_task":
        data["task_id"] = uuid4()
    else:
        data["review_digest"] = None
    with pytest.raises(ValueError):
        ReviewAuditEvent.model_validate(data)


@pytest.mark.parametrize(
    "stage",
    [
        ReviewAuditStage.DISPATCH_STARTED,
        ReviewAuditStage.DISPATCH_FAILED,
        ReviewAuditStage.DRAFT_REJECTED,
    ],
)
def test_runtime_stage_requires_host_route(stage):
    _, _, event = audit_packet()
    data = event.model_dump()
    data.update(stage=stage, evaluation=None, evaluation_outcome=None, review_digest=None)
    with pytest.raises(ValueError):
        ReviewAuditEvent.model_validate(data)


def test_no_pass_for_changed_output_and_no_audit_written(db_session, tmp_path):
    context, review, event = audit_packet(ReviewJudgment.PASS)
    data = review.model_dump()
    data["summary"][0]["text"] = "The fix is finished."
    altered = type(review).model_validate(data)
    with pytest.raises(ValueError):
        append_review_evaluation(
            db_session,
            artifacts=LocalFilesystemArtifactStore(tmp_path),
            event=event,
            review=altered,
            context=context,
            authorized_boundaries=frozenset({B.SHARED}),
        )
    assert (
        db_session.scalar(
            select(Source).where(
                Source.external_ref == f"meeting-review-audit/{event.audit_event_id}"
            )
        )
        is None
    )


def test_evaluation_boundary_or_label_cannot_be_weakened(db_session, tmp_path):
    context, review, event = audit_packet()
    altered = event.model_copy(update={"trust_boundary": B.BRAINSTORM})
    with pytest.raises(ValueError):
        append_review_evaluation(
            db_session,
            artifacts=LocalFilesystemArtifactStore(tmp_path),
            event=altered,
            review=review,
            context=context,
            authorized_boundaries=frozenset(B),
        )


def test_general_audit_api_cannot_bypass_evaluation_binding(db_session, tmp_path):
    _, _, event = audit_packet(ReviewJudgment.PASS)
    with pytest.raises(ValueError):
        append_review_audit(
            db_session,
            artifacts=LocalFilesystemArtifactStore(tmp_path),
            event=event,
            authorized_boundaries=frozenset({B.SHARED}),
        )
    assert (
        db_session.scalar(
            select(Source).where(
                Source.external_ref == f"meeting-review-audit/{event.audit_event_id}"
            )
        )
        is None
    )


def test_pending_state_edit_cannot_be_flushed_by_audit_append(db_session, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path)
    _, _, event = audit_packet()
    source_id = append(db_session, store, event)
    source = db_session.get(Source, source_id)
    source.external_ref = "pending synthetic unrelated edit"
    assert db_session.dirty

    class NoWrites:
        def put(self, *args):
            pytest.fail("pending ORM changes must reject before storage")

    with pytest.raises(ValueError):
        append(db_session, NoWrites(), event)
    assert db_session.dirty


def test_exact_evaluation_retry_is_idempotent(db_session, tmp_path):
    context, review, event = audit_packet(ReviewJudgment.PASS)
    store = LocalFilesystemArtifactStore(tmp_path)
    kwargs = {
        "artifacts": store,
        "event": event,
        "review": review,
        "context": context,
        "authorized_boundaries": frozenset({B.SHARED}),
    }
    first = append_review_evaluation(db_session, **kwargs)
    assert append_review_evaluation(db_session, **kwargs) == first
