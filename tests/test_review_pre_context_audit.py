"""Invented denials, genuine separate transactions, guarded test DB only."""

import json
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from tests import test_review_authorization as authorization_tests
from tests.test_review_host import Authorization, Runtime, run
from zacai.backup_artifacts import source_hashes_for_boundary
from zacai.intelligence.review_audit import (
    ReviewPreContextAudit,
    append_review_pre_context_audit,
)
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_host import ReviewHostError, ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import CanonicalReviewAuthorization
from zacai.state import Source, SourceSystem


@pytest.fixture
def issued(test_session_factory, tmp_path):
    setup = next(authorization_tests.host_fixture.__wrapped__(test_session_factory, tmp_path))
    return authorization_tests.issued.__wrapped__(setup)


def new_denials(factory, baseline):
    with factory() as session:
        return session.scalars(
            select(Source).where(
                Source.external_ref.startswith("meeting-review-pre-context-audit/"),
                Source.id.not_in(baseline),
            )
        ).all()


@pytest.mark.parametrize("failure", ["recovery", "authority", "pin", "context"])
def test_pre_context_failure_is_committed_without_selected_reads_or_dispatch(issued, failure):
    factory, store, captured, baseline = issued[0]
    with factory() as session:
        blocked = {
            session.get(Source, sid).content_location
            for sid in (captured.raw_source_id, captured.normalized_source_id)
        }

    class GuardedStore:
        def put(self, *args):
            return store.put(*args)

        def get(self, boundary, location):
            assert location not in blocked, "denial must precede selected artifact reads"
            return store.get(boundary, location)

    runtime = Runtime(factory, store)
    auth = issued[5]()
    options = {}
    if failure == "recovery":
        issued[4].fail = True
    elif failure == "authority":
        auth = CanonicalReviewAuthorization(
            factory=factory, store=store, approval_id=uuid4(), recovery=issued[4]
        )
    elif failure == "pin":
        runtime.model_digest = "invalid private backend marker"
    else:
        auth = Authorization()
        options["selection"] = ReviewSelection(MeetingEvidence(uuid4(), uuid4()))

    def forbidden_metadata(*args):
        pytest.fail("pre-context denial must stop runtime metadata too")

    runtime.preflight = forbidden_metadata
    with pytest.raises(ReviewHostError, match="no draft released"):
        run(issued[0], runtime=runtime, authorization=auth, artifacts=GuardedStore(), **options)
    assert runtime.calls == 0
    rows = new_denials(factory, baseline)
    assert len(rows) == 1  # visible from a genuinely separate committed connection
    source = rows[0]
    assert source.system == SourceSystem.MANUAL
    assert source.trust_boundary == B.BRAINSTORM
    assert source.data_classification == C.CONFIDENTIAL
    raw = store.get(B.BRAINSTORM, source.content_location)
    event = ReviewPreContextAudit.model_validate_json(raw)
    assert source.external_ref == f"meeting-review-pre-context-audit/{event.audit_event_id}"
    assert set(json.loads(raw)) == {
        "format",
        "audit_event_id",
        "run_id",
        "recorded_at",
        "trust_boundary",
        "data_classification",
        "stage",
    }
    assert str(captured.normalized_source_id).encode() not in raw
    assert b"private backend marker" not in raw
    with factory() as session:
        assert source.content_hash in source_hashes_for_boundary(
            session, trust_boundary=B.BRAINSTORM
        )
        assert source.content_hash not in source_hashes_for_boundary(
            session, trust_boundary=B.PERSONAL
        )


def test_denial_audit_commit_failure_is_terminal_and_not_claimed_as_durable(issued):
    factory, store, _, baseline = issued[0]

    class FailCommit(Session):
        def commit(self):
            raise RuntimeError("invented private database diagnostic")

    broken = sessionmaker(bind=factory.kw["bind"], class_=FailCommit)
    auth = Authorization()
    auth.revoked = True
    runtime = Runtime(factory, store)
    with pytest.raises(ReviewHostError, match="audit unavailable") as error:
        run((broken, *issued[0][1:]), authorization=auth, runtime=runtime)
    assert "private database" not in str(error.value)
    assert runtime.calls == 0
    assert new_denials(factory, baseline) == []


def test_pre_context_record_cannot_override_denied_journal_boundary(issued):
    factory, store, _, baseline = issued[0]
    auth = Authorization()
    auth.revoked = True
    runtime = Runtime(factory, store)
    with pytest.raises(ReviewHostError, match="audit unavailable"):
        run(issued[0], authorization=auth, runtime=runtime, authorized_boundaries=frozenset())
    assert runtime.calls == 0
    assert new_denials(factory, baseline) == []


def test_pre_context_record_is_closed_and_reuses_exact_id_only(db_session, tmp_path):
    from tests.test_review_host import NOW
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    store = LocalFilesystemArtifactStore(tmp_path)
    event = ReviewPreContextAudit(audit_event_id=uuid4(), run_id=uuid4(), recorded_at=NOW)

    def append(value):
        return append_review_pre_context_audit(
            db_session,
            artifacts=store,
            event=value,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
        )

    sid = append(event)
    assert append(event) == sid
    with pytest.raises(ValueError):
        append(event.model_copy(update={"run_id": uuid4()}))
    for field in ("task_id", "context_digest", "exception_text", "authority_granted"):
        with pytest.raises(ValueError):
            ReviewPreContextAudit.model_validate({**event.model_dump(), field: "invented"})
