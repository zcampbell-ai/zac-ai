"""Root-only post-retention negatives; real rows/owner/recovery, scripted models.

Every case starts a fresh original approval and retains ten invented PASS
judgments. It never resets phase/capability or renews any original budget.
"""

import hashlib
import time
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_complete_review_pipeline_sql import (
    actual_case as actual_case,  # noqa: PLC0414
)
from tests.test_complete_review_pipeline_sql import (
    admission_case as review_admission_case,  # noqa: F401
)
from tests.test_complete_review_pipeline_sql import (
    base_admission_case as base_admission_case,  # noqa: PLC0414
)
from tests.test_complete_review_pipeline_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_complete_review_pipeline_sql import (
    history_factory_case as history_factory_case,  # noqa: PLC0414
)
from tests.test_complete_review_pipeline_sql import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_complete_review_pipeline_sql import (
    producer_case as producer_case,  # noqa: PLC0414
)
from tests.test_complete_review_pipeline_sql import (
    review_case as review_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import all_sources
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import history_publication_review as review
from zacai.intelligence.contextual_evaluation import ContextualOutcome
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import (
    elevate_source_classification,
    get_effective_source_classification,
    record_source,
)


@pytest.fixture
def admission_case(review_admission_case):  # noqa: F811 - actual pytest dependency
    f = review_admission_case
    raw = b"Invented unrelated PERSONAL context for whole-boundary staleness."
    digest = content_hash_of(raw)
    location = f.c.artifacts.put(B.PERSONAL, digest, raw)
    # Genuine lower-label row is included BEFORE original declaration/capture.
    # Selected original/packet/assessment remain HIGHLY_RESTRICTED unchanged.
    with f.c.factory() as session, session.begin():
        row, new = record_source(
            session,
            trust_boundary=B.PERSONAL,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref=f"invented-preapproval-unrelated/{uuid4()}",
            content_hash=digest,
            content_location=location,
            captured_at=f.inputs.clock._last,
        )
        assert new
        f.unrelated_id = row.id
    return f


def artifacts_snapshot(f):
    return {
        str(path.relative_to(f.c.artifacts.root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in f.c.artifacts.root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "fault",
    [
        "owner-revoke",
        "whole-boundary-elevation",
        "selected-packet-revision",
        "unrelated-append",
        "wall-expiry",
        "wall-rollback",
        "native-expiry",
    ],
)
def test_actual_retained_ten_pass_final_release_holds_without_plaintext_repair_or_retry(
    review_case, monkeypatch, fault
):
    c = review_case
    f = c.p.f
    c.state.judgment = ReviewJudgment.PASS
    observed = c.gate.invoke()
    retained = review.capture_history_publication_assessment(c.gate, observed=observed)
    assert retained.outcome is ContextualOutcome.REVIEWED_PASS
    assert c.gate._phase == "ASSESSMENT_RETAINED" and c.gate._result is retained
    assert f.unrelated_id in dict(retained.recovery_receipt.full_boundary_source_hashes)
    assert len(c.state.posts) == len(c.p.posts) == 1

    if fault == "owner-revoke":
        f.inputs.owners.revoke()  # Real enrolled owner grant store.
        with pytest.raises(ValueError, match="owner enrollment unavailable"):
            f.inputs.owners.load()
    elif fault == "whole-boundary-elevation":
        with f.c.factory() as session, session.begin():
            elevate_source_classification(
                session,
                source_id=f.unrelated_id,
                trust_boundary=B.PERSONAL,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented final-release full-boundary elevation",
                elevated_by="invented acceptance fixture",
            )
        with f.c.factory() as session, session.begin():
            row = session.execute(
                select(SourceClassificationElevation).where(
                    SourceClassificationElevation.source_id == f.unrelated_id
                )
            ).scalar_one()
            assert row.previous_classification is C.CONFIDENTIAL
            assert row.new_classification is C.HIGHLY_RESTRICTED
            assert (
                get_effective_source_classification(session, source_id=f.unrelated_id)
                is C.HIGHLY_RESTRICTED
            )
    elif fault == "selected-packet-revision":
        packet_id = c.output.association.packet_reference.source_id
        with f.c.factory() as session:
            original = session.get(Source, packet_id)
            namespace, location = original.external_ref, original.content_location
        raw = f.c.artifacts.get_bounded(B.PERSONAL, location, max_bytes=512000) + b" "
        digest = content_hash_of(raw)
        location = f.c.artifacts.put(B.PERSONAL, digest, raw)
        with f.c.factory() as session, session.begin():
            revision, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=namespace,
                content_hash=digest,
                content_location=location,
                captured_at=f.inputs.clock._last,
            )
            assert new and revision.id != packet_id and revision.supersedes_source_id == packet_id
    elif fault == "unrelated-append":
        raw = b"Invented separately committed context after assessment retention."
        digest = content_hash_of(raw)
        location = f.c.artifacts.put(B.PERSONAL, digest, raw)
        with f.c.factory() as session, session.begin():
            row, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=f"invented-final-release-append/{uuid4()}",
                content_hash=digest,
                content_location=location,
                captured_at=f.inputs.clock._last,
            )
            assert new
            added_id = row.id
        assert added_id in all_sources(f)
    elif fault == "wall-expiry":
        # Same exact original HostObservedClock object; explicit test reader only.
        monkeypatch.setattr(
            f.inputs.clock, "_read", lambda: c.p.g.expires_at + timedelta(seconds=1)
        )
    elif fault == "wall-rollback":
        prior = f.inputs.clock._last
        monkeypatch.setattr(f.inputs.clock, "_read", lambda: prior - timedelta(seconds=1))
    elif fault == "native-expiry":
        # Root-only genuine elapsed ORIGINAL interval; trusted builtin unchanged.
        assert c.gate._profile.max_latency_ms == 60000
        assert f.active == {"canonical": 0, "admin": 0}
        started = time.monotonic()
        remaining = c.gate._deadline - started
        wait = max(0.0, remaining) + 0.01
        assert 0 < wait <= c.gate._profile.max_latency_ms / 1000
        time.sleep(wait)
        finished = time.monotonic()
        assert finished >= c.gate._deadline
        assert 0 <= finished - started <= 60
        assert f.active == {"canonical": 0, "admin": 0}

    sources = all_sources(f)
    bodies = artifacts_snapshot(f)
    with pytest.raises(review.HistoryPublicationReviewError) as error:
        review.release_history_reviewed_text(c.gate, expected=retained)
    assert str(error.value) == "complete reviewed response withheld"
    assert error.value.__cause__ is error.value.__context__ is None
    assert c.gate._phase == "HELD" and c.gate._result is None
    assert all_sources(f) == sources and artifacts_snapshot(f) == bodies
    with pytest.raises(review.HistoryPublicationReviewError):
        review.release_history_reviewed_text(c.gate, expected=retained)
    with pytest.raises(review.HistoryPublicationReviewError):
        review.capture_history_publication_assessment(c.gate, observed=observed)
    assert all_sources(f) == sources and artifacts_snapshot(f) == bodies
    assert len(c.state.posts) == len(c.p.posts) == 1
