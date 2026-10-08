"""Concrete reviewer/file/codec paths; SQL, owner, age and HTTP simulated."""
# ruff: noqa: F401, F811
import time

import pytest

from tests.test_review_burn_original_deadline import (
    authority,
    baseline_authority,
    case,
    consent_case,
    declaration_case,
    installed,
    issuer,
    packet_base,
    packet_case,
    publication_issuer,
    review_case,
)
from zacai import backup_artifacts, state_repository
from zacai.intelligence import fragment_publication_review as m


@pytest.mark.parametrize("phase", ["artifact", "append"])
def test_review_burn_rechecks_capacity_after_callbacks(review_case, monkeypatch, phase):
    f = review_case
    before = list(f.ledger)
    milestones = []
    exhausted = False

    def capacity(session, reserve):
        if exhausted:
            milestones.append(("capacity-hold", reserve))
            raise ValueError("invented unrelated append exhausted inventory")

    monkeypatch.setattr(backup_artifacts, "_assert_personal_custody_append_capacity", capacity)
    if phase == "artifact":
        original = f.p._artifacts.get_bounded

        def read(*args, **kwargs):
            nonlocal exhausted
            raw = original(*args, **kwargs)
            if b'zac-personal-fragment-publication-review-claim-v1' in raw:
                exhausted = True
                milestones.append("actual-claim-readback")
            return raw

        monkeypatch.setattr(f.p._artifacts, "get_bounded", read)
    else:
        original = state_repository.record_source

        def record(*args, **kwargs):
            nonlocal exhausted
            value = original(*args, **kwargs)
            if kwargs["external_ref"].startswith(m._review_prefix(f.consent.id)):
                exhausted = True
                milestones.append("actual-child-pending")
            return value

        monkeypatch.setattr(state_repository, "record_source", record)
    with pytest.raises(m.FragmentPublicationReviewError):
        m.invoke_personal_fragment_publication_review(f.review_gate, runtime=f.review_runtime)
    assert exhausted
    assert ("capacity-hold", 3 if phase == "artifact" else 2) in milestones
    assert f.ledger == before and not f.pending
    assert not f.review_transport.posts and f.review_gate._phase == "HELD"


def test_assessment_last_sql_crosses_original_interval_without_commit(review_case, monkeypatch):
    f = review_case
    result = m.invoke_personal_fragment_publication_review(f.review_gate, runtime=f.review_runtime)
    before = list(f.ledger)
    original = m._review_current
    milestones = []

    def delayed(*args, **kwargs):
        value = original(*args, **kwargs)
        if kwargs.get("pending_assessment_reference") is not None:
            milestones.append("actual-assessment-pending-final-sql")
            time.sleep(max(0, f.review_gate._deadline_monotonic - time.monotonic()) + 0.01)
        return value

    monkeypatch.setattr(m, "_review_current", delayed)
    with pytest.raises(m.FragmentPublicationReviewError):
        m.capture_fragment_publication_assessment(f.review_gate, runtime=f.review_runtime, result=result)
    assert milestones == ["actual-assessment-pending-final-sql"]
    assert f.ledger == before and not f.pending
    assert f.review_gate._phase == "HELD" and f.review_gate._observed_result is None
