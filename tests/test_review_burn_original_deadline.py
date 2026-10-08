"""Actual reviewer/runtime burn; SQL/owner/age/HTTP explicitly simulated."""
# ruff: noqa: F401, F811
import time

import pytest

from tests.test_fragment_publication_review_integration import declaration_case, review_case
from tests.test_original_publication_dispatch_window import (
    authority,
    baseline_authority,
    case,
    consent_case,
    installed,
    issuer,
    packet_base,
    packet_case,
    publication_issuer,
)
from zacai.intelligence import fragment_publication_review as m
from zacai.intelligence import fragment_review_runtime as runtime


def test_last_review_burn_sql_expiry_rolls_back_before_commit_and_post(review_case, monkeypatch):
    f = review_case
    before = list(f.ledger)
    original = m._review_current
    milestones = []

    def delayed(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs.get("pending_claim_reference") is not None:
            milestones.append("actual-child-source-pending-final-sql")
            remaining = f.review_gate._deadline_monotonic - time.monotonic()
            time.sleep(max(0, remaining) + 0.01)
        return result

    monkeypatch.setattr(m, "_review_current", delayed)
    with pytest.raises(m.FragmentPublicationReviewError):
        m.invoke_personal_fragment_publication_review(f.review_gate, runtime=f.review_runtime)
    assert milestones == ["actual-child-source-pending-final-sql"]
    assert f.ledger == before and f.pending == []
    assert f.review_transport.posts == []
    assert f.review_gate._phase == "HELD" and f.review_runtime._attempted
    assert f.review_runtime._authenticated_held and f.review_runtime.usage is None
