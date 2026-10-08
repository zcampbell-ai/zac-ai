"""Actual reviewer producer chain with explicitly mocked SQL/age/model HTTP."""
# ruff: noqa: F401, F811
import pytest

from tests.test_fragment_publication_review_integration import (
    authority,
    baseline_authority,
    case,
    consent_case,
    declaration_case,
    installed,
    invoke,
    issuer,
    packet_case,
    publication_issuer,
    review_case,
)
from zacai import backup_artifacts
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_publication_review as review


def complete_inventory(monkeypatch, count):
    state={'count':count,'seen':[]}
    def rows(session, **kw):
        state['seen'].append(state['count'])
        return canonical_bytes([{'id':str(n)} for n in range(state['count'])]), ()
    monkeypatch.setattr(backup_artifacts,'_personal_backup_rows',rows)
    return state


def test_actual_released_assessment_capacity_zero_own_artifact_put(review_case,monkeypatch):
    f=review_case
    result=invoke(f)
    assert f.review_gate._phase=='RELEASED' and result is f.review_runtime._authenticated_result
    state=complete_inventory(monkeypatch,4095)
    writes=[]
    monkeypatch.setattr(f.p._artifacts,'put',lambda *a: writes.append('put'))
    with pytest.raises(review.FragmentPublicationReviewError):
        review.capture_fragment_publication_assessment(f.review_gate,
            runtime=f.review_runtime,result=result)
    assert state['seen']==[4095] and writes==[]
    assert f.review_gate._phase=='HELD' and 'assessment-record' not in f.events
