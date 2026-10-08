# ruff: noqa: PLC0414 - real fixture re-exports, not authority substitutes
"""ROOT ONLY: real signed store/SQL/native age, invented Source inventory.

No model calls. Complete inventory exists before FIRST protection; the real
capacity helper denies the real canonical issuer before durable claim burn.
"""

import json

import pytest
from sqlalchemy import func, select

from tests.test_fragment_publication_generation_output_sql import (
    clean_factory as clean_factory,
)
from tests.test_fragment_publication_generation_output_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,
)
from tests.test_fragment_publication_generation_output_sql import (
    generation_case as original_generation_case,
)
from tests.test_fragment_publication_generation_output_sql import (
    http_case as http_case,
)
from tests.test_fragment_publication_generation_output_sql import (
    installed as installed,
)
from tests.test_fragment_publication_generation_output_sql import (
    original_fixture_budget as original_fixture_budget,
)
from tests.test_fragment_publication_review_sql import declaration_case as declaration_case
from tests.test_personal_fragment_protection_sql import actual_case as _base_actual_case
from zacai import backup_artifacts
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_publication_generation as generation
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

# Explicit fixture name keeps the original generator/owner-store mechanics.
unpadded_actual_case = pytest.fixture(name="unpadded_actual_case")(_base_actual_case.__wrapped__)

@pytest.fixture
def actual_case(unpadded_actual_case, clean_factory):
    """Pad BEFORE declaration, consent/admission and all recovery observations."""
    original=unpadded_actual_case
    _make,sid,digest,_request,_writer,calls,active,_sessions,_cookie,_leases=original
    assert 'actual-verify-personal-start' not in calls
    assert active=={'canonical':0,'admin':0}
    with clean_factory() as session:
        session.begin()
        row=session.get(Source,sid)
        assert row is not None and row.trust_boundary is B.PERSONAL
        assert row.content_hash==digest
        count=session.scalar(select(func.count()).select_from(Source).where(Source.trust_boundary==B.PERSONAL))
        assert 0<count<4087
        for n in range(4087-count):
            # Actual canonical records point to exact existing invented bytes.
            # They are deliberately unrelated to the task's selected evidence.
            record_source(session,trust_boundary=B.PERSONAL,data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,external_ref=f'preburn-capacity-invented/{n}',
                captured_at=row.captured_at,content_hash=row.content_hash,
                content_location=row.content_location)
        session.commit()
    with clean_factory() as session:
        assert session.scalar(select(func.count()).select_from(Source).where(Source.trust_boundary==B.PERSONAL))==4087
    assert 'actual-verify-personal-start' not in calls
    assert active=={'canonical':0,'admin':0}
    return original



@pytest.fixture
def generation_case(http_case, installed, clean_factory, monkeypatch):
    """Append unrelated actual Sources after admission, BEFORE any first proof."""
    import tests.test_fragment_publication_generation_output_sql as support

    real_post = support.post
    milestones = []
    def post_then_append(f, **kwargs):
        assert 'actual-verify-personal-start' not in f.calls
        response = real_post(f, **kwargs)
        assert response.status_code == 200 and len(f.receipts) == 1
        with clean_factory() as session:
            session.begin()
            count = session.scalar(select(func.count()).select_from(Source).where(
                Source.trust_boundary == B.PERSONAL))
            assert count == 4090
            row = session.get(Source, f.g.provenance[0].source_id)
            assert row is not None and row.trust_boundary is B.PERSONAL
            for n in range(2):
                record_source(session, trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED, system=SourceSystem.MANUAL,
                    external_ref=f'preburn-capacity-post-admission/{n}',
                    captured_at=row.captured_at, content_hash=row.content_hash,
                    content_location=row.content_location)
            session.commit()
        with clean_factory() as session:
            assert session.scalar(select(func.count()).select_from(Source).where(
                Source.trust_boundary == B.PERSONAL)) == 4092
        assert 'actual-verify-personal-start' not in f.calls
        assert f.active == {'canonical': 0, 'admin': 0}
        milestones.append('two unrelated Sources committed before first protection')
        return response
    monkeypatch.setattr(support, 'post', post_then_append)
    f = original_generation_case.__wrapped__(http_case, installed)
    assert milestones == ['two unrelated Sources committed before first protection']
    f.capacity_setup_milestones = tuple(milestones)
    return f


def ids(f):
    with f.p._factory() as session:
        return tuple(session.scalars(select(Source.id).where(Source.trust_boundary==B.PERSONAL).order_by(Source.id)))


def claim_ids(f):
    with f.p._factory() as session:
        return tuple(session.scalars(select(Source.id).where(Source.trust_boundary==B.PERSONAL,
            Source.system==SourceSystem.MANUAL,
            Source.external_ref.like(f'personal-history-fragment-claim/{f.g.id}/%')).order_by(Source.id)))


def test_actual_complete_4092_source_proof_holds_reserve6_before_burn(generation_case,monkeypatch):
    f=generation_case
    gate,_runtime,descriptor=f.new
    assert f.capacity_setup_milestones == ('two unrelated Sources committed before first protection',)
    original_consent=gate._consent
    before=ids(f)
    assert len(before)==4092 and claim_ids(f)==()
    # Genuine admission and legacy consent proof cover the SAME full inventory.
    assert len(f.initial.full_boundary_source_hashes)==4092
    assert len(f.initial.full_boundary_source_fingerprints)==4092
    assert len(f.old_initial.full_boundary_source_hashes)==4092
    assert tuple(sid for sid,_ in f.initial.full_boundary_source_hashes)==before
    with f.p._factory() as session:
        plan=backup_artifacts.prepare_personal_encrypted_custody_backup_plan(session)
    assert content_hash_of(plan.rows)==f.initial.full_plan_digest
    assert len(json.loads(plan.rows))==4092
    assert 'actual-verify-personal-end' in f.calls
    assert f.active=={'canonical':0,'admin':0}
    actual_helper=backup_artifacts._assert_personal_custody_append_capacity
    milestones=[]
    def observed(session,reserved):
        assert reserved==6 and session.in_transaction()
        count=session.scalar(select(func.count()).select_from(Source).where(Source.trust_boundary==B.PERSONAL))
        assert count==4092
        try:
            actual_helper(session,reserved)
        except ValueError as error:
            assert str(error)=='complete PERSONAL recovery capacity exhausted before burn'
            milestones.append('actual-complete-helper-rejected-4092-plus6')
            raise
        raise AssertionError('real capacity helper unexpectedly returned')
    monkeypatch.setattr(backup_artifacts,'_assert_personal_custody_append_capacity',observed)
    writes=[]
    actual_put=f.p._artifacts.put
    def put(*args,**kwargs):
        writes.append('canonical-artifact-put')
        return actual_put(*args,**kwargs)
    monkeypatch.setattr(f.p._artifacts,'put',put)
    with pytest.raises(generation.FragmentPublicationGenerationError):
        gate.recheck(f.q,descriptor)
    # Milestone first distinguishes genuine capacity rejection from stale proof.
    assert milestones==['actual-complete-helper-rejected-4092-plus6']
    assert writes==[] and claim_ids(f)==() and ids(f)==before
    assert gate._phase=='HELD' and gate._claim is None and gate._claim_reference is None
    # No durable permission burn; the rejected in-memory invocation cannot retry.
    assert gate._consent is original_consent and gate._consent == f.g
    assert gate._admission is f.admitted.admission
    assert f.active=={'canonical':0,'admin':0}
