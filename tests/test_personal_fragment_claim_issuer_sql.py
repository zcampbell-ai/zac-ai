"""Root-exclusive genuine canonical burn/recovery, invented attendance/input.

Signed owner/cookie, RC locks/Source, age and independent State/journal restore
are real when root executes. Tokenizer/approval are fixtures. Exact descriptor
callbacks are direct, with no provider POST or actual processing permission.
Concurrency targets the internal SQL burn, not simultaneous owner/recovery ops.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Event, current_thread
from time import monotonic
from types import SimpleNamespace
from uuid import uuid4

import pytest
from psycopg.pq import TransactionStatus
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import (
    actual_case,  # noqa: F401
    assert_balanced_restoration_leases,
    clean_factory,  # noqa: F401
)
from zacai import contextual_authorization as m
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence.contextual_storage import (
    _fragment_request_provenance,
    _fragment_transaction,
)
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock as canonical_uuid_lock
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem


@pytest.fixture(autouse=True)
def exact_issuer_qwen_profile(monkeypatch):
    # Apply before genuine_packet captures its canonical request/packet. Never
    # change a captured body/request or replace the actual tokenizer count.
    import tests.personal_fragment_sql_support as support
    from tests.test_local_contextual_runtime import route as synthetic_base_route
    original = synthetic_base_route
    assert support.__dict__["route"] is original
    def exact():
        value = original()
        return value.model_copy(update={"identity": value.identity.model_copy(
            update={"model_id": "qwen3.8:27b-mlx"})})
    monkeypatch.setattr(support, "route", exact)


@pytest.fixture
def issuer_case(actual_case, installed):  # noqa: F811
    make,_,_,q,writer,calls,active,sessions,cookie,leases=actual_case
    p=make('issuer-initial-cold')
    owner=p._operation.establish()
    count=OllamaQwenContextualTokenCounter(models_root=installed[0],model_digest=installed[2])
    pins=local.fragment_contextual_counter_pins(count)
    now=p._clock()
    consent=m.HistoryFragmentConsentV1(id=uuid4(),builder_id=uuid4(),task_id=q.task.task_id,
        request_digest=content_hash_of(encode_history_fragment_contextual_request(q)),
        provenance=_fragment_request_provenance(q),owner_issuer=owner.principal.identity.issuer,
        owner_subject=owner.principal.identity.subject,original_session_binding=owner.binding_digest,
        original_session_issued_at=owner.issued_at,original_session_expires_at=owner.effective_expires_at,
        approved_at=now,expires_at=min(now+timedelta(minutes=10),owner.effective_expires_at),
        human_reference='simulated-specific-approval-for-invented-mechanical-fixture',route=q.route,
        model_digest=installed[2],tokenizer_digest=pins[0],template_digest=pins[1],renderer_digest=pins[2],
        runtime_digest=local.fragment_contextual_runtime_digest(),body_digest=content_hash_of(q.prompt_body.encode()),
        prompt_tokens=count.count_prompt_tokens(q.prompt_body.encode()),max_output_tokens=q.task.max_output_tokens)
    own=m.record_history_fragment_consent(factory=p._factory,artifacts=p._artifacts,consent=consent,
        expected_request=q,operation=p._operation,clock=p._clock)
    receipt=p.protect_consent(reference=own,expected_consent=consent,expected_request=q)
    def backend(protector=None):
        protector=p if protector is None else protector
        g=m.CanonicalPersonalFragmentAuthorization(factory=protector._factory,artifacts=protector._artifacts,
            consent_reference=own,consent=consent,request=q,protector=protector,
            operation=p._operation,clock=p._clock)
        r=local.FragmentLocalContextualRuntime(route=q.route,model_digest=consent.model_digest,
            tokenizer_digest=consent.tokenizer_digest,runtime_digest=consent.runtime_digest,
            template_digest=consent.template_digest,renderer_digest=consent.renderer_digest,
            token_counter=count,recheck=g.recheck)
        g.bind_runtime(r)
        return g,r
    gate,runtime=backend()
    descriptor=local._fragment_descriptor('PRE_DISPATCH',uuid4(),q.prompt_body.encode(),
        encode_history_fragment_contextual_request(q),consent.prompt_tokens,runtime._configuration)
    return SimpleNamespace(make=make,p=p,q=q,c=consent,own=own,initial=receipt,backend=backend,
        gate=gate,runtime=runtime,d=descriptor,writer=writer,calls=calls,active=active,
        sessions=sessions,cookie=cookie,leases=leases)


def claims(f):
    with f.p._factory() as s:
        return tuple(s.scalars(select(Source.id).where(Source.trust_boundary==B.PERSONAL,
            Source.system==SourceSystem.MANUAL,
            Source.external_ref.like(f'personal-history-fragment-claim/{f.c.id}/%'))))


def test_actual_pre_release_claim_recovery_no_second_record(issuer_case,monkeypatch):
    f=issuer_case
    f.gate.recheck(f.q,f.d)
    own=f.gate._claim_reference
    assert claims(f)==(own.source_id,) and f.gate._phase=='DISPATCHED'
    assert {f.own,own}<=set(f.gate._receipt.selected_references)
    assert f.gate._receipt.attempt_id==f.d.attempt_id
    assert f.gate._receipt.consumed_at==f.gate._claim.consumed_at
    with pytest.raises(protection.ContextualProtectionError):
        f.p.recheck_consent(reference=f.own,expected_consent=f.c,expected_request=f.q)
    writes=[]
    def no_write(*a,**k):
        writes.append(True)
        raise AssertionError('RELEASE cannot mint or repair')
    monkeypatch.setattr(f.writer,'put_object',no_write)
    release=replace(f.d,phase='RELEASE',output_digest='8'*64,usage_digest='9'*64)
    f.gate.recheck(f.q,release)
    assert f.gate._phase=='RELEASED' and not writes and claims(f)==(own.source_id,)
    assert f.active=={'canonical':0,'admin':0}
    assert_balanced_restoration_leases(f.leases,expected_restorations=4)
    assert f.calls.count('actual-verify-personal-start')==4
    assert not f.runtime.did_transport_attempt
    with pytest.raises(m.ContextualAuthorizationError):
        f.gate.recheck(f.q,release)
    assert claims(f)==(own.source_id,)


def test_actual_committed_protection_failure_burns_fresh_instance(issuer_case,monkeypatch):
    f=issuer_case
    milestones=[]
    def fail(**kwargs):
        assert f.active=={'canonical':0,'admin':0}
        assert claims(f)==(kwargs['reference'].source_id,)
        milestones.append('real-committed-claim-before-protection')
        raise RuntimeError('invented first-protection failure')
    monkeypatch.setattr(f.p,'protect_claim',fail)
    with pytest.raises(m.ContextualAuthorizationError) as error:
        f.gate.recheck(f.q,f.d)
    assert error.value.__context__ is None and milestones==['real-committed-claim-before-protection']
    assert f.gate._phase=='HELD' and len(claims(f))==1
    fresh,_=f.backend(f.make('issuer-failure-fresh-cold'))
    other=replace(f.d,attempt_id=uuid4())
    with pytest.raises(m.ContextualAuthorizationError):
        fresh.recheck(f.q,other)
    # Discriminate durable prefix refusal independently of stale consent proof.
    with pytest.raises(ValueError,match='already consumed'):
        fresh._burn(other,f.initial)
    assert len(claims(f))==1 and milestones==['real-committed-claim-before-protection']
    assert f.active=={'canonical':0,'admin':0} and not f.runtime.did_transport_attempt


def test_actual_original_cookie_revoke_after_claim_restore_preserves_burn(issuer_case,monkeypatch):
    f=issuer_case
    actual=DisposableStateRestoreVerifier.verify_personal
    milestones=[]
    def revoke(verifier,*args,**kwargs):
        result=actual(verifier,*args,**kwargs)
        if f.gate._claim is not None:
            assert f.active=={'canonical':0,'admin':0}
            assert claims(f)==(f.gate._claim_reference.source_id,)
            milestones.append('real-claim-restore-closed-and-burn-committed')
            f.sessions.revoke(f.cookie)
            milestones.append('real-original-cookie-revoked')
        return result
    monkeypatch.setattr(DisposableStateRestoreVerifier,'verify_personal',revoke)
    with pytest.raises(m.ContextualAuthorizationError):
        f.gate.recheck(f.q,f.d)
    assert milestones==['real-claim-restore-closed-and-burn-committed','real-original-cookie-revoked']
    assert len(claims(f))==1 and f.gate._phase=='HELD'
    assert not f.runtime.did_transport_attempt and f.active=={'canonical':0,'admin':0}


def test_actual_two_sql_issuers_one_uuid_lock_winner(issuer_case,monkeypatch):
    f=issuer_case
    second,_=f.backend(f.make('issuer-lock-second-cold'))
    first_has_lock, second_about_to_lock, release_first=Event(),Event(),Event()
    actual_lock=canonical_uuid_lock
    pids={}
    def controlled_lock(session,consent_id):
        if current_thread().name.endswith('_0'):
            actual_lock(session,consent_id)
            first_has_lock.set()
            assert release_first.wait(15), 'bounded lock scheduling timeout'
        else:
            pids['second']=session.scalar(text('SELECT pg_backend_pid()'))
            second_about_to_lock.set()
            actual_lock(session,consent_id)
    monkeypatch.setattr(m,'_lock',controlled_lock)
    def burn(gate,descriptor):
        try:
            return ('COMMITTED',gate._burn(descriptor,f.initial)[1].source_id)
        except ValueError as error:
            assert str(error)=='original consent already consumed'
            return ('CONSUMED',None)
    f.gate._owner()
    second._owner()
    blocked=False
    with ThreadPoolExecutor(max_workers=2,thread_name_prefix='actual-fragment-burn') as pool:
        one=pool.submit(burn,f.gate,f.d)
        assert first_has_lock.wait(10)
        two=pool.submit(burn,second,replace(f.d,attempt_id=uuid4()))
        try:
            assert second_about_to_lock.wait(10)
            end=monotonic()+10
            while monotonic()<end:
                with f.p._engine.connect() as conn:
                    row=conn.execute(text('SELECT wait_event_type,wait_event FROM pg_stat_activity WHERE pid=:pid'),
                        {'pid':pids['second']}).one()
                    blocked=row.wait_event_type=='Lock' and row.wait_event=='advisory'
                if blocked:
                    break
                Event().wait(0.01)
            assert blocked, 'actual second backend must wait on PostgreSQL advisory lock'
        finally:
            release_first.set()
        results=(one.result(timeout=15),two.result(timeout=15))
    assert [v[0] for v in results]==['COMMITTED','CONSUMED']
    assert claims(f)==(results[0][1],)
    assert f.active=={'canonical':0,'admin':0}
    assert f.calls.count('actual-verify-personal-start')==1
    assert not f.runtime.did_transport_attempt


def test_actual_commit_ack_loss_preserves_claim_and_refuses_new_instance(issuer_case,monkeypatch):
    f=issuer_case
    session_class=f.p._factory.class_
    actual_commit=session_class.commit
    milestones=[]
    def lose_ack(session):
        actual_commit(session)
        actual_rows=claims(f)
        assert len(actual_rows)==1
        milestones.append('real-claim-visible-in-independent-session-after-commit')
        raise RuntimeError('invented acknowledgement loss after actual commit')
    monkeypatch.setattr(session_class,'commit',lose_ack)
    with pytest.raises(m.ContextualAuthorizationError) as error:
        f.gate.recheck(f.q,f.d)
    monkeypatch.setattr(session_class,'commit',actual_commit)
    assert error.value.__context__ is None
    assert milestones==['real-claim-visible-in-independent-session-after-commit']
    assert len(claims(f))==1 and f.gate._phase=='HELD'
    assert f.gate._claim_reference is None and f.gate._receipt is None
    fresh,_=f.backend(f.make('issuer-ack-loss-fresh-cold'))
    other=replace(f.d,attempt_id=uuid4())
    with pytest.raises(m.ContextualAuthorizationError):
        fresh.recheck(f.q,other)
    with pytest.raises(ValueError,match='already consumed'):
        fresh._burn(other,f.initial)
    assert len(claims(f))==1 and f.active=={'canonical':0,'admin':0}
    assert not f.runtime.did_transport_attempt


def test_actual_autocommit_denied_before_artifacts_or_claim(issuer_case,monkeypatch,tmp_path):
    f=issuer_case
    with f.p._factory() as session:
        session.begin()
        entry=f.gate._physical_transaction(session)
        assert entry[3].autocommit is False
        assert entry[3].info.transaction_status is TransactionStatus.INTRANS
    engine=f.p._engine.execution_options(isolation_level='AUTOCOMMIT')
    factory=sessionmaker(engine,expire_on_commit=False)
    p=protection.PersonalHistoryFragmentProtector(factory=factory,engine=engine,
        artifacts=f.p._artifacts,cold_artifacts=LocalFilesystemArtifactStore(tmp_path/'auto-cold'),
        objects=f.p._writer,verification_objects=f.p._reader,recipient=f.p._recipient,
        identity_path=f.p._identity,manifest_cache=f.p._cache,operation=f.p._operation,
        clock=f.p._clock,restoration=DisposableStateRestoreVerifier())
    gate,_=f.backend(p)
    with factory() as session:
        session.begin()
        _fragment_transaction(session)  # Existing logical helper admits this.
        driver=session.connection().connection.driver_connection
        assert driver is not None
        assert driver.autocommit is True
        assert driver.info.transaction_status is TransactionStatus.IDLE
    reads,writes=[],[]
    actual_get=f.p._artifacts.get_bounded
    actual_put=f.p._artifacts.put
    def get(*args,**kwargs):
        reads.append(True)
        return actual_get(*args,**kwargs)
    def put(*args,**kwargs):
        writes.append(True)
        return actual_put(*args,**kwargs)
    monkeypatch.setattr(f.p._artifacts,'get_bounded',get)
    monkeypatch.setattr(f.p._artifacts,'put',put)
    gate._owner()
    with pytest.raises(ValueError,match='live physical psycopg transaction required'):
        gate._burn(replace(f.d,attempt_id=uuid4()),f.initial)
    assert not reads and not writes and claims(f)==()
    assert f.active=={'canonical':0,'admin':0}
    assert not f.runtime.did_transport_attempt
