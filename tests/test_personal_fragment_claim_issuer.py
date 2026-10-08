"""Concrete backend/codecs/files and runtime construction, invented orchestration.

SQL locks/transactions/rows, signed owner and backup/age proof are simulated.
No genuine concurrency, human processing approval or model delivery is asserted.
"""
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.orm import sessionmaker

from tests.test_history_fragment_authority_protection import authority as authority  # noqa: PLC0414
from tests.test_history_fragment_authority_protection import case as case  # noqa: PLC0414
from tests.test_history_fragment_authority_protection import (
    consent_case as consent_case,  # noqa: PLC0414
)
from tests.test_history_fragment_authority_protection import (
    packet_case as packet_case,  # noqa: PLC0414
)
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai import contextual_authorization as m
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def issuer(authority, installed, monkeypatch):
    f = authority
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    pins = local.fragment_contextual_counter_pins(counter)
    c = m.HistoryFragmentConsentV1.model_validate({**f.consent.model_dump(),
        'body_digest':content_hash_of(f.q.prompt_body.encode()),
        'max_output_tokens':f.q.task.max_output_tokens,
        'model_digest':installed[2], 'tokenizer_digest':pins[0], 'template_digest':pins[1],
        'renderer_digest':pins[2], 'runtime_digest':local.fragment_contextual_runtime_digest()})
    ref = EvidenceReference(source_id=f.consent_ref.source_id,
        content_hash=content_hash_of(m.encode_history_fragment_consent(c)),
        trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
    f.consent, f.consent_ref = c, ref
    f.plan = replace(f.plan, rows=canonical_bytes([
        {'id':str(r.source_id),'content_hash':r.content_hash} for r in (*c.provenance,ref)]))
    f.current_plan['value'] = f.plan
    gate = m.CanonicalPersonalFragmentAuthorization(factory=f.p._factory,
        artifacts=f.p._artifacts,consent_reference=ref,consent=c,request=f.q,
        protector=f.p,operation=f.p._operation,clock=f.p._clock)
    runtime = local.FragmentLocalContextualRuntime(route=f.q.route,model_digest=c.model_digest,
        tokenizer_digest=c.tokenizer_digest, runtime_digest=c.runtime_digest,
        template_digest=c.template_digest,renderer_digest=c.renderer_digest,
        token_counter=counter,recheck=gate.recheck)
    gate.bind_runtime(runtime)
    f.gate, f.runtime = gate, runtime
    f.ledger, f.pending, f.commit_fault, f.active = [], [], False, 0
    original_owner = f.p._operation._read
    def owner():
        assert f.active == 0, 'owner callback under simulated canonical lease'
        return original_owner()
    monkeypatch.setattr(f.p._operation,'_read',owner)
    f.p._operation_settings = (owner,f.p._operation._host_clock)
    class FakeSession:
        def __enter__(self):
            f.active += 1
            return self
        def __exit__(self,*args):
            f.pending.clear()
            f.active -= 1
        def begin(self):
            return None
        def scalars(self,query):
            assert 'LIMIT' in str(query.compile())
            return tuple(v.id for v in f.ledger)
        def commit(self):
            f.events.append('commit')
            f.ledger.extend(f.pending)
            f.pending.clear()
            if f.commit_fault:
                raise RuntimeError('invented acknowledgement loss')
    monkeypatch.setattr(sessionmaker,'__call__',lambda *a,**k:FakeSession())
    monkeypatch.setattr(m,'_lock',lambda *a:f.events.append('uuid-lock'))
    monkeypatch.setattr(m.CanonicalPersonalFragmentAuthorization, '_physical_transaction',
        lambda self,s:('same-live-transaction',None,'simulated-connection','simulated-driver'))
    monkeypatch.setattr(m.CanonicalPersonalFragmentAuthorization, '_same_physical_transaction',
        lambda *a:None)
    monkeypatch.setattr(m,'_fragment_transaction',lambda s:('same-live-transaction',None))
    monkeypatch.setattr(m,'_fragment_same_transaction',lambda *a:None)
    monkeypatch.setattr(m,'_fragment_rows',lambda *a:())
    monkeypatch.setattr(m,'_fragment_profile_lineage',lambda *a:None)
    monkeypatch.setattr(m,'load_history_fragment_consent',lambda *a,**k:c)
    monkeypatch.setattr(m,'load_history_fragment_claim',lambda *a,**k: f.gate._claim)
    # Mechanical producer is the real protector with actual canonical receipt
    # codec and file operations; SQL and cryptographic mechanics remain mocked.
    import zacai.backup_artifacts as backup
    monkeypatch.setattr(backup,'prepare_personal_encrypted_custody_backup_plan',lambda s:f.current_plan['value'])
    # Capacity observes the same explicitly simulated complete SQL plan.
    monkeypatch.setattr(backup, '_personal_backup_rows',
        lambda s, **kw: (f.current_plan['value'].rows, f.current_plan['value'].artifacts))
    def record(session,**kwargs):
        f.events.append('record')
        assert kwargs['external_ref']==m._fragment_authority_namespace(c,claim=True)
        assert kwargs['trust_boundary'] is B.PERSONAL
        assert kwargs['data_classification'] is C.HIGHLY_RESTRICTED
        raw = f.p._artifacts.get_bounded(B.PERSONAL,kwargs['content_location'],max_bytes=64000)
        claim = m.decode_history_fragment_claim(raw)
        assert claim.attempt_id==f.descriptor.attempt_id
        source=SimpleNamespace(id=uuid4(),supersedes_source_id=None)
        f.pending.append(source)
        rows = __import__('json').loads(f.current_plan['value'].rows)
        rows.append({'id':str(source.id),'content_hash':kwargs['content_hash']})
        f.current_plan['value']=replace(f.plan,rows=canonical_bytes(rows))
        return source,True
    monkeypatch.setattr(m,'record_source',record)
    descriptor=local.FragmentContextualDispatchDescriptor(phase='PRE_DISPATCH',attempt_id=uuid4(),
        retained_request_digest=c.request_digest,body_digest=c.body_digest,prompt_tokens=c.prompt_tokens,
        route_json=gate._configuration[5],model_digest=c.model_digest,tokenizer_digest=c.tokenizer_digest,
        runtime_digest=c.runtime_digest,template_digest=c.template_digest,renderer_digest=c.renderer_digest)
    f.descriptor=descriptor
    return f


def call(f,descriptor=None):
    f.gate.recheck(f.q,f.descriptor if descriptor is None else descriptor)


def release(f,**changes):
    return replace(f.descriptor,phase='RELEASE',output_digest='8'*64,usage_digest='9'*64,**changes)


def fresh(f):
    gate=m.CanonicalPersonalFragmentAuthorization(factory=f.p._factory,artifacts=f.p._artifacts,
        consent_reference=f.consent_ref,consent=f.consent,request=f.q,protector=f.p,
        operation=f.p._operation,clock=f.p._clock)
    runtime=local.FragmentLocalContextualRuntime(route=f.runtime.route,
        model_digest=f.consent.model_digest,tokenizer_digest=f.consent.tokenizer_digest,
        runtime_digest=f.consent.runtime_digest,template_digest=f.consent.template_digest,
        renderer_digest=f.consent.renderer_digest,token_counter=f.runtime._token_counter,recheck=gate.recheck)
    gate.bind_runtime(runtime)
    return gate


def test_commit_before_claim_protection_and_release_never_mints_again(issuer):
    f=issuer
    # Producer's first consent protection is a prerequisite, not done by issuer.
    f.p.protect_consent(reference=f.consent_ref,expected_consent=f.consent,expected_request=f.q)
    f.events.clear()
    call(f)
    assert len(f.ledger)==1 and f.gate._phase=='DISPATCHED'
    assert f.events.index('commit')<f.events.index('backup')
    assert f.events.count('backup')==1
    old=f.gate._receipt
    assert old.kind=='CLAIM' and {f.consent_ref,f.gate._claim_reference}<=set(old.selected_references)
    with pytest.raises(protection.ContextualProtectionError):
        f.p.recheck_consent(reference=f.consent_ref,expected_consent=f.consent,expected_request=f.q)
    call(f,release(f))
    assert f.gate._phase=='RELEASED' and f.gate._receipt==old
    assert f.events.count('record')==f.events.count('commit')==f.events.count('backup')==1
    assert f.active==0
    with pytest.raises(m.ContextualAuthorizationError):
        call(f,release(f))
    assert len(f.ledger)==1


@pytest.mark.parametrize('fault',['protection','owner','commit-ack'])
def test_post_commit_failure_burns_and_no_instance_can_reissue(issuer,monkeypatch,fault):
    f=issuer
    f.p.protect_consent(reference=f.consent_ref,expected_consent=f.consent,expected_request=f.q)
    if fault=='protection':
        monkeypatch.setattr(f.p,'protect_claim',lambda **k:(_ for _ in ()).throw(ValueError('private fault')))
    elif fault=='owner':
        original=m.record_source
        def revoke(*a,**k):
            result=original(*a,**k)
            f.owner['value']=None
            return result
        monkeypatch.setattr(m,'record_source',revoke)
    else:
        f.commit_fault=True
    with pytest.raises(m.ContextualAuthorizationError) as caught:
        call(f)
    assert caught.value.__context__ is None and f.gate._phase=='HELD'
    assert len(f.ledger)==1 and f.events.count('record')==1 and f.active==0
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    other=fresh(f)
    with pytest.raises(m.ContextualAuthorizationError):
        other.recheck(f.q,replace(f.descriptor,attempt_id=uuid4()))
    assert len(f.ledger)==1 and f.events.count('record')==1


@pytest.mark.parametrize('field', ['body_digest','retained_request_digest','model_digest',
    'tokenizer_digest','runtime_digest','template_digest','renderer_digest','route_json','prompt_tokens'])
def test_wrong_descriptor_zero_ledger_or_protection(issuer,field):
    f=issuer
    changed=101 if field=='prompt_tokens' else '0'*64
    with pytest.raises(m.ContextualAuthorizationError):
        call(f,replace(f.descriptor,**{field:changed}))
    assert not f.ledger and not f.pending and not f.events


@pytest.mark.parametrize('fault',['attempt','output','usage','owner','plan'])
def test_release_fault_withholds_result_but_preserves_original_burn(issuer,fault):
    f=issuer
    f.p.protect_consent(reference=f.consent_ref,expected_consent=f.consent,expected_request=f.q)
    call(f)
    d=release(f)
    if fault=='attempt':
        d=replace(d,attempt_id=uuid4())
    elif fault in ('output','usage'):
        d=replace(d,**{fault+'_digest':'BAD'})
    elif fault=='owner':
        f.owner['value']=None
    else:
        f.current_plan['value']=replace(f.current_plan['value'],rows=f.plan.rows)
    with pytest.raises(m.ContextualAuthorizationError):
        call(f,d)
    assert f.gate._phase=='HELD' and f.gate._released is None
    assert len(f.ledger)==1 and f.events.count('record')==1


def test_absent_or_fake_callback_runtime_binding_denies(issuer):
    f=issuer
    gate=fresh(f)
    gate._runtime=None
    with pytest.raises(m.ContextualAuthorizationError):
        gate.recheck(f.q,f.descriptor)
    f.runtime._recheck=lambda *a:None
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    assert not f.ledger


def test_missing_initial_consent_recovery_never_records_a_claim(issuer):
    f=issuer
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    assert not f.ledger and f.gate._phase=='HELD'
    assert 'record' not in f.events and 'backup' not in f.events


def test_expiry_during_preburn_recovery_holds_original_attempt(issuer,monkeypatch):
    from datetime import timedelta
    f=issuer
    f.p.protect_consent(reference=f.consent_ref,expected_consent=f.consent,expected_request=f.q)
    original=f.p.recheck_consent
    def expire(**kwargs):
        result=original(**kwargs)
        monkeypatch.setattr(f.p._clock,'_read',lambda:f.consent.expires_at+timedelta(seconds=1))
        return result
    monkeypatch.setattr(f.p,'recheck_consent',expire)
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    assert not f.ledger and f.gate._phase=='HELD'
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    assert 'record' not in f.events


def test_original_cookie_changed_same_owner_is_not_fresh_permission(issuer):
    f=issuer
    f.owner['value']=replace(f.owner['value'],binding_digest='7'*64)
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    assert not f.ledger and 'backup' not in f.events


def test_graph_transplant_and_release_without_pre_hold(issuer):
    f=issuer
    with pytest.raises(m.ContextualAuthorizationError):
        call(f,release(f))
    f.gate._clock=object()
    with pytest.raises(m.ContextualAuthorizationError):
        call(f)
    assert not f.ledger and not f.events
