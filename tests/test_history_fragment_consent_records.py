"""Invented structural records/files; canonical SQL/owner/recovery not proven."""
import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import AT, prepared
from tests.test_history_context_metadata import base
from tests.test_local_contextual_runtime import route
from zacai import contextual_authorization as m
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
    prepare_history_fragment_contextual_request,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


@pytest.fixture
def case(tmp_path):
    read = prepared(parent=uuid4())
    read = replace(read,
        original_reference=read.original_reference.model_copy(update={'effective_classification':C.HIGHLY_RESTRICTED}),
        companion_reference=read.companion_reference.model_copy(update={'effective_classification':C.HIGHLY_RESTRICTED}),
        joint_output_classification=C.HIGHLY_RESTRICTED)
    old = base()
    items = tuple(item.model_copy(update={'reference':item.reference.model_copy(
        update={'effective_classification':C.HIGHLY_RESTRICTED})}) for item in old.task.context)
    task = IntelligenceTask.model_validate({**old.task.model_dump(), 'context':items,
        'event':{**old.task.event.model_dump(),'provenance':tuple(i.reference for i in items),
                 'data_classification':C.HIGHLY_RESTRICTED}})
    context = ReviewContext(task,old.meeting_source_id,old.related_source_ids)
    q = prepare_history_fragment_contextual_request(context,prepare(read),observed_at=AT,
        route=route().model_copy(update={'max_input_characters':32000}))
    c = m.HistoryFragmentConsentV1(id=uuid4(),builder_id=uuid4(),task_id=q.task.task_id,
        request_digest=content_hash_of(encode_history_fragment_contextual_request(q)),
        provenance=m._fragment_request_provenance(q),owner_issuer='https://accounts.google.com',
        owner_subject='invented-owner',original_session_binding='a'*64,
        original_session_issued_at=AT-timedelta(seconds=1),
        original_session_expires_at=AT+timedelta(minutes=15),approved_at=AT,
        expires_at=AT+timedelta(minutes=10),human_reference='invented-attended-reference',route=q.route,
        model_digest='b'*64,tokenizer_digest='c'*64,runtime_digest='d'*64,
        template_digest='e'*64,renderer_digest='f'*64,body_digest='1'*64,
        prompt_tokens=100,max_output_tokens=200)
    return q,c,LocalFilesystemArtifactStore(tmp_path/'files')


def test_real_request_consent_claim_closed_canonical_roundtrip(case):
    q,c,_=case
    raw=m.encode_history_fragment_consent(c)
    assert m.decode_history_fragment_consent(raw)==c
    assert m._fragment_consent_request(c,q)==encode_history_fragment_contextual_request(q)
    ref=EvidenceReference(source_id=uuid4(),content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,effective_classification=C.HIGHLY_RESTRICTED)
    claim=m.HistoryFragmentClaimV1(consent_reference=ref,consent_digest=ref.content_hash,
        request_digest=c.request_digest,attempt_id=uuid4(),task_id=c.task_id,builder_id=c.builder_id,
        original_session_binding=c.original_session_binding,body_digest=c.body_digest,
        route_digest=content_hash_of(canonical_bytes({**c.route.model_dump(mode='json'),
            'capabilities':sorted(c.route.capabilities)})),model_digest=c.model_digest,
        tokenizer_digest=c.tokenizer_digest,runtime_digest=c.runtime_digest,
        template_digest=c.template_digest,renderer_digest=c.renderer_digest,
        prompt_tokens=c.prompt_tokens,max_output_tokens=c.max_output_tokens,consumed_at=AT)
    assert m.decode_history_fragment_claim(m.encode_history_fragment_claim(claim))==claim
    assert not hasattr(m,'CanonicalHistoryFragmentAuthorization')


@pytest.mark.parametrize('fault',['extra','duplicate','whitespace','oversized','wrong-family'])
def test_codec_rejects_noncanonical_wrong_family(case,fault):
    _,c,_=case;raw=m.encode_history_fragment_consent(c)
    value=json.loads(raw)
    if fault=='extra':value['recovery_verified']=True;raw=canonical_bytes(value)
    elif fault=='duplicate':raw=raw[:-1]+b',"format":"zac-personal-history-fragment-consent-v1"}'
    elif fault=='whitespace':raw=b' '+raw
    elif fault=='oversized':raw=b' '*64001
    else:value['format']='zac-contextual-consent-v1';raw=canonical_bytes(value)
    with pytest.raises(m.ContextualAuthorizationError) as exc:m.decode_history_fragment_consent(raw)
    assert exc.value.__context__ is None


@pytest.mark.parametrize('fault',['boundary','label','duplicate','expiry','zero','unavailable','bool-token'])
def test_model_copy_cannot_bypass_closed_record(case,fault):
    _,c,_=case
    changes={'boundary':{'provenance':(c.provenance[0].model_copy(update={'trust_boundary':B.BRAINSTORM}),)},
        'label':{'provenance':(c.provenance[0].model_copy(update={'effective_classification':C.CONFIDENTIAL}),)},
        'duplicate':{'provenance':(c.provenance[0],c.provenance[0])},
        'expiry':{'expires_at':AT+timedelta(minutes=16)},'zero':{'id':__import__('uuid').UUID(int=0)},
        'unavailable':{'route':c.route.model_copy(update={'available':False})},
        'bool-token':{'prompt_tokens':True}}[fault]
    with pytest.raises(ValueError):m.encode_history_fragment_consent(c.model_copy(update=changes))


@pytest.fixture
def loader(case,monkeypatch):
    q,c,store=case;raw=m.encode_history_fragment_consent(c);digest=content_hash_of(raw)
    location=store.put(B.PERSONAL,digest,raw);sid=uuid4()
    own=EvidenceReference(source_id=sid,content_hash=digest,trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED)
    rows=[{'id':sid,'system':SourceSystem.USER_INSTRUCTION,
        'external_ref':m._fragment_authority_namespace(c,claim=False),
        'supersedes_source_id':None,'captured_at':AT,'lineage_id':sid,'content_location':location}]
    current={'rows':rows};events=[]
    sql=Session();sql.begin()
    monkeypatch.setattr(m,'_fragment_transaction',lambda s:(s.get_transaction(),s.get_nested_transaction()))
    monkeypatch.setattr(m,'_fragment_rows',lambda *args:tuple(tuple(row.items()) for row in current['rows']))
    monkeypatch.setattr(m,'_fragment_profile_lineage',lambda *args:None)
    monkeypatch.setattr(sql,'scalars',lambda *args:iter((sid,)))
    get=store.get_bounded
    def observed(*args,**kwargs):events.append('body');return get(*args,**kwargs)
    monkeypatch.setattr(store,'get_bounded',observed)
    try:yield q,c,store,sql,own,current,events
    finally:sql.close()


def load(f):
    q,c,store,sql,own,_,_=f
    return m.load_history_fragment_consent(sql,artifacts=store,reference=own,
        expected_consent=c,expected_request=q)


def test_bounded_file_load_exact_with_explicit_mocked_source_limitation(loader):
    assert load(loader)==loader[1] and loader[-1]==['body']


@pytest.mark.parametrize('fault',['namespace','system','date','lineage','shortened-union'])
def test_wrong_scalar_admission_zero_body_reads(loader,fault):
    q,c,store,sql,own,current,events=loader
    if fault=='shortened-union':
        c=c.model_copy(update={'provenance':c.provenance[:-1]})
        with pytest.raises(m.ContextualAuthorizationError):
            m.load_history_fragment_consent(sql,artifacts=store,reference=own,
                expected_consent=c,expected_request=q)
    else:
        name,value={'namespace':('external_ref','foreign'),
            'system':('system',SourceSystem.MANUAL),'date':('captured_at',AT.replace(tzinfo=None)),
            'lineage':('supersedes_source_id',uuid4())}[fault]
        current['rows'][0][name]=value
        with pytest.raises(m.ContextualAuthorizationError):load(loader)
    assert not events


@pytest.mark.parametrize('fault',['transaction','metadata'])
def test_real_file_callback_transaction_or_scalar_drift_withholds(loader,monkeypatch,fault):
    _,_,store,sql,_,current,events=loader;original=store.get_bounded
    def changed(*args,**kwargs):
        raw=original(*args,**kwargs)
        if fault=='transaction':sql.commit();sql.begin()
        else:current['rows'][0]['captured_at']=AT+timedelta(seconds=1)
        events.append('fault-applied');return raw
    monkeypatch.setattr(store,'get_bounded',changed)
    with pytest.raises(m.ContextualAuthorizationError) as exc:load(loader)
    assert events==['body','fault-applied'] and exc.value.__context__ is None


def test_missing_original_owner_dependency_denies_before_sql_or_private_io(case):
    q,c,store=case
    with pytest.raises(m.ContextualAuthorizationError):
        m.record_history_fragment_consent(factory=object(),artifacts=store,consent=c,
            expected_request=q,operation=object(),clock=object())


@pytest.mark.parametrize('field',['request_digest','builder_id','original_session_binding',
                                  'model_digest','prompt_tokens','consumed_at'])
def test_claim_mismatch_rejected_before_consent_body(loader,field):
    q,c,store,sql,ref,_,events=loader
    claim=m.HistoryFragmentClaimV1(consent_reference=ref,consent_digest=ref.content_hash,
        request_digest=c.request_digest,attempt_id=uuid4(),task_id=c.task_id,builder_id=c.builder_id,
        original_session_binding=c.original_session_binding,body_digest=c.body_digest,
        route_digest=content_hash_of(canonical_bytes({**c.route.model_dump(mode='json'),
            'capabilities':sorted(c.route.capabilities)})),model_digest=c.model_digest,
        tokenizer_digest=c.tokenizer_digest,runtime_digest=c.runtime_digest,
        template_digest=c.template_digest,renderer_digest=c.renderer_digest,
        prompt_tokens=c.prompt_tokens,max_output_tokens=c.max_output_tokens,consumed_at=AT)
    value=uuid4() if field=='builder_id' else 101 if field=='prompt_tokens' else (
        c.expires_at if field=='consumed_at' else '9'*64)
    changed=claim.model_copy(update={field:value})
    with pytest.raises(m.ContextualAuthorizationError):
        m.load_history_fragment_claim(sql,artifacts=store,reference=ref,
            expected_consent=c,expected_claim=changed,expected_request=q)
    assert not events


def test_hostile_namespace_conflicts_materialize_at_most_two(loader, monkeypatch):
    """Compiled statement limit controls simulated hostile result cardinality."""
    _,_,_,sql,_,_,events=loader
    limits=[]
    consumed=[]
    def hostile(statement):
        clause=statement._limit_clause
        limit=None if clause is None else clause.value
        limits.append(limit)
        # Simulate canonical SELECT execution respecting SQL LIMIT; no DB.
        count=1000 if limit is None else min(1000, limit)
        def rows():
            for index in range(count):
                consumed.append(index)
                yield uuid4()
        return rows()
    monkeypatch.setattr(sql,'scalars',hostile)
    with pytest.raises(m.ContextualAuthorizationError):load(loader)
    assert limits==[2] and consumed==[0,1]
    assert not events
