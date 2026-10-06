"""Real ArtifactStore/parsers/record_source body; SQL/ACL/savepoints simulated.

Not a database, authenticated human decision, recovery or concurrency proof.
"""
import copy
import json
from contextlib import contextmanager, nullcontext
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from tests.test_native_source_preparation import NOW, gmail_inputs, slack_inputs, wire
from zacai.ingestion import native_source_capture as m
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_current_source_revision


class Result:
    def __init__(self, rows):self.rows=rows
    def scalar_one_or_none(self):
        if len(self.rows)>1:raise ValueError('ambiguous')
        return self.rows[0] if self.rows else None


class Memory:
    def __init__(self):self.rows=[];self.acl={};self.savepoints=0;self.database_overrides={};self.limits=[];self.new=set();self.dirty=set();self.deleted=set();self.fail_release=False
    def get(self,cls,sid):return next((x for x in self.rows if x.id==sid),None)
    def add(self,row):self.rows.append(row);self.new.add(row)
    def flush(self):
        if self.dirty or self.deleted:raise RuntimeError('invented append-only flush denied')
        for x in self.rows:
            if x.id is None:x.id=uuid4()
        self.new.clear()
    def commit(self):raise AssertionError('writer cannot commit')
    @property
    def no_autoflush(self):return nullcontext()
    def execute(self,statement):
        limit=statement._limit_clause.value if statement._limit_clause is not None else None
        self.limits.append(limit)
        if 'effective_classification' in statement.selected_columns:
            result=[]
            for x in self.rows:
                values={'system':x.system,'trust_boundary':x.trust_boundary,'data_classification':x.data_classification,
                    'external_ref':x.external_ref,'content_hash':x.content_hash,'content_location':x.content_location,
                    'captured_at':x.captured_at,'supersedes_source_id':x.supersedes_source_id}
                values.update(self.database_overrides.get(x.id,{}))
                superseded={self.database_overrides.get(r.id,{}).get('supersedes_source_id',r.supersedes_source_id) for r in self.rows}
                result.append((x.id,*values.values(),self.acl.get(x.id,values['data_classification']),x.id not in superseded))
            params=statement.compile().params
            ids=params['id_1'];refs=params['external_ref_1']
            metadata=params.get('external_ref_2')
            if metadata is None:  # faithfully run predecessor query for RED controls
                result=[r for r in result if r[0] in ids or r[4] in refs]
            else:
                foreign={params[f'external_ref_{int(k.split("_")[-1])+2}']:v for k,v in params.items() if k.startswith('system_')}
                result=[r for r in result if r[0] in ids or (r[4] in refs and r[10]) or r[4]==metadata
                    or (r[4] in foreign and (r[1]!=foreign[r[4]] or r[2]!=B.BRAINSTORM))]
            return result[:limit] if limit is not None else result
        params=statement.compile().params
        result=list(self.rows)
        foreign='source.system !=' in str(statement)
        for key,value in params.items():
            if key in {'external_ref_1','content_hash_1','system_1','trust_boundary_1'}:
                attr=key[:-2]
                if foreign and attr in {'system','trust_boundary'}:continue
                result=[x for x in result if getattr(x,attr)==value]
        if foreign:result=[x for x in result if x.system!=params['system_1'] or x.trust_boundary!=params['trust_boundary_1']]
        if 'NOT IN' in str(statement):
            superseded={x.supersedes_source_id for x in self.rows if x.supersedes_source_id}
            result=[x for x in result if x.id not in superseded]
        return Result(result[:limit] if limit is not None else result)
    def scalars(self,statement):return self.execute(statement).rows
    @contextmanager
    def begin_nested(self):
        snapshot=copy.deepcopy(self.rows);self.savepoints+=1
        try:
            yield
            self.flush()
            if self.fail_release:raise RuntimeError('invented private RELEASE failure')
        except BaseException:
            self.rows=snapshot;self.new.clear();self.dirty.clear();self.deleted.clear()
            raise


@pytest.fixture
def setup(tmp_path,monkeypatch):
    session=Memory();store=LocalFilesystemArtifactStore(tmp_path/'artifacts')
    monkeypatch.setattr(m,'get_effective_source_classification',lambda s,source_id:s.acl.get(source_id,s.get(Source,source_id).data_classification))
    raw=b'Invented human instruction evidence; authentication is external.';digest=content_hash_of(raw)
    approval=Source(id=uuid4(),system=SourceSystem.USER_INSTRUCTION,trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,external_ref='invented-native-approval/one',content_hash=digest,
        content_location=store.put(B.BRAINSTORM,digest,raw),captured_at=NOW)
    session.rows.append(approval)
    g,_=gmail_inputs();s=slack_inputs()
    gm=(m.GmailCaptureInput(g['scope'],g['profile_response'],g['message_response'],g['expected_message_id']),)
    sl=(m.SlackCaptureInput(s['selection'],s['account_response'],s['page_response']),)
    proposal=m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=gm,slack_inputs=sl)
    args={'artifacts':store,'proposal_raw':proposal,'approved_proposal_hash':content_hash_of(proposal),
        'approval_reference':EvidenceReference(source_id=approval.id,content_hash=digest,trust_boundary=B.BRAINSTORM,effective_classification=C.CONFIDENTIAL),
        'gmail_inputs':gm,'slack_inputs':sl,'captured_at':NOW}
    return session,args


def envelope(session,args,receipt):
    source=session.get(Source,receipt.batch_reference.source_id)
    return json.loads(args['artifacts'].get(B.BRAINSTORM,source.content_location))


def test_first_write_uses_real_store_and_repository_body_without_commit_or_authority(setup):
    session,args=setup;receipt=m.record_native_batch(session,**args)
    assert len(session.rows)==8 and len(receipt.new_source_ids)==7 and session.savepoints==1
    assert not receipt.committed and not receipt.recovery_verified and not receipt.permission_granted
    assert 'Invented' not in repr(receipt)
    value=envelope(session,args,receipt)
    assert value['role']=='CANDIDATE_CONTEXT' and not value['facts_confirmed']
    for selection in value['selections']:
        for artifact in selection['artifacts']:
            source=session.get(Source,UUID(artifact['reference']['source_id']))
            assert source.content_hash==content_hash_of(args['artifacts'].get(B.BRAINSTORM,source.content_location))
            assert source.captured_at==NOW and source.system in (SourceSystem.EMAIL,SourceSystem.SLACK)
        assert selection['artifacts'][-1]['derives_from_wire']['source_id']==selection['artifacts'][1]['reference']['source_id']
        assert selection['artifacts'][-1]['provider_occurred_at']!=selection['host_observed_at']


def test_exact_batch_replay_preserves_all_original_ids_times_and_envelope(setup):
    session,args=setup;first=m.record_native_batch(session,**args)
    before=[(x.id,x.captured_at,x.content_hash,x.supersedes_source_id) for x in session.rows]
    raw=envelope(session,args,first)
    second=m.record_native_batch(session,**{**args,'captured_at':NOW+timedelta(minutes=1)})
    assert second.batch_reference==first.batch_reference and not second.new_source_ids
    assert second.original_observed_at==NOW and envelope(session,args,second)==raw
    assert before==[(x.id,x.captured_at,x.content_hash,x.supersedes_source_id) for x in session.rows]


def revised(args,new_batch=True):
    mail=args['gmail_inputs'][0];value=json.loads(mail.message_response);value['labelIds']=['INBOX']
    gm=(m.GmailCaptureInput(mail.scope,mail.profile_response,wire(**value),mail.expected_message_id),)
    bid=uuid4() if new_batch else UUID(json.loads(args['proposal_raw'])['batch_id'])
    proposal=m.prepare_native_batch_proposal(batch_id=bid,gmail_inputs=gm,slack_inputs=args['slack_inputs'])
    return {**args,'gmail_inputs':gm,'proposal_raw':proposal,'approved_proposal_hash':content_hash_of(proposal),'captured_at':NOW+timedelta(minutes=1)}


def test_new_batch_wire_revision_keeps_mime_and_old_replay_does_not_promote_old_tip(setup):
    session,args=setup;old=m.record_native_batch(session,**args);new=m.record_native_batch(session,**revised(args))
    oldwire=old.artifact_references[0][1];newwire=new.artifact_references[0][1]
    assert newwire!=oldwire and session.get(Source,newwire.source_id).supersedes_source_id==oldwire.source_id
    assert new.artifact_references[0][2]==old.artifact_references[0][2]
    replay=m.record_native_batch(session,**{**args,'captured_at':NOW+timedelta(minutes=2)})
    assert replay.artifact_references==old.artifact_references and not replay.new_source_ids
    tip=get_current_source_revision(session,system=SourceSystem.EMAIL,external_ref=session.get(Source,newwire.source_id).external_ref,trust_boundary=B.BRAINSTORM)
    assert tip.id==newwire.source_id


@pytest.mark.parametrize('fault',['proposal','approval_hash','approval_kind','approval_acl','replay_acl','tip_acl','foreignkind','samebatch'])
def test_predictable_faults_hold_before_put_or_new_rows(setup,monkeypatch,fault):
    session,args=setup;receipt=m.record_native_batch(session,**args)
    if fault=='proposal':args={**args,'approved_proposal_hash':'f'*64}
    if fault=='approval_hash':args['approval_reference']=args['approval_reference'].model_copy(update={'content_hash':'f'*64})
    if fault=='approval_kind':session.get(Source,args['approval_reference'].source_id).system=SourceSystem.MANUAL
    if fault=='approval_acl':session.acl[args['approval_reference'].source_id]=C.HIGHLY_RESTRICTED
    if fault=='replay_acl':session.acl[receipt.artifact_references[0][2].source_id]=C.HIGHLY_RESTRICTED
    if fault=='tip_acl':
        newer=m.record_native_batch(session,**revised(args));session.acl[newer.artifact_references[0][1].source_id]=C.HIGHLY_RESTRICTED
    if fault=='foreignkind':session.get(Source,receipt.artifact_references[0][2].source_id).system=SourceSystem.MANUAL
    if fault=='samebatch':args=revised(args,new_batch=False)
    before=len(session.rows);puts=[]
    original=args['artifacts'].put
    monkeypatch.setattr(args['artifacts'],'put',lambda *a:(puts.append(a),original(*a))[1])
    with pytest.raises(m.NativeBatchCaptureError) as exc:m.record_native_batch(session,**args)
    assert not puts and len(session.rows)==before and exc.value.__context__ is None


def test_corrupt_roundtrip_and_midtransaction_failure_leave_no_partial_rows(setup,monkeypatch):
    session,args=setup;store=args['artifacts'];original=store.get
    monkeypatch.setattr(store,'get',lambda b,loc:original(b,loc) if loc==session.rows[0].content_location else b'corrupt')
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert len(session.rows)==1
    monkeypatch.setattr(store,'get',original)
    record=m.record_source;count=0
    def fail_later(*a,**k):
        nonlocal count
        count+=1
        if count==3:raise RuntimeError('invented private body')
        return record(*a,**k)
    monkeypatch.setattr(m,'record_source',fail_later)
    with pytest.raises(m.NativeBatchCaptureError) as exc:m.record_native_batch(session,**args)
    assert len(session.rows)==1 and exc.value.__context__ is None
    assert list(store.root.rglob('*.bin'))  # named orphan possibility; no automatic deletion


def test_current_acl_rechecked_after_artifact_roundtrip_before_append(setup,monkeypatch):
    session,args=setup;old=m.record_native_batch(session,**args);before=len(session.rows)
    source_id=old.artifact_references[0][2].source_id;store=args['artifacts'];put=store.put
    def elevate(*a):
        session.acl[source_id]=C.HIGHLY_RESTRICTED
        return put(*a)
    monkeypatch.setattr(store,'put',elevate)
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**revised(args))
    assert len(session.rows)==before


def test_retained_provider_location_corrupt_holds_before_repair_put(setup,monkeypatch):
    session,args=setup;old=m.record_native_batch(session,**args)
    row=session.get(Source,old.artifact_references[0][2].source_id)
    get=args['artifacts'].get;puts=[]
    monkeypatch.setattr(args['artifacts'],'get',lambda b,loc:b'corrupt retained MIME' if loc==row.content_location else get(b,loc))
    monkeypatch.setattr(args['artifacts'],'put',lambda *a:puts.append(a))
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert not puts and len(session.rows)==8


def test_last_artifact_callback_elevation_holds_uncommitted_ack(setup,monkeypatch):
    session,args=setup;store=args['artifacts'];get=store.get
    approval_id=args['approval_reference'].source_id;calls=0
    def change_last_owner_evidence(b,loc):
        nonlocal calls
        raw=get(b,loc)
        if loc==session.rows[0].content_location:
            calls+=1
            if calls==3:session.acl[approval_id]=C.HIGHLY_RESTRICTED
        return raw
    monkeypatch.setattr(store,'get',change_last_owner_evidence)
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert calls==3 and len(session.rows)==1


@pytest.mark.parametrize('fault',['extra_field','foreign_account','personal','duplicate_id','expired_observation'])
def test_closed_snapshot_and_actual_parsers_hold_before_any_put(setup,monkeypatch,fault):
    from dataclasses import replace
    session,args=setup;mail=args['gmail_inputs'][0]
    if fault=='extra_field':
        value=json.loads(args['proposal_raw']);value['permission']=True
        args['proposal_raw']=wire(**value);args['approved_proposal_hash']=content_hash_of(args['proposal_raw'])
    elif fault=='expired_observation':args['captured_at']=NOW.replace(tzinfo=None)
    else:
        if fault=='foreign_account':
            mail=replace(mail,profile_response=wire(emailAddress='foreign@example.test',historyId='987',messagesTotal=5,threadsTotal=2))
        if fault=='personal':mail=replace(mail,scope=replace(mail.scope,boundary=B.PERSONAL))
        args['gmail_inputs']=(mail,mail) if fault=='duplicate_id' else (mail,)
        try:
            args['proposal_raw']=m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=args['gmail_inputs'],slack_inputs=args['slack_inputs'])
        except m.NativeBatchCaptureError:
            assert fault in {'duplicate_id','personal'} and len(session.rows)==1
            return
        args['approved_proposal_hash']=content_hash_of(args['proposal_raw'])
    puts=[];monkeypatch.setattr(args['artifacts'],'put',lambda *a:puts.append(a))
    with pytest.raises(m.NativeBatchCaptureError) as exc:m.record_native_batch(session,**args)
    assert not puts and len(session.rows)==1 and exc.value.__context__ is None


@pytest.mark.parametrize('field,value',[('system',SourceSystem.MANUAL),('trust_boundary',B.PERSONAL),
    ('data_classification',C.HIGHLY_RESTRICTED),('content_hash','f'*64),('external_ref','foreign/ref'),
    ('content_location','foreign/location'),('captured_at',NOW+timedelta(seconds=1)),('supersedes_source_id',uuid4())])
def test_final_scalar_snapshot_detects_corrupt_raw_metadata_hidden_from_identity_map(setup,monkeypatch,field,value):
    session,args=setup;old=m.record_native_batch(session,**args)
    sid=old.artifact_references[0][2].source_id;cached=session.get(Source,sid)
    oldvalue=getattr(cached,field);get=args['artifacts'].get
    def corrupt_after_read(b,loc):
        raw=get(b,loc)
        if loc==session.rows[0].content_location:
            session.database_overrides[sid]={field:value}
        return raw
    monkeypatch.setattr(args['artifacts'],'get',corrupt_after_read)
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert getattr(cached,field)==oldvalue  # SQL simulation separate from ORM identity
    assert len(session.rows)==8


def test_future_approval_observation_holds_before_provider_put(setup,monkeypatch):
    session,args=setup;session.rows[0].captured_at=NOW+timedelta(seconds=1)
    puts=[];monkeypatch.setattr(args['artifacts'],'put',lambda *a:puts.append(a))
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert not puts and len(session.rows)==1


def many_revisions(session, external_ref, system, count):
    for index in range(count):
        session.rows.append(Source(id=uuid4(),system=system,trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,external_ref=external_ref,content_hash=f'{index:064x}',
            content_location='invented-unread-location',captured_at=NOW))


def test_oversized_lineage_query_has_bound_and_holds_before_provider_put(setup,monkeypatch):
    session,args=setup
    prepared=m.prepare_gmail_source(scope=args['gmail_inputs'][0].scope,
        profile_response=args['gmail_inputs'][0].profile_response,message_response=args['gmail_inputs'][0].message_response,
        expected_message_id=args['gmail_inputs'][0].expected_message_id,captured_at=NOW)
    many_revisions(session,prepared.artifacts[0].external_ref,SourceSystem.EMAIL,1100)
    puts=[];monkeypatch.setattr(args['artifacts'],'put',lambda *a:puts.append(a))
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert session.limits==[2,1,2,2] and not puts and len(session.rows)==1101


def test_ambiguous_batch_metadata_query_has_two_row_bound_before_put(setup,monkeypatch):
    session,args=setup;bid=json.loads(args['proposal_raw'])['batch_id']
    many_revisions(session,f'native-source-batch/{bid}',SourceSystem.MANUAL,1100)
    puts=[];monkeypatch.setattr(args['artifacts'],'put',lambda *a:puts.append(a))
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert session.limits==[2] and not puts and len(session.rows)==1101


def test_final_scalar_query_limits_before_materialization_and_holds_oversized_union(setup,monkeypatch):
    session,args=setup;first=m.record_native_batch(session,**args)
    sid=first.artifact_references[0][2].source_id;target=session.get(Source,sid)
    get=args['artifacts'].get;calls=0
    def expand_only_after_last_artifact(b,loc):
        nonlocal calls
        raw=get(b,loc)
        if loc==session.rows[0].content_location:
            calls+=1
            if calls==3:many_revisions(session,target.external_ref,SourceSystem.EMAIL,1100)
        return raw
    monkeypatch.setattr(args['artifacts'],'get',expand_only_after_last_artifact)
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert calls==3 and session.limits[-1]==16
    assert len(session.rows)==8  # late expansion and writer rows rolled back in simulated savepoint


def test_exact_small_snapshot_and_lineage_still_use_actual_source_contract(setup):
    session,args=setup;first=m.record_native_batch(session,**args)
    assert len(first.new_source_ids)==7
    assert 2 in session.limits and session.limits[-1]==16
    assert len(session.rows)==8



def test_terminal_savepoint_release_failure_never_returns_receipt(setup):
    session,args=setup;session.fail_release=True
    with pytest.raises(m.NativeBatchCaptureError) as exc:m.record_native_batch(session,**args)
    assert len(session.rows)==1 and session.savepoints==1 and exc.value.__context__ is None


@pytest.mark.parametrize('pending',['new','dirty','deleted'])
def test_last_approval_artifact_callback_pending_orm_work_holds_without_flush_ack(setup,monkeypatch,pending):
    session,args=setup;get=args['artifacts'].get;calls=0
    def leave_pending(b,loc):
        nonlocal calls
        raw=get(b,loc)
        if loc==session.rows[0].content_location:
            calls+=1
            if calls==3:getattr(session,pending).add(session.rows[0])
        return raw
    monkeypatch.setattr(args['artifacts'],'get',leave_pending)
    with pytest.raises(m.NativeBatchCaptureError) as exc:m.record_native_batch(session,**args)
    assert calls==3 and len(session.rows)==1 and exc.value.__context__ is None


def test_preexisting_pending_orm_state_is_rejected_before_any_store_callback(setup,monkeypatch):
    session,args=setup;session.dirty.add(session.rows[0]);reads=[]
    monkeypatch.setattr(args['artifacts'],'get',lambda *a:reads.append(a))
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert not reads and not session.savepoints


def test_provider_put_callback_pending_fact_is_rejected_before_savepoint_flush(setup,monkeypatch):
    session,args=setup;put=args['artifacts'].put
    def stage_pending(*a):
        location=put(*a);session.new.add(object());return location
    monkeypatch.setattr(args['artifacts'],'put',stage_pending)
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert not session.savepoints and len(session.rows)==1



def test_new_revision_observation_older_than_current_tip_holds_before_put(setup,monkeypatch):
    session,args=setup;m.record_native_batch(session,**args)
    later=revised(args);m.record_native_batch(session,**later)
    older=revised(args);mail=older['gmail_inputs'][0];value=json.loads(mail.message_response);value['labelIds']=['STARRED']
    older['gmail_inputs']=(m.GmailCaptureInput(mail.scope,mail.profile_response,wire(**value),mail.expected_message_id),)
    older['captured_at']=NOW
    older['proposal_raw']=m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=older['gmail_inputs'],slack_inputs=older['slack_inputs'])
    older['approved_proposal_hash']=content_hash_of(older['proposal_raw'])
    puts=[];original_put=args['artifacts'].put
    monkeypatch.setattr(args['artifacts'],'put',lambda *a:(puts.append(a),original_put(*a))[1])
    before=len(session.rows)
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**older)
    assert not puts and len(session.rows)==before


def test_large_valid_historical_lineage_does_not_permanently_lock_out_mailbox(setup):
    session,args=setup;first=m.record_native_batch(session,**args)
    target=session.get(Source,first.artifact_references[0][0].source_id)
    prior=target.id
    for index in range(1100):
        raw=wire(emailAddress='invented@example.test',historyId=str(index+1000),messagesTotal=5,threadsTotal=2);digest=content_hash_of(raw)
        location=args['artifacts'].put(B.BRAINSTORM,digest,raw) if index==1099 else 'historical-not-read'
        row=Source(id=uuid4(),system=SourceSystem.EMAIL,trust_boundary=B.BRAINSTORM,data_classification=C.CONFIDENTIAL,
            external_ref=target.external_ref,content_hash=digest,content_location=location,captured_at=NOW,
            supersedes_source_id=prior)
        session.rows.append(row);prior=row.id
    later=revised(args);receipt=m.record_native_batch(session,**later)
    assert receipt.artifact_references[0][0]==first.artifact_references[0][0]  # old bytes replay deliberate
    tip=get_current_source_revision(session,system=SourceSystem.EMAIL,external_ref=target.external_ref,trust_boundary=B.BRAINSTORM)
    assert tip.id==prior and all(limit is None or limit<=16 for limit in session.limits)


def test_proposal_fixed_scope_mismatch_holds_before_human_review(setup):
    from dataclasses import replace
    _,args=setup;mail=args['gmail_inputs'][0]
    for scope in (replace(mail.scope,boundary=B.PERSONAL),replace(mail.scope,classification=C.HIGHLY_RESTRICTED)):
        with pytest.raises(m.NativeBatchCaptureError):
            m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=(replace(mail,scope=scope),),slack_inputs=args['slack_inputs'])


def test_two_mail_messages_divergent_shared_profile_rejected_before_review(setup):
    from dataclasses import replace
    _,args=setup;mail=args['gmail_inputs'][0]
    message=json.loads(mail.message_response);message['id']='m2'
    profile=json.loads(mail.profile_response);profile['historyId']='999'
    second=replace(mail,expected_message_id='m2',message_response=wire(**message),profile_response=wire(**profile))
    with pytest.raises(m.NativeBatchCaptureError):
        m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=(mail,second),slack_inputs=args['slack_inputs'])


def test_identical_shared_profile_and_equal_tip_time_are_allowed(setup):
    from dataclasses import replace
    session,args=setup;mail=args['gmail_inputs'][0]
    message=json.loads(mail.message_response);message['id']='m2'
    second=replace(mail,expected_message_id='m2',message_response=wire(**message))
    gm=(mail,second)
    proposal=m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=gm,slack_inputs=args['slack_inputs'])
    receipt=m.record_native_batch(session,**{**args,'gmail_inputs':gm,'proposal_raw':proposal,'approved_proposal_hash':content_hash_of(proposal)})
    assert receipt.artifact_references[0][0]==receipt.artifact_references[1][0]
    later=revised(args);later['captured_at']=NOW
    assert m.record_native_batch(session,**later).original_observed_at==NOW


def test_future_exact_replay_source_holds_before_put(setup,monkeypatch):
    session,args=setup;first=m.record_native_batch(session,**args)
    row=session.get(Source,first.artifact_references[0][0].source_id)
    row.captured_at=NOW+timedelta(seconds=1)
    before_rows=tuple(session.rows)
    puts=[];original=args['artifacts'].put
    monkeypatch.setattr(args['artifacts'],'put',lambda *a:(puts.append(a),original(*a))[1])
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert puts==[]
    assert len(session.rows)==len(before_rows)
    assert tuple(session.rows)==before_rows


def test_divergent_actual_artifact_plans_hold_before_put(setup,monkeypatch):
    from dataclasses import replace
    session,args=setup
    original_prepare=m.prepare_gmail_source
    def conflicted(**kwargs):
        prepared=original_prepare(**kwargs);p=prepared.artifacts[0]
        changed=replace(p,content_hash=content_hash_of(b'other'),original_bytes=b'other')
        return replace(prepared,artifacts=(*prepared.artifacts,changed))
    # Fixture construction must succeed outside the writer's sanitizing try.
    mail=args['gmail_inputs'][0]
    prepared=conflicted(scope=mail.scope,profile_response=mail.profile_response,
        message_response=mail.message_response,expected_message_id=mail.expected_message_id,captured_at=NOW)
    assert len(prepared.artifacts)==4
    assert prepared.artifacts[0].external_ref==prepared.artifacts[-1].external_ref
    assert prepared.artifacts[0].system is prepared.artifacts[-1].system
    assert prepared.artifacts[0].content_hash!=prepared.artifacts[-1].content_hash
    assert content_hash_of(prepared.artifacts[-1].original_bytes)==prepared.artifacts[-1].content_hash
    monkeypatch.setattr(m,'prepare_gmail_source',conflicted)
    puts=[];original=args['artifacts'].put
    monkeypatch.setattr(args['artifacts'],'put',lambda *a:(puts.append(a),original(*a))[1])
    with pytest.raises(m.NativeBatchCaptureError):m.record_native_batch(session,**args)
    assert puts==[] and len(session.rows)==1


def test_shared_slack_account_wire_snapshot_must_match_before_review(setup):
    from dataclasses import replace
    _,args=setup;first=args['slack_inputs'][0]
    second=replace(first,selection=first.selection.model_copy(update={'latest':'201.999999'}),account_response=first.account_response+b' ')
    with pytest.raises(m.NativeBatchCaptureError):
        m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=args['gmail_inputs'],slack_inputs=(first,second))


def test_overlapping_slack_selected_messages_conflict_before_put(setup,monkeypatch):
    from dataclasses import replace
    session,args=setup;first=args['slack_inputs'][0]
    page=json.loads(first.page_response);page['messages'][0]['text']='Different invented same-ts observation'
    second=replace(first,selection=first.selection.model_copy(update={'latest':'201.999999'}),page_response=wire(**page))
    sl=(first,second)
    proposal=m.prepare_native_batch_proposal(batch_id=uuid4(),gmail_inputs=args['gmail_inputs'],slack_inputs=sl)
    puts=[];original=args['artifacts'].put
    monkeypatch.setattr(args['artifacts'],'put',lambda *a:(puts.append(a),original(*a))[1])
    with pytest.raises(m.NativeBatchCaptureError):
        m.record_native_batch(session,**{**args,'slack_inputs':sl,'proposal_raw':proposal,'approved_proposal_hash':content_hash_of(proposal)})
    assert puts==[] and len(session.rows)==1


def test_actual_native_preparer_namespaces_are_system_disjoint(setup):
    _, args = setup
    mail = args['gmail_inputs'][0]
    slack = args['slack_inputs'][0]
    gmail = m.prepare_gmail_source(scope=mail.scope, profile_response=mail.profile_response,
        message_response=mail.message_response, expected_message_id=mail.expected_message_id, captured_at=NOW)
    selected = m.prepare_slack_sources(selection=slack.selection, account_response=slack.account_response,
        page_response=slack.page_response, captured_at=NOW, boundary=B.BRAINSTORM,
        classification=C.CONFIDENTIAL, requestor_boundaries=frozenset({B.BRAINSTORM}), allowed_classifications=frozenset({C.CONFIDENTIAL}))
    assert gmail.artifacts and selected.artifacts
    assert all(p.system is SourceSystem.EMAIL and p.external_ref.startswith('gmail/') for p in gmail.artifacts)
    assert all(p.system is SourceSystem.SLACK and p.external_ref.startswith('slack/') for p in selected.artifacts)
    assert {p.external_ref for p in gmail.artifacts}.isdisjoint(p.external_ref for p in selected.artifacts)
