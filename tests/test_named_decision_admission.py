"""Actual encrypted admission/session stores + real canonical decoder/assembler.

Canonical rows/recovery are invented existing memory fixtures, NOT SQL or actual
backup proof. No HTTP click, model invocation, consent issuer or source connector.
"""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_named_followup_decision import fixture as named_fixture
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import named_decision_admission as m
from zacai.interfaces.followup_authorization import FollowupHostSnapshot
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import SqliteNamedAdmissionStore
from zacai.interfaces.named_followup_decision import encode_named_decision
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import InterfacePrincipal
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    s=named_fixture.__wrapped__(monkeypatch)
    s.clock=HostObservedClock(lambda:s.now)
    s.assembler=CanonicalFollowupAssembler(capture=s.client)
    s.assembler._capture._clock=s.clock
    s.sessions=SqliteSessionStore(tmp_path/"sessions",key=b"x"*32)
    s.cookie=s.sessions.start_user(s.owner.identity,s.now)
    s.session_helper=NamedSessionContinuity(sessions=s.sessions,owner=lambda:s.owner,clock=s.clock,
        key=b"x"*32,origin="https://caz.example",client_id="invented-client")
    s.operation=s.session_helper.for_cookie(s.cookie)
    current=s.operation.establish()
    s.store_path=tmp_path/"admissions"
    s.store_args={"key":b"x"*32,"origin":"https://caz.example","client_id":"invented-client","clock":s.clock}
    s.store=SqliteNamedAdmissionStore(s.store_path,**s.store_args)
    s.issued=s.store.issue(session_binding=current.binding_digest,
        manifest_builder=lambda digest,now:s.manifest.model_copy(update={"nonce_digest":digest,"issued_at":now}))
    s.store.admit(handle=s.issued.handle,session_binding=current.binding_digest,
        question_digest=content_hash_of(s.turn.original_text.encode()),question_bytes=len(s.turn.original_text.encode()))
    s.store.attach_question(handle=s.issued.handle,session_binding=current.binding_digest,
        reference=s.decision.question_reference,recovery_digest=s.decision.question_receipt_digest)
    s.now+=timedelta(seconds=1)
    s.resolver_fail=False
    s.changed_inputs=None
    def inputs(record):
        assert s.active_sessions==0
        if s.resolver_fail:
            raise RuntimeError("PRIVATE proof lookup failure")
        return s.changed_inputs or m.QuestionRecoveryInputs(s.receipt,s.reply_inputs["text_receipt"])
    # Invented SQL query adapter; actual provenance-unique helper and canonical
    # dependency decoders run unchanged. Effective ACL lookup only is mocked.
    with s.client._factory() as session:
        session_type=type(session)
    def scalars(session,statement):
        params=statement.compile().params
        assert params['param_1']==2
        return [row for row in s.sources.values() if row.external_ref==params['external_ref_1']][:2]
    monkeypatch.setattr(session_type,'scalars',scalars,raising=False)
    def label(session,*,source_id):
        from zacai.state import Source
        return session.get(Source,source_id).data_classification
    monkeypatch.setattr(m,'get_effective_source_classification',label)
    from zacai.interfaces import named_candidate_rows
    monkeypatch.setattr(named_candidate_rows,'get_effective_source_classification',label)
    s.actual_route=s.reply_inputs["claimed"].claim.run_scope.route
    s.actual_model=s.reply_inputs["claimed"].claim.run_scope.model_digest
    def snapshot(assembled,principal):
        assert s.active_sessions==0
        return FollowupHostSnapshot(assembled,principal,s.owner,s.actual_route,s.actual_model)
    s.adapter=m.CanonicalNamedDecisionAdmission(store=s.store,operation=s.operation,assembler=s.assembler,
        recovery_inputs=inputs,snapshot_builder=snapshot,clock=s.clock)
    s.principal=InterfacePrincipal(s.owner.identity,s.owner.scopes)
    s.resolve_args=(s.issued.handle,s.principal,s.reply_inputs["request"],s.now)
    return s


def commit_declared(s,decision,attach=False):
    raw=encode_named_decision(decision)
    digest=content_hash_of(raw)
    ref=f"packet-followup-named-decision/{decision.manifest.request_id}"
    source=SimpleNamespace(id=uuid4(),system=m.SourceSystem.USER_INSTRUCTION,trust_boundary=m.B.BRAINSTORM,
        data_classification=m.C.CONFIDENTIAL,captured_at=decision.admitted_at,
        external_ref=ref,content_hash=digest,content_location=digest)
    s.raw[digest]=raw
    s.sources[ref]=source
    if attach:
        s.store.attach_decision(handle=s.issued.handle,session_binding=s.operation.establish().binding_digest,
            reference=m.EvidenceReference(source_id=source.id,content_hash=digest,
                trust_boundary=m.B.BRAINSTORM,effective_classification=m.C.CONFIDENTIAL),recovery_digest="a"*64)
    return source


def test_actual_session_store_and_canonical_question_create_exact_decision_not_authority(fixture):
    s=fixture
    decision=s.adapter.resolve(*s.resolve_args)
    assert decision.manifest==s.issued.record.manifest
    assert decision.admitted_at==s.issued.record.manifest.issued_at
    assert decision.original_observed_at==s.reply_inputs["request"].context.task.event.observed_at
    assert decision.question_reference==s.decision.question_reference
    assert decision.original_utf8_digest==content_hash_of(s.turn.original_text.encode())
    assert decision.prepared_request_digest==s.reply_inputs["request"].digest
    assert not decision.processing_authorized and not decision.execution_authorized
    assert s.adapter.recheck(s.issued.handle,s.principal,decision,s.now) is None


@pytest.mark.parametrize("attach",[False,True])
def test_committed_original_reused_after_restart_even_before_operational_attach(fixture,attach):
    s=fixture
    first=s.adapter.resolve(*s.resolve_args)
    commit_declared(s,first,attach)
    s.now+=timedelta(seconds=5)
    s.adapter._store=SqliteNamedAdmissionStore(s.store_path,**s.store_args)
    prepared=s.adapter.prepare_original(s.issued.handle,s.principal)
    assert prepared==s.reply_inputs["request"]
    later=s.adapter.resolve(s.issued.handle,s.principal,prepared,s.now)
    assert later==first and later.bound_at< s.now
    assert s.adapter.recheck(s.issued.handle,s.principal,later,s.now) is None


def test_restart_without_canonical_original_does_not_guess_observation(fixture):
    with pytest.raises(m.NamedDecisionAdmissionError):
        fixture.adapter.prepare_original(fixture.issued.handle,fixture.principal)


def test_real_revoked_session_or_new_cookie_cannot_resume(fixture):
    s=fixture
    first=s.adapter.resolve(*s.resolve_args)
    commit_declared(s,first)
    s.sessions.revoke(s.cookie)
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.recheck(s.issued.handle,s.principal,first,s.now)
    cookie=s.sessions.start_user(s.owner.identity,s.now)
    s.adapter._operation=s.session_helper.for_cookie(cookie)
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.resolve(*s.resolve_args)
    assert s.adapter.recheck_session(s.principal,first,s.now) is None


@pytest.mark.parametrize("failure",["lookup","question_proof","packet_proof"])
def test_proof_shapes_or_changed_retained_hashes_never_suffice(fixture,failure):
    s=fixture
    if failure=="lookup":
        s.resolver_fail=True
    elif failure=="question_proof":
        s.changed_inputs=m.QuestionRecoveryInputs(s.receipt,s.reply_inputs["text_receipt"].model_copy(update={"turn_digest":"0"*64}))
    else:
        s.changed_inputs=m.QuestionRecoveryInputs(s.receipt.model_copy(update={"verified_at":s.now}),s.reply_inputs["text_receipt"])
    with pytest.raises(m.NamedDecisionAdmissionError) as error:
        s.adapter.resolve(*s.resolve_args)
    assert error.value.__context__ is None


def test_actual_capture_recovery_hold_denies_constructor_valid_proof(fixture):
    s=fixture
    s.fail_recheck=True
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.resolve(*s.resolve_args)


@pytest.mark.parametrize("field,value",[("prepared_request_digest","0"*64),("original_observed_at",None),
                                      ("session_binding_digest","0"*64)])
def test_altered_original_decision_binding_holds(fixture,field,value):
    s=fixture
    decision=s.adapter.resolve(*s.resolve_args).model_copy(update={field:value})
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.recheck(s.issued.handle,s.principal,decision,s.now)


def test_expired_active_admission_held_receipt_only_owner_check_separate(fixture):
    s=fixture
    decision=s.adapter.resolve(*s.resolve_args)
    s.now=decision.processing_expires_at
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.recheck(s.issued.handle,s.principal,decision,s.now)
    assert s.adapter.recheck_session(s.principal,decision,s.now) is None


@pytest.mark.parametrize("change",["system","hash","captured_at"])
def test_committed_actual_source_provenance_denied(fixture,change):
    s=fixture
    decision=s.adapter.resolve(*s.resolve_args)
    source=commit_declared(s,decision,attach=True)
    if change=="system":
        source.system=m.SourceSystem.MANUAL
    elif change=="hash":
        source.content_hash="0"*64
    else:
        source.captured_at=s.now
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.prepare_original(s.issued.handle,s.principal)


@pytest.mark.parametrize("change",["route","model"])
def test_actual_host_profile_must_match_published_manifest(fixture,change):
    s=fixture
    if change=="route":
        s.actual_route=s.actual_route.model_copy(update={"max_output_tokens":256})
    else:
        s.actual_model="0"*64
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.resolve(*s.resolve_args)


def test_question_hash_is_exact_original_whitespace_not_projected_text(fixture):
    s=fixture
    assert s.turn.original_text!=s.turn.original_text.strip()
    decision=s.adapter.resolve(*s.resolve_args)
    assert decision.original_utf8_digest==content_hash_of(s.turn.original_text.encode())
    assert decision.original_utf8_digest!=content_hash_of(s.turn.original_text.strip().encode())


def test_attached_decision_without_actual_named_source_held(fixture):
    s=fixture
    s.store.attach_decision(handle=s.issued.handle,session_binding=s.operation.establish().binding_digest,
        reference=m.EvidenceReference(source_id=uuid4(),content_hash="a"*64,
            trust_boundary=m.B.BRAINSTORM,effective_classification=m.C.CONFIDENTIAL),recovery_digest="b"*64)
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.resolve(*s.resolve_args)


def test_owner_or_question_acl_change_denied(fixture):
    s=fixture
    decision=s.adapter.resolve(*s.resolve_args)
    source=next(row for row in s.sources.values() if row.id==decision.question_reference.source_id)
    source.data_classification=m.C.HIGHLY_RESTRICTED
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.recheck(s.issued.handle,s.principal,decision,s.now)


def test_full_admission_session_restart_uses_original_stored_observation(fixture):
    s=fixture
    first=s.adapter.resolve(*s.resolve_args)
    commit_declared(s,first,attach=True)
    s.now+=timedelta(seconds=10)
    sessions=SqliteSessionStore(s.sessions._directory,key=b"x"*32)
    helper=NamedSessionContinuity(sessions=sessions,owner=lambda:s.owner,clock=s.clock,
        key=b"x"*32,origin="https://caz.example",client_id="invented-client")
    s.adapter._operation=helper.for_cookie(s.cookie)
    s.adapter._store=SqliteNamedAdmissionStore(s.store_path,**s.store_args)
    original=s.adapter.prepare_original(s.issued.handle,s.principal)
    assert original.digest==first.prepared_request_digest
    assert original.context.task.event.observed_at==first.original_observed_at
    assert s.adapter.resolve(s.issued.handle,s.principal,original,s.now)==first


def test_future_callback_time_or_clock_dependency_not_accepted(fixture):
    s=fixture
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.resolve(s.issued.handle,s.principal,s.reply_inputs["request"],s.now+timedelta(seconds=1))
    with pytest.raises(m.NamedDecisionAdmissionError):
        m.CanonicalNamedDecisionAdmission(store=s.store,operation=s.operation,assembler=s.assembler,
            recovery_inputs=s.adapter._recovery_inputs,snapshot_builder=s.adapter._snapshot_builder,
            clock=HostObservedClock(lambda:s.now))


@pytest.mark.parametrize("action",["resolve","recheck","prepare_original"])
@pytest.mark.parametrize("mutation",["decision_acl","decision_bytes","decision_source_id","operational_attachment"])
def test_final_session_callback_change_after_early_reads_denied(fixture,monkeypatch,action,mutation):
    s=fixture
    decision=s.adapter.resolve(*s.resolve_args)
    source=commit_declared(s,decision,attach=False)
    original_recheck=s.operation.recheck
    def callback(binding):
        verified=original_recheck(binding)
        if mutation=="decision_acl":
            source.data_classification=m.C.HIGHLY_RESTRICTED
        elif mutation=="decision_bytes":
            changed=decision.model_copy(update={"bound_at":decision.bound_at+timedelta(microseconds=1)})
            raw=encode_named_decision(changed)
            source.content_hash=content_hash_of(raw)
            source.content_location=source.content_hash
            s.raw[source.content_hash]=raw
        elif mutation=="decision_source_id":
            source.id=uuid4()
        else:
            s.store.attach_decision(handle=s.issued.handle,session_binding=binding,
                reference=m.EvidenceReference(source_id=source.id,content_hash=source.content_hash,
                    trust_boundary=m.B.BRAINSTORM,effective_classification=m.C.CONFIDENTIAL),recovery_digest="a"*64)
        return verified
    monkeypatch.setattr(s.operation,"recheck",callback)
    s.now+=timedelta(seconds=1)
    with pytest.raises(m.NamedDecisionAdmissionError):
        if action=="resolve":
            s.adapter.resolve(s.issued.handle,s.principal,s.reply_inputs["request"],s.now)
        elif action=="recheck":
            s.adapter.recheck(s.issued.handle,s.principal,decision,s.now)
        else:
            s.adapter.prepare_original(s.issued.handle,s.principal)


@pytest.mark.parametrize('action',['resolve','recheck','prepare_original'])
@pytest.mark.parametrize('dependency',['question','packet','evidence'])
def test_final_snapshot_callback_dependency_acl_change_denied(fixture,action,dependency):
    s=fixture
    first=s.adapter.resolve(*s.resolve_args)
    commit_declared(s,first)
    refs={'question':first.question_reference,'packet':first.manifest.packet_reference,
          'evidence':first.manifest.evidence_references[0]}
    row=next(row for row in s.sources.values() if row.id==refs[dependency].source_id)
    original=s.adapter._snapshot_builder
    def changed(assembled,principal):
        snapshot=original(assembled,principal)
        row.data_classification=m.C.HIGHLY_RESTRICTED
        return snapshot
    s.adapter._snapshot_builder=changed
    with pytest.raises(m.NamedDecisionAdmissionError):
        if action=='resolve':s.adapter.resolve(*s.resolve_args)
        elif action=='recheck':s.adapter.recheck(s.issued.handle,s.principal,first,s.now)
        else:s.adapter.prepare_original(s.issued.handle,s.principal)


def test_effective_named_decision_acl_denied(fixture,monkeypatch):
    s=fixture
    first=s.adapter.resolve(*s.resolve_args)
    commit_declared(s,first)
    monkeypatch.setattr(m,'get_effective_source_classification',
        lambda session,source_id:m.C.HIGHLY_RESTRICTED,raising=False)
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.prepare_original(s.issued.handle,s.principal)


def test_foreign_kind_same_provenance_cannot_shadow_actual_named_source(fixture):
    s=fixture
    first=s.adapter.resolve(*s.resolve_args)
    row=commit_declared(s,first)
    s.sources['invented-other-dictionary-key']=SimpleNamespace(**{
        **vars(row),'id':uuid4(),'system':m.SourceSystem.MANUAL})
    with pytest.raises(m.NamedDecisionAdmissionError):
        s.adapter.prepare_original(s.issued.handle,s.principal)
