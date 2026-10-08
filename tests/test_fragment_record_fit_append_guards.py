"""Invented coherent requests/actual encoders; owner/SQL/crypto explicitly simulated."""
# ruff: noqa: F401, F811
from uuid import uuid4

import pytest

from tests.test_fragment_publication_generation import publication_issuer
from tests.test_fragment_publication_generation import released as publication_released
from tests.test_fragment_publication_post import post_case
from tests.test_fragment_publication_review_integration import (
    baseline_authority,
    invoke,
    review_case,
)
from tests.test_fragment_review_retention import capture, case, declaration_case, retained, writer
from tests.test_personal_fragment_claim_issuer import (
    authority,
    consent_case,
    installed,
    issuer,
    packet_case,
)
from tests.test_personal_fragment_output import released as legacy_released
from tests.test_personal_fragment_output import retain as legacy_retain
from zacai import backup_artifacts
from zacai import contextual_authorization as auth
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_publication_generation as generation
from zacai.intelligence import fragment_publication_review as review
from zacai.intelligence import fragment_review_declaration as declaration
from zacai.intelligence import fragment_review_retention as retention
from zacai.intelligence import history_fragment_contextual_codec as codec
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def expanded(f, count):
    """Rebuild actual closed request, consent and declaration, never forge counts."""
    d = f.declaration
    _, g, q = retention._parts(d)
    event = q.original_task.event
    extra = tuple(EvidenceReference(source_id=uuid4(), content_hash='a'*64,
        trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
        for _ in range(count-len(g.provenance)))
    task = q.original_task.model_copy(update={'event':event.model_copy(
        update={'provenance':(*event.provenance,*extra)})})
    original = ReviewContext(task,q.original_meeting_source_id,q.original_related_source_ids)
    profile = codec._profile(q.profile_json,q.observation)
    context = codec._derive(original,profile,q.observation,q.profile_json,q.observed_at)
    body = codec._body(context,profile,q.observation,q.route)
    q = codec.HistoryFragmentContextualRequestV1.model_validate({**q.model_dump(),
        'original_task':task,'task':context.task,'meeting_source_id':context.meeting_source_id,
        'related_source_ids':context.related_source_ids,'prompt_body':body.decode(),
        'prompt_digest':content_hash_of(body)})
    g = auth.HistoryFragmentConsentV1.model_validate({**g.model_dump(),
        'task_id':q.task.task_id,'request_digest':content_hash_of(codec.encode_history_fragment_contextual_request(q)),
        'provenance':auth._fragment_request_provenance(q),'body_digest':content_hash_of(body)})
    assert len(g.provenance)==count
    return declaration.prepare_fragment_generation_review_declaration(g,q,review=d.review)


def test_real_encoder_measurement_small_contract_positive(writer):
    sizes = review._assert_publication_review_record_fit(writer.declaration)
    assert 0<sizes[0]<sizes[1]<=review.MAX_REVIEW_RECORD_BYTES


@pytest.mark.parametrize('count',[55,89])
def test_coherent_below89_union_must_fit_actual_claim_and_assessment_before_capture(writer, count, monkeypatch):
    f=writer
    f.declaration=expanded(f,count)
    milestones=[]
    encode=review.encode_fragment_publication_review_claim
    def observed(value):
        milestones.append(('actual claim encoder',len(value.selected_references)))
        return encode(value)
    monkeypatch.setattr(review,'encode_fragment_publication_review_claim',observed)
    with pytest.raises(retention.FragmentDeclarationRetentionError):capture(f)
    assert milestones==[('actual claim encoder',count+5)]
    assert not f.events  # No owner, lock, artifact or canonical Source call.


def test_already_burned_generation_zero_declaration_put(writer, monkeypatch):
    f=writer;f.current['consumed']=(uuid4(),)
    puts=[]
    monkeypatch.setattr(f.store,'put',lambda *a: puts.append('put'))
    with pytest.raises(retention.FragmentDeclarationRetentionError):capture(f)
    assert 'lock' in f.events and puts==[] and 'record' not in f.events


def test_burn_appearing_inside_declaration_put_refuses_append(writer,monkeypatch):
    f=writer;put=f.store.put;milestones=[]
    def changed(*a):
        location=put(*a);f.current['consumed']=(uuid4(),)
        milestones.append('actual put then other claim observed');return location
    monkeypatch.setattr(f.store,'put',changed)
    with pytest.raises(retention.FragmentDeclarationRetentionError):capture(f)
    assert milestones==['actual put then other claim observed']
    assert 'record' not in f.events and 'commit' not in f.events


def complete_inventory(monkeypatch, count):
    state={'count':count,'seen':[]}
    def rows(session, **kw):
        state['seen'].append(state['count'])
        return canonical_bytes([{'id':str(n)} for n in range(state['count'])]), ()
    monkeypatch.setattr(backup_artifacts,'_personal_backup_rows',rows)
    return state


def test_publication_output_capacity_zero_packet_capture(publication_issuer,monkeypatch):
    f=publication_issuer
    publication_released(f)
    state=complete_inventory(monkeypatch,4092)
    capture_calls=[]
    monkeypatch.setattr(generation,'capture_history_fragment_contextual_packet',
        lambda *a,**kw:capture_calls.append('packet'))
    with pytest.raises(generation.FragmentPublicationGenerationError):
        generation.retain_personal_fragment_publication_output(f.gate,
            runtime=f.runtime,request=f.q,draft=f.draft)
    assert state['seen']==[4092] and capture_calls==[]
    assert f.gate._phase=='OUTPUT_HELD' and f.gate._associated_result is None


def test_legacy_output_capacity_zero_packet_capture(legacy_released,monkeypatch):
    from zacai.intelligence import personal_fragment_output as old
    f=legacy_released
    state=complete_inventory(monkeypatch,4096)
    with pytest.raises(old.PersonalFragmentOutputError):legacy_retain(f)
    assert state['seen']==[4096] and 'capture' not in f.events
    assert f.gate._phase=='OUTPUT_HELD'




def test_known_complete_review_lower_bound_uses_actual_escaped_instruction_bytes(writer):
    from zacai.intelligence.fragment_review_preparation import MAX_INSTRUCTION_BYTES
    sizes=review._assert_publication_review_record_fit(writer.declaration,
        rubric_utf8=b'brief rubric',template_utf8=b'brief template')
    assert max(sizes)<=review.MAX_REVIEW_RECORD_BYTES
    with pytest.raises(ValueError,match='known input exceeds'):
        review._assert_publication_review_record_fit(expanded(writer, 30),
            rubric_utf8=b'\x01'*MAX_INSTRUCTION_BYTES,
            template_utf8=b'\x01'*MAX_INSTRUCTION_BYTES)


@pytest.mark.parametrize('during_put',[False,True])
def test_admission_burned_parent_before_or_during_own_put_holds(post_case,tmp_path,monkeypatch,during_put):
    from sqlalchemy.orm import Session, sessionmaker

    from tests.test_fragment_publication_post import observe
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
    from zacai.intelligence import fragment_publication_admission as admission
    f=post_case;action=observe(f)
    state={'burned':not during_put,'queries':[]}
    class Simulated(Session):
        def scalars(self,statement,*a,**kw):
            assert any(str(v).startswith('personal-history-fragment-claim/')
                for v in statement.compile().params.values())
            state['queries'].append(state['burned'])
            return iter((uuid4(),)) if state['burned'] else iter(())
    monkeypatch.setattr(auth,'_fragment_decision_owner',lambda *a:None)
    monkeypatch.setattr(admission,'_lock',lambda *a:None)
    monkeypatch.setattr(admission,'_physical',lambda *a:('simulated',))
    monkeypatch.setattr(admission,'_same',lambda *a:None)
    monkeypatch.setattr(admission,'_not_withdrawn',lambda *a:None)
    monkeypatch.setattr(admission,'_fragment_rows',lambda *a:())
    monkeypatch.setattr(admission,'load_fragment_review_declaration',lambda *a,**kw:None)
    monkeypatch.setattr(admission,'_ids',lambda *a,**kw:())
    complete_inventory(monkeypatch,5)
    store=LocalFilesystemArtifactStore(tmp_path/'admission');put=store.put;milestones=[]
    def changed(*a):
        location=put(*a);state['burned']=True
        milestones.append('actual own put');return location
    monkeypatch.setattr(store,'put',changed)
    records=[]
    monkeypatch.setattr(admission,'record_source',lambda *a,**kw:records.append('Source'))
    with pytest.raises(admission.FragmentPublicationAdmissionError):
        admission._record_posted_fragment_admission(factory=sessionmaker(class_=Simulated),
            artifacts=store,action=action,clock=f.clock)
    assert state['queries']==([False,True] if during_put else [True])
    assert milestones==(['actual own put'] if during_put else []) and records==[]
