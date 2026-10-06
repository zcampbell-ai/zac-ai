"""Actual installed preparation/contracts; canonical refs entirely invented."""
import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_native_source_preparation import NOW, gmail_inputs, slack_inputs
from zacai.ingestion import native_batch_envelope as m
from zacai.ingestion.native_source_preparation import prepare_gmail_source, prepare_slack_sources
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def ref(digest):
    return EvidenceReference(source_id=uuid4(),content_hash=digest,trust_boundary=B.BRAINSTORM,effective_classification=C.CONFIDENTIAL)


def args():
    gmail,_=gmail_inputs()
    prepared=(prepare_gmail_source(**gmail),prepare_slack_sources(**slack_inputs()))
    return {'batch_id':uuid4(),'proposal_digest':'b'*64,'approval_reference':ref('a'*64),
        'prepared':prepared,'artifact_references':tuple(tuple(ref(a.content_hash) for a in p.artifacts) for p in prepared),
        'observed_at':NOW}


def test_actual_preparations_compose_exact_refs_origins_and_distinct_provider_times():
    a=args();raw=m.compose_native_batch_envelope(**a);value=json.loads(raw)
    assert raw==m.compose_native_batch_envelope(**a)
    assert {s['provider'] for s in value['selections']}=={'gmail','slack'}
    for selection,prepared,refs in zip(value['selections'],a['prepared'],a['artifact_references'],strict=True):
        assert selection['host_observed_at']==NOW.isoformat()
        for artifact,plan,reference in zip(selection['artifacts'],prepared.artifacts,refs,strict=True):
            assert artifact['reference']==reference.model_dump(mode='json')
            assert artifact['artifact_kind']==plan.artifact_kind
            if plan.derives_from:
                assert artifact['derives_from_wire']['content_hash']==plan.derives_from.content_hash
        assert selection['artifacts'][-1]['provider_occurred_at']!=selection['host_observed_at']
    assert not value['permission_granted'] and not value['facts_confirmed'] and not value['recovery_verified']
    assert 'Invented private body' not in raw.decode()


@pytest.mark.parametrize('fault',['hash','classification','boundary','approval_alias','future','origin','provider','count','uuid_conflict'])
def test_malformed_or_wrong_scope_declarations_hold_without_private_context(fault):
    a=args();groups=list(a['artifact_references']);prepared=list(a['prepared'])
    if fault in {'hash','classification','boundary','approval_alias','uuid_conflict'}:
        refs=list(groups[0]);reference=refs[0]
        if fault=='hash':reference=reference.model_copy(update={'content_hash':'f'*64})
        if fault=='classification':reference=reference.model_copy(update={'effective_classification':C.HIGHLY_RESTRICTED})
        if fault=='boundary':reference=reference.model_copy(update={'trust_boundary':B.PERSONAL})
        if fault=='approval_alias':reference=reference.model_copy(update={'source_id':a['approval_reference'].source_id})
        if fault=='uuid_conflict':reference=reference.model_copy(update={'source_id':refs[-1].source_id})
        refs[0]=reference;groups[0]=tuple(refs)
    if fault=='future':prepared[0]=replace(prepared[0],captured_at=NOW+timedelta(seconds=1))
    if fault=='origin':
        plans=list(prepared[0].artifacts)
        plans[-1]=replace(plans[-1],derives_from=replace(plans[-1].derives_from,content_hash='f'*64))
        prepared[0]=replace(prepared[0],artifacts=tuple(plans))
    if fault=='provider':prepared[1]=prepared[0];groups[1]=groups[0]
    if fault=='count':prepared=prepared[:1];groups=groups[:1]
    a['artifact_references']=tuple(groups);a['prepared']=tuple(prepared)
    with pytest.raises(m.NativeBatchEnvelopeError) as e:m.compose_native_batch_envelope(**a)
    assert e.value.__context__ is None and str(e.value)=='native selected batch composition held'
