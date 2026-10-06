"""Invented original wire only; no token, Source/artifact write or real account."""
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from tests.test_gmail_wire import message as gmail_message
from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.slack_wire import HistorySelection, RepliesSelection, SlackAccount
from zacai.ingestion import native_source_preparation as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

NOW=datetime(2026,10,6,tzinfo=UTC)


def wire(**values):return json.dumps(values).encode()


def gmail_inputs():
    value,original=gmail_message()
    return {'scope': GmailScope('business-invented','invented@example.test',B.BRAINSTORM,C.CONFIDENTIAL,
        frozenset({B.BRAINSTORM}),frozenset({C.CONFIDENTIAL})),
        'profile_response': wire(emailAddress='invented@example.test',historyId='987',messagesTotal=5,threadsTotal=2),
        'message_response': json.dumps(value,indent=2).encode(),'expected_message_id': 'abc123','captured_at': NOW},original


def slack_inputs():
    account=SlackAccount(team_id='TTEST',user_id='UTEST')
    return {'selection': HistorySelection(account=account,channel_id='CTEST',oldest='100.000001',latest='200.999999'),
        'account_response': wire(ok=True,team_id='TTEST',user_id='UTEST'),
        'page_response': wire(ok=True,messages=[{'ts':'150.123456','text':'Invented private body','files':[{'id':'FTEST'}]}],
            response_metadata={'next_cursor':'NEXT'}),'captured_at': NOW,'boundary': B.BRAINSTORM,'classification': C.CONFIDENTIAL,
        'requestor_boundaries': frozenset({B.BRAINSTORM}),'allowed_classifications': frozenset({C.CONFIDENTIAL})}


def test_mail_original_wire_and_rfc822_exact_preserved_without_authority():
    args,original=gmail_inputs();prepared=m.prepare_gmail_source(**args)
    assert prepared.artifacts[1].original_bytes==args['message_response']
    assert prepared.artifacts[2].original_bytes==original
    assert {artifact.system for artifact in prepared.artifacts}=={SourceSystem.EMAIL}
    assert prepared.captured_at==NOW and prepared.artifacts[2].source_occurred_at<NOW
    assert not prepared.capture_authorized and not prepared.recovery_verified and not prepared.complete_history_verified
    assert 'opaque' not in repr(prepared) and 'invented@example' not in repr(prepared)


def test_identical_mail_plan_is_exact_and_changed_labels_revision_separates_wire_from_mime():
    args,_=gmail_inputs();first=m.prepare_gmail_source(**args)
    assert first==m.prepare_gmail_source(**args)
    changed=json.loads(args['message_response']);changed['labelIds']=['INBOX']
    second=m.prepare_gmail_source(**{**args,'message_response':wire(**changed)})
    assert first.artifacts[1].external_ref==second.artifacts[1].external_ref
    assert first.artifacts[1].content_hash!=second.artifacts[1].content_hash
    assert first.artifacts[2].content_hash==second.artifacts[2].content_hash
    assert first.artifacts[2].external_ref==second.artifacts[2].external_ref
    assert first.artifacts[2].derives_from.content_hash!=second.artifacts[2].derives_from.content_hash


@pytest.mark.parametrize('fault',['account','id','personal','restricted','denied','future','naive'])
def test_mail_wrong_account_selection_classification_or_time_holds(fault):
    args,_=gmail_inputs()
    if fault=='account':args['profile_response']=wire(emailAddress='foreign@example.test',historyId='1',messagesTotal=1,threadsTotal=1)
    if fault=='id':args['expected_message_id']='foreign'
    if fault=='personal':args['scope']=replace(args['scope'],boundary=B.PERSONAL)
    if fault=='restricted':args['scope']=replace(args['scope'],classification=C.HIGHLY_RESTRICTED)
    if fault=='denied':args['scope']=replace(args['scope'],requestor_boundaries=frozenset({B.PERSONAL}))
    if fault=='future':args['captured_at']=datetime(2025,1,1,tzinfo=UTC)
    if fault=='naive':args['captured_at']=NOW.replace(tzinfo=None)
    with pytest.raises(m.NativeSourcePreparationError) as exc:m.prepare_gmail_source(**args)
    assert exc.value.__context__ is None


def test_slack_original_page_message_identity_and_coverage_preserved():
    args=slack_inputs();prepared=m.prepare_slack_sources(**args)
    assert prepared.artifacts[1].original_bytes==args['page_response']
    assert prepared.artifacts[2].external_ref.startswith('slack/message/TTEST/CTEST/150.123456/view/')
    assert prepared.artifacts[2].source_occurred_at.microsecond==123456
    assert prepared.next_cursor=='NEXT' and not prepared.selected_page_exhausted
    assert not prepared.complete_history_verified and not prepared.recovery_verified
    assert 'Invented private body' not in repr(prepared)
    assert 'references-only-not-downloaded' in prepared.declared_selection_bytes.decode()


def test_slack_edit_changes_hash_with_same_provider_revision_identity():
    args=slack_inputs();first=m.prepare_slack_sources(**args)
    value=json.loads(args['page_response']);value['messages'][0]['text']='Edited invented';value['messages'][0]['edited']={'ts':'175.000001'}
    second=m.prepare_slack_sources(**{**args,'page_response':wire(**value)})
    assert first.artifacts[2].external_ref==second.artifacts[2].external_ref
    assert first.artifacts[2].content_hash!=second.artifacts[2].content_hash


@pytest.mark.parametrize('fault',['team','user','bot','channel','duplicate','window','personal','restricted','denied','naive'])
def test_slack_wrong_identity_scope_or_page_holds(fault):
    args=slack_inputs()
    if fault in {'team','user','bot'}:
        obj=json.loads(args['account_response'])
        if fault=='team':obj['team_id']='TOTHER'
        elif fault=='user':obj['user_id']='UOTHER'
        else:obj['bot_id']='BTEST'
        args['account_response']=wire(**obj)
    if fault in {'channel','duplicate','window'}:
        obj=json.loads(args['page_response'])
        if fault=='channel':obj['messages'][0]['channel']='COTHER'
        elif fault=='duplicate':obj['messages']*=2
        else:obj['messages'][0]['ts']='250.000000'
        args['page_response']=wire(**obj)
    if fault=='personal':args['boundary']=B.PERSONAL
    if fault=='restricted':args['classification']=C.HIGHLY_RESTRICTED
    if fault=='denied':args['requestor_boundaries']=frozenset({B.PERSONAL})
    if fault=='naive':args['captured_at']=NOW.replace(tzinfo=None)
    with pytest.raises(m.NativeSourcePreparationError) as exc:m.prepare_slack_sources(**args)
    assert exc.value.__context__ is None and 'Invented private body' not in str(exc.value)


def test_slack_thread_replies_keep_original_parent_selection():
    args=slack_inputs();args['selection']=RepliesSelection(**args['selection'].model_dump(),parent_ts='150.123456')
    value=json.loads(args['page_response']);value['messages'].append({'ts':'180.123456','thread_ts':'150.123456','text':'Invented reply'})
    args['page_response']=wire(**value)
    result=m.prepare_slack_sources(**args)
    assert len(result.artifacts)==4 and 'conversations.replies' in result.declared_selection_bytes.decode()
