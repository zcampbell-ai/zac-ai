"""Invented provider views only; these are provenance, never account grants."""
import json
from dataclasses import replace

from tests.test_native_source_preparation import gmail_inputs, slack_inputs, wire
from zacai.connectors.slack_wire import RepliesSelection, SlackAccount
from zacai.ingestion import native_source_preparation as m


def test_distinct_mailbox_with_same_host_label_never_revises_same_mail_identity():
    args, _ = gmail_inputs()
    first = m.prepare_gmail_source(**args)
    args['scope'] = replace(args['scope'], expected_email='second@example.test')
    args['profile_response'] = wire(emailAddress='second@example.test',historyId='987',messagesTotal=5,threadsTotal=2)
    second = m.prepare_gmail_source(**args)
    assert {a.external_ref for a in first.artifacts}.isdisjoint(a.external_ref for a in second.artifacts)
    assert json.loads(second.declared_selection_bytes)['observed_mailbox'] == 'second@example.test'


def test_same_slack_message_from_different_authenticated_view_is_not_edit_lineage():
    args = slack_inputs()
    first = m.prepare_slack_sources(**args)
    for account, reply in [(SlackAccount(team_id='TTEST',user_id='UOTHER'), wire(ok=True,team_id='TTEST',user_id='UOTHER')),
                           (SlackAccount(team_id='TTEST',user_id='UTEST',token_kind='bot'), wire(ok=True,team_id='TTEST',user_id='UTEST',bot_id='BTEST'))]:
        selection = args['selection'].model_copy(update={'account': account})
        other = m.prepare_slack_sources(**{**args,'selection':selection,'account_response':reply})
        assert first.artifacts[2].external_ref != other.artifacts[2].external_ref
        assert first.artifacts[2].content_hash == other.artifacts[2].content_hash


def test_history_and_replies_observations_do_not_share_edit_lineage():
    args = slack_inputs()
    first = m.prepare_slack_sources(**args)
    second = m.prepare_slack_sources(**{**args,'selection':RepliesSelection(**args['selection'].model_dump(),parent_ts='150.123456')})
    assert first.artifacts[2].external_ref != second.artifacts[2].external_ref
    assert first.artifacts[2].content_hash == second.artifacts[2].content_hash


def test_artifact_kind_and_exact_original_wire_derivation_are_explicit():
    args, original = gmail_inputs()
    gmail = m.prepare_gmail_source(**args)
    assert [a.artifact_kind for a in gmail.artifacts] == ['provider-profile-json','provider-message-json','decoded-rfc822']
    mime = gmail.artifacts[2]
    assert mime.original_bytes == original
    assert mime.derives_from.external_ref == gmail.artifacts[1].external_ref
    assert mime.derives_from.content_hash == gmail.artifacts[1].content_hash
    slack = m.prepare_slack_sources(**slack_inputs())
    assert [a.artifact_kind for a in slack.artifacts] == ['provider-account-json','provider-page-json','canonical-message-json']
    assert slack.artifacts[2].derives_from.external_ref == slack.artifacts[1].external_ref
    assert slack.artifacts[2].derives_from.content_hash == slack.artifacts[1].content_hash
    assert slack.artifacts[0].derives_from is None and slack.artifacts[1].derives_from is None


def test_wire_serialization_change_preserves_record_bytes_but_changes_exact_origin_pin():
    args = slack_inputs()
    first = m.prepare_slack_sources(**args)
    second = m.prepare_slack_sources(**{**args,'page_response':json.dumps(json.loads(args['page_response']),indent=2).encode()})
    assert first.artifacts[2].content_hash == second.artifacts[2].content_hash
    assert first.artifacts[2].external_ref == second.artifacts[2].external_ref
    assert first.artifacts[2].derives_from.content_hash != second.artifacts[2].derives_from.content_hash
