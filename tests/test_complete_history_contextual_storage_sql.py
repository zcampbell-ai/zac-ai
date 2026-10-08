"""Root-only genuine complete-history capture/reopen; every text is invented.

Actual canonical original/companion reader, Source/elevation/lineage constraints,
physical psycopg admission and packet storage execute unchanged. The route and
answer are invented declarations; no tokenizer/model/owner approval/recovery.
"""
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select, text

from tests.conftest import (
    _reset_test_schema,
    assert_connected_to_safe_test_database,
    assert_safe_test_database_url,
)
from tests.test_claude_original_capture_sql import AT
from tests.test_history_context_metadata import base
from tests.test_history_contextual_codec import review_for
from tests.test_local_contextual_runtime import route
from zacai.claude_history_index import index_claude_member_history
from zacai.claude_original_capture import (
    observe_claude_artifact_root,
    prepare_claude_custody_proposal,
    record_claude_original,
)
from zacai.claude_original_read import load_claude_original
from zacai.history_manifest import HistorySelection
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import contextual_storage as storage
from zacai.intelligence.contracts import ContextItem, EvidenceReference, IntelligenceTask
from zacai.intelligence.history_context_metadata import (
    HistoryMessageSpan,
    prepare_claude_history_context_preview,
)
from zacai.intelligence.history_contextual_codec import (
    decode_history_contextual_packet,
    encode_history_contextual_packet,
    encode_history_contextual_request,
    prepare_history_contextual_request,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification, record_source

SCOPES = {'authorized_boundaries': frozenset({B.PERSONAL}),
          'allowed_classifications': frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})}


@pytest.fixture
def clean_factory(test_session_factory):
    engine = test_session_factory.kw['bind']
    url = engine.url.render_as_string(hide_password=False)
    assert_safe_test_database_url(url)
    with engine.connect() as connection:
        assert_connected_to_safe_test_database(connection.scalar(text('SELECT current_database()')))
    # Only the dedicated zacai_test schema is reset under conftest's session lock.
    _reset_test_schema(url, already_stamped=True)
    return test_session_factory


def original_bytes():
    cid, user_id, assistant_id, correction_id = uuid4(), uuid4(), uuid4(), uuid4()
    messages = []
    for mid, parent, sender, literal, date in (
        (user_id, '00000000-0000-0000-0000-000000000000', 'human',
         'Use short source-backed paragraphs.', '2026-10-01T12:00:00Z'),
        (assistant_id, str(user_id), 'assistant',
         'Consider a generic essay instead.', '2026-10-02T12:00:00Z'),
        (correction_id, str(assistant_id), 'human',
         'Correction: use three short paragraphs.', '2026-10-03T12:00:00Z'),
    ):
        messages.append({'uuid': str(mid), 'parent_message_uuid': parent, 'sender': sender,
                             'text': literal, 'content': [], 'created_at': date, 'updated_at': date})
    return json.dumps([{'uuid': str(cid), 'account': {'uuid': 'invented-reported-account'},
        'created_at': '2026-10-01T12:00:00Z', 'updated_at': '2026-10-03T12:00:00Z',
        'chat_messages': messages}], ensure_ascii=False).encode()


def proposal(raw, custody, captured_at):
    index = index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))
    selections = tuple(HistorySelection(original_id=str(m.original_id),
        start=m.record.start, end=m.record.end,
        content_hash=content_hash_of(raw[m.record.start:m.record.end]),
        reported_at=m.reported_created_at, role=m.historical_role)
        for m in index.conversations[0].messages)
    encoded = prepare_claude_custody_proposal(custody_id=custody, original_raw=raw,
        account_ref='invented-reported-account', acquired_at=AT, exported_at=AT,
        captured_at=captured_at, boundary=B.PERSONAL, classification=C.CONFIDENTIAL,
        selections=selections)
    return encoded, index


def capture_original(factory, artifacts, raw, proposed):
    with factory() as session, session.begin():
        assert_connected_to_safe_test_database(session.scalar(text('SELECT current_database()')))
        saved = record_claude_original(session, artifacts=artifacts,
            expected_root=observe_claude_artifact_root(artifacts), original_raw=raw,
            proposal_raw=proposed, approved_proposal_hash=content_hash_of(proposed),
            requestor_boundaries=SCOPES['authorized_boundaries'],
            allowed_classifications=SCOPES['allowed_classifications'])
        assert saved.processing_authorized is saved.recovery_verified is False
    return saved


@pytest.fixture
def complete_case(clean_factory, tmp_path):
    factory = clean_factory
    artifacts = LocalFilesystemArtifactStore(tmp_path/'canonical')
    custody = uuid4()
    raw_original = original_bytes()
    proposed, index = proposal(raw_original, custody, AT)
    saved = capture_original(factory, artifacts, raw_original, proposed)
    initial = base()
    items = []
    with factory() as session, session.begin():
        assert_connected_to_safe_test_database(session.scalar(text('SELECT current_database()')))
        for old in initial.task.context:
            raw = old.untrusted_text.encode()
            digest = content_hash_of(raw)
            location = artifacts.put(B.PERSONAL, digest, raw)
            source, _ = record_source(session, trust_boundary=B.PERSONAL,
                data_classification=C.CONFIDENTIAL, system=SourceSystem.MANUAL,
                external_ref=f'complete-history-invented-base/{uuid4()}',
                content_hash=digest, content_location=location, captured_at=AT)
            items.append(ContextItem(reference=EvidenceReference(source_id=source.id,
                content_hash=digest, trust_boundary=B.PERSONAL,
                effective_classification=C.CONFIDENTIAL), untrusted_text=old.untrusted_text))
    task = IntelligenceTask.model_validate({**initial.task.model_dump(),
        'context': tuple(items), 'event': {**initial.task.event.model_dump(),
        'provenance': tuple(x.reference for x in items)}})
    original = ReviewContext(task, items[0].reference.source_id,
                            frozenset(x.reference.source_id for x in items[1:]))
    root = observe_claude_artifact_root(artifacts)
    with factory() as session, session.begin():
        assert_connected_to_safe_test_database(session.scalar(text('SELECT current_database()')))
        read = load_claude_original(session, artifacts=artifacts, expected_root=root,
            original_reference=saved.original_reference, companion_reference=saved.companion_reference,
            expected_account_ref='invented-reported-account', expected_exported_at=AT,
            requestor_boundaries=SCOPES['authorized_boundaries'],
            allowed_classifications=SCOPES['allowed_classifications'])
    spans = tuple(HistoryMessageSpan(message_id=m.original_id, character_start=0,
        character_end=len(json.loads(raw_original[m.text_json_value.start:m.text_json_value.end]))) for m in index.conversations[0].messages)
    selected_route = route().model_copy(update={'max_input_characters': 32000})
    preview = prepare_claude_history_context_preview(original, read, selections=spans,
        observed_at=AT + timedelta(seconds=1), route=selected_route)
    request = prepare_history_contextual_request(preview, original_context=original, route=selected_route)
    payload = encode_history_contextual_packet(review_for(request), request,
        builder_id=uuid4(), created_at=AT + timedelta(seconds=2))
    args = dict(artifacts=artifacts, expected_root=root,
        expected_account_ref='invented-reported-account', expected_exported_at=AT, **SCOPES)
    with factory() as session, session.begin():
        assert_connected_to_safe_test_database(session.scalar(text('SELECT current_database()')))
        sid = storage.capture_history_contextual_packet(session, payload=payload, **args)
    return factory, artifacts, payload, request, sid, args, saved, raw_original, custody


def reopen(case):
    factory, _, payload, request, sid, args, *_ = case
    with factory() as session, session.begin():
        assert_connected_to_safe_test_database(session.scalar(text('SELECT current_database()')))
        return storage.load_history_contextual_packet(session,
            expected_packet_reference=EvidenceReference(source_id=sid, content_hash=content_hash_of(payload),
                trust_boundary=B.PERSONAL, effective_classification=decode_history_contextual_packet(payload).review.data_classification),
            expected_request=request, **args)


def test_actual_complete_user_history_commit_reopen_exact_packet(complete_case):
    case = complete_case
    packet = reopen(case)
    assert packet == decode_history_contextual_packet(case[2])
    assert encode_history_contextual_request(packet.request()) == packet.request_json.encode()
    entries = packet.request().sidecar.entries
    assert [e.historical_role for e in entries] == ['USER', 'ASSISTANT', 'USER']
    assert [e.reported_created_at.day for e in entries] == [1, 2, 3]
    assert all(e.original_binding_reference == case[6].original_reference for e in entries)
    assert all(e.companion_binding_reference == case[6].companion_reference for e in entries)
    assert packet.processing_authorized is packet.recovery_verified is packet.current_facts_verified is False
    with case[0]() as session:
        source = session.get(Source, case[4])
        assert source.system is SourceSystem.MANUAL
        assert source.external_ref == storage._history_external(content_hash_of(case[2]), case[3])
        assert source.captured_at == packet.created_at
        assert source.supersedes_source_id is None
        assert set(session.scalars(select(Source.id))) == {
            case[4], *(r.source_id for r in storage.history_packet_provenance(packet))}


def test_actual_current_elevation_denies_before_any_artifact_read(complete_case, monkeypatch):
    case = complete_case
    ref = case[6].original_reference
    with case[0]() as session, session.begin():
        elevated = elevate_source_classification(session, source_id=ref.source_id,
            trust_boundary=B.PERSONAL, new_classification=C.HIGHLY_RESTRICTED,
            reason='Invented current elevation', elevated_by='invented-root-test')
        assert elevated.source_id == ref.source_id
    reads = []

    def forbidden(*args, **kwargs):
        reads.append(args)
        pytest.fail('artifact read before failed current Source union')

    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded', forbidden)
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case)
    assert reads == []


def test_actual_original_revision_withholds_packet_before_packet_body(complete_case, monkeypatch):
    case = complete_case
    value = json.loads(case[7])
    value[0]['chat_messages'][0]['text'] = 'Invented subsequently revised user statement.'
    revised = json.dumps(value, ensure_ascii=False).encode()
    proposed, _ = proposal(revised, case[8], AT + timedelta(seconds=1))
    newer = capture_original(case[0], case[1], revised, proposed)
    assert newer.original_reference.source_id != case[6].original_reference.source_id
    with case[0]() as session:
        assert session.get(Source, newer.original_reference.source_id).supersedes_source_id == case[6].original_reference.source_id
    actual = LocalFilesystemArtifactStore.get_bounded
    packet_reads = []
    original_reads = []
    packet_location = case[1].location_for(content_hash_of(case[2]))

    def observed(store, boundary, location, **kwargs):
        if location == packet_location:
            packet_reads.append(location)
        else:
            original_reads.append(location)
        return actual(store, boundary, location, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded', observed)
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case)
    assert len(original_reads) == 2 and packet_reads == []



def test_actual_stronger_review_packet_binding_roundtrip(complete_case):
    case = complete_case
    review = review_for(case[3]).model_copy(update={'data_classification': C.HIGHLY_RESTRICTED})
    packet_before = decode_history_contextual_packet(case[2])
    raw = encode_history_contextual_packet(review, case[3], builder_id=packet_before.builder_id,
                                          created_at=packet_before.created_at)
    assert case[3].task.event.data_classification is C.CONFIDENTIAL
    with case[0]() as session, session.begin():
        sid = storage.capture_history_contextual_packet(session, payload=raw, **case[5])
    updated = (*case[:2], raw, case[3], sid, *case[5:])
    packet = reopen(updated)
    assert packet == decode_history_contextual_packet(raw)
    assert packet.review.data_classification is C.HIGHLY_RESTRICTED
    with case[0]() as session:
        assert session.get(Source, sid).data_classification is C.HIGHLY_RESTRICTED


def test_actual_post_savepoint_hold_caller_outer_rollback(complete_case):
    case = complete_case
    before_packet = decode_history_contextual_packet(case[2])
    # A distinct valid builder produces a distinct packet; the original remains.
    payload = encode_history_contextual_packet(review_for(case[3]), case[3],
        builder_id=uuid4(), created_at=before_packet.created_at)
    assert payload != case[2]
    milestones = []
    with case[0]() as session:
        session.begin()
        assert_connected_to_safe_test_database(session.scalar(text('SELECT current_database()')))
        before_ids = set(session.scalars(select(Source.id)))

        def after_release(session, transaction):
            if transaction.nested:
                milestones.append('savepoint-exited')
                source = session.get(Source, case[6].original_reference.source_id)
                source.excerpt = 'Invented unflushed callback mutation'

        event.listen(session, 'after_transaction_end', after_release)
        with pytest.raises(ValueError, match='complete history packet capture'):
            storage.capture_history_contextual_packet(session, payload=payload, **case[5])
        assert milestones == ['savepoint-exited']
        assert session.in_transaction() and session.get_transaction().is_active
        with session.no_autoflush:
            assert len(set(session.scalars(select(Source.id))) - before_ids) == 1
        event.remove(session, 'after_transaction_end', after_release)
        session.rollback()  # the product neither commits nor repairs the caller
    with case[0]() as session:
        assert set(session.scalars(select(Source.id))) == before_ids
