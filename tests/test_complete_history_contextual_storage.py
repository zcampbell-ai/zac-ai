"""Invented complete codec/files + SQLite rows; physical/reader SQL are simulated.

The bridge executes the actual original reader/indexer/profile on separately
simulated committed custody rows. This is not genuine PostgreSQL admission,
owner permission, backup or processing proof.
"""
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select, text

from tests.test_claude_original_capture import AT
from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_fragment_contextual_storage import db as db  # noqa: PLC0414
from tests.test_history_contextual_codec import prepared as prepared  # noqa: PLC0414
from tests.test_history_contextual_codec import review_for
from zacai import backup_artifacts
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import contextual_storage as m
from zacai.intelligence import fragment_review_retention as r
from zacai.intelligence.contracts import EvidenceReference
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
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


@pytest.fixture
def case(db, host, prepared, monkeypatch, request):
    factory, _ = db
    reader_session, store = host
    use_confidential = getattr(request, 'param', None) == 'CONFIDENTIAL'
    original, read, _, request = prepared
    if use_confidential:
        from tests.test_claude_original_read import load
        from tests.test_claude_reader_current_labels import confidential
        saved = confidential((reader_session, store, None, None))
        read = load(saved, allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))
        import json
        from uuid import UUID
        selection = HistoryMessageSpan(message_id=UUID(read.proposal.selections[0].original_id),
            character_start=0, character_end=len(json.loads(read.original_raw)[0]['chat_messages'][0]['text']))
        preview = prepare_claude_history_context_preview(original, read, selections=(selection,),
            observed_at=AT, route=request.route)
        request = prepare_history_contextual_request(preview, original_context=original, route=request.route)
    raw = encode_history_contextual_packet(review_for(request), request,
        builder_id=uuid4(), created_at=AT + timedelta(seconds=1))
    packet = decode_history_contextual_packet(raw)
    refs = m.history_packet_provenance(packet)
    custody_rows = {row['id']: row for row in reader_session.rows}
    with factory() as session:
        for ref in refs:
            row = custody_rows.get(ref.source_id, {})
            session.add(Source(id=ref.source_id, trust_boundary=ref.trust_boundary,
                data_classification=row.get('data_classification', ref.effective_classification),
                system=SourceSystem.MANUAL,
                external_ref=row.get('external_ref', f'invented-input/{ref.source_id}'),
                content_hash=ref.content_hash,
                content_location=row.get('content_location', f'invented-opaque/{ref.source_id}'),
                captured_at=AT))
        session.commit()
    connection, driver = object(), object()
    # Deliberate pure-only physical adapter; product guard remains actual psycopg.
    monkeypatch.setattr(r, '_physical', lambda session:
        (*m._fragment_transaction(session), connection, driver))
    monkeypatch.setattr(backup_artifacts, '_assert_personal_custody_append_capacity',
        lambda session, count: None)
    actual_reader = m.load_claude_original
    calls = []

    def bridge(session, **kwargs):
        calls.append(kwargs)
        return actual_reader(reader_session, **kwargs)

    monkeypatch.setattr(m, 'load_claude_original', bridge)
    args = {'artifacts': store, 'expected_root': observe_claude_artifact_root(store),
        'expected_account_ref': read.proposal.account_ref,
        'expected_exported_at': read.proposal.exported_at,
        'authorized_boundaries': frozenset({B.PERSONAL}),
        'allowed_classifications': frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})}
    return factory, store, raw, packet, args, calls, read, original


def capture(case):
    factory, _, raw, _, args, *_ = case
    with factory() as session, session.begin():
        return m.capture_history_contextual_packet(session, payload=raw, **args)


def reopen(case, sid, **changes):
    factory, _, raw, packet, args, *_ = case
    values = dict(expected_packet_reference=EvidenceReference(source_id=sid,
        content_hash=content_hash_of(raw), trust_boundary=packet.request().task.event.trust_boundary,
        effective_classification=packet.review.data_classification),
        expected_request=packet.request(), **args)
    values.update(changes)
    with factory() as session, session.begin():
        return m.load_history_contextual_packet(session, **values)


def test_actual_complete_codec_multimessage_capture_commit_reopen(case):
    sid = capture(case)
    packet = reopen(case, sid)
    assert packet == case[3]
    assert encode_history_contextual_request(packet.request()) == packet.request_json.encode()
    assert [e.historical_role for e in packet.request().sidecar.entries] == ['USER', 'ASSISTANT', 'USER']
    assert packet.processing_authorized is packet.recovery_verified is packet.current_facts_verified is False
    assert len(case[5]) == 2  # actual bounded original reader bridge before each operation
    with case[0]() as session:
        own = session.get(Source, sid)
        assert own.external_ref == m._history_external(content_hash_of(case[2]), packet.request())
        assert own.system is SourceSystem.MANUAL and own.supersedes_source_id is None
        assert set(session.scalars(select(Source.id))) == {sid, *(r.source_id for r in m.history_packet_provenance(packet))}


@pytest.mark.parametrize('fault', ['hash', 'missing', 'boundary', 'elevation', 'raw_downward'])
def test_current_union_denial_precedes_any_original_or_packet_read(case, monkeypatch, fault):
    sid = capture(case)
    ref = case[6].original_reference
    with case[0]() as session:
        row = session.get(Source, ref.source_id)
        if fault == 'hash':
            row.content_hash = 'f' * 64
        elif fault == 'missing':
            session.delete(row)
        elif fault == 'boundary':
            row.trust_boundary = B.BRAINSTORM
        elif fault == 'raw_downward':
            # Base synthetic task Source is CONFIDENTIAL: corrupt stronger raw
            # with supplied weaker current ref must not be admitted.
            base_ref = next(x for x in m.history_packet_provenance(case[3])
                            if x.effective_classification is C.CONFIDENTIAL)
            session.get(Source, base_ref.source_id).data_classification = C.HIGHLY_RESTRICTED
        else:
            base_ref = next(x for x in m.history_packet_provenance(case[3])
                            if x.effective_classification is C.CONFIDENTIAL)
            session.add(SourceClassificationElevation(id=uuid4(), source_id=base_ref.source_id,
                trust_boundary=B.PERSONAL, previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED, reason='Invented elevation',
                elevated_by='invented-test', elevated_at=AT))
        session.commit()
    calls = len(case[5])
    reads = []
    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded',
        lambda *a, **kw: reads.append(kw) or pytest.fail('body read before union denial'))
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid)
    assert len(case[5]) == calls and reads == []


@pytest.mark.parametrize('fault', ['account', 'export', 'root'])
def test_actual_reader_host_binding_refusal_precedes_packet_read(case, fault):
    sid = capture(case)
    changes = {'expected_account_ref': 'different-invented-account'} if fault == 'account' else (
        {'expected_exported_at': AT + timedelta(seconds=1)} if fault == 'export' else
        {'expected_root': replace(case[4]['expected_root'], inode=0)})
    with pytest.raises(ValueError, match='complete history packet load') as error:
        reopen(case, sid, **changes)
    assert error.value.__cause__ is error.value.__context__ is None
    assert len(case[5]) == 2


def test_public_constructed_valid_profile_cannot_replace_actual_custody_observation(case):
    read = replace(case[6], original_tip_id=uuid4(), superseded_at_read=True)
    old = case[3].request()
    selections = tuple(HistoryMessageSpan(message_id=e.message_id,
        character_start=e.character_start, character_end=e.character_end)
        for e in old.sidecar.entries)
    preview = prepare_claude_history_context_preview(case[7], read, selections=selections,
        observed_at=AT, route=old.route)
    request = prepare_history_contextual_request(preview, original_context=case[7], route=old.route)
    raw = encode_history_contextual_packet(review_for(request), request,
        builder_id=case[3].builder_id, created_at=case[3].created_at)
    assert decode_history_contextual_packet(raw).request() == request
    assert request != old and request.task.event.provenance == old.task.event.provenance
    with case[0]() as session, session.begin(), pytest.raises(ValueError, match='complete history packet capture'):
        m.capture_history_contextual_packet(session, payload=raw, **case[4])
    assert len(case[5]) == 1
    with case[0]() as session:
        assert len(tuple(session.scalars(select(Source.id)))) == len(m.history_packet_provenance(case[3]))


def test_put_transaction_mutation_holds_before_packet_readback(case, monkeypatch):
    actual_put = LocalFilesystemArtifactStore.put
    actual_physical = r._physical
    put = []
    reads = []

    def changed_put(*args):
        location = actual_put(*args)
        put.append(location)
        monkeypatch.setattr(r, '_physical', lambda session:
            (*m._fragment_transaction(session), object(), object()))
        return location

    actual_get = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        if put:
            reads.append(args[2])
        return actual_get(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, 'put', changed_put)
    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded', get)
    with pytest.raises(ValueError, match='complete history packet capture'):
        capture(case)
    assert len(put) == 1 and reads == []
    monkeypatch.setattr(r, '_physical', actual_physical)
    with case[0]() as session:
        assert len(tuple(session.scalars(select(Source.id)))) == len(m.history_packet_provenance(case[3]))


@pytest.mark.parametrize('fault', ['captured_at', 'system', 'namespace', 'sibling'])
def test_own_packet_canonical_metadata_before_original_read(case, fault):
    sid = capture(case)
    with case[0]() as session:
        row = session.get(Source, sid)
        if fault == 'captured_at':
            row.captured_at += timedelta(seconds=1)
        elif fault == 'system':
            row.system = SourceSystem.EMAIL
        elif fault == 'namespace':
            row.external_ref = 'contextual-review-packet/not-this-family'
        else:
            session.add(Source(id=uuid4(), system=SourceSystem.MANUAL,
                trust_boundary=row.trust_boundary, data_classification=row.data_classification,
                content_hash='f' * 64, content_location='invented-sibling',
                external_ref=row.external_ref, captured_at=row.captured_at,
                supersedes_source_id=row.id))
        session.commit()
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid)
    # Timestamp is compared after exact packet decode; other metadata fails before reader.
    assert len(case[5]) == (2 if fault == 'captured_at' else 1)


def test_packet_body_callback_current_source_mutation_holds(case, monkeypatch):
    sid = capture(case)
    actual_get = LocalFilesystemArtifactStore.get_bounded
    hits = []
    digest = content_hash_of(case[2])

    def get(store, boundary, location, **kwargs):
        raw = actual_get(store, boundary, location, **kwargs)
        if content_hash_of(raw) == digest:
            with case[0]() as session:
                row = session.get(Source, sid)
                row.captured_at += timedelta(seconds=1)
                session.commit()
            hits.append(location)
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded', get)
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid)
    assert len(hits) == 1


@pytest.mark.parametrize('fault', ['original_date', 'companion_date', 'companion_identity'])
def test_actual_original_reader_pair_metadata_hold(case, host, fault):
    sid = capture(case)
    session, _ = host
    row = session.rows[0 if fault == 'original_date' else 1]
    if fault == 'companion_identity':
        row['external_ref'] = 'claude-original-companion/not-exact-custody'
    else:
        row['captured_at'] += timedelta(seconds=1)
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid)
    assert len(case[5]) == 2


def test_packet_byte_corruption_held_after_actual_read(case, monkeypatch):
    sid = capture(case)
    actual_get = LocalFilesystemArtifactStore.get_bounded
    hits = []
    decoded = []
    actual_decode = m.decode_history_contextual_packet

    def decode(raw):
        decoded.append(raw)
        return actual_decode(raw)

    def get(*args, **kwargs):
        raw = actual_get(*args, **kwargs)
        if content_hash_of(raw) == content_hash_of(case[2]):
            hits.append(True)
            return raw + b' '
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded', get)
    monkeypatch.setattr(m, 'decode_history_contextual_packet', decode)
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid)
    assert hits == [True]
    assert decoded == []  # corrupted bytes never reach the full packet parser


def test_physical_hold_precedes_any_original_or_packet_io(case, monkeypatch):
    calls = len(case[5])
    monkeypatch.setattr(r, '_physical', lambda session:
        (_ for _ in ()).throw(ValueError('simulated AUTOCOMMIT or dead driver')))
    with pytest.raises(ValueError, match='complete history packet capture'):
        capture(case)
    assert len(case[5]) == calls


def test_actual_filesystem_packet_oversize_holds_without_unbounded_get(case, monkeypatch):
    sid = capture(case)
    store = case[1]
    path = store.root / B.PERSONAL.value / store.location_for(content_hash_of(case[2]))
    path.write_bytes(b'x' * (m.MAX_PACKET_BYTES + 1))
    assert path.stat().st_size == m.MAX_PACKET_BYTES + 1
    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get',
        lambda *a, **kw: pytest.fail('unbounded fallback'))
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid)


@pytest.mark.parametrize('case', ['CONFIDENTIAL'], indirect=True)
def test_valid_stronger_review_packet_binding_roundtrip(case):
    request = case[3].request()
    assert request.task.event.data_classification is C.CONFIDENTIAL
    stronger = review_for(request).model_copy(update={'data_classification': C.HIGHLY_RESTRICTED})
    raw = encode_history_contextual_packet(stronger, request, builder_id=case[3].builder_id,
                                          created_at=case[3].created_at)
    packet = decode_history_contextual_packet(raw)
    changed = (*case[:2], raw, packet, *case[4:])
    sid = capture(changed)
    assert reopen(changed, sid) == packet
    with case[0]() as session:
        assert session.get(Source, sid).data_classification is C.HIGHLY_RESTRICTED


@pytest.mark.parametrize('case', ['CONFIDENTIAL'], indirect=True)
@pytest.mark.parametrize('fault', ['weak', 'boundary', 'digest', 'identity', 'current_elevation'])
def test_bad_retained_packet_binding_holds_before_artifact_read(case, monkeypatch, fault):
    sid = capture(case)
    reference = EvidenceReference(source_id=sid, content_hash=content_hash_of(case[2]),
        trust_boundary=B.PERSONAL, effective_classification=case[3].review.data_classification)
    if fault == 'weak':
        reference = reference.model_copy(update={'effective_classification': C.INTERNAL})
    elif fault == 'boundary':
        reference = reference.model_copy(update={'trust_boundary': B.BRAINSTORM})
    elif fault == 'digest':
        reference = reference.model_copy(update={'content_hash': 'f' * 64})
    elif fault == 'identity':
        reference = reference.model_copy(update={'source_id': case[6].original_reference.source_id})
    else:
        # A current binding cannot silently reinterpret an unchanged lower-label packet.
        reference = reference.model_copy(update={'effective_classification': C.HIGHLY_RESTRICTED})
        with case[0]() as session:
            session.add(SourceClassificationElevation(id=uuid4(), source_id=sid,
                trust_boundary=B.PERSONAL, previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED, reason='Invented current packet elevation',
                elevated_by='invented-test', elevated_at=AT))
            session.commit()
    reads = []
    monkeypatch.setattr(LocalFilesystemArtifactStore, 'get_bounded',
        lambda *a, **kw: reads.append(kw) or pytest.fail('body before binding refusal'))
    with pytest.raises(ValueError, match='complete history packet load'):
        reopen(case, sid, expected_packet_reference=reference)
    assert reads == []


def test_post_savepoint_hold_remains_caller_owned_outer_rollback(case):
    factory, _, raw, _, args, *_ = case
    milestones = []
    with factory() as session:
        session.begin()
        # SQLite driver needs an explicit physical BEGIN for genuine outer rollback
        # of a released savepoint. PostgreSQL admission is still simulated here.
        session.execute(text('BEGIN'))
        before = tuple(session.scalars(select(Source.id)))

        def after_release(session, transaction):
            if transaction.nested:
                milestones.append('savepoint-exited')
                row = session.get(Source, case[6].original_reference.source_id)
                row.excerpt = 'Invented unrelated dirty callback'

        event.listen(session, 'after_transaction_end', after_release)
        with pytest.raises(ValueError, match='complete history packet capture'):
            m.capture_history_contextual_packet(session, payload=raw, **args)
        assert milestones == ['savepoint-exited']
        assert session.get_transaction() is not None  # no auto-commit/outer repair
        event.remove(session, 'after_transaction_end', after_release)
        session.rollback()  # caller-required transaction disposition
    with factory() as session:
        assert set(session.scalars(select(Source.id))) == set(before)
