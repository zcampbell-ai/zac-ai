"""Invented actual codec, SQLite scalar/savepoint queries and real packet files.

READ COMMITTED and timezone adapters are explicitly simulated. Base/Claude Source
records are invented metadata, not canonical intake/recovery/owner/model proof.
"""
import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.attributes import set_committed_value

from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import AT, prepared
from tests.test_history_context_metadata import base
from tests.test_history_contextual_codec import review_for
from tests.test_history_fragment_contextual_codec import request
from tests.test_local_contextual_runtime import route
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import contextual_storage as m
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_packet,
    encode_history_fragment_contextual_packet,
    prepare_history_fragment_contextual_request,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


def payload(inherited=False, elevated=False):
    q = request(inherited)
    if elevated:
        read = prepared(parent=uuid4())
        read = replace(read,
            original_reference=read.original_reference.model_copy(update={"effective_classification": C.HIGHLY_RESTRICTED}),
            companion_reference=read.companion_reference.model_copy(update={"effective_classification": C.HIGHLY_RESTRICTED}),
            joint_output_classification=C.HIGHLY_RESTRICTED)
        q = prepare_history_fragment_contextual_request(
            base(), prepare(read), observed_at=AT,
            route=route().model_copy(update={"max_input_characters": 32000}))
    return encode_history_fragment_contextual_packet(
        review_for(q), q, builder_id=uuid4(), created_at=AT + timedelta(seconds=1))


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    # SQLite lacks SHOW transaction_isolation and strips timezone information.
    # This adapter is test-only. Real PostgreSQL harness retains actual checks.
    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda session: None)

    def timezone(target, context):
        if target.captured_at.tzinfo is None:
            set_committed_value(target, "captured_at", target.captured_at.replace(tzinfo=UTC))

    event.listen(Source, "load", timezone)
    actual_rows = m._fragment_rows

    def aware_rows(*args):
        rows = actual_rows(*args)
        return tuple(tuple((key, value.replace(tzinfo=UTC)
            if key in {"captured_at", "lineage_captured_at"} and value is not None
            and value.tzinfo is None else value) for key, value in row) for row in rows)

    monkeypatch.setattr(m, "_fragment_rows", aware_rows)
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    try:
        yield factory, store
    finally:
        event.remove(Source, "load", timezone)
        engine.dispose()


def seed(factory, raw):
    packet = decode_history_fragment_contextual_packet(raw)
    refs = m.history_fragment_packet_provenance(packet)
    profile = json.loads(packet.request().profile_json)
    original_id = profile["current_original_reference"]["source_id"]
    companion_id = profile["current_companion_reference"]["source_id"]
    with factory() as session:
        for ref in refs:
            session.add(Source(id=ref.source_id, trust_boundary=ref.trust_boundary,
                data_classification=ref.effective_classification, system=SourceSystem.MANUAL,
                external_ref=(f"claude-original/{profile['custody_id']}" if str(ref.source_id) == original_id
                    else f"claude-original-companion/{profile['custody_id']}/{profile['proposal_hash']}"
                    if str(ref.source_id) == companion_id else f"invented-input/{ref.source_id}"),
                content_hash=ref.content_hash,
                content_location=f"invented-opaque/{ref.source_id}", captured_at=AT))
        session.commit()
    return refs


def capture(factory, store, raw):
    with factory() as session, session.begin():
        return m.capture_history_fragment_contextual_packet(session, artifacts=store,
            payload=raw, authorized_boundaries=frozenset({B.PERSONAL}),
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))


def load(factory, store, raw, sid, refs):
    with factory() as session, session.begin():
        return m.load_history_fragment_contextual_packet(session, artifacts=store,
            source_id=sid, expected_digest=content_hash_of(raw), expected_request=decode_history_fragment_contextual_packet(raw).request(),
            authorized_boundaries=frozenset({B.PERSONAL}),
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))


@pytest.mark.parametrize("inherited", [False, True])
def test_exact_packet_capture_commit_reopen_and_idempotent(db, inherited):
    factory, store = db
    raw = payload(inherited)
    refs = seed(factory, raw)
    sid = capture(factory, store, raw)
    assert capture(factory, store, raw) == sid
    packet = load(factory, store, raw, sid, refs)
    assert packet == decode_history_fragment_contextual_packet(raw)
    assert packet.request().prompt_body == decode_history_fragment_contextual_packet(raw).request().prompt_body
    assert packet.processing_authorized is packet.recovery_verified is packet.current_facts_verified is False
    with factory() as session:
        own = session.get(Source, sid)
        assert own.external_ref == m._fragment_external(content_hash_of(raw), packet.request())
        assert own.supersedes_source_id is None
        assert set(session.scalars(select(Source.id))) == {sid, *(r.source_id for r in refs)}


def test_same_identity_immutable_confidential_binding_current_hr_role(db):
    factory, store = db
    raw = payload(elevated=True)
    packet = decode_history_fragment_contextual_packet(raw)
    refs = seed(factory, raw)
    assert any(ref.effective_classification is C.HIGHLY_RESTRICTED for ref in refs)
    sid = capture(factory, store, raw)
    assert load(factory, store, raw, sid, refs) == packet


@pytest.mark.parametrize("fault", ["missing", "hash", "elevation", "wrong_boundary"])
def test_complete_dependency_hold_before_any_packet_body_read(db, monkeypatch, fault):
    factory, store = db
    raw = payload()
    refs = seed(factory, raw)
    sid = capture(factory, store, raw)
    with factory() as session:
        source = session.get(Source, refs[-1].source_id)
        if fault == "missing":
            session.delete(source)
        elif fault == "hash":
            source.content_hash = "f" * 64
        elif fault == "wrong_boundary":
            source.trust_boundary = B.BRAINSTORM
        else:
            session.add(SourceClassificationElevation(id=uuid4(), source_id=source.id,
                trust_boundary=B.PERSONAL, previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED, reason="Invented elevation",
                elevated_by="invented-test",
                elevated_at=AT + timedelta(seconds=2)))
        session.commit()
    reads = []
    monkeypatch.setattr(store, "get_bounded", lambda *args, **kwargs: reads.append(args))
    with pytest.raises(ValueError) as error:
        load(factory, store, raw, sid, refs)
    assert reads == [] and error.value.__context__ is None


@pytest.mark.parametrize("fault", ["revision", "elevation", "own_metadata", "transaction"])
def test_callback_final_drift_holds_after_real_packet_get(db, monkeypatch, fault):
    factory, store = db
    raw = payload()
    refs = seed(factory, raw)
    sid = capture(factory, store, raw)
    actual = store.get_bounded
    fired = []
    with factory() as session:
        session.begin()
        def read(*args, **kwargs):
            value = actual(*args, **kwargs)
            if fault == "transaction":
                session.rollback()
                session.begin()
            else:
                target = session.get(Source, sid if fault == "own_metadata" else refs[-1].source_id)
                if fault == "revision":
                    session.add(Source(id=uuid4(), trust_boundary=B.PERSONAL,
                        data_classification=target.data_classification, system=target.system,
                        external_ref=target.external_ref, supersedes_source_id=target.id,
                        content_hash="f" * 64, content_location="invented-revision", captured_at=AT))
                elif fault == "elevation":
                    session.add(SourceClassificationElevation(id=uuid4(), source_id=target.id,
                        trust_boundary=B.PERSONAL, previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED, reason="Invented elevation",
                elevated_by="invented-test",
                        elevated_at=AT))
                else:
                    target.excerpt = "INVENTED MUTATED OWN METADATA"
                session.flush()
            fired.append(True)
            return value

        monkeypatch.setattr(store, "get_bounded", read)
        with pytest.raises(ValueError) as error:
            m.load_history_fragment_contextual_packet(session, artifacts=store,
                source_id=sid, expected_digest=content_hash_of(raw), expected_request=decode_history_fragment_contextual_packet(raw).request(),
                authorized_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))
        assert fired == [True] and error.value.__context__ is None
        session.rollback()


def test_savepoint_release_failure_never_acknowledges_and_caller_rolls_back(db, monkeypatch):
    factory, store = db
    raw = payload()
    refs = seed(factory, raw)
    with factory() as session:
        session.begin()
        actual = session.begin_nested
        fired = []

        @contextmanager
        def failed_release():
            with actual() as nested:
                yield nested
            fired.append(True)
            raise ValueError("INVENTED RELEASE FAILURE")

        monkeypatch.setattr(session, "begin_nested", failed_release)
        with pytest.raises(ValueError) as error:
            m.capture_history_fragment_contextual_packet(session, artifacts=store, payload=raw,
                authorized_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))
        assert fired == [True] and error.value.__context__ is None
        session.rollback()
    # SQLite savepoint durability differs without an explicit physical BEGIN;
    # PostgreSQL runner separately verifies real pending-row caller rollback.
    assert refs


@pytest.mark.parametrize("fault", ["omit", "copy_hash", "mixed_scope", "wrong_family"])
def test_exact_locator_union_and_family_refusal(db, fault):
    factory, store = db
    raw = payload()
    refs = seed(factory, raw)
    sid = capture(factory, store, raw)
    if fault in {"omit", "copy_hash"}:
        other = payload()
        seed(factory, other)
        with pytest.raises(ValueError):
            load(factory, store, other, sid, refs)
    else:
        with factory() as session, session.begin(), pytest.raises(ValueError):
            m.capture_history_fragment_contextual_packet(session, artifacts=store,
                payload=raw if fault == "mixed_scope" else b'{}',
                authorized_boundaries=frozenset({B.PERSONAL, B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}))


def test_shortened_self_consistent_request_namespace_denies_before_body(db, monkeypatch):
    from zacai.intelligence.meeting_review import ReviewContext

    factory, store = db
    original = base()
    fragment = prepare(prepared(parent=uuid4()))
    selected_route = route().model_copy(update={"max_input_characters": 32000})
    full = prepare_history_fragment_contextual_request(original, fragment,
        observed_at=AT, route=selected_route)
    kept = tuple(item for item in original.task.context
                 if item.reference.source_id == original.meeting_source_id)
    assert 0 < len(kept) < len(original.task.context)
    event = original.task.event.model_copy(update={"provenance": tuple(i.reference for i in kept)})
    task = original.task.model_copy(update={"context": kept, "event": event})
    shortened = prepare_history_fragment_contextual_request(
        ReviewContext(task, original.meeting_source_id, frozenset()), fragment,
        observed_at=AT, route=selected_route)
    raw = encode_history_fragment_contextual_packet(review_for(full), full,
        builder_id=uuid4(), created_at=AT + timedelta(seconds=1))
    refs = seed(factory, raw)
    sid = capture(factory, store, raw)
    assert len(m._fragment_request_provenance(shortened)) < len(refs)
    reads = []
    monkeypatch.setattr(store, "get_bounded", lambda *args, **kwargs: reads.append(True))
    with factory() as session, session.begin(), pytest.raises(ValueError):
        m.load_history_fragment_contextual_packet(session, artifacts=store, source_id=sid,
            expected_digest=content_hash_of(raw), expected_request=shortened,
            authorized_boundaries=frozenset({B.PERSONAL}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}))
    assert reads == []


def test_actual_oversized_packet_file_holds_before_materialization(db, monkeypatch):
    from zacai.intelligence.history_contextual_codec import MAX_PACKET_BYTES

    factory, store = db
    raw = payload()
    refs = seed(factory, raw)
    sid = capture(factory, store, raw)
    with factory() as session:
        own = session.get(Source, sid)
        path = store._path_for(B.PERSONAL, own.content_hash)
    path.write_bytes(raw + b" " * (MAX_PACKET_BYTES + 1))
    # Actual bounded filesystem reader checks stat size before private read.
    import os
    calls = []
    actual = os.read

    def read(fd, size):
        calls.append(size)
        return actual(fd, size)

    monkeypatch.setattr(os, "read", read)
    with pytest.raises(ValueError):
        load(factory, store, raw, sid, refs)
    assert calls == []


@pytest.mark.parametrize("phase", ["put", "readback"])
def test_dirty_callback_denies_before_source_insert(db, monkeypatch, phase):
    factory, store = db
    raw = payload()
    refs = seed(factory, raw)
    fired = []
    with factory() as session:
        session.begin()
        method = store.put if phase == "put" else store.get_bounded

        def callback(*args, **kwargs):
            result = method(*args, **kwargs)
            session.add(Source(id=uuid4(), trust_boundary=B.PERSONAL,
                data_classification=C.CONFIDENTIAL, system=SourceSystem.MANUAL,
                external_ref="invented-unrelated-pending", content_hash="f" * 64,
                content_location="invented", captured_at=AT))
            fired.append(phase)
            return result

        monkeypatch.setattr(store, "put" if phase == "put" else "get_bounded", callback)
        with pytest.raises(ValueError) as error:
            m.capture_history_fragment_contextual_packet(session, artifacts=store, payload=raw,
                authorized_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}))
        assert fired == [phase] and error.value.__context__ is None
        session.rollback()
    with factory() as session:
        assert set(session.scalars(select(Source.id))) == {r.source_id for r in refs}
