"""Root-only invented PostgreSQL fragment packet storage.

Canonical custody capture/read, actual artifacts, full Source/elevation queries,
READ COMMITTED and savepoints are real. Base Source bodies are retained invented
inputs; their meeting/related relationship is not authenticated. No owner, claim,
model, recovery, private archive or crypto proof is inferred from this fixture.
"""

import json
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import text

from tests.test_claude_original_capture_sql import AT, artifact_store, prepared
from tests.test_history_context_metadata import base
from tests.test_history_contextual_codec import review_for
from tests.test_local_contextual_runtime import route
from zacai.claude_historical_fragment import prepare_claude_historical_fragment
from zacai.claude_history_index import index_claude_member_history
from zacai.claude_original_capture import (
    observe_claude_artifact_root,
    prepare_claude_custody_proposal,
    record_claude_original,
)
from zacai.claude_original_read import load_claude_original
from zacai.history_manifest import HistorySelection
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import contextual_storage as m
from zacai.intelligence.contracts import ContextItem, EvidenceReference, IntelligenceTask
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_packet,
    prepare_history_fragment_contextual_request,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem
from zacai.state_repository import record_source

# Fixture export only; there is no live artifact callback as proof.
assert artifact_store is not None
SCOPES = {"authorized_boundaries": frozenset({B.PERSONAL}),
          "allowed_classifications": frozenset({C.HIGHLY_RESTRICTED})}


def record(session, store, original, proposal):
    if not session.in_transaction():
        session.begin()
    assert session.scalar(text("SELECT current_database()")) == "zacai_test"
    return record_claude_original(session, artifacts=store,
        expected_root=observe_claude_artifact_root(store), proposal_raw=proposal,
        original_raw=original, approved_proposal_hash=content_hash_of(proposal),
        requestor_boundaries=SCOPES["authorized_boundaries"],
        allowed_classifications=SCOPES["allowed_classifications"])


def genuine_packet(factory, store, *, superseded=False):
    custody, original, _ = prepared()
    data = json.loads(original)
    data[0]["chat_messages"][0]["parent_message_uuid"] = str(uuid4())
    original = json.dumps(data, ensure_ascii=False).encode()
    indexed = index_claude_member_history(original, expected_file_hash=content_hash_of(original))
    row = indexed.conversations[0].messages[0]
    selection = HistorySelection(original_id=str(row.original_id), start=row.record.start,
        end=row.record.end, content_hash=content_hash_of(original[row.record.start:row.record.end]),
        reported_at=row.reported_created_at, role=row.historical_role)
    proposal = prepare_claude_custody_proposal(custody_id=custody, original_raw=original,
        account_ref="invented-reported-account", exported_at=AT, acquired_at=AT,
        captured_at=AT, boundary=B.PERSONAL, classification=C.HIGHLY_RESTRICTED,
        selections=(selection,))
    with factory() as session:
        saved = record(session, store, original, proposal)
        session.commit()
    if superseded:
        _, newer_raw, newer_proposal = prepared(custody, text="Invented subsequent revision",
                                                at=AT + timedelta(seconds=1))
        with factory() as session:
            revised = record(session, store, newer_raw, newer_proposal)
            session.commit()
        assert revised.original_reference.source_id != saved.original_reference.source_id
    original_context = base()
    items = []
    with factory() as session:
        session.begin()
        assert session.scalar(text("SELECT current_database()")) == "zacai_test"
        for item in original_context.task.context:
            body = item.untrusted_text.encode()
            digest = content_hash_of(body)
            location = store.put(B.PERSONAL, digest, body)
            source, _ = record_source(session, trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED, system=SourceSystem.MANUAL,
                external_ref=f"fragment-invented-base/{uuid4()}", content_hash=digest,
                content_location=location, captured_at=AT)
            items.append(ContextItem(reference=EvidenceReference(source_id=source.id,
                content_hash=digest, trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED), untrusted_text=item.untrusted_text))
        session.commit()
    task = IntelligenceTask.model_validate({**original_context.task.model_dump(),
        "context": tuple(items), "event": {**original_context.task.event.model_dump(),
                                             "provenance": tuple(i.reference for i in items),
                                             "data_classification": C.HIGHLY_RESTRICTED}})
    context = ReviewContext(task, items[0].reference.source_id,
                           frozenset(i.reference.source_id for i in items[1:]))
    with factory() as session:
        session.begin()
        read = load_claude_original(session, artifacts=store,
            expected_root=observe_claude_artifact_root(store),
            original_reference=saved.original_reference, companion_reference=saved.companion_reference,
            expected_account_ref="invented-reported-account", expected_exported_at=AT,
            requestor_boundaries=SCOPES["authorized_boundaries"],
            allowed_classifications=SCOPES["allowed_classifications"])
    assert read.superseded_at_read is superseded
    fragment = prepare_claude_historical_fragment(read, message_id=UUID(selection.original_id),
                                                 character_start=0, character_end=8)
    request = prepare_history_fragment_contextual_request(context, fragment,
        observed_at=AT + timedelta(seconds=2),
        route=route().model_copy(update={"max_input_characters": 32000}))
    raw = encode_history_fragment_contextual_packet(review_for(request), request,
        builder_id=uuid4(), created_at=AT + timedelta(seconds=3))
    return raw, request, items[0].reference


def capture(factory, store, raw):
    with factory() as session:
        session.begin()
        assert session.scalar(text("SELECT current_database()")) == "zacai_test"
        sid = m.capture_history_fragment_contextual_packet(session, artifacts=store,
                                                            payload=raw, **SCOPES)
        session.commit()
    return sid


def reopen(session, store, raw, request, sid):
    return m.load_history_fragment_contextual_packet(session, artifacts=store,
        source_id=sid, expected_digest=content_hash_of(raw), expected_request=request, **SCOPES)
