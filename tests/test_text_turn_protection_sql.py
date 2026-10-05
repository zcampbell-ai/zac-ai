"""Real controlled test SQL + age + local clients, never B2 or live state.

The shared zacai_test inventory accumulates other tests' synthetic Sources with
unavailable ephemeral artifacts. Only raw-artifact inventory/coverage functions
are narrowed to this fixture's new Sources, as existing protector tests do.
The actual complete SQL snapshot/restore/journal/selected-row comparisons and
_hashes/_protect_state/admin/operator/reentrant leases are never replaced.
This is selected-fixture recovery evidence, not whole accumulated test-artifact
coverage, production readiness or off-device recovery.
"""

import csv
import io
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text

from tests.test_contextual_storage import stored
from tests.test_fireflies_protection import keypair
from zacai import backup, backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt, age_encrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import decode_contextual_packet
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.text_followup import FOLLOWUP_CAPABILITY, FOLLOWUP_INSTRUCTION
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_turn_capture import (
    CanonicalTextTurnCapture,
    TextTurn,
    TextTurnCheckpointScope,
    TextTurnRecoveryReceipt,
    encode_text_turn,
)
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


def test_actual_turn_protect_recheck_and_immutable_receipt_with_real_sql(
    test_session_factory, tmp_path, monkeypatch
):
    factory, artifacts, packet_bytes, packet_id, _, baseline = stored.__wrapped__(
        test_session_factory, tmp_path
    )
    packet = decode_contextual_packet(packet_bytes)
    assert packet.review.data_classification == C.CONFIDENTIAL

    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(h, loc) for sid, h, loc in found if sid not in baseline]

    def scoped_hashes(conn):
        found = conn.execute(
            select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
        ).all()
        return {h for sid, h in found if sid not in baseline and h is not None}

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", scoped_hashes)
    identity = tmp_path / "throwaway-turn.agekey"
    recipient = keypair(identity)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=artifacts,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    gate = BrainstormTextTurnProtection(protector=protector, clock=lambda: datetime.now(UTC))
    # Produce a real retained packet checkpoint, not fabricated receipt metadata.
    packet_receipt = protector.protect(packet_id, content_hash_of(packet_bytes))
    packet_receipt_digest = content_hash_of(encode_recovery_receipt(packet_receipt))
    captured = datetime.now(UTC)
    request_id = uuid4()
    conversation_id = uuid4()
    packet_reference = EvidenceReference(
        source_id=packet_id,
        content_hash=content_hash_of(packet_bytes),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    parent = TextTurn(
        request_id=uuid4(),
        conversation_id=conversation_id,
        issuer=GOOGLE_ISSUER,
        subject="invented-sql-owner",
        original_text="  Invented first question?\r\nKeep spacing.  ",
        packet_reference=packet_reference,
        packet_receipt_digest=packet_receipt_digest,
        recorded_at=captured,
    )
    parent_bytes = encode_text_turn(parent)
    parent_digest = content_hash_of(parent_bytes)
    parent_location = artifacts.put(B.BRAINSTORM, parent_digest, parent_bytes)
    with factory() as session:
        parent_source, _ = record_source(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.USER_INSTRUCTION,
            external_ref=f"text-turn/{parent.request_id}",
            content_hash=parent_digest,
            content_location=parent_location,
            captured_at=captured,
        )
        parent_id = parent_source.id
        session.commit()
    parent_reference = EvidenceReference(
        source_id=parent_id,
        content_hash=parent_digest,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    owner = OwnerGrant(
        Identity(GOOGLE_ISSUER, "invented-sql-owner"),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    )
    principal = InterfacePrincipal(owner.identity, owner.scopes)
    capture = CanonicalTextTurnCapture(
        factory=factory,
        artifacts=artifacts,
        owner=lambda: owner,
        protection=gate,
        clock=lambda: datetime.now(UTC),
    )
    original_text = " \r\nInvented follow-up about the original evidence?  "
    saved = capture.capture(
        principal=principal,
        request_id=request_id,
        conversation_id=conversation_id,
        original_utf8=original_text.encode(),
        retained_receipt=packet_receipt,
        expected_receipt_digest=packet_receipt_digest,
        parent_references=(parent_reference,),
    )
    envelope = saved.turn
    captured = envelope.recorded_at
    source_id, digest = saved.source_id, saved.turn_digest
    turn_bytes = encode_text_turn(envelope)
    scope = TextTurnCheckpointScope(source_id, digest, captured)
    assert gate._hashes(scope)[parent_id] == parent_digest
    receipt = gate.protect(scope)
    original_receipt = reader.get_object(receipt.receipt_object)
    assert (
        TextTurnRecoveryReceipt.model_validate_json(age_decrypt(original_receipt, identity))
        == receipt
    )
    gate.recheck(scope, receipt)
    assert gate.protect(scope) == receipt
    # The pending direct parent has no individual text-turn receipt. Its exact
    # Source and bytes are recovered as an explicit dependency of this child.
    assert not any(
        f"text-turn-{parent_id}" in str(path) for path in (tmp_path / "objects").rglob("*")
    )
    assembled = CanonicalFollowupAssembler(capture=capture).assemble(
        principal=principal,
        source_id=source_id,
        expected_turn_digest=digest,
        retained_receipt=packet_receipt,
        expected_receipt_digest=packet_receipt_digest,
        recovery_receipt=receipt,
    )
    assert assembled.saved_turn == saved
    assert assembled.direct_parent_turns == (parent,)
    assert assembled.saved_turn.turn.original_text == original_text
    assert assembled.user_original_offset == 3
    assert assembled.parent_original_offsets == ((parent_id, 2),)
    context = assembled.context
    items = {item.reference.source_id: item for item in context.task.context}
    assert items[source_id].untrusted_text == original_text.strip()
    assert items[parent_id].untrusted_text == parent.original_text.strip()
    assert context.parent_references == (parent_reference,)
    assert context.packet_reference == packet_reference
    assert context.task.event.event_type == "packet_followup_requested"
    assert context.task.event.producer == "private_text_host"
    assert context.task.required_capabilities == frozenset({FOLLOWUP_CAPABILITY})
    assert context.task.instruction == FOLLOWUP_INSTRUCTION
    assert context.task.max_latency_ms == 60_000
    assert context.task.max_estimated_cost_usd == 0
    assert context.task.max_output_tokens == 512
    prepared = prepare_followup_request(context)
    evidence = json.loads(prepared.evidence_json)
    assert evidence["current_user_question_projection"]["untrusted_text"] == original_text.strip()
    assert evidence["historical_parent_turns"][0]["untrusted_text"] == parent.original_text.strip()
    assert len(evidence["original_evidence"]) == len(packet.task.context)
    assert not assembled.processing_authorized and not assembled.execution_authorized
    assert not prepared.processing_authorized and not prepared.execution_authorized
    # Real randomized backup repair cannot invalidate exact plaintext recovery.
    writer.put_object(receipt.artifact_object, age_encrypt(turn_bytes, recipient))
    assert (
        content_hash_of(reader.get_object(receipt.artifact_object))
        != receipt.artifact_ciphertext_hash
    )
    gate.recheck(scope, receipt)
    assert reader.get_object(receipt.receipt_object) == original_receipt
    assert protector._lease_guard is None
    with backup._admin_connection() as admin:
        assert (
            admin.scalar(
                text("SELECT count(*) FROM pg_database WHERE datname='zacai_restore_test'")
            )
            == 0
        )
    assert not list(tmp_path.rglob("*.csv"))
    # Actual PostgreSQL COPY time representation, not Python fixture isoformat.
    journal = age_decrypt(reader.get_object(receipt.journal_object), identity)
    run = next(
        row
        for row in csv.DictReader(io.StringIO(journal.decode()))
        if row["id"] == str(receipt.artifact_backup_run_id)
    )
    assert " " in run["started_at"]
    started, finished = (
        datetime.fromisoformat(run["started_at"]),
        datetime.fromisoformat(run["finished_at"]),
    )
    assert captured <= started <= finished <= receipt.verified_at

    # Exercise PostgreSQL's short UTC offset form (+00) independently of the
    # server's local timezone, preserving the same actual run timestamps.
    with factory.kw["bind"].connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        conn.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        raw = backup._raw_connection(conn)
        with (
            raw.cursor() as cur,
            cur.copy(
                "COPY (SELECT started_at, finished_at FROM artifact_backup_run WHERE id = %s) "
                "TO STDOUT WITH (FORMAT csv, HEADER true)",
                (receipt.artifact_backup_run_id,),
            ) as copied,
        ):
            utc_csv = b"".join(bytes(chunk) for chunk in copied)
    utc_row = next(csv.DictReader(io.StringIO(utc_csv.decode())))
    assert utc_row["started_at"].endswith("+00")
    assert datetime.fromisoformat(utc_row["started_at"]) == started
    assert datetime.fromisoformat(utc_row["finished_at"]) == finished
