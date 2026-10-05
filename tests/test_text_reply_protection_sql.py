"""Invented guarded SQL/age/local clients, never production, B2 or model calls.

Packet, user turn, consent/claim and generated reply are real canonical SQL
records with actual artifact encryption, snapshot/journal/cold restore, leases
and current selected-row comparison. Authority recovery preflight and semantic
usefulness are explicitly invented fixture gates, not real processing permission
or complete production readiness. Route/model pin and reported usage are invented.

Only raw-artifact inventory coverage is narrowed to new fixture Sources because
shared test DB rows may reference prior tests' unavailable ephemeral artifacts.
The full SQL snapshot, journal and restored selected row checks remain real.
This proves selected-fixture mechanics, not all accumulated test artifacts or
actual off-device/key/credential recovery. No external services are contacted.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from tests.test_contextual_storage import stored
from tests.test_fireflies_protection import keypair
from zacai import backup, backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import decode_contextual_packet
from zacai.intelligence.contracts import ModelRoute, RouteIdentity, UsageObservation
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.text_followup import FollowupDraft, release_text_followup
from zacai.interfaces.followup_authorization import (
    CanonicalFollowupAuthorization,
    FollowupAuthorizationError,
    FollowupConsent,
    FollowupHostSnapshot,
    scope_from_snapshot,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_reply_capture import (
    CanonicalTextReplyCapture,
    TextReplyCaptureError,
    TextReplyCheckpointScope,
    TextReplyRecoveryReceipt,
    decode_text_reply,
    encode_text_reply,
)
from zacai.interfaces.text_reply_protection import BrainstormTextReplyProtection
from zacai.interfaces.text_turn_capture import CanonicalTextTurnCapture
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem


@pytest.mark.parametrize("pending_after_expiry", [False, True])
def test_actual_sql_generated_reply_capture_cold_restore_and_immutable_retry(
    test_session_factory, tmp_path, monkeypatch, pending_after_expiry
):
    factory, artifacts, packet_bytes, packet_id, _, baseline = stored.__wrapped__(
        test_session_factory, tmp_path
    )
    packet = decode_contextual_packet(packet_bytes)

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
    key_path = tmp_path / "throwaway-reply.agekey"
    recipient = keypair(key_path)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=artifacts,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=key_path,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    packet_receipt = protector.protect(packet_id, content_hash_of(packet_bytes))
    packet_receipt_digest = content_hash_of(encode_recovery_receipt(packet_receipt))
    clock_offset = timedelta(0)
    clock = HostObservedClock(lambda: datetime.now(UTC) + clock_offset)
    owner = OwnerGrant(
        Identity(GOOGLE_ISSUER, "invented-sql-reply-owner"),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    )
    principal = InterfacePrincipal(owner.identity, owner.scopes)
    turns = CanonicalTextTurnCapture(
        factory=factory,
        artifacts=artifacts,
        owner=lambda: owner,
        clock=clock,
        protection=BrainstormTextTurnProtection(protector=protector, clock=clock),
    )
    saved_turn = turns.capture(
        principal=principal,
        request_id=uuid4(),
        conversation_id=uuid4(),
        original_utf8=b"  What does the original reporting evidence say?\r\n",
        retained_receipt=packet_receipt,
        expected_receipt_digest=packet_receipt_digest,
    )
    assembler = CanonicalFollowupAssembler(capture=turns)
    route = ModelRoute(
        identity=RouteIdentity(provider_id="invented", model_id="invented", runtime_id="invented"),
        destination=Destination.LOCAL,
        capabilities=frozenset({"packet_followup"}),
        max_input_characters=64_000,
        max_output_tokens=512,
        estimated_latency_ms=1,
        estimated_cost_usd=0,
        available=True,
    )

    def snapshot():
        return FollowupHostSnapshot(
            assembler.assemble(
                principal=principal,
                source_id=saved_turn.source_id,
                expected_turn_digest=saved_turn.turn_digest,
                retained_receipt=packet_receipt,
                expected_receipt_digest=packet_receipt_digest,
                recovery_receipt=saved_turn.recovery_receipt,
            ),
            principal,
            owner,
            route,
            "1" * 64,
        )

    selected = snapshot()
    request = prepare_followup_request(selected.assembled.context)
    scope = scope_from_snapshot(selected, run_id=uuid4(), builder_id=uuid4())
    authority_recovery_checks = []

    class InventedAuthorityRecovery:
        def preflight(self, consent):
            # Deliberately not real credential/key/consent-checkpoint recovery.
            # The actual generated reply snapshot will include these Sources.
            assert consent.scope == scope
            authority_recovery_checks.append(consent.id)

    authority = CanonicalFollowupAuthorization(
        factory=factory,
        store=artifacts,
        refresh=snapshot,
        owner=lambda: owner,
        recovery=InventedAuthorityRecovery(),
        clock=clock,
    )
    consent_time = clock()
    consent = FollowupConsent(
        id=uuid4(),
        scope=scope,
        approved_at=consent_time,
        expires_at=consent_time + timedelta(minutes=15),
        human_reference="invented controlled test human decision",
    )
    approval_id = authority.record(consent)
    # Exact duplicate recording preserves the original Source/expiry and grants
    # no second attempt. A conflicting record would be refused by _write.
    assert authority.record(consent) == approval_id
    claimed = authority.claim(approval_id=approval_id, scope=scope, request=request)
    authority.recheck(claimed, request)
    assert authority.record(consent) == approval_id
    with factory() as session:
        repeated = session.get(Source, approval_id)
        assert repeated.captured_at == consent.approved_at
        assert (
            len(
                session.scalars(
                    select(Source).where(
                        Source.external_ref == f"packet-followup-consent/{consent.id}"
                    )
                ).all()
            )
            == 1
        )
        assert (
            len(
                session.scalars(
                    select(Source).where(
                        Source.external_ref == f"packet-followup-claim/{approval_id}"
                    )
                ).all()
            )
            == 1
        )
    with pytest.raises(FollowupAuthorizationError):
        authority.claim(approval_id=approval_id, scope=scope, request=request)

    # Deterministic invented support gate; no model has generated this answer.
    answer = packet.review.overview[0]
    draft = FollowupDraft(
        task_id=request.context.task.task_id,
        user_source_id=saved_turn.source_id,
        user_content_hash=saved_turn.turn_digest,
        packet_digest=scope.packet_reference.content_hash,
        answers=(answer,),
    )

    class InventedSemanticGate:
        def recheck(self, context, actual):
            assert actual == draft and context.user_reference == saved_turn.reference
            assert actual.answers == (context.packet.review.overview[0],)

    semantic = InventedSemanticGate()
    release = release_text_followup(request.context, draft, gate=semantic)
    reply_protection = BrainstormTextReplyProtection(protector=protector, clock=clock)
    replies = CanonicalTextReplyCapture(
        assembler=assembler,
        authorization=authority,
        release_gate=semantic,
        protection=reply_protection,
    )
    inputs = {
        "principal": principal,
        "request": request,
        "claimed": claimed,
        "release": release,
        "usage": UsageObservation(input_tokens=10, output_tokens=20, latency_ms=1, cost_usd=0),
        "retained_receipt": packet_receipt,
        "text_receipt": saved_turn.recovery_receipt,
    }
    if pending_after_expiry:
        original_protect = reply_protection.protect
        attempted = []

        def fail_after_canonical_commit(checkpoint):
            with factory() as session:
                committed = session.get(Source, checkpoint.source_id)
                assert committed is not None and committed.content_hash == checkpoint.reply_digest
                assert committed.system == SourceSystem.MANUAL
            attempted.append(checkpoint)
            raise ValueError("invented protection failure after canonical reply commit")

        monkeypatch.setattr(reply_protection, "protect", fail_after_canonical_commit)
        with pytest.raises(TextReplyCaptureError):
            replies.capture(**inputs)
        monkeypatch.setattr(reply_protection, "protect", original_protect)
        assert len(attempted) == 1
        source_id, reply_digest = attempted[0].source_id, attempted[0].reply_digest
        with factory() as session:
            committed = session.get(Source, source_id)
            record = decode_text_reply(artifacts.get(B.BRAINSTORM, committed.content_location))
            assert (
                consent.approved_at
                <= record.claim.claimed_at
                <= record.recorded_at
                < consent.expires_at
            )
            original_recorded_at, original_digest = committed.captured_at, committed.content_hash
        # Advance only the invented shared host reader, never the OS/DB clock.
        # Original reply timestamp stays before actual SQL backup-run timestamps.
        clock_offset = timedelta(minutes=16)
        assert clock() > consent.expires_at
        revoked_id = authority.revoke(
            approval_id=approval_id, human_reference="invented controlled test cancellation"
        )
        with pytest.raises(FollowupAuthorizationError):
            authority.recheck(claimed, request)
        with pytest.raises(TextReplyCaptureError):
            replies.capture(**inputs)
        recovery_receipt = replies.protect_pending(
            principal=principal, source_id=source_id, expected_reply_digest=reply_digest
        )
        assert type(recovery_receipt) is TextReplyRecoveryReceipt
        assert not hasattr(recovery_receipt, "display_text") and not hasattr(
            recovery_receipt, "reply"
        )
        assert recovery_receipt.captured_at == original_recorded_at
        assert recovery_receipt.verified_at > consent.expires_at
        with factory() as session:
            committed = session.get(Source, source_id)
            assert (
                committed.captured_at == original_recorded_at
                and committed.content_hash == original_digest
            )
            assert session.get(Source, revoked_id).system == SourceSystem.USER_INSTRUCTION
            assert (
                len(
                    session.scalars(
                        select(Source).where(
                            Source.external_ref == f"packet-followup-claim/{approval_id}"
                        )
                    ).all()
                )
                == 1
            )
            assert (
                len(
                    session.scalars(
                        select(Source).where(
                            Source.external_ref == f"text-reply/{record.request_id}"
                        )
                    ).all()
                )
                == 1
            )
        # The real complete snapshot also contains the cancellation Source;
        # selected-row validation cannot silently invent an active grant.
        restored_frame = age_decrypt(reader.get_object(recovery_receipt.state_object), key_path)
        assert str(revoked_id).encode() in restored_frame
    else:
        saved = replies.capture(**inputs)
        source_id, reply_digest, record = saved.source_id, saved.reply_digest, saved.reply
        recovery_receipt = saved.recovery_receipt
        assert not saved.execution_authorized and not saved.processing_authorized
    raw = encode_text_reply(record)
    assert record.display_text == release.text
    assert record.claim == claimed.claim and record.claim_reference == claimed.reference
    with factory() as session:
        source = session.get(Source, source_id)
        assert source.system == SourceSystem.MANUAL
        assert source.external_ref == f"text-reply/{record.request_id}"
        assert source.content_hash == content_hash_of(raw) == reply_digest
        assert decode_text_reply(artifacts.get(B.BRAINSTORM, source.content_location)) == record
    encrypted = reader.get_object(recovery_receipt.receipt_object)
    assert (
        TextReplyRecoveryReceipt.model_validate_json(age_decrypt(encrypted, key_path))
        == recovery_receipt
    )
    checkpoint = TextReplyCheckpointScope(source_id, reply_digest, record.recorded_at)
    with reply_protection._lease():
        inventory = reply_protection._hashes(checkpoint)
    assert inventory[source_id] == reply_digest
    assert inventory[claimed.reference.source_id] == claimed.reference.content_hash
    assert (
        inventory[claimed.claim.consent_reference.source_id]
        == claimed.claim.consent_reference.content_hash
    )
    assert inventory[saved_turn.source_id] == saved_turn.turn_digest
    assert inventory[packet_id] == content_hash_of(packet_bytes)
    assert set(inventory) == {
        source_id,
        claimed.reference.source_id,
        claimed.claim.consent_reference.source_id,
        packet_id,
        *(r.source_id for r in scope.context_references),
    }
    reply_protection.recheck(checkpoint, recovery_receipt)
    load_inputs = {
        "principal": principal,
        "source_id": source_id,
        "expected_reply_digest": reply_digest,
        "retained_receipt": packet_receipt,
        "text_receipt": saved_turn.recovery_receipt,
        "recovery_receipt": recovery_receipt,
    }
    if pending_after_expiry:
        with pytest.raises(TextReplyCaptureError):
            replies.load(**load_inputs)
        assert (
            replies.protect_pending(
                principal=principal, source_id=source_id, expected_reply_digest=reply_digest
            )
            == recovery_receipt
        )
        with pytest.raises(TextReplyCaptureError):
            replies.capture(**inputs)
    else:
        assert replies.load(**load_inputs) == saved
        assert replies.capture(**inputs) == saved
    assert reader.get_object(recovery_receipt.receipt_object) == encrypted
    assert authority_recovery_checks and protector._lease_guard is None
    with backup._admin_connection() as admin:
        assert (
            admin.scalar(
                text("SELECT count(*) FROM pg_database WHERE datname='zacai_restore_test'")
            )
            == 0
        )
    assert not list(tmp_path.rglob("*.csv"))
