"""Actual disposable SQL/local age named-decision retention and cold recovery.

Admission/session fixtures are invented, not an actual authenticated owner POST.
Full snapshots/journal/selected-row restoration and encryption/readback are real.
Local object clients and invented key escrow flags do not attest B2/1Password.
Raw artifact inventory is limited to fixture Sources due to shared test history.
"""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select, text, update

from tests.test_contextual_storage import stored
from tests.test_fireflies_protection import keypair
from zacai import backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import ModelRoute, RouteIdentity
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.interfaces.followup_authorization import FollowupHostSnapshot, scope_from_snapshot
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_decision_capture import (
    CanonicalNamedDecisionCapture,
    NamedDecisionCaptureError,
    _require_request_lock,
)
from zacai.interfaces.named_decision_inventory import load_named_decision_inventory
from zacai.interfaces.named_decision_recovery import BrainstormNamedDecisionRecovery
from zacai.interfaces.named_followup_decision import (
    NamedFollowupDecision,
    NamedFollowupManifest,
    named_manifest_digest,
    validate_declared_bindings,
)
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_turn_capture import CanonicalTextTurnCapture
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem


@pytest.mark.parametrize("pending", [False, True, "foreign_kind", "row_flush", "row_commit", "row_bulk_update", "row_raw_update", "row_connection_update", "row_rollback", "row_dml_cte"])
def test_named_decision_actual_sql_cold_restore_and_expired_pending_repair(
    test_session_factory, tmp_path, monkeypatch, pending,
):
    factory, artifacts, packet_bytes, packet_id, _, baseline = stored.__wrapped__(
        test_session_factory, tmp_path
    )

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
    admitted_at = clock()
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
    manifest = NamedFollowupManifest(
        actor_issuer=scope.actor_issuer, actor_subject=scope.actor_subject,
        owner_grant_digest=scope.owner_grant_digest,
        conversation_id=scope.conversation_id, request_id=saved_turn.turn.request_id,
        run_id=scope.run_id, builder_id=scope.builder_id,
        nonce_digest="9" * 64, issued_at=admitted_at,
        admission_expires_at=admitted_at + timedelta(minutes=5), processing_ttl_seconds=900,
        packet_reference=scope.packet_reference, packet_receipt_digest=scope.packet_receipt_digest,
        evidence_references=tuple(i.reference for i in selected.assembled.context.packet.task.context),
        parents=(), route=scope.route, model_digest=scope.model_digest,
        runtime_endpoint="http://127.0.0.1:11434", tokenizer_digest="b" * 64,
        request_template_digest="c" * 64,
        max_output_tokens=scope.max_output_tokens, max_latency_ms=scope.max_latency_ms,
        max_estimated_cost_usd=scope.max_estimated_cost_usd,
    )
    decision = NamedFollowupDecision(
        manifest=manifest, manifest_digest=named_manifest_digest(manifest),
        admitted_at=admitted_at, processing_expires_at=admitted_at + timedelta(minutes=15),
        bound_at=clock(), original_observed_at=request.context.task.event.observed_at,
        session_binding_digest="a" * 64, question_reference=saved_turn.reference,
        original_utf8_digest=content_hash_of(saved_turn.turn.original_text.encode()),
        question_receipt_digest=scope.text_receipt_digest,
        prepared_request_digest=request.digest, run_scope=scope,
    )

    class InventedAdmission:
        def resolve(self, handle, actor, original_request, now):
            assert handle == "invented-consumed-handle" and actor == principal
            assert original_request == request
            return decision

        def recheck(self, handle, actor, exact, now):
            assert handle == "invented-consumed-handle" and actor == principal and exact == decision

        def recheck_session(self, actor, exact, now):
            assert actor == principal and exact == decision

    class Binding:
        def verify_fresh(self, exact, now):
            latest = snapshot().assembled
            event = latest.context.task.event.model_copy(update={"observed_at": exact.original_observed_at})
            context = replace(latest.context, task=latest.context.task.model_copy(update={"event": event}))
            validate_declared_bindings(
                exact, owner=owner, turn=latest.saved_turn.turn,
                turn_source_id=latest.saved_turn.source_id,
                turn_receipt=latest.saved_turn.recovery_receipt, packet_receipt=packet_receipt,
                request=prepare_followup_request(context), runtime_endpoint=manifest.runtime_endpoint,
                tokenizer_digest=manifest.tokenizer_digest,
                request_template_digest=manifest.request_template_digest,
            )

        def verify_rows(self, session, exact, now):
            # SQL fixture validates canonical dependencies without recovery callbacks.
            for ref in (exact.question_reference, exact.manifest.packet_reference,
                        *exact.manifest.evidence_references):
                row = session.get(Source, ref.source_id)
                assert row and row.content_hash == ref.content_hash
                assert row.trust_boundary == B.BRAINSTORM and row.data_classification == C.CONFIDENTIAL
            row = session.get(Source, exact.question_reference.source_id)
            assert row.system == SourceSystem.USER_INSTRUCTION
            assert row.external_ref == f"text-turn/{saved_turn.turn.request_id}"

    binding = Binding()
    # Independent invented proof retains actual encrypted snapshot bytes using
    # the existing proof's legacy namespace; production validator is unchanged.
    proof_state = f"BRAINSTORM/state/{uuid4()}/{packet_receipt.state_ciphertext_hash}.age"
    writer.put_object(proof_state, reader.get_object(packet_receipt.state_object))
    proof = canonical_bytes({
        "format": "zac-existing-state-recovery-v1", "boundary": "BRAINSTORM",
        "full_row_field_comparison": "passed", "target_cleaned": True,
        "off_device_retrieval": True, "recovered_identity_from_password_manager": True,
        "temporary_recovered_key_removed": True, "state_object": proof_state,
        "ciphertext_hash": packet_receipt.state_ciphertext_hash,
        "plaintext_hash": packet_receipt.state_plaintext_hash,
    })
    proof_path = tmp_path / "invented-key-proof.json"
    proof_path.write_bytes(proof)
    proof_path.chmod(0o600)
    recovery = BrainstormNamedDecisionRecovery(
        protector=protector, clock=clock, fresh=binding.verify_fresh,
        recovered_key_receipt=proof_path, expected_key_proof_digest=content_hash_of(proof),
    )
    capture = CanonicalNamedDecisionCapture(
        factory=factory, artifacts=artifacts, owner=lambda: owner,
        admission=InventedAdmission(), binding=binding, protection=recovery, clock=clock,
    )
    inputs = {"admission_handle": "invented-consumed-handle", "principal": principal, "original_request": request}
    if type(pending) is str and pending.startswith("row_"):
        original_rows = binding.verify_rows
        cte_reached_cursor = []
        def faulty_rows(session, exact, now):
            original_rows(session, exact, now)
            if pending == "row_commit":
                session.commit()
            elif pending == "row_flush":
                session.get(Source, saved_turn.source_id).data_classification = C.HIGHLY_RESTRICTED
                session.flush()
            elif pending == "row_rollback":
                session.rollback()
            elif pending == "row_bulk_update":
                session.execute(update(Source).where(Source.id == saved_turn.source_id)
                                .values(data_classification=C.HIGHLY_RESTRICTED))
            elif pending == "row_dml_cte":
                side_write = update(Source).where(Source.id == saved_turn.source_id).values(
                    data_classification=C.HIGHLY_RESTRICTED,
                ).cte("classification_write")
                statement = select(Source.id).add_cte(side_write)
                assert statement.is_select and side_write.element.is_dml
                connection = session.connection()
                def record_cursor(*args):
                    cte_reached_cursor.append(True)
                # Registered after the gate: reaching this proves the guard
                # admitted the CTE, even if Source's append-only trigger denies it.
                event.listen(connection, "before_cursor_execute", record_cursor)
                try:
                    session.execute(statement)
                finally:
                    event.remove(connection, "before_cursor_execute", record_cursor)
            elif pending == "row_connection_update":
                session.connection().execute(update(Source).where(Source.id == saved_turn.source_id)
                                             .values(data_classification=C.HIGHLY_RESTRICTED))
            else:
                session.execute(text("UPDATE source SET data_classification='HIGHLY_RESTRICTED' WHERE id=:id"),
                                {"id": saved_turn.source_id})
        binding.verify_rows = faulty_rows
        with pytest.raises(NamedDecisionCaptureError):
            capture.capture(**inputs)
        assert not cte_reached_cursor
        with factory() as session:
            assert session.get(Source, saved_turn.source_id).data_classification == C.CONFIDENTIAL
            assert session.scalar(select(Source.id).where(
                Source.external_ref == f"packet-followup-named-decision/{manifest.request_id}",
                Source.system == SourceSystem.USER_INSTRUCTION,
            )) is None
        return
    if pending == "foreign_kind":
        # Source uniqueness includes system: another kind can occupy this same
        # external reference. It must not permit a second named decision.
        with factory() as session:
            session.add(Source(
                id=uuid4(), system=SourceSystem.MANUAL,
                external_ref=f"packet-followup-named-decision/{manifest.request_id}",
                trust_boundary=B.BRAINSTORM, data_classification=C.CONFIDENTIAL,
                content_hash=saved_turn.turn_digest, content_location=saved_turn.turn_digest,
                captured_at=admitted_at,
            ))
            session.commit()
        with pytest.raises(NamedDecisionCaptureError):
            capture.capture(**inputs)
        with factory() as session:
            assert session.scalar(select(Source.id).where(
                Source.external_ref == f"packet-followup-named-decision/{manifest.request_id}",
                Source.system == SourceSystem.USER_INSTRUCTION,
            )) is None
        return
    if pending:
        original_protect = recovery.protect
        def failed_after_commit(checkpoint):
            with factory() as session:
                assert session.get(Source, checkpoint.source_id) is not None
            raise ValueError("invented checkpoint failure")
        recovery.protect = failed_after_commit
        with pytest.raises(NamedDecisionCaptureError):
            capture.capture(**inputs)
        recovery.protect = original_protect
        with factory() as session:
            row = session.scalar(select(Source).where(
                Source.external_ref == f"packet-followup-named-decision/{manifest.request_id}"))
            sid, digest = row.id, row.content_hash
        clock_offset = timedelta(minutes=16)
        receipt = capture.protect_pending(principal=principal, source_id=sid, expected_decision_digest=digest)
        with pytest.raises(NamedDecisionCaptureError):
            capture.load(principal=principal, admission_handle=inputs["admission_handle"],
                         source_id=sid, expected_decision_digest=digest, recovery_receipt=receipt)
        assert capture.protect_pending(principal=principal, source_id=sid, expected_decision_digest=digest) == receipt
    else:
        saved = capture.capture(**inputs)
        assert saved.decision == decision and not saved.processing_authorized and not saved.execution_authorized
        sid, digest = saved.reference.source_id, saved.reference.content_hash
        assert capture.capture(**inputs) == saved
        with factory() as session:
            actual = load_named_decision_inventory(session, artifacts=artifacts, reference=saved.reference, as_of=clock())
        assert actual.decision == decision
        assert sid in dict(actual.hashes) and saved_turn.source_id in dict(actual.hashes)
        assert saved.recovery_receipt.key_proof_digest == content_hash_of(proof)
        clock_offset = timedelta(minutes=16)
        assert capture.protect_pending(principal=principal, source_id=sid, expected_decision_digest=digest) == saved.recovery_receipt
        with pytest.raises(NamedDecisionCaptureError):
            capture.capture(**inputs)


def test_named_request_lock_exact_physical_key(test_session_factory):
    request_id, different_request_id = uuid4(), uuid4()
    assert request_id.int % 2**63 != different_request_id.int % 2**63
    with test_session_factory() as session:
        _lock(session, request_id)
        # These calls are outside row-validation hooks and reach PostgreSQL.
        _require_request_lock(session, request_id)
        with pytest.raises(ValueError, match="serialization lock lost"):
            _require_request_lock(session, different_request_id)
