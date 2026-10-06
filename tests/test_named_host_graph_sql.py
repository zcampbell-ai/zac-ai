"""Prepared real SQL/local-age vertical graph; DO NOT run concurrently with suite.

Actual operational SQLite session/admission bindings precede canonical capture.
Canonical Sources, local encrypted backup/cold restore are real disposable tests.
Google identity, runtime metadata, tokenizer inventory, semantic answer and key
escrow flags are invented fixtures: no cloud auth/model/B2/readiness claim.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.test_contextual_storage import stored
from tests.test_fireflies_protection import keypair
from tests.test_local_followup_runtime import route
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_private_web import InventedProvider
from tests.test_text_followup import Gate
from zacai import backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.contracts import EvidenceReference, UsageObservation
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.followup_prompt_counter import OllamaQwenFollowupTokenCounter
from zacai.intelligence.text_followup import FollowupDraft, UnsupportedReason, release_text_followup
from zacai.interfaces import named_runtime_binding as runtime_module
from zacai.interfaces.followup_authority_recovery import BrainstormFollowupAuthorityRecovery
from zacai.interfaces.followup_authorization import (
    CanonicalFollowupAuthorization,
    FollowupAuthorizationError,
    FollowupConsentV2,
    FollowupHostSnapshot,
    _owner_digest,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import SqliteNamedAdmissionStore
from zacai.interfaces.named_browser_pointer import (
    NamedAdmissionReuseCoordinator,
    NamedBrowserPointerCodec,
)
from zacai.interfaces.named_consent_binding import (
    CanonicalNamedFollowupConsentBinding,
    NamedConsentBindingError,
)
from zacai.interfaces.named_decision_admission import (
    CanonicalNamedDecisionAdmission,
    NamedDecisionAdmissionError,
)
from zacai.interfaces.named_decision_binding import CanonicalNamedDecisionBinding
from zacai.interfaces.named_decision_capture import (
    CanonicalNamedDecisionCapture,
    NamedDecisionCaptureError,
)
from zacai.interfaces.named_decision_inventory import load_named_decision_inventory
from zacai.interfaces.named_decision_recovery import BrainstormNamedDecisionRecovery
from zacai.interfaces.named_followup_decision import (
    NamedFollowupManifest,
    named_decision_consent_id,
)
from zacai.interfaces.named_followup_web import NamedFollowupWeb
from zacai.interfaces.named_published_display import CanonicalNamedPublishedDisplayGate
from zacai.interfaces.named_recovery_inputs import (
    RetainedNamedDecisionProofs,
    RetainedQuestionRecoveryInputs,
)
from zacai.interfaces.named_runtime_binding import FixedLocalNamedRuntimeBinding
from zacai.interfaces.named_session_binding import NamedSessionBindingError, NamedSessionContinuity
from zacai.interfaces.named_worker_lifecycle import NamedWorkerRegistry
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import PreparedNamedOwnerHost, prepare_owner_host
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_reply_capture import CanonicalTextReplyCapture, TextReplyCaptureError
from zacai.interfaces.text_reply_protection import BrainstormTextReplyProtection
from zacai.interfaces.text_turn_capture import CanonicalTextTurnCapture
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source


def test_actual_published_admission_question_named_recovery_v2_reply_graph(
    test_session_factory,
    tmp_path,
    monkeypatch,
    installed,
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
    key_path = tmp_path / "throwaway-graph.agekey"
    recipient = keypair(key_path)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=artifacts,
        objects=objects,
        verification_objects=reader,
        recipient=recipient,
        identity_path=key_path,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    packet_receipt = protector.protect(packet_id, content_hash_of(packet_bytes))
    packet_digest = content_hash_of(packet_bytes)
    packet_receipt_digest = content_hash_of(encode_recovery_receipt(packet_receipt))
    clock_offset = timedelta(0)
    clock = HostObservedClock(lambda: datetime.now(UTC) + clock_offset)
    owner = OwnerGrant(
        Identity(GOOGLE_ISSUER, "invented-vertical-sql-owner"),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    )
    principal = InterfacePrincipal(owner.identity, owner.scopes)
    question_protection = BrainstormTextTurnProtection(protector=protector, clock=clock)
    turns = CanonicalTextTurnCapture(
        factory=factory,
        artifacts=artifacts,
        owner=lambda: owner,
        clock=clock,
        protection=question_protection,
    )
    assembler = CanonicalFollowupAssembler(capture=turns)
    host_key = b"K" * 32  # invented in-memory operational seal key, never escrow proof
    origin, client_id = "https://invented.test", "123-invented.apps.googleusercontent.com"
    sessions = SqliteSessionStore(tmp_path / "sessions", key=host_key)
    cookie = sessions.start_user(owner.identity, clock())
    continuity = NamedSessionContinuity(
        sessions=sessions,
        owner=lambda: owner,
        clock=clock,
        key=host_key,
        origin=origin,
        client_id=client_id,
    )
    operation = continuity.for_cookie(cookie)
    verified = operation.establish()
    admissions = SqliteNamedAdmissionStore(
        tmp_path / "admissions", key=host_key, origin=origin, client_id=client_id, clock=clock
    )
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    metadata_calls = []

    def metadata(method, path, body=None):
        metadata_calls.append((method, path, body))
        if path == "/api/version":
            return {"version": "0.35.1"}
        if path == "/api/tags":
            return {"models": [{"name": route().identity.model_id, "digest": installed[2]}]}
        if path == "/api/show":
            return {}
        pytest.fail("actual generation is forbidden in this fixture")

    runtime = FixedLocalNamedRuntimeBinding(
        route=route(),
        model_digest=installed[2],
        counter=counter,
        transport_factory=lambda request, started: metadata,
    )
    # Published metadata has no request, so its concrete deadline transport is
    # a separate seam. Keep this SQL fixture fully isolated from live loopback.
    monkeypatch.setattr(runtime_module, "FollowupLoopbackTransport", lambda **kwargs: metadata)
    pins = runtime.pins()
    with factory() as session:
        packet = load_contextual_packet(
            session,
            artifacts=artifacts,
            source_id=packet_id,
            expected_digest=packet_digest,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
    request_id, conversation_id, run_id, builder_id = uuid4(), uuid4(), uuid4(), uuid4()

    def published(nonce_digest, now):
        return NamedFollowupManifest(
            actor_issuer=owner.identity.issuer,
            actor_subject=owner.identity.subject,
            owner_grant_digest=_owner_digest(owner),
            conversation_id=conversation_id,
            request_id=request_id,
            run_id=run_id,
            builder_id=builder_id,
            nonce_digest=nonce_digest,
            issued_at=now,
            admission_expires_at=now + timedelta(minutes=5),
            processing_ttl_seconds=900,
            packet_reference=EvidenceReference(
                source_id=packet_id,
                content_hash=packet_digest,
                trust_boundary=B.BRAINSTORM,
                effective_classification=C.CONFIDENTIAL,
            ),
            packet_receipt_digest=packet_receipt_digest,
            evidence_references=tuple(item.reference for item in packet.task.context),
            parents=(),
            route=runtime.route,
            model_digest=runtime.model_digest,
            runtime_endpoint="http://127.0.0.1:11434",
            tokenizer_digest=pins.tokenizer_digest,
            request_template_digest=pins.request_template_digest,
            max_output_tokens=512,
            max_latency_ms=60_000,
            max_estimated_cost_usd=0.0,
        )

    issued = admissions.issue(session_binding=verified.binding_digest, manifest_builder=published)
    question = b"  What does the original reporting evidence say?\r\n"
    operation.recheck(verified.binding_digest)
    admitted = admissions.admit(
        handle=issued.handle,
        session_binding=verified.binding_digest,
        question_digest=content_hash_of(question),
        question_bytes=len(question),
    )
    assert admitted.admitted_at is not None
    assert admitted.phase == "ADMITTED" and admitted.admitted_at >= issued.record.manifest.issued_at
    saved_turn = turns.capture(
        principal=principal,
        request_id=request_id,
        conversation_id=conversation_id,
        original_utf8=question,
        retained_receipt=packet_receipt,
        expected_receipt_digest=packet_receipt_digest,
    )
    assert issued.record.manifest.issued_at <= admitted.admitted_at <= saved_turn.turn.recorded_at
    admissions.attach_question(
        handle=issued.handle,
        session_binding=verified.binding_digest,
        reference=saved_turn.reference,
        recovery_digest=content_hash_of(
            canonical_bytes(saved_turn.recovery_receipt.model_dump(mode="json"))
        ),
    )
    question_inputs = RetainedQuestionRecoveryInputs(
        protector=protector, question_protection=question_protection, clock=clock
    )

    def snapshot_builder(assembled, actor):
        return FollowupHostSnapshot(assembled, actor, owner, runtime.route, runtime.model_digest)

    admission = CanonicalNamedDecisionAdmission(
        store=admissions,
        operation=operation,
        assembler=assembler,
        clock=clock,
        recovery_inputs=question_inputs,
        snapshot_builder=snapshot_builder,
    )
    binding = CanonicalNamedDecisionBinding(
        assembler=assembler,
        clock=clock,
        recovery_inputs=question_inputs.for_decision,
        snapshot_builder=snapshot_builder,
        runtime=runtime,
    )
    # Actual snapshot bytes; independent key escrow/off-device flags remain
    # explicitly invented, matching existing local-age SQL test limitations.
    proof_state = f"BRAINSTORM/state/{uuid4()}/{packet_receipt.state_ciphertext_hash}.age"
    objects.put_object(proof_state, reader.get_object(packet_receipt.state_object))
    proof = canonical_bytes(
        {
            "format": "zac-existing-state-recovery-v1",
            "boundary": "BRAINSTORM",
            "full_row_field_comparison": "passed",
            "target_cleaned": True,
            "off_device_retrieval": True,
            "recovered_identity_from_password_manager": True,
            "temporary_recovered_key_removed": True,
            "state_object": proof_state,
            "ciphertext_hash": packet_receipt.state_ciphertext_hash,
            "plaintext_hash": packet_receipt.state_plaintext_hash,
        }
    )
    proof_path = tmp_path / "invented-key-proof.json"
    proof_path.write_bytes(proof)
    proof_path.chmod(0o600)
    display = CanonicalNamedPublishedDisplayGate(
        protector=protector,
        question_protection=question_protection,
        clock=clock,
        runtime=runtime,
        recovered_key_receipt=proof_path,
        expected_key_proof_digest=content_hash_of(proof),
    )
    # Actual packet checkpoint decryption/full restore and canonical display
    # rows, with only runtime reporting and external escrow assertions invented.
    assert display.verify_fresh(operation, issued.record) is None
    assert display.verify_rows(issued.record, clock()) is None
    # Real enrolled host/session/native GET composition over actual canonical
    # SQL and encrypted restore. Identity provider + local pairing remain invented.
    owner_store = OwnerGrantStore(tmp_path / "owner", key=host_key, origin=origin, client_id=client_id)
    enrollment = OwnerEnrollment(opened_at=clock())
    pending = enrollment.capture(owner.identity, clock(), origin=origin)
    assert owner_store.confirm_and_save(
        enrollment=enrollment, candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code, origin=origin, identity=owner.identity,
        scopes=owner.scopes, now=clock(),
    ) == owner

    def native_factory(inputs):
        actual_continuity = NamedSessionContinuity(
            sessions=inputs.sessions, owner=inputs.owner, clock=inputs.clock,
            key=inputs.session_key, origin=inputs.origin, client_id=inputs.client_id,
        )
        codec = NamedBrowserPointerCodec(key=inputs.session_key, origin=inputs.origin,
            client_id=inputs.client_id, clock=inputs.clock)
        def manifest_builder(actual, nonce_digest, now):
            assert actual.principal == principal
            return published(nonce_digest, now).model_copy(update={
                "request_id": uuid4(), "run_id": uuid4(), "builder_id": uuid4(),
            })
        coordinator = NamedAdmissionReuseCoordinator(store=admissions, codec=codec,
            clock=inputs.clock, manifest_builder=manifest_builder)
        controller = NamedFollowupWeb(coordinator=coordinator, continuity=actual_continuity,
            store=admissions, clock=inputs.clock, display_gate=display)
        return PreparedNamedOwnerHost(controller, NamedWorkerRegistry(clock=inputs.clock))

    async def selected_view(actor):
        assert actor == principal
        return "<main>Invented selected view</main>"

    host = prepare_owner_host(
        configuration=OwnerStartupConfiguration(client_id, origin, "invented-secret", host_key),
        directory=tmp_path, view=selected_view, clock=clock,
        identities=InventedProvider(owner.identity), named_factory=native_factory,
    )
    with TestClient(host.app, base_url=origin, follow_redirects=False) as browser:
        browser.cookies.set("__Host-zac-session", cookie)
        page = browser.get("/ask-caz-locally")
        assert page.status_code == 200
        assert "Ask Caz locally" in page.text and "disabled" in page.text
        assert str(packet_id) in page.text and "__Host-zac-named-action" in page.headers["set-cookie"]
        assert browser.post("/ask-caz-locally").status_code == 405
    recovery = BrainstormNamedDecisionRecovery(
        protector=protector,
        clock=clock,
        fresh=binding.verify_historical,
        recovered_key_receipt=proof_path,
        expected_key_proof_digest=content_hash_of(proof),
    )
    capture = CanonicalNamedDecisionCapture(
        factory=factory,
        artifacts=artifacts,
        owner=lambda: owner,
        admission=admission,
        binding=binding,
        protection=recovery,
        clock=clock,
    )
    assembled = assembler.assemble(
        principal=principal,
        source_id=saved_turn.source_id,
        expected_turn_digest=saved_turn.turn_digest,
        retained_receipt=packet_receipt,
        expected_receipt_digest=packet_receipt_digest,
        recovery_receipt=saved_turn.recovery_receipt,
    )
    request = prepare_followup_request(assembled.context)
    saved = capture.capture(
        admission_handle=issued.handle, principal=principal, original_request=request
    )
    assert saved.decision.original_observed_at == request.context.task.event.observed_at
    assert saved.decision.session_binding_digest == verified.binding_digest
    assert not saved.processing_authorized and not saved.execution_authorized
    admissions.attach_decision(
        handle=issued.handle,
        session_binding=verified.binding_digest,
        reference=saved.reference,
        recovery_digest=content_hash_of(
            canonical_bytes(saved.recovery_receipt.model_dump(mode="json"))
        ),
    )
    assert (
        capture.capture(
            admission_handle=issued.handle, principal=principal, original_request=request
        )
        == saved
    )
    assert admission.prepare_original(issued.handle, principal) == request
    with factory() as session:
        inventory = load_named_decision_inventory(
            session, artifacts=artifacts, reference=saved.reference, as_of=clock()
        )
    assert inventory.decision == saved.decision
    decision_proofs = RetainedNamedDecisionProofs(
        question_inputs=question_inputs, decision_recovery=recovery
    )
    named_binding = CanonicalNamedFollowupConsentBinding(
        admission=admission,
        recovery_inputs=question_inputs,
        decision_proofs=decision_proofs,
        clock=clock,
    )
    consent = FollowupConsentV2(
        id=named_decision_consent_id(saved.reference.source_id),
        scope=saved.decision.run_scope,
        approved_at=saved.decision.admitted_at,
        expires_at=saved.decision.processing_expires_at,
        human_reference="invented authenticated named POST",
        decision_reference=saved.reference,
        decision_recovery_digest=content_hash_of(
            canonical_bytes(saved.recovery_receipt.model_dump(mode="json"))
        ),
    )
    assert named_binding.verify_active(handle=issued.handle, consent=consent, now=clock()) is None

    def snapshot():
        current = assembler.assemble(
            principal=principal,
            source_id=saved_turn.source_id,
            expected_turn_digest=saved_turn.turn_digest,
            retained_receipt=packet_receipt,
            expected_receipt_digest=packet_receipt_digest,
            recovery_receipt=saved_turn.recovery_receipt,
        )
        return snapshot_builder(current, principal)

    authority_recovery = BrainstormFollowupAuthorityRecovery(
        protector=protector,
        clock=clock,
        refresh=snapshot,
        owner=lambda: owner,
        recovered_key_receipt=proof_path,
        expected_key_proof_digest=content_hash_of(proof),
        named_binding=named_binding,
    )
    authorization = CanonicalFollowupAuthorization(
        factory=factory,
        store=artifacts,
        owner=lambda: owner,
        refresh=snapshot,
        recovery=authority_recovery,
        clock=clock,
        named_binding=named_binding,
        named_only=True,
    )
    approval = authorization.record(consent)
    claimed = authorization.claim(approval_id=approval, scope=consent.scope, request=request)
    authorization.recheck(claimed, request)
    gate = Gate()  # explicitly synthetic unsupported reply, no useful/model claim
    draft = FollowupDraft(
        task_id=request.context.task.task_id,
        user_source_id=saved_turn.source_id,
        user_content_hash=saved_turn.turn_digest,
        packet_digest=packet_digest,
        unsupported=UnsupportedReason.OUTSIDE_PACKET,
    )
    released = release_text_followup(request.context, draft, gate=gate)
    replies = CanonicalTextReplyCapture(
        assembler=assembler,
        authorization=authorization,
        release_gate=gate,
        protection=BrainstormTextReplyProtection(
            protector=protector, clock=clock, named_binding=named_binding
        ),
    )
    saved_reply = replies.capture(
        principal=principal,
        request=request,
        claimed=claimed,
        release=released,
        usage=UsageObservation(input_tokens=10, output_tokens=20, latency_ms=5, cost_usd=0),
        retained_receipt=packet_receipt,
        text_receipt=saved_turn.recovery_receipt,
    )
    reply_args = {
        "principal": principal,
        "source_id": saved_reply.source_id,
        "expected_reply_digest": saved_reply.reply_digest,
        "retained_receipt": packet_receipt,
        "text_receipt": saved_turn.recovery_receipt,
        "recovery_receipt": saved_reply.recovery_receipt,
    }
    assert replies.load(**reply_args) == saved_reply
    assert all(path in ("/api/version", "/api/tags", "/api/show") for _, path, _ in metadata_calls)
    # Actual session-store restart preserves original continuity exactly.
    reopened = SqliteSessionStore(tmp_path / "sessions", key=host_key)
    restarted = NamedSessionContinuity(
        sessions=reopened,
        owner=lambda: owner,
        clock=clock,
        key=host_key,
        origin=origin,
        client_id=client_id,
    )
    assert restarted.for_cookie(cookie).recheck(verified.binding_digest).principal == principal
    reopened.revoke(cookie)
    with pytest.raises(NamedSessionBindingError):
        operation.recheck(verified.binding_digest)
    replacement_cookie = reopened.start_user(owner.identity, clock())
    replacement_operation = restarted.for_cookie(replacement_cookie)
    with pytest.raises(NamedSessionBindingError):
        replacement_operation.recheck(verified.binding_digest)
    replacement_admission = CanonicalNamedDecisionAdmission(
        store=admissions,
        operation=replacement_operation,
        assembler=assembler,
        clock=clock,
        recovery_inputs=question_inputs,
        snapshot_builder=snapshot_builder,
    )
    replacement_binding = CanonicalNamedFollowupConsentBinding(
        admission=replacement_admission,
        recovery_inputs=question_inputs,
        decision_proofs=decision_proofs,
        clock=clock,
    )
    with pytest.raises(NamedConsentBindingError):
        replacement_binding.verify_active(handle=issued.handle, consent=consent, now=clock())
    with pytest.raises(NamedDecisionAdmissionError):
        replacement_admission.prepare_original(issued.handle, principal)
    # Fresh current owner session may preserve already committed exact history.
    # It cannot renew the original session/admission/processing window.
    clock_offset = timedelta(minutes=16)
    receipt_capture = CanonicalNamedDecisionCapture(
        factory=factory,
        artifacts=artifacts,
        owner=lambda: owner,
        admission=replacement_admission,
        binding=binding,
        protection=recovery,
        clock=clock,
    )
    assert (
        receipt_capture.protect_pending(
            principal=principal,
            source_id=saved.reference.source_id,
            expected_decision_digest=saved.reference.content_hash,
        )
        == saved.recovery_receipt
    )
    assert replacement_binding.verify_fresh(consent, clock()) is None
    with pytest.raises(NamedConsentBindingError):
        replacement_binding.verify_active(handle=issued.handle, consent=consent, now=clock())
    with pytest.raises(NamedDecisionCaptureError):
        receipt_capture.capture(
            admission_handle=issued.handle, principal=principal, original_request=request
        )
    with pytest.raises(FollowupAuthorizationError):
        authorization.recheck(claimed, request)
    with pytest.raises(TextReplyCaptureError):
        replies.load(**reply_args)
