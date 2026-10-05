"""Invented canonical SQL + local age authority recovery composition.

Full State snapshots/journals, disposable cold restore, selected canonical rows,
leases and encryption/readback are actual. Object clients are local, identity
is throwaway and operator-proof flags are invented test attestations, not a
password-manager or off-device credential drill. No live model/provider/B2.
Only raw artifact inventory is narrowed to newly created fixture Sources, as
shared test DB history may refer to other tests' deleted temporary artifacts.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_contextual_storage import stored
from tests.test_fireflies_protection import keypair
from zacai import backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import ModelRoute, RouteIdentity
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.interfaces.followup_authorization import (
    CanonicalFollowupAuthorization,
    FollowupAuthorizationError,
    FollowupConsent,
    FollowupHostSnapshot,
    _raw,
    scope_from_snapshot,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_turn_capture import CanonicalTextTurnCapture
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source


@pytest.mark.parametrize("pending_claim", [False, True])
def test_actual_sql_authority_recovery_and_pending_claim_after_expiry(
    test_session_factory, tmp_path, monkeypatch, pending_claim
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
    # Independently pinned invented operator proof points at the actual
    # recovered packet snapshot. This does not attest real 1Password/B2 setup.
    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.intelligence.contracts import EvidenceReference
    from zacai.interfaces.followup_authority_recovery import (
        BrainstormFollowupAuthorityRecovery,
        claim_subject,
        consent_subject,
    )
    from zacai.interfaces.followup_authorization import ClaimedFollowup, FollowupClaim

    # Existing independent proof permits its original legacy state namespace.
    # Reuse actual encrypted snapshot bytes there; do not broaden production
    # proof validation to every newer checkpoint family.
    proof_state = f"BRAINSTORM/state/{uuid4()}/{packet_receipt.state_ciphertext_hash}.age"
    writer.put_object(proof_state, reader.get_object(packet_receipt.state_object))
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
    proof_path = tmp_path / "invented-independent-proof.json"
    proof_path.write_bytes(proof)
    proof_path.chmod(0o600)
    recovery = BrainstormFollowupAuthorityRecovery(
        protector=protector,
        clock=clock,
        refresh=snapshot,
        owner=lambda: owner,
        recovered_key_receipt=proof_path,
        expected_key_proof_digest=content_hash_of(proof),
    )
    authority = CanonicalFollowupAuthorization(
        factory=factory,
        store=artifacts,
        refresh=snapshot,
        owner=lambda: owner,
        recovery=recovery,
        clock=clock,
    )
    approved_at = clock()
    consent = FollowupConsent(
        id=uuid4(),
        scope=scope,
        approved_at=approved_at,
        expires_at=approved_at + timedelta(minutes=15),
        human_reference="invented explicit SQL drill decision",
    )
    approval = authority.record(consent)
    with factory() as session:
        source = session.get(Source, approval)
        consent_ref = EvidenceReference(
            source_id=source.id,
            content_hash=source.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
    consent_checkpoint = consent_subject(consent, consent_ref)
    consent_receipt = recovery.protect(consent_checkpoint)
    recovery.recheck(consent_checkpoint, consent_receipt)
    if pending_claim:

        def fail_acknowledgement(*, claimed, request):
            # The canonical one-shot attempt is already committed. Durability
            # repair may later run, but cannot redispatch or acknowledge it.
            with factory() as session:
                assert session.get(Source, claimed.reference.source_id) is not None
            raise ValueError("invented post-commit protection failure")

        original_hook = recovery.protect_claim
        recovery.protect_claim = fail_acknowledgement
        with pytest.raises(FollowupAuthorizationError):
            authority.claim(approval_id=approval, scope=scope, request=request)
        recovery.protect_claim = original_hook
        with factory() as session:
            source = session.scalar(
                select(Source).where(Source.external_ref == f"packet-followup-claim/{approval}")
            )
            raw = artifacts.get(B.BRAINSTORM, source.content_location)
            parsed = FollowupClaim.model_validate_json(raw)
            assert _raw(parsed) == raw
            claimed = ClaimedFollowup(
                parsed,
                EvidenceReference(
                    source_id=source.id,
                    content_hash=source.content_hash,
                    trust_boundary=B.BRAINSTORM,
                    effective_classification=C.CONFIDENTIAL,
                ),
            )
    else:
        claimed = authority.claim(approval_id=approval, scope=scope, request=request)
    checkpoint = claim_subject(claimed, request)
    clock_offset = timedelta(minutes=16)
    authority.revoke(approval_id=approval, human_reference="invented explicit cancellation")
    receipt = recovery.protect(checkpoint)
    recovery.recheck(checkpoint, receipt)
    assert receipt.processing_authorized is False and receipt.execution_authorized is False
    assert receipt.subject == checkpoint
    with pytest.raises(FollowupAuthorizationError):
        authority.recheck(claimed, request)
    with pytest.raises(FollowupAuthorizationError):
        authority.claim(approval_id=approval, scope=scope, request=request)
    assert recovery.protect(checkpoint) == receipt
