"""Invented canonical-byte fixtures; SQL, claim authority and recovery mocked.

These prove retention mechanics only, not genuine processing grants, semantic
quality, actual encrypted recovery or production release readiness.
"""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_text_followup import Gate
from tests.test_text_followup_context import assemble
from tests.test_text_followup_context import fixture as assembly_fixture
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import ModelRoute, RouteIdentity, UsageObservation
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.text_followup import FollowupDraft, UnsupportedReason, release_text_followup
from zacai.interfaces import text_reply_capture as module
from zacai.interfaces.followup_authorization import (
    CanonicalFollowupAuthorization,
    ClaimedFollowup,
    FollowupClaim,
    FollowupConsent,
    FollowupHostSnapshot,
    scope_from_snapshot,
)
from zacai.policy import Destination
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    state = assembly_fixture.__wrapped__(monkeypatch)
    saved = state.client.capture(**state.inputs)
    assembled = assemble(state, saved)
    request = prepare_followup_request(assembled.context)
    route = ModelRoute(
        identity=RouteIdentity(provider_id="invented", model_id="invented", runtime_id="invented"),
        destination=Destination.LOCAL,
        capabilities=frozenset({"packet_followup"}),
        max_input_characters=64_000,
        max_output_tokens=512,
        estimated_latency_ms=0,
        estimated_cost_usd=0,
        available=True,
    )
    scope = scope_from_snapshot(
        FollowupHostSnapshot(
            assembled, state.inputs["principal"], state.client._owner(), route, "1" * 64
        ),
        run_id=uuid4(),
        builder_id=uuid4(),
    )
    consent = FollowupConsent(
        id=uuid4(),
        scope=scope,
        approved_at=state.now,
        expires_at=state.now + timedelta(minutes=5),
        human_reference="invented explicit decision",
    )
    consent_raw = canonical_bytes(consent.model_dump(mode="json"))
    consent_ref = saved.reference.model_copy(
        update={"source_id": uuid4(), "content_hash": content_hash_of(consent_raw)}
    )
    claim = FollowupClaim(
        consent_reference=consent_ref,
        run_scope=scope,
        request_digest=request.digest,
        claimed_at=state.now,
    )
    claim_raw = canonical_bytes(claim.model_dump(mode="json"))
    claimed = ClaimedFollowup(
        claim,
        saved.reference.model_copy(
            update={"source_id": uuid4(), "content_hash": content_hash_of(claim_raw)}
        ),
    )
    for ref, raw, system, external, at in (
        (
            consent_ref,
            consent_raw,
            SourceSystem.USER_INSTRUCTION,
            f"packet-followup-consent/{consent.id}",
            consent.approved_at,
        ),
        (
            claimed.reference,
            claim_raw,
            SourceSystem.MANUAL,
            f"packet-followup-claim/{consent_ref.source_id}",
            claim.claimed_at,
        ),
    ):
        state.raw[ref.content_hash] = raw
        state.sources[external] = Source(
            id=ref.source_id,
            trust_boundary=ref.trust_boundary,
            data_classification=ref.effective_classification,
            system=system,
            external_ref=external,
            content_hash=ref.content_hash,
            content_location=ref.content_hash,
            captured_at=at,
        )
    state.claim_denied = False
    state.claim_checks = 0

    def claim_check(self, actual, prepared):
        state.claim_checks += 1
        assert actual == claimed and prepared.digest == request.digest
        if state.claim_denied:
            raise ValueError("PRIVATE expired or revoked grant")

    monkeypatch.setattr(CanonicalFollowupAuthorization, "recheck", claim_check)
    authorization = object.__new__(CanonicalFollowupAuthorization)
    draft = FollowupDraft(
        task_id=request.context.task.task_id,
        user_source_id=saved.source_id,
        user_content_hash=saved.turn_digest,
        packet_digest=scope.packet_reference.content_hash,
        unsupported=UnsupportedReason.OUTSIDE_PACKET,
    )
    state.release_gate = Gate()
    release = release_text_followup(request.context, draft, gate=state.release_gate)
    state.reply_receipts = {}
    state.reply_fail = False
    state.reply_after_recheck = None

    class Protection:
        def protect(self, scope):
            assert state.active_sessions == 0
            assert any(s.id == scope.source_id for s in state.sources.values())
            if state.reply_fail:
                raise ValueError("PRIVATE failed recovery")
            if scope.source_id not in state.reply_receipts:
                state.reply_receipts[scope.source_id] = module.TextReplyRecoveryReceipt(
                    source_id=scope.source_id,
                    reply_digest=scope.reply_digest,
                    captured_at=scope.captured_at,
                    verified_at=state.now,
                    artifact_backup_run_id=uuid4(),
                    artifact_ciphertext_hash="4" * 64,
                    state_ciphertext_hash="5" * 64,
                    state_plaintext_hash="6" * 64,
                    journal_ciphertext_hash="7" * 64,
                    journal_plaintext_hash="8" * 64,
                )
            return state.reply_receipts[scope.source_id]

        def recheck(self, scope, receipt):
            assert state.active_sessions == 0
            assert state.reply_receipts[scope.source_id] == receipt
            if state.reply_after_recheck:
                state.reply_after_recheck()

    def record(session, **fields):
        source = Source(id=uuid4(), **fields)
        session.pending[source.external_ref] = source
        return source, True

    monkeypatch.setattr(module, "record_source", record)
    monkeypatch.setattr(module, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(module, "_lock", lambda session, id: None)
    monkeypatch.setattr(module, "_find", lambda session, ref, system: state.sources.get(ref))
    monkeypatch.setattr(
        module,
        "get_effective_source_classification",
        lambda session, source_id: session.get(Source, source_id).data_classification,
    )
    state.replies = module.CanonicalTextReplyCapture(
        assembler=state.assembler,
        authorization=authorization,
        release_gate=state.release_gate,
        protection=Protection(),
    )
    state.reply_inputs = {
        "principal": state.inputs["principal"],
        "request": request,
        "claimed": claimed,
        "release": release,
        "usage": UsageObservation(input_tokens=10, output_tokens=20, latency_ms=5, cost_usd=0),
        "retained_receipt": state.receipt,
        "text_receipt": saved.recovery_receipt,
    }

    return state


def load(state, saved):
    return state.replies.load(
        principal=state.reply_inputs["principal"],
        source_id=saved.source_id,
        expected_reply_digest=saved.reply_digest,
        retained_receipt=state.receipt,
        text_receipt=state.reply_inputs["text_receipt"],
        recovery_receipt=saved.recovery_receipt,
    )


def test_generated_reply_committed_then_protected_exact_bytes_and_retry(fixture):
    s = fixture
    saved = s.replies.capture(**s.reply_inputs)
    source = next(v for v in s.sources.values() if v.id == saved.source_id)
    assert source.system == SourceSystem.MANUAL
    assert source.external_ref == f"text-reply/{saved.reply.request_id}"
    assert saved.reply.kind == "generated_followup_reply"
    assert module.decode_text_reply(module.encode_text_reply(saved.reply)) == saved.reply
    assert source.content_hash == content_hash_of(module.encode_text_reply(saved.reply))
    assert load(s, saved) == saved
    s.now += timedelta(seconds=1)
    assert s.replies.capture(**s.reply_inputs) == saved
    assert len([v for v in s.sources.values() if v.external_ref.startswith("text-reply/")]) == 1
    assert not saved.processing_authorized and not saved.execution_authorized
    assert saved.reply.display_text not in repr(saved)


def test_recovery_failure_leaves_pending_identical_retry_not_visible(fixture):
    s = fixture
    s.reply_fail = True
    with pytest.raises(module.TextReplyCaptureError):
        s.replies.capture(**s.reply_inputs)
    pending = [v for v in s.sources.values() if v.external_ref.startswith("text-reply/")]
    assert len(pending) == 1 and not s.reply_receipts
    s.reply_fail = False
    saved = s.replies.capture(**s.reply_inputs)
    assert saved.source_id == pending[0].id


@pytest.mark.parametrize("gate", ["claim", "release"])
def test_current_gate_denial_before_reply_write(fixture, gate):
    s = fixture
    if gate == "claim":
        s.claim_denied = True
    else:
        s.release_gate.deny = True
    with pytest.raises(module.TextReplyCaptureError) as error:
        s.replies.capture(**s.reply_inputs)
    assert error.value.__context__ is None
    assert not [v for v in s.sources.values() if v.external_ref.startswith("text-reply/")]


def test_forged_release_text_denied_before_write(fixture):
    s = fixture
    from dataclasses import replace

    forged = replace(s.reply_inputs["release"], text="PRIVATE fabricated completion")
    with pytest.raises(module.TextReplyCaptureError):
        s.replies.capture(**{**s.reply_inputs, "release": forged})
    assert not s.reply_receipts


def test_revocation_during_long_recovery_holds_existing_reply(fixture):
    s = fixture
    saved = s.replies.capture(**s.reply_inputs)
    s.reply_after_recheck = lambda: setattr(s, "claim_denied", True)
    with pytest.raises(module.TextReplyCaptureError):
        load(s, saved)


def test_conflicting_usage_same_attempt_denied_not_new_source(fixture):
    s = fixture
    s.replies.capture(**s.reply_inputs)
    usage = s.reply_inputs["usage"].model_copy(update={"output_tokens": 21})
    with pytest.raises(module.TextReplyCaptureError):
        s.replies.capture(**{**s.reply_inputs, "usage": usage})
    assert len(s.reply_receipts) == 1


@pytest.mark.parametrize("mutation", ["unknown", "duplicate", "whitespace", "kind", "identity"])
def test_codec_exact_shape_canonical_bytes_and_no_human_impersonation(fixture, mutation):
    saved = fixture.replies.capture(**fixture.reply_inputs)
    raw = module.encode_text_reply(saved.reply)
    if mutation == "unknown":
        raw = raw[:-1] + b',"execution_authorized":true}'
    elif mutation == "duplicate":
        raw = raw[:-1] + b',"kind":"generated_followup_reply"}'
    elif mutation == "whitespace":
        raw = b" " + raw
    else:
        data = saved.reply.model_dump(mode="json")
        data["kind" if mutation == "kind" else "request_id"] = (
            "user_input" if mutation == "kind" else str(uuid4())
        )
        raw = canonical_bytes(data)
    with pytest.raises(module.TextReplyCaptureError) as error:
        module.decode_text_reply(raw)
    assert error.value.__context__ is None


def test_dependency_acl_change_inside_semantic_gate_holds_final_ack(fixture):
    s = fixture
    saved = s.replies.capture(**s.reply_inputs)
    original = s.release_gate.recheck
    ref = saved.reply.claim.run_scope.packet_reference

    def changed(context, draft):
        from zacai.policy import DataClassification

        original(context, draft)
        next(
            v for v in s.sources.values() if v.id == ref.source_id
        ).data_classification = DataClassification.HIGHLY_RESTRICTED

    s.release_gate.recheck = changed
    with pytest.raises(module.TextReplyCaptureError):
        load(s, saved)


@pytest.mark.parametrize(
    "update", [{"output_tokens": 513}, {"latency_ms": 60_001}, {"cost_usd": 0.01}]
)
def test_reported_usage_above_exact_claim_ceiling_holds_before_write(fixture, update):
    s = fixture
    usage = s.reply_inputs["usage"].model_copy(update=update)
    with pytest.raises(module.TextReplyCaptureError):
        s.replies.capture(**{**s.reply_inputs, "usage": usage})
    assert not s.reply_receipts


def test_processing_deadline_crossed_inside_semantic_gate_holds_final_ack(fixture):
    s = fixture
    saved = s.replies.capture(**s.reply_inputs)
    original = s.release_gate.recheck

    def expired(context, draft):
        original(context, draft)
        s.now += timedelta(minutes=6)

    s.release_gate.recheck = expired
    with pytest.raises(module.TextReplyCaptureError):
        load(s, saved)


def pending(state):
    state.reply_fail = True
    with pytest.raises(module.TextReplyCaptureError):
        state.replies.capture(**state.reply_inputs)
    source = next(v for v in state.sources.values() if v.external_ref.startswith("text-reply/"))
    state.reply_fail = False
    return source


def recover_pending(state, source):
    return state.replies.protect_pending(principal=state.reply_inputs["principal"],
                                        source_id=source.id, expected_reply_digest=source.content_hash)


def test_expired_pending_reply_receipt_only_recovery_not_processing_or_display(fixture):
    s = fixture
    source = pending(s)
    original_bytes = s.raw[source.content_hash]
    s.now += timedelta(minutes=6)
    s.claim_denied = True
    checks = s.claim_checks
    s.release_gate.deny = True
    receipt = recover_pending(s, source)
    assert type(receipt) is module.TextReplyRecoveryReceipt
    assert not hasattr(receipt, "reply") and not hasattr(receipt, "display_text")
    assert receipt.source_id == source.id and receipt.reply_digest == source.content_hash
    assert s.raw[source.content_hash] == original_bytes
    assert s.claim_checks == checks  # No expired claim renewal or processing gate invoked.
    with pytest.raises(module.TextReplyCaptureError):
        s.replies.load(principal=s.reply_inputs["principal"], source_id=source.id,
                       expected_reply_digest=source.content_hash, retained_receipt=s.receipt,
                       text_receipt=s.reply_inputs["text_receipt"], recovery_receipt=receipt)
    with pytest.raises(module.TextReplyCaptureError):
        s.replies.capture(**s.reply_inputs)


@pytest.mark.parametrize("mutation", ["owner", "acl", "hash", "claim_bytes", "consent_bytes"])
def test_pending_recovery_current_binding_and_original_authority_hold_before_protection(fixture, mutation):
    s = fixture
    source = pending(s)
    digest = source.content_hash
    if mutation == "owner":
        from zacai.interfaces.private_web import OwnerGrant
        from zacai.interfaces.session_store import Identity

        original_owner = s.client._owner()
        s.client._owner = lambda: OwnerGrant(Identity("https://accounts.google.com", "changed-owner"), original_owner.scopes)
    elif mutation == "acl":
        from zacai.policy import DataClassification

        source.data_classification = DataClassification.HIGHLY_RESTRICTED
    elif mutation == "hash":
        digest = "f" * 64
    else:
        reply = module.decode_text_reply(s.raw[source.content_hash])
        ref = reply.claim_reference if mutation == "claim_bytes" else reply.claim.consent_reference
        s.raw[ref.content_hash] = b'{"malformed_original_authority":true}'
    with pytest.raises(module.TextReplyCaptureError) as error:
        s.replies.protect_pending(principal=s.reply_inputs["principal"], source_id=source.id,
                                 expected_reply_digest=digest)
    assert not s.reply_receipts
    assert error.value.__context__ is None


def test_pending_recovery_rechecks_owner_after_expensive_protection(fixture):
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    s = fixture
    source = pending(s)
    original_owner = s.client._owner()
    s.reply_after_recheck = lambda: setattr(s.client, "_owner", lambda: OwnerGrant(
        Identity("https://accounts.google.com", "changed-during-recovery"), original_owner.scopes))
    with pytest.raises(module.TextReplyCaptureError):
        recover_pending(s, source)
    assert source.id in s.reply_receipts  # Durable recovery is not owner acknowledgement.


def rewrite_original_consent(state, source, *, approved_at):
    """Invented fully rebound canonical records; not a genuine authority write."""
    reply = module.decode_text_reply(state.raw[source.content_hash])
    old_ref = reply.claim.consent_reference
    consent = module.FollowupConsent.model_validate_json(state.raw[old_ref.content_hash])
    consent = consent.model_copy(update={"approved_at": approved_at,
                                         "expires_at": approved_at + timedelta(minutes=5)})
    raw = canonical_bytes(consent.model_dump(mode="json"))
    ref = old_ref.model_copy(update={"content_hash": content_hash_of(raw)})
    consent_source = next(v for v in state.sources.values() if v.id == ref.source_id)
    consent_source.content_hash = consent_source.content_location = ref.content_hash
    consent_source.captured_at = approved_at
    state.raw[ref.content_hash] = raw
    claim = reply.claim.model_copy(update={"consent_reference": ref})
    claim_raw = canonical_bytes(claim.model_dump(mode="json"))
    claim_ref = reply.claim_reference.model_copy(update={"content_hash": content_hash_of(claim_raw)})
    claim_source = next(v for v in state.sources.values() if v.id == claim_ref.source_id)
    claim_source.content_hash = claim_source.content_location = claim_ref.content_hash
    state.raw[claim_ref.content_hash] = claim_raw
    reply = reply.model_copy(update={"claim": claim, "claim_reference": claim_ref,
                                    "request_id": module.text_reply_request_id(claim.run_scope.run_id, claim_ref, claim.request_digest)})
    raw = module.encode_text_reply(reply)
    source.content_hash = source.content_location = content_hash_of(raw)
    source.external_ref = f"text-reply/{reply.request_id}"
    state.raw[source.content_hash] = raw
    return reply


@pytest.mark.parametrize("offset", [timedelta(seconds=1), timedelta(minutes=-6)])
def test_pending_recovery_denies_fully_rebound_claim_outside_original_consent(fixture, offset):
    s = fixture
    source = pending(s)
    rewrite_original_consent(s, source, approved_at=s.now + offset)
    s.now += timedelta(minutes=6)
    with pytest.raises(module.TextReplyCaptureError):
        recover_pending(s, source)
    assert not s.reply_receipts


@pytest.mark.parametrize("elapsed", [timedelta(minutes=5), timedelta(minutes=6)])
def test_original_record_timestamp_at_or_after_deadline_holds_recovery_only(fixture, elapsed):
    s = fixture
    source = pending(s)
    s.now += elapsed
    reply = module.decode_text_reply(s.raw[source.content_hash]).model_copy(update={"recorded_at": s.now})
    raw = module.encode_text_reply(reply)
    source.content_hash = source.content_location = content_hash_of(raw)
    source.captured_at = reply.recorded_at
    s.raw[source.content_hash] = raw
    s.claim_denied = True
    with pytest.raises(module.TextReplyCaptureError):
        recover_pending(s, source)
    assert not s.reply_receipts  # Only genuinely timely committed history is preservable.


@pytest.mark.parametrize("mutation", ["acl", "hash"])
def test_pending_recovery_dependency_changed_during_protection_withholds_receipt(fixture, mutation):
    from zacai.policy import DataClassification

    s = fixture
    source = pending(s)
    reply = module.decode_text_reply(s.raw[source.content_hash])
    dependency = next(v for v in s.sources.values() if v.id == reply.claim.run_scope.packet_reference.source_id)

    def change():
        if mutation == "acl":
            dependency.data_classification = DataClassification.HIGHLY_RESTRICTED
        else:
            dependency.content_hash = "f" * 64

    s.reply_after_recheck = change
    with pytest.raises(module.TextReplyCaptureError):
        recover_pending(s, source)
    assert source.id in s.reply_receipts
