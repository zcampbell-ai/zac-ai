"""Actual V2 codecs/Source inventory/ledger; invented SQL and recovery seams.

No model, network, real SQL, credentials or actual owner admission is used.
"""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_followup_authorization import fixture as ledger_fixture
from tests.test_text_followup import Gate
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import EvidenceReference, UsageObservation
from zacai.intelligence.text_followup import FollowupDraft, UnsupportedReason, release_text_followup
from zacai.interfaces import named_decision_capture, named_decision_inventory, text_reply_capture
from zacai.interfaces.followup_authorization import FollowupConsentV2
from zacai.interfaces.named_followup_decision import (
    ManifestUserParent,
    NamedFollowupDecision,
    NamedFollowupManifest,
    encode_named_decision,
    named_decision_consent_id,
    named_manifest_digest,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    s = ledger_fixture.__wrapped__(monkeypatch)
    clock = s.authority._clock
    s.client._clock = clock
    scope = s.scope
    turn = s.saved.turn
    admitted = turn.recorded_at - timedelta(seconds=1)
    manifest = NamedFollowupManifest(
        actor_issuer=scope.actor_issuer,
        actor_subject=scope.actor_subject,
        owner_grant_digest=scope.owner_grant_digest,
        conversation_id=scope.conversation_id,
        request_id=turn.request_id,
        run_id=scope.run_id,
        builder_id=scope.builder_id,
        nonce_digest="9" * 64,
        issued_at=admitted,
        admission_expires_at=admitted + timedelta(minutes=5),
        processing_ttl_seconds=300,
        packet_reference=scope.packet_reference,
        packet_receipt_digest=scope.packet_receipt_digest,
        evidence_references=tuple(i.reference for i in s.request.context.packet.task.context),
        parents=tuple(ManifestUserParent(reference=ref) for ref in scope.parent_references),
        route=scope.route,
        model_digest=scope.model_digest,
        runtime_endpoint="http://127.0.0.1:11434",
        tokenizer_digest="b" * 64,
        request_template_digest="c" * 64,
        max_output_tokens=scope.max_output_tokens,
        max_latency_ms=scope.max_latency_ms,
        max_estimated_cost_usd=scope.max_estimated_cost_usd,
    )
    decision = NamedFollowupDecision(
        manifest=manifest,
        manifest_digest=named_manifest_digest(manifest),
        admitted_at=admitted,
        processing_expires_at=admitted + timedelta(minutes=5),
        bound_at=s.now,
        original_observed_at=s.request.context.task.event.observed_at,
        session_binding_digest="a" * 64,
        question_reference=s.saved.reference,
        original_utf8_digest=content_hash_of(turn.original_text.encode()),
        question_receipt_digest=scope.text_receipt_digest,
        prepared_request_digest=s.request.digest,
        run_scope=scope,
    )
    raw = encode_named_decision(decision)
    row = Source(
        id=uuid4(),
        system=SourceSystem.USER_INSTRUCTION,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        content_hash=content_hash_of(raw),
        content_location=content_hash_of(raw),
        external_ref=f"packet-followup-named-decision/{turn.request_id}",
        captured_at=admitted,
    )
    s.sources[row.external_ref], s.raw[row.content_hash], s.decision_row = row, raw, row
    ref = EvidenceReference(
        source_id=row.id,
        content_hash=row.content_hash,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )

    class Binding:
        host_clock = clock

        def verify_fresh(self, consent, now):
            assert s.active_sessions == 0
            with s.client._factory() as session:
                named_decision_inventory.load_named_decision_inventory(
                    session, artifacts=s.client._artifacts, reference=ref, as_of=now
                )

        def verify_rows(self, session, consent, now):
            assert s.active_sessions == 1
            named_decision_inventory.load_named_decision_inventory(
                session, artifacts=s.client._artifacts, reference=ref, as_of=now
            )

    s.binding = Binding()
    s.authority._recovery.named_binding = s.binding
    from zacai.interfaces.followup_authorization import CanonicalFollowupAuthorization

    s.authority = CanonicalFollowupAuthorization(
        factory=s.authority._factory,
        store=s.authority._store,
        refresh=s.authority._refresh,
        owner=s.authority._owner,
        recovery=s.authority._recovery,
        clock=clock,
        named_binding=s.binding,
    )
    monkeypatch.setattr(
        named_decision_inventory,
        "get_effective_source_classification",
        lambda session, source_id: session.get(Source, source_id).data_classification,
    )
    # Memory Session has no real SQLAlchemy Connection; the real guarded SQL
    # composition and guard tests are separate. Invoke the actual row binding.
    monkeypatch.setattr(
        named_decision_capture,
        "_checked_rows",
        lambda session, binding, value, now: binding.verify_rows(session, value, now),
    )
    monkeypatch.setattr(named_decision_capture, "_require_request_lock", lambda *a: None)
    s.consent = FollowupConsentV2(
        id=named_decision_consent_id(row.id),
        scope=scope,
        approved_at=admitted,
        expires_at=decision.processing_expires_at,
        human_reference="invented admitted named action",
        decision_reference=ref,
        decision_recovery_digest="d" * 64,
    )
    approval = s.authority.record(s.consent)
    claimed = s.authority.claim(approval_id=approval, scope=scope, request=s.request)
    receipts = {}

    class Protection:
        host_clock = clock
        named_binding = s.binding

        def protect(self, scope):
            assert s.active_sessions == 0
            receipt = text_reply_capture.TextReplyRecoveryReceipt(
                source_id=scope.source_id,
                reply_digest=scope.reply_digest,
                captured_at=scope.captured_at,
                verified_at=clock(),
                artifact_backup_run_id=uuid4(),
                artifact_ciphertext_hash="1" * 64,
                state_ciphertext_hash="2" * 64,
                state_plaintext_hash="3" * 64,
                journal_ciphertext_hash="4" * 64,
                journal_plaintext_hash="5" * 64,
            )
            receipts[scope.source_id] = receipt
            return receipt

        def recheck(self, scope, receipt):
            assert s.active_sessions == 0 and receipts[scope.source_id] == receipt

    def record(session, **fields):
        source = Source(id=uuid4(), **fields)
        session.pending[source.external_ref] = source
        return source, True

    monkeypatch.setattr(text_reply_capture, "record_source", record)
    monkeypatch.setattr(text_reply_capture, "_lock", lambda *a: None)
    monkeypatch.setattr(
        text_reply_capture, "_find", lambda session, ref, system: s.sources.get(ref)
    )
    monkeypatch.setattr(
        text_reply_capture,
        "get_effective_source_classification",
        lambda session, source_id: session.get(Source, source_id).data_classification,
    )
    release_gate = Gate()
    draft = FollowupDraft(
        task_id=s.request.context.task.task_id,
        user_source_id=scope.user_reference.source_id,
        user_content_hash=scope.user_reference.content_hash,
        packet_digest=scope.packet_reference.content_hash,
        unsupported=UnsupportedReason.OUTSIDE_PACKET,
    )
    s.replies = text_reply_capture.CanonicalTextReplyCapture(
        assembler=s.assembler,
        authorization=s.authority,
        release_gate=release_gate,
        protection=Protection(),
    )
    s.saved_reply = s.replies.capture(
        principal=s.inputs["principal"],
        request=s.request,
        claimed=claimed,
        release=release_text_followup(s.request.context, draft, gate=release_gate),
        usage=UsageObservation(input_tokens=10, output_tokens=20, latency_ms=5, cost_usd=0),
        retained_receipt=s.receipt,
        text_receipt=s.saved.recovery_receipt,
    )
    return s


def load(s):
    saved = s.saved_reply
    return s.replies.load(
        principal=s.inputs["principal"],
        source_id=saved.source_id,
        expected_reply_digest=saved.reply_digest,
        retained_receipt=s.receipt,
        text_receipt=s.saved.recovery_receipt,
        recovery_receipt=saved.recovery_receipt,
    )


def test_actual_v2_final_owner_callback_decision_acl_change_holds(fixture):
    s = fixture
    original = s.client._owner
    calls = []

    def owner():
        calls.append(None)
        return original()

    s.client._owner = owner
    assert load(s) == s.saved_reply
    total = len(calls)
    calls.clear()

    def revoked_owner():
        calls.append(None)
        if len(calls) == total:
            assert s.active_sessions == 0
            s.decision_row.data_classification = C.HIGHLY_RESTRICTED
        return original()

    s.client._owner = revoked_owner
    with pytest.raises(text_reply_capture.TextReplyCaptureError):
        load(s)
    assert s.decision_row.data_classification is C.HIGHLY_RESTRICTED


@pytest.mark.parametrize("ending", ["expiry", "revocation"])
def test_new_reply_cannot_backdate_past_last_validation_window(monkeypatch, ending):
    from tests.test_text_reply_capture import fixture as legacy_reply_fixture

    s = legacy_reply_fixture.__wrapped__(monkeypatch)
    original = s.replies._validate

    def long_validation(*args):
        original(*args)
        claimed = s.reply_inputs["claimed"]
        consent_source = next(
            row for row in s.sources.values() if row.id == claimed.claim.consent_reference.source_id
        )
        if ending == "expiry":
            from zacai.interfaces.followup_authorization import decode_followup_consent

            consent = decode_followup_consent(s.raw[consent_source.content_hash])
            s.now = consent.expires_at
        else:
            s.sources[f"packet-followup-revocation/{consent_source.id}"] = Source(
                id=uuid4(),
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=f"packet-followup-revocation/{consent_source.id}",
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                content_hash="a" * 64,
                captured_at=s.now,
            )

    s.replies._validate = long_validation
    with pytest.raises(text_reply_capture.TextReplyCaptureError):
        s.replies.capture(**s.reply_inputs)
    assert not any(row.external_ref.startswith("text-reply/") for row in s.sources.values())


def test_v2_protection_clock_and_named_binding_must_match(fixture):
    from zacai.interfaces.host_clock import HostObservedClock

    s = fixture
    kwargs = {
        "assembler": s.assembler,
        "authorization": s.authority,
        "release_gate": s.replies._release_gate,
    }

    class DifferentProtection:
        host_clock = HostObservedClock(lambda: s.now)
        named_binding = s.binding

    with pytest.raises(text_reply_capture.TextReplyCaptureError):
        text_reply_capture.CanonicalTextReplyCapture(**kwargs, protection=DifferentProtection())


@pytest.mark.parametrize("ending", ["expiry", "revocation"])
def test_artifact_write_window_cannot_commit_stale_reply(monkeypatch, ending):
    from tests.test_text_reply_capture import fixture as legacy_reply_fixture
    from zacai.interfaces.followup_authorization import decode_followup_consent

    s = legacy_reply_fixture.__wrapped__(monkeypatch)
    store = s.client._artifacts
    original = store.put
    consent_source = next(
        row
        for row in s.sources.values()
        if row.id == s.reply_inputs["claimed"].claim.consent_reference.source_id
    )
    consent = decode_followup_consent(s.raw[consent_source.content_hash])

    def slow_put(boundary, digest, raw):
        result = original(boundary, digest, raw)
        if ending == "expiry":
            s.now = consent.expires_at
        else:
            s.sources[f"packet-followup-revocation/{consent_source.id}"] = Source(
                id=uuid4(),
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=f"packet-followup-revocation/{consent_source.id}",
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                content_hash="a" * 64,
                captured_at=s.now,
            )
        return result

    monkeypatch.setattr(store, "put", slow_put)
    with pytest.raises(text_reply_capture.TextReplyCaptureError):
        s.replies.capture(**s.reply_inputs)
    assert not any(row.external_ref.startswith("text-reply/") for row in s.sources.values())


def test_new_reply_uses_locked_time_and_retry_keeps_original(monkeypatch):
    from tests.test_text_reply_capture import fixture as legacy_reply_fixture

    s = legacy_reply_fixture.__wrapped__(monkeypatch)
    original = s.replies._validate

    def slower(*args):
        original(*args)
        s.now += timedelta(seconds=1)

    monkeypatch.setattr(s.replies, "_validate", slower)
    locks = []
    monkeypatch.setattr(
        text_reply_capture, "_lock", lambda session, identity: locks.append(identity)
    )
    initial = s.now
    saved = s.replies.capture(**s.reply_inputs)
    assert saved.reply.recorded_at == initial + timedelta(seconds=1)
    assert locks[:2] == [
        s.reply_inputs["claimed"].claim.consent_reference.source_id,
        saved.reply.request_id,
    ]
    assert s.replies.capture(**s.reply_inputs) == saved


@pytest.mark.parametrize("failure", ["binding", "property"])
def test_v2_protection_binding_and_private_property_fail_closed(fixture, failure):
    s = fixture

    class WrongProtection:
        host_clock = s.client._clock

        @property
        def named_binding(self):
            if failure == "property":
                raise ValueError("PRIVATE dependency information")
            return object()

    with pytest.raises(text_reply_capture.TextReplyCaptureError) as caught:
        text_reply_capture.CanonicalTextReplyCapture(
            assembler=s.assembler,
            authorization=s.authority,
            release_gate=s.replies._release_gate,
            protection=WrongProtection(),
        )
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__context__ is None


@pytest.mark.parametrize("operation", ["protect", "recheck"])
def test_reply_protector_final_named_callback_inventory_mutation_holds(
    tmp_path, monkeypatch, operation
):
    from tests.test_text_reply_protection import protected
    from zacai.interfaces.text_reply_protection import TextReplyProtectionError

    # Actual local age mechanics; inventory/SQL/host binding explicitly mocked.
    s = protected.__wrapped__(tmp_path, monkeypatch)
    receipt = s.gate.protect(s.scope) if operation == "recheck" else None
    s.gate._named_binding = object()
    original = s.gate._hashes
    calls = []
    changed = False

    def fresh(scope):
        nonlocal changed
        assert not s.active and s.p._lease_guard is None
        calls.append(scope)
        if len(calls) == 2:
            changed = True

    def inventory(scope):
        hashes = original(scope)
        if changed:
            hashes[s.scope.source_id] = "f" * 64
        return hashes

    monkeypatch.setattr(s.gate, "_fresh_named", fresh)
    monkeypatch.setattr(s.gate, "_hashes", inventory)
    with pytest.raises(TextReplyProtectionError):
        if operation == "protect":
            s.gate.protect(s.scope)
        else:
            s.gate.recheck(s.scope, receipt)
    assert len(calls) == 2 and changed


def test_concrete_reply_protector_private_clock_property_sanitized(tmp_path, monkeypatch):
    from tests.test_text_reply_protection import protected
    from zacai.interfaces.host_clock import HostObservedClock
    from zacai.interfaces.text_reply_protection import (
        BrainstormTextReplyProtection,
        TextReplyProtectionError,
    )

    s = protected.__wrapped__(tmp_path, monkeypatch)

    class PrivateBinding:
        @property
        def host_clock(self):
            raise ValueError("PRIVATE dependency information")

    with pytest.raises(TextReplyProtectionError) as caught:
        BrainstormTextReplyProtection(
            protector=s.p, clock=HostObservedClock(lambda: s.now), named_binding=PrivateBinding()
        )
    assert "PRIVATE" not in str(caught.value) and caught.value.__context__ is None


def test_v2_pending_repair_owner_callbacks_stay_outside_sql(fixture):
    s = fixture
    original = s.client._owner
    observed = []

    def owner():
        assert s.active_sessions == 0
        observed.append(None)
        return original()

    s.client._owner = owner
    result = s.replies.protect_pending(
        principal=s.inputs["principal"],
        source_id=s.saved_reply.source_id,
        expected_reply_digest=s.saved_reply.reply_digest,
    )
    assert result.source_id == s.saved_reply.source_id
    assert result.reply_digest == s.saved_reply.reply_digest and observed
