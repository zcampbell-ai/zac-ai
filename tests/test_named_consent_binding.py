"""Actual session/canonical inventory; SQL and protected receipt mocked.

These test protocol composition/expiry separation, not crypto or SQL restoration.
Actual encrypted resolver mechanics have separate invented local-age tests.
"""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_named_decision_admission import commit_declared
from tests.test_named_decision_admission import fixture as admission_fixture
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.interfaces import named_consent_binding as m
from zacai.interfaces import named_decision_inventory
from zacai.interfaces.named_decision_capture import NamedDecisionRecoveryReceipt
from zacai.interfaces.named_decision_recovery import BrainstormNamedDecisionRecovery
from zacai.interfaces.named_followup_decision import named_decision_consent_id
from zacai.interfaces.named_recovery_inputs import (
    RetainedNamedDecisionProofs,
    RetainedQuestionRecoveryInputs,
)
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    s = admission_fixture.__wrapped__(tmp_path, monkeypatch)
    decision = s.adapter.resolve(*s.resolve_args)
    row = commit_declared(s, decision, attach=True)
    record = s.store.get(
        handle=s.issued.handle, session_binding=s.operation.establish().binding_digest
    )
    receipt = NamedDecisionRecoveryReceipt(
        source_id=row.id,
        decision_digest=row.content_hash,
        captured_at=decision.admitted_at,
        verified_at=s.now,
        artifact_backup_run_id=uuid4(),
        artifact_ciphertext_hash="1" * 64,
        state_ciphertext_hash="2" * 64,
        state_plaintext_hash="3" * 64,
        journal_ciphertext_hash="4" * 64,
        journal_plaintext_hash="5" * 64,
        inventory_digest="6" * 64,
        key_proof_digest="7" * 64,
    )
    digest = content_hash_of(canonical_bytes(receipt.model_dump(mode="json")))
    s.consent = m.FollowupConsentV2(
        id=named_decision_consent_id(row.id),
        scope=decision.run_scope,
        approved_at=decision.admitted_at,
        expires_at=decision.processing_expires_at,
        human_reference="invented actual canonical selection",
        decision_reference=record.decision_reference,
        decision_recovery_digest=digest,
    )
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._approval_id = None
    p._factory = s.client._factory
    p._artifacts = s.client._artifacts
    q = BrainstormTextTurnProtection.__new__(BrainstormTextTurnProtection)
    q._protector = p
    q._clock = s.clock
    d = BrainstormNamedDecisionRecovery.__new__(BrainstormNamedDecisionRecovery)
    d._protector = p
    d._clock = s.clock
    resolver = RetainedQuestionRecoveryInputs(protector=p, question_protection=q, clock=s.clock)
    s.client._protection = q
    s.adapter._recovery_inputs = resolver
    proofs = RetainedNamedDecisionProofs(question_inputs=resolver, decision_recovery=d)
    s.calls = []

    def proof(projected):
        assert s.active_sessions == 0
        assert projected.decision_reference == s.consent.decision_reference
        assert projected.decision_recovery_digest == s.consent.decision_recovery_digest
        s.calls.append(projected)
        return receipt

    monkeypatch.setattr(proofs, "resolve_decision", proof)
    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(named_decision_inventory, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(
        named_decision_inventory,
        "get_effective_source_classification",
        lambda session, source_id: session.get(m.Source, source_id).data_classification,
    )
    s.binding = m.CanonicalNamedFollowupConsentBinding(
        admission=s.adapter,
        recovery_inputs=resolver,
        decision_proofs=proofs,
        clock=s.clock,
    )
    s.resolver, s.decision_proofs, s.decision, s.decision_source = (
        resolver,
        proofs,
        decision,
        row,
    )
    return s


def test_fresh_and_readonly_rows_actual_canonical_binding(fixture):
    s = fixture
    assert s.binding.host_clock is s.clock
    assert s.binding.verify_fresh(s.consent, s.now) is None and s.calls
    with s.client._factory() as session:
        before = len(s.calls)
        assert s.binding.verify_rows(session, s.consent, s.now) is None
        assert len(s.calls) == before


def test_expired_history_does_not_read_active_operational_store(fixture, monkeypatch):
    s = fixture
    s.now = s.consent.expires_at + timedelta(seconds=1)

    def no_active_get(**kwargs):
        raise AssertionError("expired active store lookup")

    monkeypatch.setattr(s.store, "get", no_active_get)
    assert s.binding.verify_fresh(s.consent, s.now) is None
    assert s.calls[-1].processing_expires_at == s.consent.expires_at
    with pytest.raises(m.NamedConsentBindingError):
        s.binding.verify_active(handle=s.issued.handle, consent=s.consent, now=s.now)


@pytest.mark.parametrize("failure", ["receipt", "current_owner", "final_acl"])
def test_private_callback_or_current_acl_holds(fixture, monkeypatch, failure):
    s = fixture
    if failure == "receipt":
        monkeypatch.setattr(s.decision_proofs, "resolve_decision", lambda record: True)
    elif failure == "current_owner":
        monkeypatch.setattr(s.adapter, "recheck_session", lambda *args: True)
    else:
        original = s.adapter.recheck_session
        calls = []

        def last(*args):
            result = original(*args)
            calls.append(None)
            assert s.active_sessions == 0
            if len(calls) == 2:
                s.decision_source.data_classification = C.HIGHLY_RESTRICTED
            return result

        monkeypatch.setattr(s.adapter, "recheck_session", last)
    with pytest.raises(m.NamedConsentBindingError) as caught:
        s.binding.verify_fresh(s.consent, s.now)
    assert caught.value.__context__ is None


def test_active_method_uses_actual_original_handle_and_session(fixture, monkeypatch):
    from zacai.interfaces.named_decision_admission import QuestionRecoveryInputs

    s = fixture
    # Explicit restoration mocks only; actual encrypted session/admission
    # stores, canonical decision/assembler and original handle checks remain.
    monkeypatch.setattr(
        type(s.resolver),
        "__call__",
        lambda self, record: QuestionRecoveryInputs(s.receipt, s.reply_inputs["text_receipt"]),
    )
    monkeypatch.setattr(s.client._protection, "recheck", lambda *args: None)
    assert s.binding.verify_active(handle=s.issued.handle, consent=s.consent, now=s.now) is None
    with pytest.raises(m.NamedConsentBindingError):
        s.binding.verify_active(handle="x" * 43, consent=s.consent, now=s.now)
    cookie = s.sessions.start_user(s.owner.identity, s.now)
    s.adapter._operation = s.session_helper.for_cookie(cookie)
    # Current same-owner session can preserve protected history.
    assert s.binding.verify_fresh(s.consent, s.now) is None
    # It cannot replay original processing admission from a different cookie.
    with pytest.raises(m.NamedConsentBindingError):
        s.binding.verify_active(handle=s.issued.handle, consent=s.consent, now=s.now)


def test_advancing_recovery_clock_preserves_original_history_after_ttl(fixture, monkeypatch):
    s = fixture
    original = s.decision_proofs.resolve_decision
    original_decision = s.decision
    original_consent = s.consent
    original_now = s.now

    def long_recovery(record):
        receipt = original(record)
        assert s.active_sessions == 0
        s.now = s.consent.expires_at + timedelta(seconds=1)
        return receipt

    monkeypatch.setattr(s.decision_proofs, "resolve_decision", long_recovery)
    assert s.binding.verify_fresh(s.consent, original_now) is None
    assert s.now > s.consent.expires_at
    assert s.decision == original_decision and s.consent == original_consent
    assert s.calls[-1].admitted_at == original_decision.admitted_at
    assert s.calls[-1].processing_expires_at == original_decision.processing_expires_at


@pytest.mark.parametrize("timing", ["valid_later", "expiry", "rollback"])
def test_post_admission_clock_observation_controls_active_ack(fixture, monkeypatch, timing):
    from zacai.interfaces.named_decision_admission import QuestionRecoveryInputs

    s = fixture
    monkeypatch.setattr(
        type(s.resolver),
        "__call__",
        lambda self, record: QuestionRecoveryInputs(s.receipt, s.reply_inputs["text_receipt"]),
    )
    monkeypatch.setattr(s.client._protection, "recheck", lambda *args: None)
    original = s.adapter.recheck
    original_observed = s.decision.original_observed_at
    original_deadline = s.consent.expires_at
    original_now = s.now

    def slower(*args):
        result = original(*args)
        assert s.active_sessions == 0
        if timing == "valid_later":
            s.now = original_now + timedelta(seconds=2)
        elif timing == "expiry":
            s.now = original_deadline
        else:
            s.now = original_now - timedelta(seconds=1)
        return result

    monkeypatch.setattr(s.adapter, "recheck", slower)
    if timing == "valid_later":
        assert (
            s.binding.verify_active(handle=s.issued.handle, consent=s.consent, now=original_now)
            is None
        )
    else:
        with pytest.raises(m.NamedConsentBindingError):
            s.binding.verify_active(handle=s.issued.handle, consent=s.consent, now=original_now)
    assert s.decision.original_observed_at == original_observed
    assert s.consent.expires_at == original_deadline
