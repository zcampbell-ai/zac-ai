"""Actual codecs/canonical memory Sources; host/recovery graph deliberately mocked.

No live session, model, PostgreSQL or independent recovery readiness proof.
These regressions test deterministic lookup after lost acknowledgement only.
"""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.test_v2_final_release import fixture as reply_fixture
from zacai.interfaces import named_question_pipeline as m
from zacai.interfaces.named_consent_binding import CanonicalNamedFollowupConsentBinding
from zacai.interfaces.named_recovery_inputs import RetainedNamedDecisionProofs
from zacai.interfaces.named_session_binding import (
    NamedSessionOperation,
    VerifiedNamedSession,
)
from zacai.interfaces.text_reply_capture import (
    HistoricalReplyStatus,
    SavedHistoricalTextReply,
)
from zacai.interfaces.text_reply_protection import BrainstormTextReplyProtection


@pytest.fixture
def fixture(monkeypatch):
    s = reply_fixture.__wrapped__(monkeypatch)
    clock = s.authority._clock
    s.client._clock = clock
    s.principal = s.inputs["principal"]
    operation = object.__new__(NamedSessionOperation)
    operation._host_clock = lambda: clock
    operation._read = lambda: VerifiedNamedSession(
        s.principal,
        "a" * 64,
        s.now - timedelta(hours=1),
        s.now + timedelta(hours=1),
        s.now + timedelta(minutes=30),
    )
    s.operation = operation
    pipeline = object.__new__(m.CanonicalNamedAskPipeline)
    pipeline._turns, pipeline._clock, pipeline._assembler = s.client, clock, s.assembler
    s.pipeline = pipeline
    pipeline._question_inputs = lambda record: SimpleNamespace(
        packet_receipt=s.receipt, question_receipt=s.saved.recovery_receipt
    )
    monkeypatch.setattr(m, "_find_named", lambda session, key: s.sources.get(key))
    # No protocol-only gate is installed. Exact-class fixtures bypass constructor
    # solely to isolate lookup; their actual recovery calls are explicitly mocked.
    previous_binding = s.replies._named_binding
    binding = object.__new__(CanonicalNamedFollowupConsentBinding)
    binding._clock = clock
    proofs = object.__new__(RetainedNamedDecisionProofs)
    binding._decision_proofs = proofs
    monkeypatch.setattr(
        RetainedNamedDecisionProofs,
        "resolve_decision",
        lambda self, record: (
            None
            if record.decision_reference == s.consent.decision_reference
            and record.decision_recovery_digest == s.consent.decision_recovery_digest
            else (_ for _ in ()).throw(ValueError("invented proof mismatch"))
        ),
    )
    monkeypatch.setattr(
        CanonicalNamedFollowupConsentBinding,
        "verify_fresh",
        lambda self, consent, now: previous_binding.verify_fresh(consent, now),
    )
    s.replies._named_binding = binding
    previous_protection = s.replies._protection
    protection = object.__new__(BrainstormTextReplyProtection)
    s.receipt_present = True
    s.receipt_corrupt = False
    protection._protector = SimpleNamespace(
        _reader=SimpleNamespace(exists=lambda key: s.receipt_present)
    )

    def retained(self, key):
        if s.receipt_corrupt:
            raise ValueError("invented corrupt receipt")
        assert key == s.saved_reply.recovery_receipt.receipt_object
        return s.saved_reply.recovery_receipt

    monkeypatch.setattr(BrainstormTextReplyProtection, "_load_receipt", retained)
    monkeypatch.setattr(
        BrainstormTextReplyProtection,
        "recheck",
        lambda self, scope, receipt: previous_protection.recheck(scope, receipt),
    )
    s.replies._protection = protection
    monkeypatch.setattr(
        m.CanonicalNamedAskPipeline,
        "_history_components",
        lambda self, operation, record: s.replies,
    )

    forbidden_calls = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append((args, kwargs))
        raise AssertionError("no generation/admission/claim/renewal in reconcile")

    pipeline._build = pipeline._active = pipeline._build_history = forbidden
    s.authority.record = s.authority.claim = forbidden
    s.forbidden_calls = forbidden_calls
    return s


def test_lost_capture_acknowledgement_resolves_canonical_reply_after_original_expiry(
    fixture,
):
    s = fixture
    s.now = s.consent.expires_at + timedelta(seconds=1)
    result = s.pipeline.reconcile(
        operation=s.operation, decision_reference=s.consent.decision_reference
    )
    assert type(result) is SavedHistoricalTextReply
    assert result.saved == s.saved_reply and result.original_permission_expired
    assert not result.processing_authorized
    assert s.forbidden_calls == []


def test_missing_retained_receipt_returns_status_not_generation_or_repair(fixture):
    s = fixture
    s.receipt_present = False
    result = s.pipeline.reconcile(
        operation=s.operation, decision_reference=s.consent.decision_reference
    )
    assert type(result) is HistoricalReplyStatus and result.protection_pending
    assert result.source_id == s.saved_reply.source_id and not hasattr(result, "saved")
    assert s.forbidden_calls == []


@pytest.mark.parametrize(
    "fault", ["receipt", "reply_hash", "claim_hash", "decision_selector"]
)
def test_corrupt_or_substituted_original_provenance_holds_reconcile(fixture, fault):
    s = fixture
    reference = s.consent.decision_reference
    if fault == "receipt":
        s.receipt_corrupt = True
    elif fault == "reply_hash":
        next(
            r for r in s.sources.values() if r.id == s.saved_reply.source_id
        ).content_hash = "f" * 64
    elif fault == "claim_hash":
        next(
            r
            for r in s.sources.values()
            if r.id == s.saved_reply.reply.claim_reference.source_id
        ).content_hash = "f" * 64
    else:
        reference = reference.model_copy(update={"content_hash": "f" * 64})
    with pytest.raises(m.NamedQuestionPipelineError):
        s.pipeline.reconcile(operation=s.operation, decision_reference=reference)
    assert s.forbidden_calls == []
