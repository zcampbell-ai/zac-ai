"""Invented canonical fixtures and mocked exact session operation, no SQL/proof readiness."""

from datetime import timedelta

import pytest

from tests.test_text_reply_capture import fixture as reply_fixture
from zacai.interfaces import text_reply_capture as m
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import (
    NamedSessionOperation,
    VerifiedNamedSession,
)
from zacai.policy import DataClassification


@pytest.fixture
def fixture(monkeypatch):
    s = reply_fixture.__wrapped__(monkeypatch)
    s.clock = HostObservedClock(lambda: s.now)
    s.client._clock = s.clock
    # Construct after clock injection: no post-construction named-clock bypass.
    old = s.replies
    s.replies = m.CanonicalTextReplyCapture(assembler=s.assembler, authorization=old._authorization,
        release_gate=old._release_gate, protection=old._protection)
    assert s.replies._named_clock is s.clock
    s.saved = s.replies.capture(**s.reply_inputs)
    s.session_denied = False
    s.after_session = None
    s.reads = 0

    def current():
        s.reads += 1
        if s.session_denied:
            raise ValueError("invented revoked session")
        if s.after_session:
            s.after_session()
        return VerifiedNamedSession(s.reply_inputs["principal"], "a" * 64,
                                    s.saved.reply.recorded_at,
                                    s.saved.reply.recorded_at + timedelta(hours=8),
                                    s.saved.reply.recorded_at + timedelta(minutes=30))

    # Exact operation class with invented session read: not production authentication.
    s.operation = object.__new__(NamedSessionOperation)
    s.operation._read = current
    s.operation._host_clock = lambda: s.clock
    s.history = {
        "operation": s.operation, "principal": s.reply_inputs["principal"],
        "source_id": s.saved.source_id, "expected_reply_digest": s.saved.reply_digest,
        "retained_receipt": s.receipt, "text_receipt": s.reply_inputs["text_receipt"],
        "recovery_receipt": s.saved.recovery_receipt,
    }
    return s


def test_expired_history_reads_without_active_claim_recheck_or_generation(fixture):
    s = fixture
    s.now += timedelta(minutes=6)
    s.claim_denied = True
    old_checks = s.claim_checks
    result = s.replies.load_history(**s.history)
    assert type(result) is m.SavedHistoricalTextReply
    assert result.saved == s.saved and result.recorded_at == s.saved.reply.recorded_at
    assert result.original_permission_expired and not result.original_permission_revoked
    assert not result.processing_authorized and not result.execution_authorized
    assert s.claim_checks == old_checks
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load(**{k: v for k, v in s.history.items() if k != "operation"})


def test_missing_receipt_is_status_only_without_repair(fixture):
    s = fixture
    s.reply_fail = True
    result = s.replies.load_history(**{**s.history, "recovery_receipt": None})
    assert type(result) is m.HistoricalReplyStatus and result.protection_pending
    assert not hasattr(result, "reply") and not hasattr(result, "saved")
    assert s.saved.reply.display_text not in repr(result)


@pytest.mark.parametrize("missing", [False, True])
@pytest.mark.parametrize("fault", ["session", "reply_acl", "dependency_acl", "digest", "receipt"])
def test_current_auth_canonical_acl_and_exact_proof_required(fixture, fault, missing):
    s = fixture
    args = {**s.history, "recovery_receipt": None} if missing else dict(s.history)
    if fault == "session":
        s.session_denied = True
    elif fault == "reply_acl":
        next(v for v in s.sources.values() if v.id == s.saved.source_id).data_classification = DataClassification.HIGHLY_RESTRICTED
    elif fault == "dependency_acl":
        ref = s.saved.reply.claim.run_scope.packet_reference
        next(v for v in s.sources.values() if v.id == ref.source_id).data_classification = DataClassification.HIGHLY_RESTRICTED
    elif fault == "digest":
        args["expected_reply_digest"] = "e" * 64
    else:
        # A supplied held receipt never silently downgrades to pending status.
        args["recovery_receipt"] = s.saved.recovery_receipt.model_copy(update={"reply_digest": "e" * 64})
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load_history(**args)


def test_final_session_callback_cannot_leave_elevated_reply_acl(fixture):
    s = fixture
    def elevate():
        if s.reads == 2:
            next(v for v in s.sources.values() if v.id == s.saved.source_id).data_classification = DataClassification.HIGHLY_RESTRICTED
    s.after_session = elevate
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load_history(**s.history)


def test_actual_idle_session_expires_during_final_canonical_rows(fixture, tmp_path, monkeypatch):
    """Actual encrypted sessions; canonical/recovery memory fixtures remain invented."""
    from zacai.interfaces.named_session_binding import NamedSessionContinuity
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.sqlite_sessions import SqliteSessionStore

    s = fixture
    principal = s.reply_inputs["principal"]
    sessions = SqliteSessionStore(tmp_path / "history-session", key=b"x" * 32)
    started = s.now
    cookie = sessions.start_user(principal.identity, started)
    helper = NamedSessionContinuity(sessions=sessions,
        owner=lambda: OwnerGrant(principal.identity, principal.scopes), clock=s.clock,
        key=b"x" * 32, origin="https://caz.example", client_id="invented-client")
    operation = helper.for_cookie(cookie)
    original = operation.establish()
    assert original.effective_expires_at == started + timedelta(minutes=30)
    assert original.expires_at > original.effective_expires_at
    s.now = original.effective_expires_at - timedelta(microseconds=1)
    final_session = False
    recheck = operation.recheck

    def checked(binding):
        nonlocal final_session
        result = recheck(binding)
        final_session = True
        return result

    monkeypatch.setattr(operation, "recheck", checked)
    rows = s.replies._reply_authority_rows

    def final_rows(*args, **kwargs):
        result = rows(*args, **kwargs)
        if final_session:
            s.now = original.effective_expires_at
        return result

    monkeypatch.setattr(s.replies, "_reply_authority_rows", final_rows)
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load_history(**{**s.history, "operation": operation})
    assert final_session
    assert sessions.peek_user(cookie, s.now) is None


def rewrite_original(s, *, parent=False, named=False, monkeypatch=None):
    """Coherently rebound invented canonical bytes; no actual named recovery proof."""
    from dataclasses import replace
    from types import SimpleNamespace
    from uuid import uuid4

    from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
    from zacai.interfaces.followup_authorization import (
        FollowupConsentV2,
        decode_followup_consent,
    )
    from zacai.interfaces.named_followup_decision import named_decision_consent_id
    from zacai.state import Source, SourceSystem

    reply = s.saved.reply
    old_scope = reply.claim.run_scope
    refs = old_scope.parent_references
    if parent:
        # Actual canonical user-instruction parent fixture, separate from evidence.
        saved_parent = s.client.capture(**{**s.inputs, 'request_id': uuid4()})
        refs = (saved_parent.reference,)
    # The actual closed scope requires user and all parents in context refs.
    scope = old_scope.model_copy(update={'context_references':
        (*old_scope.context_references, *(r for r in refs if r not in old_scope.context_references)),
        'parent_references': refs})
    consent_source = next(v for v in s.sources.values() if v.id == reply.claim.consent_reference.source_id)
    consent = decode_followup_consent(s.raw[consent_source.content_hash])
    if named:
        decision_raw = b'invented named decision bytes; canonical inventory is mocked'
        decision_ref = old_scope.packet_reference.model_copy(update={
            'source_id': uuid4(), 'content_hash': content_hash_of(decision_raw)})
        s.raw[decision_ref.content_hash] = decision_raw
        s.sources['invented-named-decision'] = Source(id=decision_ref.source_id,
            trust_boundary=decision_ref.trust_boundary, data_classification=decision_ref.effective_classification,
            system=SourceSystem.USER_INSTRUCTION, external_ref='invented-named-decision',
            content_hash=decision_ref.content_hash, content_location=decision_ref.content_hash,
            captured_at=consent.approved_at)
        consent = FollowupConsentV2(id=named_decision_consent_id(decision_ref.source_id), scope=scope,
            approved_at=consent.approved_at, expires_at=consent.expires_at,
            human_reference='invented original named admission', decision_reference=decision_ref,
            decision_recovery_digest='d' * 64)
    else:
        consent = consent.model_copy(update={'scope': scope})
    def write(source, raw):
        digest = content_hash_of(raw)
        s.raw[digest] = raw
        source.content_hash = source.content_location = digest
        return digest
    consent_digest = write(consent_source, canonical_bytes(consent.model_dump(mode='json')))
    consent_source.external_ref = f'packet-followup-consent/{consent.id}'
    claim = reply.claim.model_copy(update={'run_scope': scope,
        'consent_reference': reply.claim.consent_reference.model_copy(update={'content_hash': consent_digest})})
    claim_source = next(v for v in s.sources.values() if v.id == reply.claim_reference.source_id)
    claim_digest = write(claim_source, canonical_bytes(claim.model_dump(mode='json')))
    claim_ref = reply.claim_reference.model_copy(update={'content_hash': claim_digest})
    reply = m.TextReply.model_validate(reply.model_copy(update={'claim': claim, 'claim_reference': claim_ref,
        'request_id': m.text_reply_request_id(scope.run_id, claim_ref, claim.request_digest)}))
    source = next(v for v in s.sources.values() if v.id == s.saved.source_id)
    digest = write(source, m.encode_text_reply(reply))
    source.external_ref = f'text-reply/{reply.request_id}'
    receipt = s.saved.recovery_receipt.model_copy(update={'reply_digest': digest})
    s.saved = replace(s.saved, reply_digest=digest, reply=reply, recovery_receipt=receipt)
    s.reply_receipts[source.id] = receipt
    s.history.update(expected_reply_digest=digest, recovery_receipt=receipt)
    if named:
        s.named_rows = SimpleNamespace(decision=SimpleNamespace(original_observed_at=reply.original_observed_at,
            prepared_request_digest=claim.request_digest, bound_at=claim.claimed_at))
        s.named_checks = []
        class Binding:
            host_clock = s.clock
            def verify_fresh(self, actual, now):
                assert actual == consent and now == s.now
                s.named_checks.append(now)
        binding = Binding()
        old = s.replies
        old._authorization._named_binding = binding
        old._authorization._clock = s.clock
        old._protection.host_clock = s.clock
        old._protection.named_binding = binding
        s.replies = m.CanonicalTextReplyCapture(assembler=s.assembler, authorization=old._authorization,
            release_gate=old._release_gate, protection=old._protection)
        assert s.replies._named_clock is s.clock
        monkeypatch.setattr(m, 'load_named_consent_inventory', lambda *args, **kwargs: s.named_rows)
    return consent


@pytest.mark.parametrize('which', ['user', 'parent'])
@pytest.mark.parametrize('missing', [False, True])
def test_final_session_callback_rechecks_valid_user_and_parent_dependencies(fixture, monkeypatch, which, missing):
    s = fixture
    rewrite_original(s, parent=which == 'parent')
    ref = s.saved.reply.claim.run_scope.user_reference if which == 'user' else s.saved.reply.claim.run_scope.parent_references[0]
    assert ref in s.saved.reply.claim.run_scope.context_references
    # Parent history fixture uses status-only: real original parent assembly is
    # independently tested by canonical assembler, not invented here.
    args = {**s.history, 'recovery_receipt': None} if missing or which == 'parent' else s.history
    def elevate():
        if s.reads == 2:
            next(v for v in s.sources.values() if v.id == ref.source_id).data_classification = DataClassification.HIGHLY_RESTRICTED
    s.after_session = elevate
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load_history(**args)
    assert s.reads == 2


@pytest.mark.parametrize('named', [False, True])
@pytest.mark.parametrize('missing', [False, True])
def test_original_revoked_permission_label_never_grants_processing(fixture, monkeypatch, named, missing):
    from uuid import uuid4

    from zacai.state import Source, SourceSystem
    s = fixture
    if named:
        rewrite_original(s, named=True, monkeypatch=monkeypatch)
    ref = s.saved.reply.claim.consent_reference
    external = f'packet-followup-revocation/{ref.source_id}'
    s.sources[external] = Source(id=uuid4(), system=SourceSystem.USER_INSTRUCTION, external_ref=external,
        trust_boundary=ref.trust_boundary, data_classification=ref.effective_classification,
        content_hash='e' * 64, content_location='e' * 64, captured_at=s.now)
    s.now += timedelta(minutes=6)
    result = s.replies.load_history(**({**s.history, 'recovery_receipt': None} if missing else s.history))
    assert result.original_permission_expired and result.original_permission_revoked
    assert not result.processing_authorized and not result.execution_authorized


def test_named_v2_expired_history_retains_original_chronology_without_active_renewal(fixture, monkeypatch):
    s = fixture
    consent = rewrite_original(s, named=True, monkeypatch=monkeypatch)
    s.now = consent.expires_at + timedelta(seconds=1)
    s.claim_denied = True
    checks = s.claim_checks
    result = s.replies.load_history(**s.history)
    assert result.saved == s.saved and result.original_permission_expired
    assert s.named_checks == [s.now] and s.claim_checks == checks
    assert not result.processing_authorized


@pytest.mark.parametrize('fault', ['observation', 'request', 'bound'])
def test_named_v2_original_chronology_mismatch_holds(fixture, monkeypatch, fault):
    s = fixture
    consent = rewrite_original(s, named=True, monkeypatch=monkeypatch)
    s.now = consent.expires_at + timedelta(seconds=1)
    decision = s.named_rows.decision
    if fault == 'observation':
        decision.original_observed_at += timedelta(microseconds=1)
    elif fault == 'request':
        decision.prepared_request_digest = 'e' * 64
    else:
        decision.bound_at = s.saved.reply.claim.claimed_at + timedelta(microseconds=1)
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load_history(**s.history)


def test_closed_scope_already_rejects_omitted_user_or_parent_context_coverage(fixture):
    from pydantic import ValidationError

    from zacai.interfaces.followup_authorization import FollowupRunScope
    s = fixture
    scope = s.saved.reply.claim.run_scope
    sparse = scope.model_copy(update={'context_references': tuple(
        r for r in scope.context_references if r != scope.user_reference)})
    with pytest.raises(ValidationError):
        FollowupRunScope.model_validate(sparse)
    parent = scope.context_references[0]
    without_parent = scope.model_copy(update={'parent_references': (parent,),
        'context_references': tuple(r for r in scope.context_references if r != parent)})
    with pytest.raises(ValidationError):
        FollowupRunScope.model_validate(without_parent)
