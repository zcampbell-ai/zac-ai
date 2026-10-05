"""Invented memory-ledger V2 seams; no actual SQL, session or recovery proof."""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_followup_authorization import fixture as legacy_fixture
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import followup_authorization as module
from zacai.interfaces import named_decision_capture, named_decision_inventory
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_followup_decision import named_decision_consent_id
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def fixture(monkeypatch):
    s = legacy_fixture.__wrapped__(monkeypatch)
    source_id = uuid4()
    s.named_inventory = SimpleNamespace(decision=SimpleNamespace(
        run_scope=s.scope, admitted_at=s.now - timedelta(seconds=1),
        processing_expires_at=s.now + timedelta(minutes=14),
        prepared_request_digest=s.request.digest,
        original_observed_at=s.request.context.task.event.observed_at,
    ))
    s.named_fresh_calls = s.named_row_calls = 0
    s.named_fresh_result = s.named_row_result = None
    s.named_error = False
    class Binding:
        host_clock = s.authority._clock
        def verify_fresh(self, consent, now):
            assert s.active_sessions == 0
            s.named_fresh_calls += 1
            if s.named_error or consent.decision_recovery_digest != 'd' * 64:
                raise ValueError('invented missing proof')
            return s.named_fresh_result
        def verify_rows(self, session, consent, now):
            assert s.active_sessions == 1
            s.named_row_calls += 1
            return s.named_row_result
    s.binding = Binding()
    s.authority._named_binding = s.binding
    s.authority._recovery.named_binding = s.binding
    s.consent = module.FollowupConsentV2(
        id=named_decision_consent_id(source_id), scope=s.scope,
        approved_at=s.named_inventory.decision.admitted_at,
        expires_at=s.named_inventory.decision.processing_expires_at,
        human_reference='invented named owner admission',
        decision_reference=EvidenceReference(source_id=source_id, content_hash='e' * 64,
            trust_boundary=B.BRAINSTORM, effective_classification=C.CONFIDENTIAL),
        decision_recovery_digest='d' * 64,
    )
    monkeypatch.setattr(named_decision_inventory, 'load_named_decision_inventory',
                        lambda *a, **kw: s.named_inventory)
    # The actual ORM/connection guard is tested in the parent SQL fixture;
    # memory Session has no Connection. Preserve callback invocation here.
    monkeypatch.setattr(named_decision_capture, '_checked_rows',
                        lambda session, binding, decision, now:
                        None if binding.verify_rows(session, decision, now) is None
                        else (_ for _ in ()).throw(ValueError('invented row denial')))
    monkeypatch.setattr(named_decision_capture, '_require_request_lock', lambda *a: None)
    return s


def test_v2_record_claim_recheck_original_window_and_one_shot(fixture):
    s = fixture
    approval = s.authority.record(s.consent)
    assert s.authority.named_binding is s.binding
    claimed = s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    s.authority.recheck(claimed, s.request)
    assert claimed.claim.consent_reference.content_hash == module.content_hash_of(module._raw(s.consent))
    assert s.named_fresh_calls and s.named_row_calls
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)


@pytest.mark.parametrize('fault', ['absent', 'fresh_truthy', 'row_truthy', 'proof', 'id', 'approved', 'expires', 'scope'])
def test_v2_record_fails_closed(fixture, fault):
    s = fixture
    if fault == 'absent': s.authority._named_binding = None
    elif fault == 'fresh_truthy': s.named_fresh_result = True
    elif fault == 'row_truthy': s.named_row_result = True
    elif fault == 'proof': s.consent = s.consent.model_copy(update={'decision_recovery_digest': 'f' * 64})
    elif fault == 'id': s.consent = s.consent.model_copy(update={'id': uuid4()})
    elif fault == 'approved': s.consent = s.consent.model_copy(update={'approved_at': s.now})
    elif fault == 'expires': s.consent = s.consent.model_copy(update={'expires_at': s.now + timedelta(minutes=13)})
    elif fault == 'scope': s.named_inventory.decision.run_scope = s.scope.model_copy(update={'run_id': uuid4()})
    with pytest.raises(module.FollowupAuthorizationError): s.authority.record(s.consent)


@pytest.mark.parametrize('field', ['prepared_request_digest', 'original_observed_at'])
def test_v2_exact_original_request_is_required_before_claim(fixture, field):
    s = fixture
    approval = s.authority.record(s.consent)
    setattr(s.named_inventory.decision, field,
            'f' * 64 if field == 'prepared_request_digest' else s.now + timedelta(seconds=1))
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    assert not s.protected_claims


def test_v2_revoke_after_expiry_does_not_require_processing_proof(fixture):
    s = fixture
    approval = s.authority.record(s.consent)
    s.now = s.consent.expires_at
    s.named_error = True
    assert s.authority.revoke(approval_id=approval, human_reference='invented cancellation')
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)


def test_v1_original_bytes_and_no_named_binding( monkeypatch):
    s = legacy_fixture.__wrapped__(monkeypatch)
    original = module._raw(s.consent)
    assert module.encode_followup_consent(s.consent) == original
    assert module.decode_followup_consent(original) == s.consent
    assert s.authority.named_binding is None
    approval = s.authority.record(s.consent)
    claimed = s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    s.authority.recheck(claimed, s.request)


def test_v2_constructor_rejects_different_binding_clock(fixture):
    s = fixture
    s.binding.host_clock = HostObservedClock(lambda: s.now)
    with pytest.raises(module.FollowupAuthorizationError):
        module.CanonicalFollowupAuthorization(factory=s.authority._factory, store=s.authority._store,
            refresh=s.authority._refresh, owner=s.authority._owner, recovery=s.authority._recovery,
            clock=s.authority._clock, named_binding=s.binding)


def test_v2_owner_callback_is_outside_sql_in_all_paths(fixture):
    s = fixture
    def owner():
        assert s.active_sessions == 0
        return s.owner
    s.authority._owner = owner
    approval = s.authority.record(s.consent)
    claimed = s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    s.authority.recheck(claimed, s.request)
    s.authority.revoke(approval_id=approval, human_reference='invented cancellation')


def test_v2_proof_changed_during_recovery_withholds_record_ack(fixture):
    s = fixture
    s.after_protect_consent = lambda: setattr(s, 'named_error', True)
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.record(s.consent)
    assert s.protected_consents
    assert not s.protected_claims


def test_v2_original_request_changed_during_claim_recovery_withholds_ack(fixture):
    s = fixture
    approval = s.authority.record(s.consent)
    s.after_protect_claim = lambda: setattr(s.named_inventory.decision, 'prepared_request_digest', 'f' * 64)
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    assert s.protected_claims
    # Failed acknowledgement never creates a second attempt.
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)


def rebuilt(s, *, binding=None, named_only=False):
    return module.CanonicalFollowupAuthorization(
        factory=s.authority._factory, store=s.authority._store,
        refresh=s.authority._refresh, owner=s.authority._owner,
        recovery=s.authority._recovery, clock=s.authority._clock,
        named_binding=s.binding if binding is None else binding, named_only=named_only,
    )


def test_actual_v2_constructor_pins_exact_recovery_binding(fixture):
    s = fixture
    authority = rebuilt(s, named_only=True)
    approval = authority.record(s.consent)
    assert authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    other = SimpleNamespace(host_clock=s.authority._clock,
        verify_fresh=s.binding.verify_fresh, verify_rows=s.binding.verify_rows)
    with pytest.raises(module.FollowupAuthorizationError):
        rebuilt(s, binding=other)


def test_named_only_mode_rejects_new_v1_but_preserves_existing_v1_history(fixture):
    s = fixture
    legacy = module.FollowupConsent(id=uuid4(), scope=s.scope,
        approved_at=s.now, expires_at=s.now + timedelta(minutes=10), human_reference="invented manual legacy")
    historical_id = s.authority.record(legacy)
    named_authority = rebuilt(s, named_only=True)
    with pytest.raises(module.FollowupAuthorizationError):
        named_authority.record(legacy)
    named_authority.revoke(approval_id=historical_id, human_reference="invented historical cancellation")


def test_v2_postcommit_protection_failure_retry_preserves_source(fixture):
    s = fixture
    s.protect_consent_error = True
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.record(s.consent)
    before = {source.id for source in s.sources.values()}
    s.protect_consent_error = False
    approval = s.authority.record(s.consent)
    assert approval in before and {source.id for source in s.sources.values()} == before
    assert s.authority.record(s.consent) == approval
    s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)


@pytest.mark.parametrize("bad", [None, 1, "yes"])
def test_named_mode_configuration_must_be_boolean(fixture, bad):
    with pytest.raises(module.FollowupAuthorizationError):
        rebuilt(fixture, named_only=bad)
