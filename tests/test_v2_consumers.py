"""Invented version/fresh-binding seams; actual row decoder, no SQL/authority."""

from threading import RLock
from types import SimpleNamespace

import pytest

from tests.test_followup_consent_versions import consents as consents  # noqa: PLC0414
from tests.test_named_decision_inventory import fixture as named_fixture
from zacai.interfaces import followup_authority_recovery as authority
from zacai.interfaces import followup_authorization as authorization
from zacai.interfaces import named_decision_capture
from zacai.interfaces.followup_authorization import FollowupConsentV2
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_followup_decision import named_decision_consent_id


def test_v1_consent_subject_retains_same_bytes_and_reference(consents):
    v1, _ = consents
    reference = v1.scope.user_reference.model_copy(
        update={"content_hash": authority.content_hash_of(authorization._raw(v1))}
    )
    subject = authority.consent_subject(v1, reference)
    assert (
        subject.reference == reference
        and subject.scope_digest == authorization.followup_scope_digest(v1.scope)
    )


@pytest.mark.parametrize("ack", [True, False, 0, "approved"])
def test_named_fresh_boolean_or_prose_not_ack(consents, ack):
    _, consent = consents
    gate = object.__new__(authority.BrainstormFollowupAuthorityRecovery)
    gate._protector = SimpleNamespace(_lease_guard=None)
    gate._clock = HostObservedClock(lambda: consent.approved_at)
    gate._lock = RLock()
    gate._last_observed = None
    gate._named_binding = SimpleNamespace(verify_fresh=lambda *a: ack)
    with pytest.raises(ValueError):
        gate._named_fresh(consent)


def test_v2_cannot_use_missing_or_inlease_named_fresh_binding(consents):
    _, consent = consents
    gate = object.__new__(authority.BrainstormFollowupAuthorityRecovery)
    gate._protector = SimpleNamespace(_lease_guard=None)
    gate._clock = HostObservedClock(lambda: consent.approved_at)
    gate._lock = RLock()
    gate._last_observed = None
    gate._named_binding = None
    with pytest.raises(ValueError):
        gate._named_fresh(consent)
    calls = []
    gate._named_binding = SimpleNamespace(verify_fresh=lambda *a: calls.append(a))
    gate._protector._lease_guard = lambda: None
    with pytest.raises(ValueError):
        gate._named_fresh(consent)
    assert calls == []


def test_actual_named_row_inventory_v2_dependency_and_fixed_window(monkeypatch):
    s = named_fixture.__wrapped__(monkeypatch)
    consent = FollowupConsentV2(
        id=named_decision_consent_id(s.ref.source_id),
        scope=s.decision.run_scope,
        approved_at=s.decision.admitted_at,
        expires_at=s.decision.processing_expires_at,
        human_reference="invented admitted action",
        decision_reference=s.ref,
        decision_recovery_digest="a" * 64,
    )
    gate = object.__new__(authority.BrainstormFollowupAuthorityRecovery)
    gate._protector = SimpleNamespace(_artifacts=s.client._artifacts)
    gate._clock = HostObservedClock(lambda: s.decision.bound_at)
    calls = []
    binding = SimpleNamespace(
        host_clock=gate._clock,
        verify_rows=lambda session, declared, now: calls.append((declared, now)),
    )
    gate._named_binding = binding
    # Row guard mechanics have their own real Session adversarial tests; this
    # invented Session cannot install SQLAlchemy connection listeners.
    monkeypatch.setattr(
        named_decision_capture,
        "_checked_rows",
        lambda session, adapter, decision, now: adapter.verify_rows(session, decision, now),
    )
    with s.client._factory() as session:
        inventory = gate._named_rows(session, consent, s.decision.bound_at)
    assert dict(inventory.hashes)[s.ref.source_id] == s.ref.content_hash
    assert inventory.decision.prepared_request_digest == s.decision.prepared_request_digest
    assert len(calls) == 1
    for update in (
        {"id": consent.scope.run_id},
        {"expires_at": consent.expires_at.replace(year=2027)},
    ):
        with (
            s.client._factory() as session,
            pytest.raises((ValueError, authorization.FollowupAuthorizationError)),
        ):
            gate._named_rows(session, consent.model_copy(update=update), s.decision.bound_at)
