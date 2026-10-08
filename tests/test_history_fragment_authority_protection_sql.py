"""Root-only genuine PG/age mechanics, invented input and attendance.

Uses genuine signed owner/cookie/current Sources and actual independent object
read/decrypt/State/journal disposable restore. Claim row is a fixture writer,
NOT a production claim issuer, consent approval or processing authorization.
"""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_personal_fragment_protection_sql import (
    actual_case,  # noqa: F401
    assert_balanced_restoration_leases,
    clean_factory,  # noqa: F401
)
from zacai import contextual_authorization as auth
from zacai import contextual_protection as m
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import _fragment_request_provenance
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


@pytest.fixture
def actual_authority(actual_case):  # noqa: F811
    make, _, _, request, writer, calls, active, sessions, cookie, leases = actual_case
    protector = make('authority-cold-first')
    operation, clock = protector._operation, protector._clock
    owner = operation.establish()
    now = clock()
    consent = auth.HistoryFragmentConsentV1(id=uuid4(), builder_id=uuid4(),
        task_id=request.task.task_id,
        request_digest=content_hash_of(encode_history_fragment_contextual_request(request)),
        provenance=_fragment_request_provenance(request),
        owner_issuer=owner.principal.identity.issuer, owner_subject=owner.principal.identity.subject,
        original_session_binding=owner.binding_digest, original_session_issued_at=owner.issued_at,
        original_session_expires_at=owner.effective_expires_at, approved_at=now,
        expires_at=min(now+timedelta(minutes=10), owner.effective_expires_at),
        human_reference='simulated-specific-approval-for-invented-local-task', route=request.route,
        model_digest='b'*64, tokenizer_digest='c'*64, runtime_digest='d'*64,
        template_digest='e'*64, renderer_digest='f'*64, body_digest='1'*64,
        prompt_tokens=100, max_output_tokens=200)
    reference = auth.record_history_fragment_consent(factory=protector._factory,
        artifacts=protector._artifacts, consent=consent, expected_request=request,
        operation=operation, clock=clock)
    return make, protector, reference, consent, request, writer, calls, active, sessions, cookie, leases


def append_claim(protector, reference, consent):
    claim = auth.HistoryFragmentClaimV1(consent_reference=reference,
        consent_digest=reference.content_hash, request_digest=consent.request_digest,
        attempt_id=uuid4(), task_id=consent.task_id, builder_id=consent.builder_id,
        original_session_binding=consent.original_session_binding, body_digest=consent.body_digest,
        route_digest=content_hash_of(canonical_bytes({**consent.route.model_dump(mode='json'),
            'capabilities':sorted(consent.route.capabilities)})), model_digest=consent.model_digest,
        tokenizer_digest=consent.tokenizer_digest, runtime_digest=consent.runtime_digest,
        template_digest=consent.template_digest, renderer_digest=consent.renderer_digest,
        prompt_tokens=consent.prompt_tokens, max_output_tokens=consent.max_output_tokens,
        consumed_at=protector._clock())
    raw = auth.encode_history_fragment_claim(claim)
    digest = content_hash_of(raw)
    # Trusted canonical fixture write, not authorization or concurrency acceptance.
    location = protector._artifacts.put(B.PERSONAL, digest, raw)
    with protector._factory() as session, session.begin():
        source, created = record_source(session, trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED, system=SourceSystem.MANUAL,
            external_ref=auth._fragment_authority_namespace(consent, claim=True),
            content_hash=digest, content_location=location, captured_at=protector._clock())
        assert created
        own = EvidenceReference(source_id=source.id, content_hash=digest,
            trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
    return own, claim


def test_actual_consent_protect_reopen_original_owner_outside_leases(actual_authority, monkeypatch):
    make, protector, own, consent, request, writer, calls, active, _, _, leases = actual_authority
    kwargs = {'reference': own, 'expected_consent': consent, 'expected_request': request}
    receipt = protector.protect_consent(**kwargs)
    writes = []
    def no_put(*args, **kwargs):
        writes.append(True)
        raise AssertionError('read-existing cannot mint or repair')
    monkeypatch.setattr(writer, 'put_object', no_put)
    assert make('authority-cold-reopen').recheck_consent(**kwargs) == receipt
    assert not writes and active == {'canonical':0, 'admin':0}
    assert_balanced_restoration_leases(leases, expected_restorations=2)
    assert calls.count('actual-verify-personal-start') == 2
    assert not receipt.processing_authorized and not receipt.recovery_verified
    with protector._factory() as session:
        expected = {s.id:s.content_hash for s in session.scalars(
            select(Source).where(Source.trust_boundary == B.PERSONAL))}
    assert dict(receipt.full_boundary_source_hashes) == expected
    assert own in receipt.selected_references


def test_actual_claim_append_stales_consent_new_checkpoint_covers_both(actual_authority):
    make, protector, own, consent, request, _, calls, active, _, _, leases = actual_authority
    old = protector.protect_consent(reference=own, expected_consent=consent, expected_request=request)
    claim_ref, claim = append_claim(protector, own, consent)
    with pytest.raises(m.ContextualProtectionError):
        make('authority-stale-consent').recheck_consent(reference=own,
            expected_consent=consent, expected_request=request)
    assert calls.count('actual-verify-personal-start') == 1
    kwargs = {'reference': claim_ref, 'expected_consent': consent, 'expected_claim': claim,
                  'expected_request': request}
    new = make('authority-claim-first').protect_claim(**kwargs)
    assert new.attempt_id == claim.attempt_id and new.receipt_object != old.receipt_object
    assert {own, claim_ref}.issubset(set(new.selected_references))
    assert make('authority-claim-reopen').recheck_claim(**kwargs) == new
    assert calls.count('actual-verify-personal-start') == 3
    assert_balanced_restoration_leases(leases, expected_restorations=3)
    assert active == {'canonical':0, 'admin':0}


def test_actual_cookie_revoke_after_restore_holds_authority_receipt(actual_authority, monkeypatch):
    _, protector, own, consent, request, writer, _, active, sessions, cookie, _ = actual_authority
    original = DisposableStateRestoreVerifier.verify_personal
    milestones = []
    def revoke(verifier, *args, **kwargs):
        result = original(verifier, *args, **kwargs)
        assert active == {'canonical':0, 'admin':0}
        milestones.append('actual-restoration-leases-closed')
        sessions.revoke(cookie)
        milestones.append('real-original-cookie-revoked')
        return result
    monkeypatch.setattr(DisposableStateRestoreVerifier, 'verify_personal', revoke)
    with pytest.raises(m.ContextualProtectionError):
        protector.protect_consent(reference=own, expected_consent=consent, expected_request=request)
    assert milestones == ['actual-restoration-leases-closed','real-original-cookie-revoked']
    assert not writer.exists(f'PERSONAL/state/history-fragment-authority-consent-{own.source_id}/'
                             f'receipt-{consent.request_digest}.age')


def test_actual_missing_claim_receipt_no_backup_restore_or_remint(actual_authority, monkeypatch):
    _, protector, own, consent, request, writer, calls, active, _, _, _ = actual_authority
    claim_ref, claim = append_claim(protector, own, consent)
    writes = []
    def no_put(*args, **kwargs):
        writes.append(True)
        raise AssertionError('missing consumed-claim proof cannot repair')
    monkeypatch.setattr(writer, 'put_object', no_put)
    with pytest.raises(m.ContextualProtectionError):
        protector.recheck_claim(reference=claim_ref, expected_consent=consent,
            expected_claim=claim, expected_request=request)
    assert not writes and 'actual-verify-personal-start' not in calls
    assert active == {'canonical':0, 'admin':0}
    with protector._factory() as session:
        assert session.get(Source, claim_ref.source_id).content_hash == claim_ref.content_hash


@pytest.mark.parametrize('kind', ['consent','claim'])
def test_actual_missing_own_source_zero_authority_body_reads(actual_authority, monkeypatch, kind):
    _, protector, own, consent, request, _, calls, active, _, _, _ = actual_authority
    claim = None
    if kind == 'claim':
        own, claim = append_claim(protector, own, consent)
    missing = own.model_copy(update={'source_id':uuid4()})
    body_reads = []
    actual = protector._artifacts.get_bounded
    def observed(*args, **kwargs):
        body_reads.append(True)
        return actual(*args, **kwargs)
    monkeypatch.setattr(protector._artifacts,'get_bounded',observed)
    with pytest.raises(m.ContextualProtectionError):
        if kind == 'consent':
            protector.protect_consent(reference=missing, expected_consent=consent,
                expected_request=request)
        else:
            protector.protect_claim(reference=missing, expected_consent=consent,
                expected_claim=claim, expected_request=request)
    assert not body_reads and 'actual-verify-personal-start' not in calls
    assert active == {'canonical':0,'admin':0}
