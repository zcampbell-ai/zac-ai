"""Actual codecs/files; SQL, signed owner, backup, age and restore are simulated.

These are adapter ordering/resource/denial controls, not genuine recovered proofs.
"""
import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_history_fragment_consent_records import case as case  # noqa: PLC0414
from tests.test_history_fragment_consent_records import case as consent_case  # noqa: F401
from tests.test_history_fragment_consent_records import loader as loader  # noqa: PLC0414
from tests.test_personal_fragment_protection import assembled as packet_case  # noqa: F401
from zacai import contextual_authorization as auth
from zacai import contextual_protection as m
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def authority(packet_case, consent_case, monkeypatch):  # noqa: F811
    f = packet_case
    q, consent, _ = consent_case
    consent_ref = EvidenceReference(source_id=uuid4(),
        content_hash=content_hash_of(auth.encode_history_fragment_consent(consent)),
        trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
    claim = auth.HistoryFragmentClaimV1(consent_reference=consent_ref,
        consent_digest=consent_ref.content_hash, request_digest=consent.request_digest,
        attempt_id=uuid4(), task_id=consent.task_id, builder_id=consent.builder_id,
        original_session_binding=consent.original_session_binding,
        body_digest=consent.body_digest, route_digest=content_hash_of(canonical_bytes(
            {**consent.route.model_dump(mode='json'),
             'capabilities':sorted(consent.route.capabilities)})),
        model_digest=consent.model_digest, tokenizer_digest=consent.tokenizer_digest,
        runtime_digest=consent.runtime_digest, template_digest=consent.template_digest,
        renderer_digest=consent.renderer_digest, prompt_tokens=consent.prompt_tokens,
        max_output_tokens=consent.max_output_tokens, consumed_at=consent.approved_at)
    claim_ref = EvidenceReference(source_id=uuid4(),
        content_hash=content_hash_of(auth.encode_history_fragment_claim(claim)),
        trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
    f.q, f.consent, f.consent_ref, f.claim, f.claim_ref = q, consent, consent_ref, claim, claim_ref
    f.owner['value'] = replace(f.verified, issued_at=consent.original_session_issued_at)
    refs = (*consent.provenance, consent_ref)
    plan = replace(f.plan, rows=canonical_bytes([
        {'id':str(r.source_id), 'content_hash':r.content_hash} for r in refs]))
    f.current_plan['value'] = plan
    f.plan = plan
    monkeypatch.setattr(f.p, '_authority_subject',
        lambda *args: f.events.append('canonical-authority-load'))
    return f


def invoke(f, *, claim=False, existing=False, **changes):
    values = {'reference': f.claim_ref if claim else f.consent_ref,
                  'expected_consent': f.consent, 'expected_request': f.q}
    if claim:
        values['expected_claim'] = f.claim
    values.update(changes)
    method = ((f.p.recheck_claim if existing else f.p.protect_claim) if claim
              else (f.p.recheck_consent if existing else f.p.protect_consent))
    return method(**values)


def add_claim(f):
    rows = json.loads(f.plan.rows)
    rows.append({'id':str(f.claim_ref.source_id), 'content_hash':f.claim_ref.content_hash})
    f.current_plan['value'] = replace(f.plan, rows=canonical_bytes(rows))


def test_consent_checkpoint_and_read_existing_exact_false_flags_no_puts(authority, monkeypatch):
    f = authority
    result = invoke(f)
    assert result.kind == 'CONSENT' and result.consent_reference == f.consent_ref
    assert not result.processing_authorized and not result.recovery_verified
    assert f.events.index('owner') < f.events.index('canonical-authority-load')
    assert f.events.count('backup') == f.events.count('restore') == 1
    assert f.consent_ref.source_id in f.restored[0][1]
    writes = []
    monkeypatch.setattr(f.writer, 'put_object', lambda *a: writes.append(a))
    assert invoke(f, existing=True) == result
    assert not writes and f.events.count('backup') == 1 and f.events.count('restore') == 2


def test_claim_append_stales_consent_and_claim_checkpoint_covers_both(authority):
    f = authority
    old = invoke(f)
    add_claim(f)
    with pytest.raises(m.ContextualProtectionError):
        invoke(f, existing=True)
    assert f.events.count('restore') == 1  # mismatch before new restoration
    new = invoke(f, claim=True)
    assert new.kind == 'CLAIM' and new.attempt_id == f.claim.attempt_id
    assert {f.consent_ref, f.claim_ref}.issubset(set(new.selected_references))
    assert old.receipt_object != new.receipt_object
    assert f.events.count('backup') == 2 and f.events.count('restore') == 2
    assert invoke(f, claim=True, existing=True) == new


@pytest.mark.parametrize('fault', ['request', 'digest', 'boundary', 'classification', 'owner'])
def test_wrong_binding_holds_before_private_load_or_backup(authority, fault):
    f = authority
    kwargs = {}
    if fault == 'request':
        kwargs['expected_request'] = f.q.model_copy(update={'observed_at':f.consent.expires_at})
    elif fault == 'digest':
        kwargs['reference'] = f.consent_ref.model_copy(update={'content_hash':'0'*64})
    elif fault in ('boundary', 'classification'):
        kwargs['reference'] = f.consent_ref.model_copy(update={
            'trust_boundary':B.BRAINSTORM} if fault == 'boundary' else {
            'effective_classification':C.CONFIDENTIAL})
    else:
        kwargs['expected_consent'] = f.consent.model_copy(update={'owner_subject':'other-owner'})
        kwargs['reference'] = f.consent_ref.model_copy(update={'content_hash':content_hash_of(
            auth.encode_history_fragment_consent(kwargs['expected_consent']))})
    with pytest.raises(m.ContextualProtectionError) as error:
        invoke(f, **kwargs)
    assert 'canonical-authority-load' not in f.events and 'backup' not in f.events
    assert error.value.__context__ is None


def test_missing_claim_receipt_no_remint_no_restore(authority, monkeypatch):
    f = authority
    add_claim(f)
    writes = []
    monkeypatch.setattr(f.writer, 'put_object', lambda *a: writes.append(a))
    with pytest.raises(m.ContextualProtectionError):
        invoke(f, claim=True, existing=True)
    assert not writes and 'backup' not in f.events and 'restore' not in f.events
    assert f.claim.attempt_id.int != 0  # existing consumed bytes never changed


def test_missing_union_holds_before_backup(authority):
    f = authority
    rows = json.loads(f.plan.rows)
    rows.pop(0)
    f.current_plan['value'] = replace(f.plan, rows=canonical_bytes(rows))
    with pytest.raises(m.ContextualProtectionError):
        invoke(f)
    assert 'canonical-authority-load' not in f.events and 'backup' not in f.events


def test_expiry_during_actual_object_callback_holds_before_restore(authority, monkeypatch):
    f = authority
    put = f.writer.put_object
    fired = []
    now = {'value': f.p._clock()}
    monkeypatch.setattr(f.p._clock, '_read', lambda: now['value'])
    def expire_after_put(key, raw):
        put(key, raw)
        fired.append(key)
        now['value'] = f.consent.expires_at
    monkeypatch.setattr(f.writer, 'put_object', expire_after_put)
    with pytest.raises(m.ContextualProtectionError):
        invoke(f)
    assert fired and 'restore' not in f.events


def test_restore_callback_revokes_owner_and_denies_receipt_publication(authority, monkeypatch):
    f = authority
    original = m.DisposableStateRestoreVerifier.verify_personal
    fired = []
    def revoke(self, *args, **kwargs):
        original(self, *args, **kwargs)
        fired.append(True)
        f.owner['value'] = None
    monkeypatch.setattr(m.DisposableStateRestoreVerifier, 'verify_personal', revoke)
    with pytest.raises(m.ContextualProtectionError):
        invoke(f)
    assert fired and f.events.count('restore') == 1
    keys = [p.name for p in f.writer._root.rglob('*.age')]
    assert not any(k.startswith('receipt-') for k in keys)


@pytest.mark.parametrize('fault', ['kind', 'attempt', 'extra', 'duplicate', 'whitespace'])
def test_closed_authority_receipt_codec_rejects_mutation(authority, fault):
    result = invoke(authority)
    raw = m.encode_personal_fragment_authority_receipt(result)
    value = json.loads(raw)
    if fault == 'kind': value['kind'] = 'CLAIM'
    elif fault == 'attempt': value['attempt_id'] = str(uuid4())
    elif fault == 'extra': value['processing_authorized'] = True
    elif fault == 'duplicate': raw = raw[:-1]+b',"kind":"CONSENT"}'
    else: raw = b' '+raw
    if fault in ('kind', 'attempt', 'extra'): raw = canonical_bytes(value)
    with pytest.raises(ValueError):
        m.decode_personal_fragment_authority_receipt(raw)


def test_existing_receipt_refuses_second_protection_before_any_backup(authority):
    f = authority
    invoke(f)
    before = f.events.count('backup')
    with pytest.raises(m.ContextualProtectionError):
        invoke(f)
    assert f.events.count('backup') == before


@pytest.mark.parametrize('fault', ['own-row', 'fingerprint', 'journal'])
def test_restore_callback_then_canonical_drift_denies_receipt(authority, monkeypatch, fault):
    f = authority
    actual = m.DisposableStateRestoreVerifier.verify_personal
    fired = []
    def drift(self, *args, **kwargs):
        actual(self, *args, **kwargs)
        fired.append(True)
        if fault == 'journal':
            monkeypatch.setattr(f.p, '_run_row', lambda *a: b'changed-operational-journal')
        else:
            rows = json.loads(f.plan.rows)
            if fault == 'own-row':
                rows = [r for r in rows if r['id'] != str(f.consent_ref.source_id)]
            else:
                rows[0]['effective_classification'] = 'changed-invented-scalar'
            f.current_plan['value'] = replace(f.plan, rows=canonical_bytes(rows))
    monkeypatch.setattr(m.DisposableStateRestoreVerifier, 'verify_personal', drift)
    with pytest.raises(m.ContextualProtectionError):
        invoke(f)
    assert fired and f.events.count('restore') == 1
    assert not any(p.name.startswith('receipt-') for p in f.writer._root.rglob('*.age'))


def test_canonical_loader_failure_never_becomes_proof(authority, monkeypatch):
    f = authority
    fired = []
    def deny(*args):
        fired.append(True)
        raise auth.ContextualAuthorizationError('simulated absent canonical consent')
    monkeypatch.setattr(f.p, '_authority_subject', deny)
    with pytest.raises(m.ContextualProtectionError):
        invoke(f)
    assert fired and 'backup' not in f.events and 'restore' not in f.events


def test_claim_wrong_attempt_exact_own_hash_holds_before_owner(authority):
    f = authority
    add_claim(f)
    changed = f.claim.model_copy(update={'attempt_id':uuid4()})
    with pytest.raises(m.ContextualProtectionError):
        invoke(f, claim=True, expected_claim=changed)
    assert not f.events


@pytest.mark.parametrize('fault', ['full-hashes', 'references', 'verified-time', 'fingerprint-ids'])
def test_receipt_closed_union_and_time_invariants(authority, fault):
    f = authority
    receipt = invoke(f)
    data = receipt.model_dump()
    if fault == 'full-hashes':
        data['full_boundary_source_hashes'] = data['full_boundary_source_hashes'][:-1]
    elif fault == 'references':
        data['selected_references'] = (f.claim_ref,)
    elif fault == 'verified-time':
        data['verified_at'] = f.consent.expires_at
    else:
        data['full_boundary_source_fingerprints'] = tuple(reversed(
            data['full_boundary_source_fingerprints']))
    with pytest.raises(ValueError):
        m.PersonalFragmentAuthorityReceiptV1.model_validate(data)


@pytest.mark.parametrize('existing', [False, True])
def test_public_claim_method_none_cannot_enter_consent_family(authority, existing):
    f = authority
    with pytest.raises(m.ContextualProtectionError):
        invoke(f, claim=True, existing=existing, reference=f.consent_ref, expected_claim=None)
    assert not f.events


@pytest.mark.parametrize('claim', [False, True])
def test_missing_own_source_before_any_canonical_subject_body(authority, claim):
    f = authority
    if claim:
        add_claim(f)
    original = f.claim_ref if claim else f.consent_ref
    missing = original.model_copy(update={'source_id':uuid4()})
    with pytest.raises(m.ContextualProtectionError):
        invoke(f, claim=claim, reference=missing)
    assert 'canonical-authority-load' not in f.events
    assert 'backup' not in f.events and 'decrypt' not in f.events


def test_missing_claim_plan_zero_actual_consent_body_reads(authority, loader, monkeypatch):
    f = authority
    q, consent, store, sql, own, _, body_reads = loader
    claim = f.claim.model_copy(update={
        **{n:getattr(consent,n) for n in ('request_digest','task_id','builder_id',
            'original_session_binding','body_digest','model_digest','tokenizer_digest',
            'runtime_digest','template_digest','renderer_digest','prompt_tokens','max_output_tokens')},
        'consent_reference':own, 'consent_digest':own.content_hash,
        'route_digest':content_hash_of(canonical_bytes({**consent.route.model_dump(mode='json'),
            'capabilities':sorted(consent.route.capabilities)})), 'consumed_at':consent.approved_at})
    missing = EvidenceReference(source_id=uuid4(),
        content_hash=content_hash_of(auth.encode_history_fragment_claim(claim)),
        trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
    rows = [{'id':str(r.source_id),'content_hash':r.content_hash}
            for r in (*consent.provenance,own)]
    f.current_plan['value'] = replace(f.plan,rows=canonical_bytes(rows))
    def canonical_subject(reference, expected_consent, request, expected_claim):
        auth.load_history_fragment_claim(sql, artifacts=store, reference=reference,
            expected_consent=expected_consent, expected_claim=expected_claim, expected_request=request)
    monkeypatch.setattr(f.p,'_authority_subject',canonical_subject)
    with pytest.raises(m.ContextualProtectionError):
        f.p.protect_claim(reference=missing, expected_consent=consent,
            expected_claim=claim, expected_request=q)
    # Real bounded consent artifact file, canonical SQL rows/owner explicitly mocked.
    assert body_reads == [] and 'backup' not in f.events
