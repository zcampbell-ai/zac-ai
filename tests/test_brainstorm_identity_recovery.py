"""Invented proof files, mock crypto/object clients; no keys, SQL or network.

Passing invented operator flags proves parsing/binding only, not actual escrow,
password-manager interaction, off-device storage or canonical recovery readiness.
"""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from zacai import brainstorm_identity_recovery as module
from zacai import review_recovery
from zacai.ingestion.artifact_store import content_hash_of


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    state = SimpleNamespace(plain=b'invented independently recovered state', cipher=b'invented ciphertext',
                            calls=[], bad_decrypt=False, bad_challenge=False, size=None)
    digest = content_hash_of(state.cipher)
    state.proof = {
        'format': 'zac-existing-state-recovery-v1', 'boundary': 'BRAINSTORM',
        'state_object': f'BRAINSTORM/state/{uuid4()}/{digest}.age',
        'ciphertext_hash': digest, 'plaintext_hash': content_hash_of(state.plain),
        'full_row_field_comparison': 'passed', 'target_cleaned': True,
        'off_device_retrieval': True, 'recovered_identity_from_password_manager': True,
        'temporary_recovered_key_removed': True,
    }
    state.path = tmp_path / 'invented-proof.json'
    state.identity = tmp_path / 'invented-not-a-real-key'
    state.recipient = 'invented-not-a-real-recipient'

    def write():
        state.path.write_bytes(json.dumps(state.proof).encode())
        state.path.chmod(0o600)
        return content_hash_of(state.path.read_bytes())

    state.pin = write()
    state.write = write

    class Objects:
        def stat(self, key):
            state.calls.append(('stat', key))
            assert key == state.proof['state_object']
            return SimpleNamespace(size=len(state.cipher) if state.size is None else state.size)

        def get_object(self, key):
            state.calls.append(('get', key))
            assert key == state.proof['state_object']
            return state.cipher

    def decrypt(raw, identity):
        assert identity == state.identity
        state.calls.append(('decrypt', raw))
        if raw == b'invented challenge ciphertext':
            return b'wrong challenge' if state.bad_challenge else b'zacai BRAINSTORM pre-context recovery identity readiness'
        assert raw == state.cipher
        if state.bad_decrypt:
            raise RuntimeError('INVENTED PRIVATE CRYPTO DIAGNOSTIC')
        return state.plain

    def encrypt(raw, recipient):
        assert recipient == state.recipient
        assert raw == b'zacai BRAINSTORM pre-context recovery identity readiness'
        state.calls.append(('challenge', recipient))
        return b'invented challenge ciphertext'

    monkeypatch.setattr(module, 'age_decrypt', decrypt)
    monkeypatch.setattr(module, 'age_encrypt', encrypt)
    state.objects = Objects()
    state.inputs = {'verification_objects': state.objects, 'recipient': state.recipient,
                    'identity_path': state.identity, 'recovered_key_receipt': state.path,
                    'expected_receipt_hash': state.pin}
    return state


def test_exact_original_object_current_identity_and_recipient_challenge(fixture):
    s = fixture
    original = s.path.read_bytes()
    assert module.verify_brainstorm_recovered_identity(**s.inputs) is None
    assert [c[0] for c in s.calls] == ['stat', 'get', 'decrypt', 'challenge', 'decrypt']
    assert s.path.read_bytes() == original
    assert not s.identity.exists()


@pytest.mark.parametrize('field', ['target_cleaned', 'off_device_retrieval',
    'recovered_identity_from_password_manager', 'temporary_recovered_key_removed'])
@pytest.mark.parametrize('value', [False, 1, 'true'])
def test_operator_flags_must_be_exact_true_before_object_read(fixture, field, value):
    s = fixture
    s.proof[field] = value
    s.inputs['expected_receipt_hash'] = s.write()
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert s.calls == []


@pytest.mark.parametrize('field,value', [('format', 'other'), ('boundary', 'PERSONAL'),
    ('full_row_field_comparison', 'partial'), ('plaintext_hash', 'invalid')])
def test_proof_contract_denied_before_object_read(fixture, field, value):
    s = fixture
    s.proof[field] = value
    s.inputs['expected_receipt_hash'] = s.write()
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert s.calls == []


def test_proof_pin_required_even_when_json_is_plausible(fixture):
    s = fixture
    s.proof['extra_invented_operator_note'] = 'still not a trust anchor'
    s.write()
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert s.calls == []


def test_duplicate_json_rejected_even_when_exact_pin_matches(fixture):
    s = fixture
    raw = s.path.read_bytes().rstrip()[:-1] + b',"target_cleaned":true}'
    s.path.write_bytes(raw)
    s.inputs['expected_receipt_hash'] = content_hash_of(raw)
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert s.calls == []


@pytest.mark.parametrize('mode', [0o644, 0o400, 0o700])
def test_exact_private_mode_required(fixture, mode):
    s = fixture
    s.path.chmod(mode)
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert s.calls == []


def test_oversize_proof_denied_before_object_read(fixture):
    s = fixture
    raw = b'x' * 64_001
    s.path.write_bytes(raw)
    s.inputs['expected_receipt_hash'] = content_hash_of(raw)
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert s.calls == []


@pytest.mark.parametrize('size', [0, 65_000_001, 1])
def test_original_object_capacity_or_stat_read_mismatch(fixture, size):
    s = fixture
    s.size = size
    with pytest.raises(module.BrainstormIdentityRecoveryError):
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert not any(c[0] == 'decrypt' for c in s.calls)


@pytest.mark.parametrize('failure', ['cipher', 'plaintext', 'decrypt', 'challenge'])
def test_actual_crypto_binding_failure_is_closed(fixture, failure):
    s = fixture
    if failure == 'cipher':
        s.cipher += b'changed'
    elif failure == 'plaintext':
        s.plain += b'changed'
    elif failure == 'decrypt':
        s.bad_decrypt = True
    else:
        s.bad_challenge = True
    with pytest.raises(module.BrainstormIdentityRecoveryError) as exc:
        module.verify_brainstorm_recovered_identity(**s.inputs)
    assert str(exc.value) == 'Brainstorm recovered identity unavailable'
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None


@pytest.mark.parametrize('prefix', ['', 'review-', 'contextual-research-'])
def test_original_state_key_namespace_preserved(prefix):
    digest = 'a' * 64
    key = f'BRAINSTORM/state/{prefix}{uuid4()}/{digest}.age'
    assert module.assert_brainstorm_recovery_state_key(key, digest) is None
    assert review_recovery._state_key is module.assert_brainstorm_recovery_state_key


@pytest.mark.parametrize('key', ['PERSONAL/state/{id}/{hash}.age',
    'BRAINSTORM/state/text-turn-{id}/{hash}.age', 'BRAINSTORM/state/../{id}/{hash}.age'])
def test_new_or_cross_boundary_key_not_silently_allowed(key):
    digest = 'a' * 64
    with pytest.raises(ValueError):
        module.assert_brainstorm_recovery_state_key(key.format(id=uuid4(), hash=digest), digest)


def test_review_gate_delegates_exact_existing_inputs(fixture, monkeypatch):
    s = fixture
    gate = object.__new__(review_recovery.BrainstormReviewRecoveryGate)
    gate._objects, gate._recipient, gate._identity = s.objects, s.recipient, s.identity
    gate._receipt = s.path
    gate._checkpoint = SimpleNamespace(recovered_key_receipt_hash=s.pin)
    seen = []
    monkeypatch.setattr(review_recovery, 'verify_brainstorm_recovered_identity', lambda **kwargs: seen.append(kwargs))
    gate._verify_recovered_identity()
    assert seen == [s.inputs]


def test_review_preflight_keeps_existing_public_error_boundary(fixture, monkeypatch):
    s = fixture
    gate = object.__new__(review_recovery.BrainstormReviewRecoveryGate)
    gate._objects, gate._recipient, gate._identity = s.objects, s.recipient, s.identity
    gate._receipt = s.path
    point = review_recovery.ReviewRecoveryCheckpoint(state_object=s.proof['state_object'],
        ciphertext_hash=s.proof['ciphertext_hash'], plaintext_hash=s.proof['plaintext_hash'],
        recovered_key_receipt_hash=s.pin)
    gate._checkpoint = point
    consent = SimpleNamespace(state_recovery_reference=point.state_reference,
        artifact_recovery_reference=point.artifact_reference, credential_recovery_reference=point.credential_reference)
    monkeypatch.setattr(review_recovery.ReviewConsent, 'model_validate', lambda value: value)
    s.path.chmod(0o644)
    with pytest.raises(review_recovery.ReviewRecoveryError) as exc:
        gate.preflight(consent)
    assert str(exc.value) == 'review recovery prerequisites unavailable'
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__ is True
    assert s.calls == []
