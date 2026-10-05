"""Invented actual temporary SQLite sessions/admissions; no routes or processing."""

import base64
import json
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from tests.test_named_admission_store import fixture as admission_fixture
from zacai.interfaces import named_browser_pointer as m
from zacai.interfaces.followup_authorization import _owner_digest
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    s = admission_fixture.__wrapped__(tmp_path, monkeypatch)
    s.owner = OwnerGrant(Identity(s.template.actor_issuer, s.template.actor_subject),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),))
    s.sessions = SqliteSessionStore(tmp_path / 'sessions', key=s.key)
    s.cookie = s.sessions.start_user(s.owner.identity, s.now)
    s.continuity_args = {'sessions': s.sessions, 'owner': lambda: s.owner, 'clock': s.clock,
        'key': s.key, 'origin': s.args['origin'], 'client_id': s.args['client_id']}
    s.helper = NamedSessionContinuity(**s.continuity_args)
    s.operation = s.helper.for_cookie(s.cookie)
    s.codec_args = {'key': s.key, 'origin': s.args['origin'], 'client_id': s.args['client_id'], 'clock': s.clock}
    s.codec = m.NamedBrowserPointerCodec(**s.codec_args)
    s.builds = 0
    def build(verified, digest, now):
        s.builds += 1
        return s.build(digest, now).model_copy(update={
            'actor_issuer': verified.principal.identity.issuer,
            'actor_subject': verified.principal.identity.subject,
            'owner_grant_digest': _owner_digest(s.owner),
        })
    s.coordinator_args = {'store': s.store, 'codec': s.codec, 'clock': s.clock, 'manifest_builder': build}
    s.coordinator = m.NamedAdmissionReuseCoordinator(**s.coordinator_args)
    return s


def get(s, pointer=None):
    return s.coordinator.reuse_or_issue(operation=s.operation, pointer=pointer)


def count(s):
    with sqlite3.connect(s.path / 'admissions.sqlite') as conn:
        return conn.execute('SELECT COUNT(*) FROM admissions').fetchone()[0]


def test_repeated_get_and_concurrent_initial_get_coalesce(fixture):
    s = fixture
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: get(s), range(12)))
    assert len({x.sealed_pointer for x in results}) == count(s) == s.builds == 1
    first = results[0]
    for _ in range(140):
        assert get(s, first.sealed_pointer) == first
    assert count(s) == s.builds == 1
    assert first.record.phase == 'ISSUED' and not first.processing_authorized and not first.execution_authorized
    assert first.sealed_pointer not in repr(first)


def test_restart_original_cookie_pointer_reuses_exact_record(fixture):
    s = fixture
    first = get(s)
    s.now += timedelta(seconds=1)
    reopened = SqliteSessionStore(s.sessions._directory, key=s.key)
    s.helper = NamedSessionContinuity(**{**s.continuity_args, 'sessions': reopened})
    s.operation = s.helper.for_cookie(s.cookie)
    s.coordinator = m.NamedAdmissionReuseCoordinator(**s.coordinator_args)
    assert get(s, first.sealed_pointer) == first
    assert count(s) == s.builds == 1


@pytest.mark.parametrize('fault', ['corrupt', 'empty', 'unknown', 'expired', 'new_session', 'revoked'])
def test_existing_pointer_failure_never_allocates_or_renews(fixture, fault):
    s = fixture
    first = get(s)
    pointer = first.sealed_pointer
    if fault == 'corrupt': pointer = pointer[:-1] + ('A' if pointer[-1] != 'A' else 'B')
    elif fault == 'empty': pointer = ''
    elif fault == 'unknown':
        with sqlite3.connect(s.path / 'admissions.sqlite') as conn: conn.execute('DELETE FROM admissions')
    elif fault == 'expired': s.now = first.record.manifest.admission_expires_at
    elif fault == 'new_session': s.operation = s.helper.for_cookie(s.sessions.start_user(s.owner.identity, s.now))
    elif fault == 'revoked': s.sessions.revoke(s.cookie)
    expected_count = count(s)
    with pytest.raises(m.NamedBrowserPointerError): get(s, pointer)
    assert count(s) == expected_count and s.builds == 1


def test_expired_admitted_record_held_without_deletion(fixture):
    s = fixture
    first = get(s)
    verified = s.operation.establish()
    decoded = s.codec.decode(first.sealed_pointer, verified)
    admitted = s.store.admit(handle=decoded.handle, session_binding=verified.binding_digest,
        question_digest='b' * 64, question_bytes=12)
    s.now = admitted.processing_expires_at
    with pytest.raises(m.NamedBrowserPointerError): get(s, first.sealed_pointer)
    with sqlite3.connect(s.path / 'admissions.sqlite') as conn:
        assert conn.execute('SELECT phase FROM admissions').fetchall() == [('ADMITTED',)]


def test_explicit_start_new_allocates_without_modifying_original(fixture):
    s = fixture
    first = get(s)
    verified = s.operation.establish()
    decoded = s.codec.decode(first.sealed_pointer, verified)
    admitted = s.store.admit(handle=decoded.handle, session_binding=verified.binding_digest,
        question_digest='b' * 64, question_bytes=12)
    second = s.coordinator.start_new(operation=s.operation)
    assert second.record.manifest.nonce_digest != first.record.manifest.nonce_digest
    assert s.store.get(handle=decoded.handle, session_binding=verified.binding_digest) == admitted
    assert count(s) == 2


@pytest.mark.parametrize('change', ['key', 'origin', 'client'])
def test_pointer_context_key_pin_and_no_authority(fixture, change):
    s = fixture
    first = get(s)
    args = dict(s.codec_args)
    args[change if change != 'client' else 'client_id'] = {'key': b'y' * 32, 'origin': 'https://other.example', 'client': 'other'}[change]
    different = m.NamedBrowserPointerCodec(**args)
    with pytest.raises(m.NamedBrowserPointerError): different.decode(first.sealed_pointer, s.operation.establish())
    decoded = s.codec.decode(first.sealed_pointer, s.operation.establish())
    assert not decoded.processing_authorized and decoded.handle not in repr(decoded)
    assert all(type(x) is str and x != decoded.handle for x in s.coordinator._cache.values())


@pytest.mark.parametrize('fault', ['unknown_field', 'missing_format', 'wrong_handle_type', 'future', 'expiry_equal', 'duplicate'])
def test_authenticated_malformed_pointer_payload_denied(fixture, fault):
    s = fixture
    first = get(s)
    sealed = base64.urlsafe_b64decode(first.sealed_pointer + '=' * (-len(first.sealed_pointer) % 4))
    raw = s.codec._cipher.decrypt(sealed[:12], sealed[12:], s.codec._aad)
    data = json.loads(raw)
    if fault == 'unknown_field': data['extra'] = 'no'
    elif fault == 'missing_format': del data['format']
    elif fault == 'wrong_handle_type': data['handle'] = 1
    elif fault == 'future': data['issued_at'] = (s.now + timedelta(seconds=1)).isoformat()
    elif fault == 'expiry_equal': data['expires_at'] = s.now.isoformat()
    changed = m.canonical_bytes(data)
    if fault == 'duplicate': changed = changed[:-1] + b',"format":"zac-named-browser-pointer-v1"}'
    nonce = secrets.token_bytes(12)
    forged = base64.urlsafe_b64encode(nonce + s.codec._cipher.encrypt(nonce, changed, s.codec._aad)).rstrip(b'=').decode()
    with pytest.raises(m.NamedBrowserPointerError): get(s, forged)
    assert count(s) == s.builds == 1


def test_missing_pointer_after_restart_is_new_issued_not_old_admission(fixture):
    s = fixture
    first = get(s)
    verified = s.operation.establish()
    decoded = s.codec.decode(first.sealed_pointer, verified)
    old = s.store.admit(handle=decoded.handle, session_binding=verified.binding_digest,
        question_digest='b' * 64, question_bytes=12)
    s.coordinator = m.NamedAdmissionReuseCoordinator(**s.coordinator_args)
    fresh = get(s)
    assert fresh.record.phase == 'ISSUED'
    assert fresh.record.manifest.request_id != old.manifest.request_id
    assert fresh.record.manifest.nonce_digest != old.manifest.nonce_digest
    assert s.store.get(handle=decoded.handle, session_binding=verified.binding_digest) == old
    assert count(s) == 2 and not fresh.processing_authorized


def test_coordinator_cache_capacity_holds_without_store_or_session_eviction(fixture):
    s = fixture
    s.coordinator = m.NamedAdmissionReuseCoordinator(**s.coordinator_args, capacity=1)
    first = get(s)
    s.operation = s.helper.for_cookie(s.sessions.start_user(s.owner.identity, s.now))
    with pytest.raises(m.NamedBrowserPointerError): get(s)
    assert count(s) == s.builds == 1
    assert s.sessions.user(s.cookie, s.now) is not None
    assert first.record.phase == 'ISSUED'


def test_coordinator_rejects_store_clock_mismatch(fixture):
    from zacai.interfaces.host_clock import HostObservedClock
    s = fixture
    s.store._clock = HostObservedClock(lambda: s.now)
    with pytest.raises(m.NamedBrowserPointerError):
        m.NamedAdmissionReuseCoordinator(**s.coordinator_args)


def test_actual_operation_different_clock_identity_denied_before_session_read(fixture):
    from zacai.interfaces.host_clock import HostObservedClock
    s = fixture
    alternative = NamedSessionContinuity(**{
        **s.continuity_args, 'clock': HostObservedClock(lambda: s.now),
    })
    operation = alternative.for_cookie(s.cookie)
    assert operation.host_clock is not s.clock
    # Equal wall times do not satisfy the shared-observation composition contract.
    assert operation.host_clock() == s.clock()
    before = s.sessions.user(s.cookie, s.now)
    with pytest.raises(m.NamedBrowserPointerError):
        s.coordinator.reuse_or_issue(operation=operation, pointer=None)
    assert count(s) == s.builds == 0
    assert s.sessions.user(s.cookie, s.now) == before


def test_cache_expiry_releases_capacity_without_removing_admitted_row(fixture):
    s=fixture
    s.coordinator=m.NamedAdmissionReuseCoordinator(**s.coordinator_args,capacity=1)
    first=get(s)
    verified=s.operation.establish()
    decoded=s.codec.decode(first.sealed_pointer,verified)
    s.store.admit(handle=decoded.handle,session_binding=verified.binding_digest,
        question_digest='b'*64,question_bytes=12)
    s.now=decoded.expires_at+timedelta(microseconds=1)
    s.operation=s.helper.for_cookie(s.sessions.start_user(s.owner.identity,s.now))
    next_page=get(s)
    assert next_page.record.phase=='ISSUED'
    assert next_page.record.manifest.nonce_digest!=first.record.manifest.nonce_digest
    with sqlite3.connect(s.path/'admissions.sqlite') as conn:
        assert sorted(row[0] for row in conn.execute('SELECT phase FROM admissions'))==['ADMITTED','ISSUED']


def test_old_explicit_tab_pointer_cannot_replace_newer_pointerless_action(fixture):
    s=fixture
    older=get(s)
    newer=s.coordinator.start_new(operation=s.operation)
    assert get(s,older.sealed_pointer)==older
    assert get(s)==newer
    assert count(s)==s.builds==2
