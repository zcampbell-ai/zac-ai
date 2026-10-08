"""Root-only genuine PG/age/owner-cookie mechanics; all inputs invented.

Identity provider attendance is simulated by existing enroll fixture; signed
owner storage and encrypted sessions, canonical packet, backups, native age and
disposable State/journal restoration are real. No processing approval follows.
"""
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import event, select, text

from tests.conftest import (
    _reset_test_schema,
    assert_connected_to_safe_test_database,
    assert_safe_test_database_url,
)
from tests.personal_fragment_sql_support import capture, genuine_packet
from tests.test_private_host import CONFIG, ORIGIN, OWNER, enroll
from zacai import backup
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.claude_local_custody import _SCOPE
from zacai.contextual_protection import ContextualProtectionError, PersonalHistoryFragmentProtector
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source


@pytest.fixture
def clean_factory(test_session_factory):
    engine = test_session_factory.kw["bind"]
    url = engine.url.render_as_string(hide_password=False)
    assert_safe_test_database_url(url)
    with engine.connect() as connection:
        assert_connected_to_safe_test_database(connection.scalar(text("SELECT current_database()")))
    # Whole-boundary coverage requires dedicated isolated test schema, NEVER
    # production Source deletion or scope-away of unrelated committed evidence.
    _reset_test_schema(url, already_stamped=True)
    return test_session_factory


@pytest.fixture
def actual_case(clean_factory, tmp_path, monkeypatch):
    engine = clean_factory.kw['bind']
    local = LocalFilesystemArtifactStore(tmp_path/'canonical')
    raw, request, _ = genuine_packet(clean_factory, local)
    sid = capture(clean_factory, local, raw)
    clock = HostObservedClock(lambda: datetime.now(UTC))
    enrolled = enroll(tmp_path/'owner', clock, scopes=_SCOPE)
    sessions = SqliteSessionStore(tmp_path/'sessions', key=b'x'*32)
    cookie = sessions.start_user(OWNER, clock())
    active = {'canonical': 0, 'admin': 0}
    calls = []
    lease_events = []
    phases = ['outside-restoration']

    def checked_owner():
        assert active == {'canonical': 0, 'admin': 0}, 'owner called within canonical lease'
        calls.append('genuine-owner-load')
        return enrolled.owners.load()

    continuity = NamedSessionContinuity(sessions=sessions, owner=checked_owner,
        clock=clock, key=b'x'*32, origin=ORIGIN, client_id=CONFIG.client_id)
    operation = continuity.for_cookie(cookie)
    operation.establish()
    def checkout(*args):
        active['canonical'] += 1
    def checkin(*args):
        active['canonical'] -= 1
    event.listen(engine, 'checkout', checkout)
    event.listen(engine, 'checkin', checkin)
    original_admin = backup._admin_connection
    @contextmanager
    def admin():
        with original_admin() as connection:
            active['admin'] += 1
            calls.append('genuine-admin-enter')
            lease_events.append(('enter', phases[-1], active['admin']))
            try:
                yield connection
            finally:
                lease_events.append(('exit', phases[-1], active['admin']))
                active['admin'] -= 1
                calls.append('genuine-admin-exit')
    monkeypatch.setattr(backup, '_admin_connection', admin)
    original_verify = DisposableStateRestoreVerifier.verify_personal
    def observed_verify(verifier, *args, **kwargs):
        phases.append('verify-personal')
        calls.append('actual-verify-personal-start')
        try:
            return original_verify(verifier, *args, **kwargs)
        finally:
            phases.pop()
            calls.append('actual-verify-personal-end')
    monkeypatch.setattr(DisposableStateRestoreVerifier, 'verify_personal', observed_verify)
    for name, phase in (('upgrade_restore_test_schema', 'schema-upgrade'),
                        ('restore_boundary_stream', 'copy-restore')):
        actual = getattr(backup, name)
        def observed(*args, _actual=actual, _phase=phase, **kwargs):
            phases.append(_phase)
            try:
                return _actual(*args, **kwargs)
            finally:
                phases.pop()
        monkeypatch.setattr(backup, name, observed)
    identity = tmp_path/'invented.agekey'
    subprocess.run(['age-keygen','-o',str(identity)], capture_output=True, check=True, timeout=15)
    recipient = subprocess.run(['age-keygen','-y',str(identity)], capture_output=True,
        check=True, timeout=15).stdout.decode().strip()
    writer = LocalDirectoryBackupStore(tmp_path/'ciphertexts')
    reader = LocalDirectoryBackupStore(tmp_path/'ciphertexts')
    def protector(cold_name):
        return PersonalHistoryFragmentProtector(factory=clean_factory, engine=engine,
            artifacts=local, cold_artifacts=LocalFilesystemArtifactStore(tmp_path/cold_name),
            objects=writer, verification_objects=reader, recipient=recipient,
            identity_path=identity, manifest_cache=tmp_path/'manifest.json',
            operation=operation, clock=clock, restoration=DisposableStateRestoreVerifier())
    try:
        yield protector, sid, content_hash_of(raw), request, writer, calls, active, sessions, cookie, lease_events
    finally:
        event.remove(engine,'checkout',checkout)
        event.remove(engine,'checkin',checkin)
        identity.unlink(missing_ok=True)


def assert_balanced_restoration_leases(events, *, expected_restorations):
    stack = []
    finished = []
    phases_in_restore = set()
    for direction, phase, depth in events:
        assert phase in {'verify-personal', 'schema-upgrade', 'copy-restore'}
        if direction == 'enter':
            assert depth == len(stack) + 1
            if not stack:
                assert phase == 'verify-personal'
                phases_in_restore = set()
            else:
                assert stack[0] == 'verify-personal'
            stack.append(phase)
            phases_in_restore.add(phase)
        else:
            assert direction == 'exit' and stack
            assert depth == len(stack) and stack[-1] == phase
            stack.pop()
            if not stack:
                assert phases_in_restore == {'verify-personal', 'schema-upgrade', 'copy-restore'}
                finished.append(phase)
    assert not stack and finished == ['verify-personal'] * expected_restorations


def test_actual_protect_reopen_and_real_cookie_outside_all_sql_leases(actual_case, clean_factory, monkeypatch):
    make, sid, digest, request, writer, calls, active, _, _, leases = actual_case
    first = make('cold-first').protect(source_id=sid, expected_digest=digest, expected_request=request)
    assert 'genuine-admin-enter' in calls and 'genuine-admin-exit' in calls
    assert active == {'canonical': 0, 'admin': 0}
    assert_balanced_restoration_leases(leases, expected_restorations=1)
    assert calls.count('actual-verify-personal-start') == 1
    assert calls.count('actual-verify-personal-end') == 1
    with clean_factory() as session:
        expected = {row.id:row.content_hash for row in session.scalars(
            select(Source).where(Source.trust_boundary == B.PERSONAL))}
    assert dict(first.full_boundary_source_hashes) == expected
    assert first.request_digest and first.selected_references
    writes = []
    def forbidden(*args, **kwargs):
        writes.append(True)
        raise AssertionError('read-existing must never publish/remint')
    monkeypatch.setattr(writer, 'put_object', forbidden)
    second = make('cold-reopen').recheck(source_id=sid, expected_digest=digest, expected_request=request)
    assert second == first and not writes
    assert_balanced_restoration_leases(leases, expected_restorations=2)
    assert calls.count('actual-verify-personal-start') == 2
    assert calls.count('actual-verify-personal-end') == 2
    assert active == {'canonical': 0, 'admin': 0}
    assert calls.count('genuine-admin-enter') == calls.count('genuine-admin-exit')
    assert not second.processing_authorized and not second.recovery_verified


def test_actual_cookie_revoked_after_disposable_restore_withholds_receipt(actual_case, monkeypatch):
    make, sid, digest, request, writer, _calls, active, sessions, cookie, leases = actual_case
    actual = DisposableStateRestoreVerifier.verify_personal
    milestones = []
    def restore(verifier, *args, **kwargs):
        result = actual(verifier, *args, **kwargs)
        assert active == {'canonical': 0, 'admin': 0}
        milestones.append('actual-restore-complete-and-lease-closed')
        sessions.revoke(cookie)
        milestones.append('original-cookie-revoked')
        return result
    monkeypatch.setattr(DisposableStateRestoreVerifier,'verify_personal',restore)
    with pytest.raises(ContextualProtectionError):
        make('cold-revoked').protect(source_id=sid, expected_digest=digest, expected_request=request)
    assert milestones == ['actual-restore-complete-and-lease-closed', 'original-cookie-revoked']
    assert leases[0] == ('enter', 'verify-personal', 1)
    assert leases[-1] == ('exit', 'verify-personal', 1)
    assert active == {'canonical': 0, 'admin': 0}
    assert not writer.exists(f'PERSONAL/state/history-fragment-{sid}/receipt-' +
        content_hash_of(encode_history_fragment_contextual_request(request)) + '.age')


@pytest.mark.parametrize('fault', ['missing-receipt', 'tampered-state-ciphertext'])
def test_actual_read_existing_missing_or_tampered_holds_before_restore(actual_case, monkeypatch, fault):
    make, sid, digest, request, writer, calls, active, _, _, leases = actual_case
    receipt = make('cold-first').protect(source_id=sid, expected_digest=digest,
        expected_request=request)
    assert calls.count('actual-verify-personal-start') == 1
    key = receipt.receipt_object if fault == 'missing-receipt' else receipt.state_object
    target = writer._path(key)
    assert target.is_file()
    if fault == 'missing-receipt':
        target.unlink()
        assert not writer.exists(key)
    else:
        target.write_bytes(b'invented corrupted encrypted State; not private plaintext')
        assert content_hash_of(target.read_bytes()) != receipt.state_ciphertext_hash
    milestones = [fault + '-actually-applied']
    writes = []
    def forbidden(*args, **kwargs):
        writes.append(True)
        raise AssertionError('failed read-existing cannot publish or repair')
    monkeypatch.setattr(writer, 'put_object', forbidden)
    with pytest.raises(ContextualProtectionError) as exc:
        make('cold-fault').recheck(source_id=sid, expected_digest=digest,
            expected_request=request)
    assert milestones == [fault + '-actually-applied']
    assert not writes and exc.value.__context__ is None
    assert calls.count('actual-verify-personal-start') == 1
    assert calls.count('actual-verify-personal-end') == 1
    assert_balanced_restoration_leases(leases, expected_restorations=1)
    assert active == {'canonical': 0, 'admin': 0}
    if fault == 'missing-receipt':
        assert not target.exists()
    else:
        assert target.read_bytes() == b'invented corrupted encrypted State; not private plaintext'
