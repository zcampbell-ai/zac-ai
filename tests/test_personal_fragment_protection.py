"""Invented mechanical adapter controls, not actual owner/SQL/age recovery proof.

Real canonical fragment codec and bounded object files; operation issuer, SQL
loader/whole-boundary plan/backup journal/snapshot/restore and age are simulated.
Root must execute genuine PostgreSQL/age full-union acceptance separately.
"""
import json
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_claude_large_original_message import AT
from tests.test_fragment_contextual_storage import payload
from zacai import contextual_protection as m
from zacai.backup_artifacts import LocalDirectoryBackupStore, PersonalFullOriginalBackupPlan
from zacai.claude_local_custody import _SCOPE
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_storage import history_fragment_packet_provenance
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_packet,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.private_web import InterfacePrincipal
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRunStatus


@pytest.fixture
def assembled(tmp_path, monkeypatch):
    raw_packet = payload(elevated=True)
    packet = decode_history_fragment_contextual_packet(raw_packet)
    q = packet.request()
    engine = create_engine('postgresql+psycopg://zacai@127.0.0.1:5432/zacai_test')
    factory = sessionmaker(engine, expire_on_commit=False)
    clock = HostObservedClock(lambda: AT + timedelta(seconds=5))
    operation = object.__new__(NamedSessionOperation)
    operation._host_clock = lambda: clock
    principal = InterfacePrincipal(Identity('https://accounts.google.com', 'invented-owner'), _SCOPE)
    verified = VerifiedNamedSession(principal, 'a'*64, AT,
        AT + timedelta(minutes=15), AT + timedelta(minutes=15))
    events = []
    owner = {'value': verified}
    def read_owner():
        events.append('owner')
        value = owner['value']
        if value is None:
            raise ValueError('invented owner revoked')
        return value
    operation._read = read_owner
    objects = LocalDirectoryBackupStore(tmp_path/'objects')
    reader = LocalDirectoryBackupStore(tmp_path/'objects')
    artifacts = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    cold = LocalFilesystemArtifactStore(tmp_path/'cold')
    restoration = DisposableStateRestoreVerifier()
    key_path=tmp_path/'invented-recovered-key'
    key_path.write_bytes(b'invented mocked recovered identity; not an age key')
    key_path.chmod(0o600)
    p = m.PersonalHistoryFragmentProtector(factory=factory, engine=engine,
        artifacts=artifacts, cold_artifacts=cold, objects=objects,
        verification_objects=reader, recipient='age1'+'q'*58,
        identity_path=tmp_path/'invented-recovered-key', manifest_cache=tmp_path/'cache',
        operation=operation, clock=clock, restoration=restoration)
    sid, digest, run_id = uuid4(), content_hash_of(raw_packet), uuid4()
    # sid/digest represent a simulated canonical row. Full packet is actual codec.
    refs = history_fragment_packet_provenance(packet)
    rows = [{'id':str(ref.source_id), 'content_hash':ref.content_hash} for ref in refs]
    rows.append({'id':str(sid),'content_hash':digest})
    plan = PersonalFullOriginalBackupPlan(engine, canonical_bytes(rows),
        tuple(sorted({(ref.content_hash, f'{ref.content_hash[:2]}/{ref.content_hash}.bin') for ref in refs})),
        profile='personal-encrypted-custody-backup-v2')
    current_plan = {'value':plan}
    monkeypatch.setattr(p, '_plan', lambda: current_plan['value'])
    def loader(*args):
        events.append('packet')
        return packet
    monkeypatch.setattr(p, '_packet', loader)
    monkeypatch.setattr(m.backup, '_admin_connection', lambda: nullcontext())
    monkeypatch.setattr(p, '_snapshot', lambda *args: (b'invented-state',b'invented-journal'))
    monkeypatch.setattr(p, '_run_row', lambda run: b'invented-live-successful-run')
    monkeypatch.setattr(p, '_artifacts_recover', lambda *args: (events.append('artifact-recover') or ()))
    def backup(*args, **kwargs):
        events.append('backup')
        return SimpleNamespace(id=run_id,status=ArtifactBackupRunStatus.SUCCEEDED)
    monkeypatch.setattr(m, 'run_artifact_backup', backup)
    import zacai.claude_local_protection as local
    def encrypt(raw,*args):
        events.append('encrypt')
        return b'invented-cipher:'+raw
    def decrypt(raw,*args):
        events.append('decrypt')
        assert raw.startswith(b'invented-cipher:')
        return raw[len(b'invented-cipher:'):]
    monkeypatch.setattr(local,'_crypt',encrypt)
    monkeypatch.setattr(local,'_recover',decrypt)
    restored=[]
    def restore(self, raw, expected, **kwargs):
        restored.append((raw,expected,kwargs))
        events.append('restore')
    monkeypatch.setattr(DisposableStateRestoreVerifier,'verify_personal',restore)
    try:
        yield SimpleNamespace(p=p,q=q,packet=packet,sid=sid,digest=digest,
            events=events,owner=owner,verified=verified,plan=plan,current_plan=current_plan,
            writer=objects,reader=reader,restored=restored,local=local,run=run_id)
    finally:
        engine.dispose()


def call(f, existing=False, **changes):
    values={'source_id':f.sid,'expected_digest':f.digest,'expected_request':f.q}
    values.update(changes)
    return (f.p.recheck if existing else f.p.protect)(**values)


def test_protect_then_read_existing_repeats_restore_never_backup_or_receipt_repair(assembled,monkeypatch):
    f=assembled
    receipt=call(f)
    assert f.events.count('backup')==1 and f.events.count('restore')==1
    assert f.events.index('owner') < f.events.index('packet') < f.events.index('decrypt')
    assert f.restored[0][0]==b'invented-state'
    assert f.restored[0][2]['operational_journal']==b'invented-journal'
    assert f.sid in f.restored[0][1]
    assert not receipt.processing_authorized and not receipt.recovery_verified
    writes=[]
    monkeypatch.setattr(f.writer,'put_object',lambda *args:writes.append(args))
    assert call(f,existing=True)==receipt
    assert not writes and f.events.count('backup')==1 and f.events.count('restore')==2


@pytest.mark.parametrize('change',['digest','request-type','source-type','boundary','classification'])
def test_wrong_subject_denies_before_any_owner_private_or_backup_callback(assembled,change):
    f=assembled
    kwargs={'digest':{'expected_digest':'BAD'},'request-type':{'expected_request':object()},
        'source-type':{'source_id':str(f.sid)},
        'boundary':{'expected_request':f.q.model_copy(update={'task':f.q.task.model_copy(update={
            'event':f.q.task.event.model_copy(update={'trust_boundary':B.BRAINSTORM})})})},
        'classification':{'expected_request':f.q.model_copy(update={'task':f.q.task.model_copy(update={
            'event':f.q.task.event.model_copy(update={'data_classification':C.CONFIDENTIAL})})})}}[change]
    with pytest.raises(m.ContextualProtectionError) as exc:
        call(f,**kwargs)
    assert not f.events and exc.value.__context__ is None


def test_revoked_owner_zero_private_or_key_reads(assembled):
    f=assembled;f.owner['value']=None
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert f.events==['owner'] and not f.restored


def test_missing_full_union_holds_before_backup(assembled):
    f=assembled
    rows=json.loads(f.plan.rows);rows.pop(0)
    f.current_plan['value']=replace(f.plan,rows=canonical_bytes(rows))
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'packet' in f.events and 'backup' not in f.events and not f.restored


def test_plan_drift_after_actual_packet_loader_seam_holds(assembled,monkeypatch):
    f=assembled
    def changed(*args):
        f.events.append('packet-drift')
        f.current_plan['value']=replace(f.plan,rows=f.plan.rows+b' ')
        return f.packet
    monkeypatch.setattr(f.p,'_packet',changed)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'packet-drift' in f.events and 'backup' not in f.events


def test_read_existing_missing_receipt_never_mints_or_runs_backup(assembled):
    f=assembled
    with pytest.raises(m.ContextualProtectionError):call(f,existing=True)
    assert 'backup' not in f.events and 'encrypt' not in f.events and not f.restored


def test_second_protect_refuses_existing_receipt_before_new_backup(assembled):
    f=assembled;call(f);f.events.clear()
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'backup' not in f.events and 'restore' not in f.events


def test_owner_withdrawal_during_key_callback_holds_before_restore(assembled,monkeypatch):
    f=assembled;original=f.local._recover
    def logout(*args):
        value=original(*args);f.owner['value']=None;f.events.append('logout');return value
    monkeypatch.setattr(f.local,'_recover',logout)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'logout' in f.events and not f.restored


def test_live_journal_drift_after_restore_withholds_receipt(assembled,monkeypatch):
    f=assembled
    def restore(*args,**kwargs):
        f.events.append('restore-drift')
        monkeypatch.setattr(f.p,'_run_row',lambda run:b'changed-live-journal')
    monkeypatch.setattr(f.p._restoration,'verify_personal',restore)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'restore-drift' in f.events
    from zacai.intelligence.history_fragment_contextual_codec import (
        encode_history_fragment_contextual_request,
    )
    actual=f'PERSONAL/state/history-fragment-{f.sid}/receipt-{content_hash_of(encode_history_fragment_contextual_request(f.q))}.age'
    assert not f.writer.exists(actual)


def test_restore_failure_has_no_receipt_acknowledgment(assembled,monkeypatch):
    f=assembled
    def fail(*args,**kwargs):raise RuntimeError('invented-private-diagnostic')
    monkeypatch.setattr(f.p._restoration,'verify_personal',fail)
    with pytest.raises(m.ContextualProtectionError) as exc:call(f)
    assert str(exc.value)=='PERSONAL fragment recovery unavailable or mismatched'
    assert exc.value.__context__ is None


def test_terminal_owner_callback_source_plan_mutation_holds(assembled,monkeypatch):
    f=assembled;original=f.p._access;count=[]
    def mutate(prior=None):
        value=original(prior)
        if f.events.count('restore') and f.events.count('encrypt')>=3:
            f.current_plan['value']=replace(f.plan,rows=f.plan.rows+b' ');count.append(True)
        return value
    monkeypatch.setattr(f.p,'_access',mutate)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert count and f.events.count('restore')==1


def test_canonical_receipt_rejects_duplicate_extra_and_cross_boundary(assembled):
    f=assembled;receipt=call(f);raw=m.encode_personal_fragment_receipt(receipt)
    assert m.decode_personal_fragment_receipt(raw)==receipt
    for changed in (raw.replace(b'{',b'{"format":"duplicate",',1),
        raw[:-1]+b',"extra":true}',raw.replace(b'PERSONAL',b'BRAINSTORM')):
        with pytest.raises(ValueError):m.decode_personal_fragment_receipt(changed)


def test_stale_receipt_plan_rejects_before_second_restore(assembled):
    f=assembled;call(f);f.events.clear()
    f.current_plan['value']=replace(f.plan,rows=f.plan.rows+b' ')
    with pytest.raises(m.ContextualProtectionError):call(f,existing=True)
    assert 'decrypt' in f.events and 'restore' not in f.events and 'backup' not in f.events


def test_actual_bounded_manifest_wrong_boundary_holds_before_private_artifact_reads(assembled,monkeypatch):
    f=assembled
    from zacai.backup_artifacts import Manifest, manifest_key_for
    wrong=Manifest(boundary=B.BRAINSTORM.value,generated_at=AT.isoformat(),entries={})
    f.writer.put_object(manifest_key_for(B.PERSONAL),b'invented-cipher:'+wrong.to_json_bytes())
    monkeypatch.delattr(f.p,'_artifacts_recover')
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'decrypt' in f.events and not f.restored


def test_exact_recovered_state_hash_mismatch_denies_before_disposable_restore(assembled,monkeypatch):
    f=assembled;original=f.local._recover
    def corrupt(raw,*args):
        value=original(raw,*args)
        return b'wrong-state' if value==b'invented-state' else value
    monkeypatch.setattr(f.local,'_recover',corrupt)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'decrypt' in f.events and not f.restored


def test_clock_expiry_during_recovered_key_callback_holds(assembled,monkeypatch):
    f=assembled;original=f.local._recover
    def expire(*args):
        value=original(*args)
        monkeypatch.setattr(f.p._clock,'_read',lambda:AT+timedelta(minutes=16))
        f.events.append('expiry')
        return value
    monkeypatch.setattr(f.local,'_recover',expire)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'expiry' in f.events and not f.restored


def test_identity_file_replacement_during_decrypt_withholds_restore(assembled,monkeypatch):
    f=assembled;original=f.local._recover
    def changed(*args):
        value=original(*args)
        f.p._identity.write_bytes(b'changed invented identity')
        f.events.append('key-change')
        return value
    monkeypatch.setattr(f.local,'_recover',changed)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'key-change' in f.events and not f.restored


def test_cleanup_uncertainty_keeps_distinct_fixed_operator_hold(assembled,monkeypatch):
    from zacai.review_protection import ReviewProtectionCleanupUncertain
    f=assembled
    def uncertain(*args,**kwargs):
        f.events.append('cleanup-uncertain')
        raise ReviewProtectionCleanupUncertain('invented persistent quarantine')
    monkeypatch.setattr(f.p._restoration,'verify_personal',uncertain)
    with pytest.raises(m.PersonalFragmentCleanupUncertain) as exc:call(f)
    assert 'cleanup-uncertain' in f.events
    assert 'operator review required' in str(exc.value) and exc.value.__context__ is None


def test_original_operation_callback_transplant_during_decryption_holds(assembled,monkeypatch):
    f=assembled;original=f.local._recover
    def transplant(*args):
        value=original(*args)
        f.p._operation._read=lambda:f.verified
        f.events.append('operation-transplant')
        return value
    monkeypatch.setattr(f.local,'_recover',transplant)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'operation-transplant' in f.events and not f.restored


def test_reader_root_transplant_during_callback_holds(assembled,tmp_path,monkeypatch):
    f=assembled;original=f.local._recover
    other=tmp_path/'other-objects';other.mkdir(mode=0o700)
    def transplant(*args):
        value=original(*args);f.reader._root=other
        f.events.append('reader-transplant');return value
    monkeypatch.setattr(f.local,'_recover',transplant)
    with pytest.raises(m.ContextualProtectionError):call(f)
    assert 'reader-transplant' in f.events and not f.restored


def test_owner_callbacks_outside_all_adapter_sql_and_restore_contexts(assembled, monkeypatch):
    """Simulated ordering discriminator; genuine cookie/SQL acceptance is separate."""
    f = assembled
    active = []
    milestones = []

    @contextmanager
    def lease(name):
        active.append(name)
        milestones.append(name)
        try:
            yield
        finally:
            active.pop()

    monkeypatch.setattr(m.backup, '_admin_connection', lambda: lease('outer-admin'))
    original_owner = f.p._operation._read

    def owner():
        assert not active, 'owner callback inside SQL/restore lease'
        return original_owner()

    monkeypatch.setattr(f.p._operation, '_read', owner)
    f.p._operation_settings = (owner, f.p._operation._host_clock)
    for name in ('_plan', '_packet', '_snapshot', '_run_row'):
        original = getattr(f.p, name)

        def wrapped(*args, _original=original, _name=name):
            with lease(_name):
                return _original(*args)

        monkeypatch.setattr(f.p, name, wrapped)
    original_restore = f.p._restoration.verify_personal

    def restore(*args, **kwargs):
        with lease('restore-admin'):
            return original_restore(*args, **kwargs)

    monkeypatch.setattr(f.p._restoration, 'verify_personal', restore)
    receipt = call(f)
    assert receipt.packet_reference.source_id == f.sid
    assert 'restore-admin' in milestones and '_snapshot' in milestones
    assert 'outer-admin' not in milestones and not active
