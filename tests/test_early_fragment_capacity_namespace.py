"""Invented pure guard controls. SQL/owner/recovery simulated except SQLite prefix query."""
# ruff: noqa: F401, F811
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from tests.test_fragment_publication_post import observe, post_case
from tests.test_fragment_review_retention import capture, case, declaration_case, retained, writer
from tests.test_personal_bounded_backup import fixture
from tests.test_personal_fragment_claim_issuer import (
    authority,
    call,
    consent_case,
    installed,
    issuer,
    packet_case,
)
from zacai import backup_artifacts as backup
from zacai import contextual_authorization as auth
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_publication_admission as admission
from zacai.intelligence import fragment_review_retention as retention
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


def inventory(monkeypatch, count):
    state = {'count': count, 'observed': []}
    def rows(session, **kw):
        state['observed'].append(state['count'])
        return canonical_bytes([{'id': str(i)} for i in range(state['count'])]), ()
    monkeypatch.setattr(backup, '_personal_backup_rows', rows)
    return state


@pytest.mark.parametrize('count', [4089, 4095, 4096])
def test_declaration_overflow_before_any_artifact_write(writer, monkeypatch, count):
    f = writer
    state = inventory(monkeypatch, count)
    writes = []
    monkeypatch.setattr(f.store, 'put', lambda *a: writes.append('write') or (_ for _ in ()).throw(ValueError('stop')))
    with pytest.raises(retention.FragmentDeclarationRetentionError):
        capture(f)
    assert state['observed'] == [count]
    assert writes == [] and 'record' not in f.events and 'commit' not in f.events


def test_declaration_exact_full_chain_capacity_and_replay(writer, monkeypatch):
    f = writer
    state = inventory(monkeypatch, 4088)
    assert capture(f).reference == f.own
    assert state['observed'] == [4088, 4088, 4088]
    assert f.events.count('record') == 1
    assert capture(f).reference == f.own
    assert state['observed'] == [4088, 4088, 4088]  # Existing read does not reserve or renew.


def test_declaration_capacity_rechecked_after_file_callback(writer, monkeypatch):
    f = writer
    state = inventory(monkeypatch, 4088)
    put = f.store.put
    milestones = []
    def changed(*a):
        location = put(*a)
        state['count'] = 4089
        milestones.append('actual artifact put finished')
        return location
    monkeypatch.setattr(f.store, 'put', changed)
    with pytest.raises(retention.FragmentDeclarationRetentionError):
        capture(f)
    assert milestones == ['actual artifact put finished']
    assert state['observed'] == [4088, 4089]
    assert 'record' not in f.events and 'commit' not in f.events


def test_admission_overflow_before_own_artifact_write(post_case, tmp_path, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
    f = post_case
    action = observe(f)  # Actual Request/CSRF/session observer, not fabricated action.
    store = LocalFilesystemArtifactStore(tmp_path / 'admission-files')
    state = inventory(monkeypatch, 4090)
    monkeypatch.setattr(auth, '_fragment_decision_owner', lambda *a: None)  # Owner scope simulated.
    # Negative consumed-parent query is simulated in this capacity-only control.
    # Separate SQLite namespace controls exercise the real query.
    monkeypatch.setattr(auth, '_assert_fragment_generation_unconsumed', lambda *a: None)
    monkeypatch.setattr(admission, '_lock', lambda *a: None)
    monkeypatch.setattr(admission, '_physical', lambda *a: ('simulated',))
    monkeypatch.setattr(admission, '_same', lambda *a: None)
    monkeypatch.setattr(admission, '_not_withdrawn', lambda *a: None)
    monkeypatch.setattr(admission, '_fragment_rows', lambda *a: ())
    monkeypatch.setattr(admission, 'load_fragment_review_declaration', lambda *a, **kw: None)
    monkeypatch.setattr(admission, '_ids', lambda *a, **kw: ())
    writes = []
    monkeypatch.setattr(store, 'put', lambda *a: writes.append('write') or (_ for _ in ()).throw(ValueError('stop')))
    with pytest.raises(admission.FragmentPublicationAdmissionError):
        admission._record_posted_fragment_admission(factory=sessionmaker(class_=Session),
            artifacts=store, action=action, clock=f.clock)
    assert state['observed'] == [4090] and writes == []


@pytest.mark.parametrize('reserved', [3, 6, 7, 8])
def test_capacity_exact_boundary_and_overflow_preserves_full_inventory(fixture, monkeypatch, reserved):
    state = inventory(monkeypatch, 4096 - reserved)
    backup._assert_personal_custody_append_capacity(fixture['session'], reserved)
    state['count'] += 1
    with pytest.raises(ValueError, match='complete PERSONAL recovery capacity exhausted before burn'):
        backup._assert_personal_custody_append_capacity(fixture['session'], reserved)
    assert state['observed'] == [4096 - reserved, 4097 - reserved]


@pytest.mark.parametrize('reserved', [0, 9, True])
def test_invalid_reservation_never_reads_inventory(monkeypatch, reserved):
    state = inventory(monkeypatch, 1)
    with pytest.raises(ValueError, match='exact bounded custody append count'):
        backup._assert_personal_custody_append_capacity(object(), reserved)
    assert not state['observed']


def test_exact_prospective_prefix_real_sqlite_does_not_match_other_family(fixture):
    session = fixture['session']
    parent = uuid4()
    source = fixture['source']
    source.external_ref = f'personal-history-fragment-declaration-v2/{parent}/invented'
    source.system = SourceSystem.USER_INSTRUCTION
    session.commit()
    auth._assert_fragment_no_prospective_declaration(session, parent)
    source.system = SourceSystem.MANUAL
    session.commit()
    auth._assert_fragment_no_prospective_declaration(session, uuid4())
    with pytest.raises(ValueError, match='requires its publication admission'):
        auth._assert_fragment_no_prospective_declaration(session, parent)
    source.trust_boundary = B.BRAINSTORM
    session.commit()
    auth._assert_fragment_no_prospective_declaration(session, parent)


def test_legacy_burn_prospective_namespace_denies_before_consent_body(issuer, monkeypatch):
    f = issuer
    f.p.protect_consent(reference=f.consent_ref, expected_consent=f.consent, expected_request=f.q)
    f.events.clear()
    original = type(f.gate._factory()).scalars
    queries = []
    def scalars(session, query):
        params = query.compile().params
        if any(str(v).startswith('personal-history-fragment-declaration-v2/') for v in params.values()):
            queries.append('actual prefix query')
            return (uuid4(),)
        return original(session, query)
    monkeypatch.setattr(type(f.gate._factory()), 'scalars', scalars)
    with pytest.raises(auth.ContextualAuthorizationError):
        call(f)
    assert queries == ['actual prefix query']
    assert 'record' not in f.events and not f.ledger and f.gate._phase == 'HELD'


def test_legacy_recorder_prospective_parent_refuses_before_write(case, fixture, monkeypatch):
    q, c, store = case
    session = fixture['session']
    source = fixture['source']
    source.external_ref = f'personal-history-fragment-declaration-v2/{c.id}/invented'
    source.system = SourceSystem.MANUAL
    session.commit()
    monkeypatch.setattr(auth, '_fragment_decision_owner', lambda *a: None)
    monkeypatch.setattr(auth, '_lock', lambda *a: None)
    monkeypatch.setattr(auth, '_fragment_rows', lambda *a: ())
    monkeypatch.setattr(auth, '_fragment_profile_lineage', lambda *a: None)
    monkeypatch.setattr(auth, '_fragment_transaction', lambda s: ('simulated',))
    monkeypatch.setattr(auth, '_fragment_same_transaction', lambda *a: None)
    writes = []
    monkeypatch.setattr(store, 'put', lambda *a: writes.append('write') or (_ for _ in ()).throw(ValueError('stop')))
    factory = sessionmaker(bind=session.get_bind())
    with pytest.raises(auth.ContextualAuthorizationError):
        auth.record_history_fragment_consent(factory=factory, artifacts=store,
            consent=c, expected_request=q, operation=object(), clock=object())
    assert writes == []
    # The same literal namespace is observed by the real SQLite predicate.
    with pytest.raises(ValueError, match='requires its publication admission'):
        auth._assert_fragment_no_prospective_declaration(session, c.id)


def test_legacy_recorder_capacity_holds_before_artifact_write(case, fixture, monkeypatch):
    q, c, store = case
    state = inventory(monkeypatch, 4094)
    monkeypatch.setattr(auth, '_fragment_decision_owner', lambda *a: None)
    monkeypatch.setattr(auth, '_lock', lambda *a: None)
    monkeypatch.setattr(auth, '_fragment_rows', lambda *a: ())
    monkeypatch.setattr(auth, '_fragment_profile_lineage', lambda *a: None)
    monkeypatch.setattr(auth, '_fragment_transaction', lambda s: ('simulated',))
    monkeypatch.setattr(auth, '_fragment_same_transaction', lambda *a: None)
    writes = []
    monkeypatch.setattr(store, 'put', lambda *a: writes.append('write') or (_ for _ in ()).throw(ValueError('stop')))
    with pytest.raises(auth.ContextualAuthorizationError):
        auth.record_history_fragment_consent(factory=sessionmaker(bind=fixture['session'].get_bind()),
            artifacts=store, consent=c, expected_request=q, operation=object(), clock=object())
    assert state['observed'] == [4094] and writes == []


def test_legacy_burn_rechecks_prospective_namespace_after_claim_file(issuer, monkeypatch):
    f = issuer
    f.p.protect_consent(reference=f.consent_ref, expected_consent=f.consent, expected_request=f.q)
    f.events.clear()
    state = {'declaration': False, 'queries': []}
    original = type(f.gate._factory()).scalars
    def scalars(session, query):
        if any(str(v).startswith('personal-history-fragment-declaration-v2/')
               for v in query.compile().params.values()):
            state['queries'].append(state['declaration'])
            return (uuid4(),) if state['declaration'] else ()
        return original(session, query)
    monkeypatch.setattr(type(f.gate._factory()), 'scalars', scalars)
    put = f.p._artifacts.put
    milestones = []
    def changed(*a):
        result = put(*a)
        state['declaration'] = True
        milestones.append('actual claim put completed')
        return result
    monkeypatch.setattr(f.p._artifacts, 'put', changed)
    with pytest.raises(auth.ContextualAuthorizationError):
        call(f)
    assert milestones == ['actual claim put completed']
    assert state['queries'] == [False, True]
    assert 'record' not in f.events and 'commit' not in f.events and not f.ledger
