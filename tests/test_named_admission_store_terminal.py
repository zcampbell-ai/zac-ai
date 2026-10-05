"""Trusted low-level terminal seam only; no real worker-drain/auth authority.

The modeled request lock below illustrates the caller requirement, not an actual
production submission registry. GET reuse locks cannot attest worker completion.
"""

import sqlite3
from datetime import timedelta
from threading import Event, Lock, Thread

import pytest

from tests.test_named_admission_store import admit, ref
from tests.test_named_admission_store import fixture as store_fixture
from zacai.interfaces import named_admission_store as m


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    s = store_fixture.__wrapped__(tmp_path, monkeypatch)
    s.store = m.SqliteNamedAdmissionStore(s.path, **{**s.args,"capacity":1})
    return s


def prepare(s, phase):
    issued=s.issue()
    row=issued.record
    if phase!="ISSUED":
        row=admit(s,issued)
    if phase in ("QUESTION_BOUND","DECISION_BOUND"):
        row=s.store.attach_question(handle=issued.handle,session_binding=s.session,
                                    reference=ref(),recovery_digest="d"*64)
    if phase=="DECISION_BOUND":
        row=s.store.attach_decision(handle=issued.handle,session_binding=s.session,
                                    reference=ref(),recovery_digest="e"*64)
    expiry=row.manifest.admission_expires_at if phase=="ISSUED" else row.processing_expires_at
    return issued,expiry


@pytest.mark.parametrize("phase",["ISSUED","ADMITTED","QUESTION_BOUND","DECISION_BOUND"])
def test_explicit_terminal_retirement_at_expiry_releases_capacity_no_renewal(fixture,phase):
    s=fixture
    issued,expiry=prepare(s,phase)
    s.now=expiry
    # Trusted caller represents a genuinely drained operation, not an API grant.
    assert s.store.retire_expired(handle=issued.handle,session_binding=s.session) is None
    replacement=s.issue()
    assert replacement.handle!=issued.handle
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.get(handle=issued.handle,session_binding=s.session)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.retire_expired(handle=issued.handle,session_binding=s.session)


@pytest.mark.parametrize("phase",["ISSUED","ADMITTED","QUESTION_BOUND","DECISION_BOUND"])
def test_active_record_never_retires(fixture,phase):
    s=fixture
    issued,expiry=prepare(s,phase)
    s.now=expiry-timedelta(microseconds=1)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.retire_expired(handle=issued.handle,session_binding=s.session)
    assert s.store.get(handle=issued.handle,session_binding=s.session).phase==phase


@pytest.mark.parametrize("binding",[None,True,"0"*64,"a"*63,"G"*64])
def test_original_session_binding_required_even_after_expiry(fixture,binding):
    s=fixture
    issued,expiry=prepare(s,"ADMITTED")
    s.now=expiry
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.retire_expired(handle=issued.handle,session_binding=binding)
    with sqlite3.connect(s.path/"admissions.sqlite") as conn:
        assert conn.execute("SELECT COUNT(*) FROM admissions").fetchone()[0]==1


@pytest.mark.parametrize("part",["sealed","phase","issued","expires"])
def test_corrupt_or_changed_terminal_metadata_holds(fixture,part):
    s=fixture
    issued,expiry=prepare(s,"ADMITTED")
    s.now=expiry
    with sqlite3.connect(s.path/"admissions.sqlite") as conn:
        conn.execute(f"UPDATE admissions SET {part}=?",({"sealed":b"x"*64,"phase":"ISSUED","issued":0,"expires":0}[part],))
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.retire_expired(handle=issued.handle,session_binding=s.session)
    with sqlite3.connect(s.path/"admissions.sqlite") as conn:
        assert conn.execute("SELECT COUNT(*) FROM admissions").fetchone()[0]==1


def test_real_caller_guard_waits_for_modeled_worker_before_low_level_retirement(fixture):
    s=fixture
    issued,expiry=prepare(s,"ADMITTED")
    s.now=expiry
    guard=Lock()
    entered,release,retired=Event(),Event(),Event()
    failures=[]
    def worker():
        with guard:
            entered.set()
            release.wait(3)
    def terminal_host():
        try:
            with guard:
                s.store.retire_expired(handle=issued.handle,session_binding=s.session)
            retired.set()
        except Exception as error:  # noqa: BLE001 - invented thread failure type only
            failures.append(type(error))
    active=Thread(target=worker)
    cleanup=Thread(target=terminal_host)
    active.start()
    assert entered.wait(1)
    cleanup.start()
    try:
        assert not retired.wait(0.05)
        with sqlite3.connect(s.path/"admissions.sqlite") as conn:
            assert conn.execute("SELECT COUNT(*) FROM admissions").fetchone()[0]==1
    finally:
        release.set()
        active.join(3)
        cleanup.join(3)
    assert retired.is_set() and failures==[]
