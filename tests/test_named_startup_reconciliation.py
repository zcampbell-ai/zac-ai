"""Disposable encrypted SQLite only; low-level store tests do not attest operator flock."""

import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_named_admission_store import fixture as admission_fixture
from tests.test_named_owner_host import (
    setup as setup,  # noqa: PLC0414 - shared pytest fixture re-export
)
from zacai.interfaces.followup_authorization import _owner_digest
from zacai.interfaces.named_admission_store import (
    NamedAdmissionStoreError,
    SqliteNamedAdmissionStore,
)
from zacai.interfaces.oidc_identity import Identity
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    s = admission_fixture.__wrapped__(tmp_path, monkeypatch)
    s.owner = OwnerGrant(Identity(s.template.actor_issuer, s.template.actor_subject),
                         (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),))
    s.template = s.template.model_copy(update={"owner_grant_digest": _owner_digest(s.owner)})
    return s


def rows(s):
    with sqlite3.connect(s.path / "admissions.sqlite") as connection:
        return connection.execute("SELECT digest,phase,issued,expires,sealed FROM admissions").fetchall()


def test_repeated_restart_reclaims_expired_admitted_metadata_without_raw_handles(fixture):
    s = fixture
    for _ in range(3):
        for _ in range(128):
            issued = s.issue()
            s.store.admit(handle=issued.handle, session_binding=s.session,
                          question_digest="b" * 64, question_bytes=12)
        assert len(rows(s)) == 128
        s.now += timedelta(minutes=16)
        s.store = SqliteNamedAdmissionStore(s.path, **s.args)
        assert s.store._reconcile_expired_for_owner(s.owner) == 128
        assert rows(s) == []
    assert s.issue().record.phase == "ISSUED"


def test_active_and_unknown_owner_scope_records_unchanged(fixture):
    s = fixture
    s.issue()
    original = rows(s)
    assert s.store._reconcile_expired_for_owner(s.owner) == 0
    assert rows(s) == original
    s.now += timedelta(minutes=6)
    foreign = OwnerGrant(Identity(s.owner.identity.issuer, "foreign"), s.owner.scopes)
    assert s.store._reconcile_expired_for_owner(foreign) == 0
    assert rows(s) == original
    assert s.store._reconcile_expired_for_owner(s.owner) == 1


def test_corrupt_expired_record_rolls_back_all_cleanup(fixture):
    s = fixture
    s.issue()
    bad = s.issue()
    s.now += timedelta(minutes=6)
    with sqlite3.connect(s.path / "admissions.sqlite") as connection:
        connection.execute("UPDATE admissions SET sealed=? WHERE digest=?",
                           (b"corrupt", bad.record.manifest.nonce_digest))
    original = rows(s)
    with pytest.raises(NamedAdmissionStoreError):
        s.store._reconcile_expired_for_owner(s.owner)
    assert rows(s) == original


def test_operator_startup_denies_nonempty_registry_before_reconciliation(setup, monkeypatch):
    from tests.test_named_owner_host import operator_args

    args, factory, _ = setup
    called = []
    monkeypatch.setattr(SqliteNamedAdmissionStore, "_reconcile_expired_for_owner",
                        lambda self, owner: called.append(owner))

    def invalid(inputs):
        pair = factory(inputs)
        pair.workers._entries[uuid4()] = object()  # Invented ambiguous prior worker.
        return pair

    with (pytest.raises(PrivateOperatorError),
          open_private_operator(mode=PrivateOperatorMode.OWNER, view=args["view"],
                                named_factory=invalid, **operator_args(args))):
        raise AssertionError("no app exposure")
    assert called == []



def test_operator_reconciliation_occurs_under_real_mode_flock_before_exposure(setup, monkeypatch):
    import fcntl
    import os

    from tests.test_named_owner_host import operator_args

    args, factory, _ = setup
    original = SqliteNamedAdmissionStore._reconcile_expired_for_owner
    checked = []

    def locked(self, owner):
        fd = os.open(args["directory"] / "private-mode.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        checked.append(owner)
        return original(self, owner)

    monkeypatch.setattr(SqliteNamedAdmissionStore, "_reconcile_expired_for_owner", locked)
    with open_private_operator(mode=PrivateOperatorMode.OWNER, view=args["view"],
                               named_factory=factory, **operator_args(args)):
        assert len(checked) == 1


def test_overcapacity_expired_database_holds_before_cleanup(fixture):
    s = fixture
    s.issue()
    original = rows(s)[0]
    with sqlite3.connect(s.path / "admissions.sqlite") as connection:
        for i in range(128):
            connection.execute("INSERT INTO admissions VALUES(?,?,?,?,?)",
                               (f"f{i:063x}", *original[1:]))
    s.now += timedelta(minutes=6)
    before = rows(s)
    with pytest.raises(NamedAdmissionStoreError):
        s.store._reconcile_expired_for_owner(s.owner)
    assert rows(s) == before and len(before) == 129


def test_failed_factory_worker_drains_before_flock_and_logging_release(setup):
    import fcntl
    import logging
    import os
    import sys
    from threading import Event, Thread

    from tests.test_named_owner_host import operator_args

    args, factory, _ = setup
    started, release, stopped, observed = Event(), Event(), Event(), Event()
    failures = []
    disabled = logging.root.manager.disable

    def private_work():
        started.set()
        try:
            release.wait()
        finally:
            stopped.set()

    def inspect_then_release():
        try:
            assert started.wait(3)
            for _ in range(300):
                if logging.root.manager.disable == sys.maxsize:
                    break
                observed.wait(0.01)
            assert not stopped.is_set()
            assert logging.root.manager.disable == sys.maxsize
            fd = os.open(args["directory"] / "private-mode.lock", os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            observed.set()
        except Exception as error:  # noqa: BLE001 - assert observer thread failures
            failures.append(error)
        finally:
            release.set()

    # A pre-existing test observer is deliberately preserved by startup drain.
    observer = Thread(target=inspect_then_release)
    observer.start()
    private = Thread(target=private_work)

    def invalid(inputs):
        factory(inputs)
        private.start()
        assert started.wait(3)
        raise ValueError("invented startup failure after native work")

    try:
        with (pytest.raises(PrivateOperatorError),
              open_private_operator(mode=PrivateOperatorMode.OWNER, view=args["view"],
                                    named_factory=invalid, **operator_args(args))):
            raise AssertionError("not exposed")
    finally:
        release.set()
        observer.join(4)
        if private.ident is not None:
            private.join(4)
    assert not failures and observed.is_set() and stopped.is_set()
    assert not private.is_alive() and logging.root.manager.disable == disabled
