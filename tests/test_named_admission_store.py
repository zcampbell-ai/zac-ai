"""Invented encrypted operational files; no real auth/SQL/model authority."""

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_named_followup_decision import fixture as named_fixture
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import named_admission_store as m
from zacai.interfaces.host_clock import HostObservedClock
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    original = named_fixture.__wrapped__(monkeypatch)
    s = SimpleNamespace(now=original.manifest.issued_at, template=original.manifest,
                        path=tmp_path / "admissions", key=b"x"*32, session="a"*64)
    s.clock = HostObservedClock(lambda: s.now)
    s.args = {"key": s.key, "origin": "https://caz.example", "client_id": "invented-client", "clock": s.clock}
    s.store = m.SqliteNamedAdmissionStore(s.path, **s.args)
    def build(nonce, now):
        return s.template.model_copy(update={"nonce_digest": nonce, "issued_at": now,
            "admission_expires_at": now + timedelta(minutes=5), "request_id": uuid4()})
    s.build = build
    s.issue = lambda: s.store.issue(session_binding=s.session, manifest_builder=build)
    return s


def admit(s, issued, **updates):
    return s.store.admit(handle=issued.handle, session_binding=s.session,
                         question_digest=updates.get("question_digest", "b"*64), question_bytes=updates.get("question_bytes", 12))


def ref():
    return EvidenceReference(source_id=uuid4(), content_hash="c"*64,
                             trust_boundary=B.BRAINSTORM, effective_classification=C.CONFIDENTIAL)


def test_issue_atomic_admit_exact_retry_and_reopen(fixture):
    s = fixture
    issued = s.issue()
    assert issued.record.phase == "ISSUED"
    assert issued.record.manifest.nonce_digest == m.named_admission_nonce_digest(issued.handle)
    first = admit(s, issued)
    s.now += timedelta(seconds=5)
    assert admit(s, issued) == first
    s.store = m.SqliteNamedAdmissionStore(s.path, **s.args)
    assert s.store.get(handle=issued.handle, session_binding=s.session) == first
    assert first.admitted_at == issued.record.manifest.issued_at
    assert first.processing_expires_at == first.admitted_at + timedelta(seconds=first.manifest.processing_ttl_seconds)
    assert issued.handle not in repr(issued) and s.session not in repr(first)


def test_only_ciphertext_no_raw_operational_nonce(fixture):
    s = fixture
    issued = s.issue()
    admit(s, issued)
    raw = (s.path / "admissions.sqlite").read_bytes()
    assert issued.handle.encode() not in raw
    assert s.session.encode() not in raw and b"https://accounts.google.com" not in raw
    assert s.template.actor_subject.encode() not in raw
    assert s.template.packet_reference.source_id.bytes not in raw
    assert os.stat(s.path).st_mode & 0o777 == 0o700
    assert os.stat(s.path / "admissions.sqlite").st_mode & 0o777 == 0o600


@pytest.mark.parametrize("update", [{"question_digest": "d"*64}, {"question_bytes": 13},
                                    {"question_bytes": True}, {"question_bytes": "12"}])
def test_conflicting_retry_does_not_change_admission(fixture, update):
    s = fixture
    issued = s.issue()
    first = admit(s, issued)
    with pytest.raises(m.NamedAdmissionStoreError):
        admit(s, issued, **update)
    assert s.store.get(handle=issued.handle, session_binding=s.session) == first


def test_original_session_binding_required(fixture):
    s = fixture
    issued = s.issue()
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.get(handle=issued.handle, session_binding="0"*64)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.admit(handle=issued.handle, session_binding="0"*64, question_digest="b"*64, question_bytes=12)


def test_atomic_concurrent_identical_and_conflicting_admissions(fixture):
    s = fixture
    issued = s.issue()
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(lambda _: admit(s, issued), range(2)))
    assert rows[0] == rows[1]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(admit, s, issued, question_digest=digest) for digest in ("b"*64, "d"*64)]
        assert futures[0].result() == rows[0]
        with pytest.raises(m.NamedAdmissionStoreError):
            futures[1].result()


def test_attach_phases_are_exact_idempotent_and_not_proof(fixture):
    s = fixture
    issued = s.issue()
    admit(s, issued)
    question, decision = ref(), ref()
    fields = {"handle": issued.handle, "session_binding": s.session, "reference": question, "recovery_digest": "d"*64}
    first = s.store.attach_question(**fields)
    assert first.phase == "QUESTION_BOUND" and s.store.attach_question(**fields) == first
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.attach_question(**{**fields, "reference": ref()})
    second = s.store.attach_decision(**{**fields, "reference": decision})
    assert second.phase == "DECISION_BOUND"
    assert s.store.attach_decision(**{**fields, "reference": decision}) == second
    assert not hasattr(second, "processing_authorized")


@pytest.mark.parametrize("bad", ["before_question", "same_source", "family"])
def test_bad_attachment_phase_or_dependency(fixture, bad):
    s = fixture
    issued = s.issue()
    admit(s, issued)
    question = ref()
    if bad != "before_question":
        s.store.attach_question(handle=issued.handle, session_binding=s.session, reference=question, recovery_digest="d"*64)
    reference = question if bad == "same_source" else ref()
    if bad == "family":
        reference = reference.model_copy(update={"trust_boundary": B.PERSONAL})
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.attach_decision(handle=issued.handle, session_binding=s.session, reference=reference, recovery_digest="d"*64)


@pytest.mark.parametrize("phase", ["issued", "admitted"])
def test_expiry_equality_reopen_never_renews(fixture, phase):
    s = fixture
    issued = s.issue()
    record = issued.record if phase == "issued" else admit(s, issued)
    s.now = record.manifest.admission_expires_at if phase == "issued" else record.processing_expires_at
    s.store = m.SqliteNamedAdmissionStore(s.path, **s.args)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.get(handle=issued.handle, session_binding=s.session)
    with pytest.raises(m.NamedAdmissionStoreError):
        admit(s, issued)


def test_persisted_clock_rollback_detected_with_new_process_clock(fixture):
    s = fixture
    issued = s.issue()
    s.now += timedelta(seconds=5)
    s.store.get(handle=issued.handle, session_binding=s.session)
    s.now -= timedelta(seconds=1)
    with pytest.raises(m.NamedAdmissionStoreError):
        m.SqliteNamedAdmissionStore(s.path, **{**s.args, "clock": HostObservedClock(lambda: s.now)})


@pytest.mark.parametrize("change", ["key", "origin", "client"])
def test_key_or_configuration_substitution_closed(fixture, change):
    s = fixture
    s.issue()
    args = dict(s.args)
    args[{"key":"key", "origin":"origin", "client":"client_id"}[change]] = {
        "key": b"y"*32, "origin":"https://other.example", "client":"other-client"}[change]
    with pytest.raises(m.NamedAdmissionStoreError):
        m.SqliteNamedAdmissionStore(s.path, **args)


@pytest.mark.parametrize("part", ["sealed", "phase", "issued", "expires", "digest"])
def test_tamper_payload_or_complete_metadata_denies(fixture, part):
    s = fixture
    issued = s.issue()
    with sqlite3.connect(s.path / "admissions.sqlite") as conn:
        if part == "sealed":
            conn.execute("UPDATE admissions SET sealed=?", (b"x"*64,))
        else:
            conn.execute(f"UPDATE admissions SET {part}=?", ({"phase":"DECISION_BOUND", "issued":0, "expires":999999999999999999, "digest":"f"*64}[part],))
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.get(handle=issued.handle, session_binding=s.session)


def test_capacity_and_expired_unused_purge(fixture):
    s = fixture
    s.store = m.SqliteNamedAdmissionStore(s.path, **{**s.args, "capacity": 1})
    first = s.issue()
    with pytest.raises(m.NamedAdmissionStoreError):
        s.issue()
    s.now = first.record.manifest.admission_expires_at
    second = s.issue()
    assert second.handle != first.handle


@pytest.mark.parametrize("unsafe", ["directory_mode", "file_mode", "symlink", "hardlink", "version"])
def test_unsafe_existing_store_closed(fixture, unsafe):
    s = fixture
    path = s.path / "admissions.sqlite"
    if unsafe == "directory_mode":
        s.path.chmod(0o755)
    elif unsafe == "file_mode":
        path.chmod(0o644)
    elif unsafe == "symlink":
        target = s.path / "target.sqlite"
        path.rename(target)
        path.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(path, s.path / "linked.sqlite")
    else:
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA user_version=2")
    with pytest.raises(m.NamedAdmissionStoreError):
        m.SqliteNamedAdmissionStore(s.path, **s.args)


def test_valid_manifest_builder_takes_independent_immediate_lock_then_issue_succeeds(fixture):
    s = fixture
    locks = []
    def build(nonce, now):
        conn = sqlite3.connect(s.path / "admissions.sqlite", timeout=0)
        try:
            conn.execute("BEGIN IMMEDIATE")
            locks.append(True)
            conn.execute("ROLLBACK")
        finally:
            conn.close()
        return s.build(nonce, now)
    issued = s.store.issue(session_binding=s.session, manifest_builder=build)
    assert locks == [True]
    assert s.store.get(handle=issued.handle, session_binding=s.session) == issued.record


def test_manifest_builder_cannot_rebind_nonce(fixture):
    s = fixture
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.issue(session_binding=s.session, manifest_builder=lambda nonce, now: s.build("0"*64, now))


@pytest.mark.parametrize("field,value", [("question_bytes", 0), ("question_bytes", 8001),
                                        ("question_digest", "not-a-digest"), ("question_digest", None)])
def test_initial_admission_bounds_closed(fixture, field, value):
    s = fixture
    issued = s.issue()
    with pytest.raises(m.NamedAdmissionStoreError):
        admit(s, issued, **{field: value})
    assert s.store.get(handle=issued.handle, session_binding=s.session).phase == "ISSUED"


def test_store_capacity_never_evicts_unexpired_admitted_record(fixture):
    s = fixture
    s.store = m.SqliteNamedAdmissionStore(s.path, **{**s.args, "capacity": 1})
    issued = s.issue()
    original = admit(s, issued)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.issue()
    assert s.store.get(handle=issued.handle, session_binding=s.session) == original


@pytest.mark.parametrize("change", ["unknown_table", "missing_watermark", "watermark_tamper"])
def test_schema_and_authenticated_watermark_closed(fixture, change):
    s = fixture
    with sqlite3.connect(s.path / "admissions.sqlite") as conn:
        if change == "unknown_table":
            conn.execute("CREATE TABLE extra(data TEXT)")
        elif change == "missing_watermark":
            conn.execute("DELETE FROM watermark")
        else:
            conn.execute("UPDATE watermark SET sealed=?", (b"x"*64,))
    with pytest.raises(m.NamedAdmissionStoreError):
        m.SqliteNamedAdmissionStore(s.path, **s.args)


@pytest.mark.parametrize("phase", ["ADMITTED", "QUESTION_BOUND", "DECISION_BOUND"])
def test_expired_admitted_or_bound_work_never_automatically_evicted(fixture, phase):
    s = fixture
    s.store = m.SqliteNamedAdmissionStore(s.path, **{**s.args, "capacity": 1})
    issued = s.issue()
    row = admit(s, issued)
    if phase != "ADMITTED":
        row = s.store.attach_question(handle=issued.handle, session_binding=s.session,
                                     reference=ref(), recovery_digest="d"*64)
    if phase == "DECISION_BOUND":
        row = s.store.attach_decision(handle=issued.handle, session_binding=s.session,
                                     reference=ref(), recovery_digest="e"*64)
    s.now = row.processing_expires_at + timedelta(seconds=1)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.issue()
    with sqlite3.connect(s.path / "admissions.sqlite") as conn:
        assert conn.execute("SELECT phase FROM admissions").fetchall() == [(phase,)]


@pytest.mark.parametrize("binding", [None, True, "", "a"*63, "G"*64, "é"*64, b"a"*64])
def test_incompatible_session_binding_shapes_denied(fixture, binding):
    s = fixture
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.issue(session_binding=binding, manifest_builder=s.build)
    issued = s.issue()
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.get(handle=issued.handle, session_binding=binding)
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.admit(handle=issued.handle, session_binding=binding, question_digest="b"*64, question_bytes=12)


@pytest.mark.parametrize("change", ["duplicate", "nested_duplicate", "unknown", "coerced", "nonfinite"])
def test_authenticated_but_noncanonical_or_invalid_json_payload_denied(fixture, change):
    import json

    from zacai.ingestion.artifact_store import canonical_bytes

    s = fixture
    issued = s.issue()
    admit(s, issued)
    with sqlite3.connect(s.path / "admissions.sqlite") as conn:
        digest, phase, observed, expires, sealed = conn.execute("SELECT * FROM admissions").fetchone()
        aad = s.store._aad(digest, phase, observed, expires)
        raw = s.store._open(sealed, aad)
        if change == "duplicate":
            raw = b'{"phase":"ISSUED",' + raw[1:]
        elif change == "nested_duplicate":
            raw = raw.replace(b'"manifest":{', b'"manifest":{"action":"wrong",', 1)
        elif change == "nonfinite":
            raw = raw.replace(b'"question_bytes":12', b'"question_bytes":NaN')
        else:
            data = json.loads(raw)
            if change == "unknown":
                data["approved"] = True
            else:
                data["question_bytes"] = "12"
            raw = canonical_bytes(data)
        conn.execute("UPDATE admissions SET sealed=?", (s.store._seal(raw, aad),))
    with pytest.raises(m.NamedAdmissionStoreError):
        s.store.get(handle=issued.handle, session_binding=s.session)



def test_failed_first_open_can_retry_empty_rolled_back_schema(fixture):
    s = fixture
    directory = s.path.parent / "interrupted-first-open"
    def fail_clock():
        raise RuntimeError("invented first-open interruption")
    with pytest.raises(m.NamedAdmissionStoreError):
        m.SqliteNamedAdmissionStore(directory, **{**s.args, "clock": HostObservedClock(fail_clock)})
    path = directory / "admissions.sqlite"
    assert path.is_file() and path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute("SELECT name FROM sqlite_master").fetchall() == []
    reopened = m.SqliteNamedAdmissionStore(directory, **s.args)
    issued = reopened.issue(session_binding=s.session, manifest_builder=s.build)
    assert reopened.get(handle=issued.handle, session_binding=s.session) == issued.record


def test_empty_private_file_visible_to_peer_initializes_atomically(fixture):
    s = fixture
    directory = s.path.parent / "peer-first-open"
    directory.mkdir(mode=0o700)
    fd = os.open(directory / "admissions.sqlite", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    def open_peer(_):
        return m.SqliteNamedAdmissionStore(directory, **s.args)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(open_peer, range(2)))
    issued = first.issue(session_binding=s.session, manifest_builder=s.build)
    assert second.get(handle=issued.handle, session_binding=s.session) == issued.record


def test_version_zero_existing_objects_are_never_reinitialized(fixture):
    s = fixture
    directory = s.path.parent / "unrelated-schema"
    directory.mkdir(mode=0o700)
    fd = os.open(directory / "admissions.sqlite", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with sqlite3.connect(directory / "admissions.sqlite") as conn:
        conn.execute("CREATE TABLE unrelated(data TEXT)")
    with pytest.raises(m.NamedAdmissionStoreError):
        m.SqliteNamedAdmissionStore(directory, **s.args)
    with sqlite3.connect(directory / "admissions.sqlite") as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute("SELECT name FROM sqlite_master").fetchall() == [("unrelated",)]
