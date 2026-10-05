"""Actual age/local encrypted object readback; SQL and restore are invented mocks.

No production state, network, credentials or real disposable database is used.
These tests prove adapter bindings/order, not a completed live recovery receipt.
"""

import csv
import io
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_fireflies_protection import keypair
from tests.test_work_choice_capture import fixture as choice_fixture
from zacai import backup
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import work_choice_protection as module
from zacai.interfaces.work_choice_capture import ChoiceCheckpointScope
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import ReviewAuthorizationError
from zacai.state import Base


@pytest.fixture
def protected(tmp_path, monkeypatch):
    identity = tmp_path / "throwaway.agekey"
    recipient = keypair(identity)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    raw = b"invented canonical choice bytes"
    scope = ChoiceCheckpointScope(uuid4(), content_hash_of(raw), datetime(2026, 10, 5, tzinfo=UTC))
    state = SimpleNamespace(
        now=scope.captured_at,
        backup_calls=0,
        restores=0,
        lease=True,
        admin=True,
        admin_cleanup_failure=False,
        corrupt_restore=False,
        after_restore=None,
        scope=scope,
        objects=objects,
        reader=reader,
        active=False,
        journal_status="SUCCEEDED",
        wrong_run=False,
        run_started_offset=0,
        run_finished_offset=0,
    )
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._approval_id = None
    p._lease_guard = None
    p._reader, p._objects = reader, objects
    p._identity, p._recipient = identity, recipient
    p._assert_target = lambda: None

    class Lease:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def execute(self, statement):
            assert str(statement).startswith("SET ")

        def scalar(self, statement):
            if "server_version_num" in str(statement):
                return 170000
            return state.lease

    p._engine = SimpleNamespace(connect=Lease, url=SimpleNamespace(database="zacai_test"))

    @contextmanager
    def admin():
        if not state.admin:
            raise ValueError("invented target lease unavailable")
        state.active = True
        try:
            yield object()
        finally:
            state.active = False
            if state.admin_cleanup_failure:
                raise ValueError("invented target cleanup failed")

    monkeypatch.setattr(backup, "_admin_connection", admin)
    gate = module.BrainstormWorkChoiceProtection(protector=p, clock=lambda: state.now)
    hashes = {scope.source_id: scope.choice_digest}

    def inventory(request):
        assert request == scope
        if state.now < scope.captured_at:
            raise ValueError("invented future choice")
        return hashes.copy()

    gate._hashes = inventory
    objects.put_object(
        backup_object_key_for(B.BRAINSTORM, scope.choice_digest), age_encrypt(raw, recipient)
    )

    def verify(plain, expected, *, current_selected_sources, operational_journal):
        assert state.active and p._lease_guard is not None
        p._lease_guard()
        assert plain == b"invented final canonical state " + str(scope.source_id).encode()
        assert expected == hashes and current_selected_sources is p._engine
        assert backup._csv_columns("artifact_backup_run", operational_journal)
        state.restores += 1
        if state.corrupt_restore:
            raise ValueError("invented exact restored row mismatch")
        if state.after_restore:
            state.after_restore()

    p._restoration = SimpleNamespace(verify=verify)

    def protect_state(expected, prefix):
        assert expected == hashes and prefix == f"BRAINSTORM/state/work-choice-{scope.source_id}"
        assert state.active
        state.backup_calls += 1
        run_id = uuid4()
        stream = io.StringIO()
        columns = list(Base.metadata.tables["artifact_backup_run"].columns.keys())
        writer = csv.DictWriter(stream, columns)
        writer.writeheader()
        writer.writerow(
            {
                "id": str(uuid4() if state.wrong_run else run_id),
                "trust_boundary": "BRAINSTORM",
                "status": state.journal_status,
                "started_at": (
                    scope.captured_at + timedelta(seconds=state.run_started_offset)
                ).isoformat(),
                "finished_at": (
                    scope.captured_at + timedelta(seconds=state.run_finished_offset)
                ).isoformat(),
            }
        )
        plain = b"invented final canonical state " + str(scope.source_id).encode()
        journal = stream.getvalue().encode()
        state_cipher, journal_cipher = (
            age_encrypt(plain, recipient),
            age_encrypt(journal, recipient),
        )
        sh, jh = content_hash_of(state_cipher), content_hash_of(journal_cipher)
        sk, jk = f"{prefix}/{sh}.age", f"{prefix}/journal-{jh}.age"
        p._put(sk, state_cipher)
        p._put(jk, journal_cipher)
        return ProtectedState(
            run_id, sk, sh, content_hash_of(plain), jk, jh, content_hash_of(journal)
        )

    p._protect_state = protect_state
    state.gate, state.p = gate, p
    return state


def test_crypto_readback_recovery_binding_and_identical_retry(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    assert receipt.source_id == s.scope.source_id
    assert receipt.choice_digest == s.scope.choice_digest
    assert s.backup_calls == s.restores == 1
    s.now += timedelta(seconds=1)
    assert s.gate.protect(s.scope) == receipt
    s.gate.recheck(s.scope, receipt)
    assert s.backup_calls == 1 and s.restores == 3
    assert s.p._lease_guard is None and not s.active


@pytest.mark.parametrize(
    "object_name", ["receipt_object", "state_object", "journal_object", "artifact_object"]
)
def test_corrupt_existing_objects_never_overwrite_receipt(protected, object_name):
    s = protected
    receipt = s.gate.protect(s.scope)
    key = getattr(receipt, object_name)
    s.objects.put_object(key, b"invented corruption")
    before = s.reader.get_object(receipt.receipt_object)
    with pytest.raises(module.WorkChoiceProtectionError) as error:
        s.gate.protect(s.scope)
    assert error.value.__context__ is None
    assert s.backup_calls == 1
    assert s.reader.get_object(receipt.receipt_object) == before
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("field", ["lease", "admin"])
def test_unavailable_operator_or_target_lease_denies_before_backup(protected, field):
    s = protected
    setattr(s, field, False)
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)
    assert s.backup_calls == s.restores == 0
    assert s.p._lease_guard is None


def test_cleanup_failure_withholds_ack_even_with_retained_receipt(protected):
    s = protected
    s.admin_cleanup_failure = True
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)
    assert s.backup_calls == 1
    s.admin_cleanup_failure = False
    receipt = s.gate.protect(s.scope)
    assert s.backup_calls == 1
    s.admin_cleanup_failure = True
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("status,wrong_run", [("FAILED", False), ("SUCCEEDED", True)])
def test_backup_journal_requires_exact_successful_run_before_receipt(protected, status, wrong_run):
    s = protected
    s.journal_status, s.wrong_run = status, wrong_run
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)
    key = f"BRAINSTORM/state/work-choice-{s.scope.source_id}/receipt-{s.scope.choice_digest}.age"
    assert not s.reader.exists(key) and s.restores == 0


def test_failed_actual_restore_gate_withholds_receipt(protected):
    s = protected
    s.corrupt_restore = True
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)
    key = f"BRAINSTORM/state/work-choice-{s.scope.source_id}/receipt-{s.scope.choice_digest}.age"
    assert not s.reader.exists(key)


def test_lost_lease_during_restore_and_backwards_clock_deny(protected):
    s = protected
    s.after_restore = lambda: setattr(s, "lease", False)
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)
    s.lease = True
    s.after_restore = lambda: setattr(s, "now", s.scope.captured_at - timedelta(seconds=1))
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)


def test_retained_receipt_must_match_exact_host_pointer(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    changed = receipt.model_copy(update={"state_plaintext_hash": "f" * 64})
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.recheck(s.scope, changed)


@pytest.mark.parametrize(
    "prefix", ["contextual-packet", "contextual-attempt", "contextual-research", "work-choice"]
)
def test_namespace_guard_accepts_only_existing_families_and_choice_uuid(prefix):
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)

    def stop():
        raise LookupError("stop before actual DB or backup")

    p._assert_target = stop
    with pytest.raises(LookupError):
        p._protect_state({uuid4(): "a" * 64}, f"BRAINSTORM/state/{prefix}-{uuid4()}")


@pytest.mark.parametrize(
    "prefix",
    [
        "PERSONAL/state/work-choice-",
        "BRAINSTORM/state/other-",
        "BRAINSTORM/state/work-choice-../",
        "BRAINSTORM/state/work-choice-",
    ],
)
def test_namespace_guard_rejects_unknown_or_noncanonical_before_io(prefix):
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._assert_target = lambda: pytest.fail("must reject namespace before I/O")
    suffix = "bad-id" if prefix.endswith("choice-") else str(uuid4())
    with pytest.raises(ValueError):
        p._protect_state({uuid4(): "a" * 64}, prefix + suffix)


@pytest.mark.parametrize(
    "change",
    [
        "boundary",
        "classification",
        "external_ref",
        "captured_at",
        "isolation",
        "database",
        "future",
        "packet",
    ],
)
def test_inventory_exact_committed_choice_and_current_acl(monkeypatch, change):
    state = choice_fixture.__wrapped__(monkeypatch)
    saved = state.client.capture(**state.inputs)
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._approval_id = None
    base = state.client._factory

    class Session(base):
        def scalar(self, statement):
            if str(statement) == "SELECT current_database()":
                return getattr(state, "database", "zacai_test")
            return super().scalar(statement)

    p._factory, p._artifacts = Session, state.client._artifacts
    p._engine = SimpleNamespace(url=SimpleNamespace(database="zacai_test"))
    monkeypatch.setattr(
        module,
        "get_effective_source_classification",
        lambda session, source_id: next(iter(state.sources.values())).data_classification,
    )
    monkeypatch.setattr(module, "load_contextual_packet", lambda *args, **kwargs: state.packet)
    gate = module.BrainstormWorkChoiceProtection(protector=p, clock=lambda: state.now)
    scope = ChoiceCheckpointScope(saved.source_id, saved.choice_digest, state.now)
    hashes = gate._hashes(scope)
    assert hashes[saved.source_id] == saved.choice_digest
    assert state.receipt.locator.packet_source_id in hashes
    source = next(iter(state.sources.values()))
    if change == "boundary":
        source.trust_boundary = B.PERSONAL
    elif change == "classification":
        source.data_classification = module.C.HIGHLY_RESTRICTED
    elif change == "external_ref":
        source.external_ref = "work-choice/another"
    elif change == "captured_at":
        source.captured_at += timedelta(seconds=1)
    elif change == "isolation":
        state.isolation = "repeatable read"
    elif change == "database":
        state.database = "another_database"
    elif change == "future":
        state.now -= timedelta(seconds=1)
    elif change == "packet":
        state.packet = state.packet.model_copy(
            update={"created_at": state.now + timedelta(seconds=1)}
        )
    with pytest.raises((ValueError, ReviewAuthorizationError)):
        gate._hashes(scope)


def test_clock_rollback_during_receipt_encryption_withholds_ack(protected, monkeypatch):
    s = protected
    s.now += timedelta(seconds=60)
    original = module.age_encrypt

    def encrypt(raw, recipient):
        encrypted = original(raw, recipient)
        if raw.startswith(b'{"artifact_backup_run_id"'):
            s.now -= timedelta(seconds=30)
        return encrypted

    monkeypatch.setattr(module, "age_encrypt", encrypt)
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)


def test_reencrypted_artifact_preserves_exact_plaintext_recovery_and_receipt(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    # Same fixed object key and plaintext, randomized independent encryption.
    s.objects.put_object(
        receipt.artifact_object, age_encrypt(b"invented canonical choice bytes", s.p._recipient)
    )
    assert (
        content_hash_of(s.reader.get_object(receipt.artifact_object))
        != receipt.artifact_ciphertext_hash
    )
    s.gate.recheck(s.scope, receipt)
    assert s.gate.protect(s.scope) == receipt
    assert s.reader.get_object(receipt.receipt_object) == before
    s.objects.put_object(
        receipt.artifact_object, age_encrypt(b"invented WRONG choice plaintext", s.p._recipient)
    )
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.recheck(s.scope, receipt)
    assert s.reader.get_object(receipt.receipt_object) == before


def test_verified_timestamp_records_completed_restore(protected):
    s = protected
    began = s.now
    s.after_restore = lambda: setattr(s, "now", began + timedelta(seconds=45))
    receipt = s.gate.protect(s.scope)
    assert receipt.verified_at == began + timedelta(seconds=45)
    assert receipt.captured_at == began


@pytest.mark.parametrize("started,finished", [(-1, 0), (1, 0), (0, 1)])
def test_journal_run_cannot_predate_choice_or_have_invalid_completion(protected, started, finished):
    s = protected
    s.run_started_offset, s.run_finished_offset = started, finished
    with pytest.raises(module.WorkChoiceProtectionError):
        s.gate.protect(s.scope)
    assert not s.reader.exists(module.choice_receipt_key(s.scope.source_id, s.scope.choice_digest))
