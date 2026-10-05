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
from tests.test_text_turn_capture import fixture as turn_fixture
from zacai import backup
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import text_turn_protection as module
from zacai.interfaces.text_turn_capture import TextTurnCheckpointScope
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import ReviewAuthorizationError
from zacai.state import Base


@pytest.fixture
def protected(tmp_path, monkeypatch):
    identity = tmp_path / "throwaway.agekey"
    recipient = keypair(identity)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    raw = b"invented canonical turn bytes"
    scope = TextTurnCheckpointScope(
        uuid4(), content_hash_of(raw), datetime(2026, 10, 5, tzinfo=UTC)
    )
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
    gate = module.BrainstormTextTurnProtection(protector=p, clock=lambda: state.now)
    hashes = {scope.source_id: scope.turn_digest}

    def inventory(request):
        assert request == scope
        if state.now < scope.captured_at:
            raise ValueError("invented future turn")
        return hashes.copy()

    gate._hashes = inventory
    objects.put_object(
        backup_object_key_for(B.BRAINSTORM, scope.turn_digest), age_encrypt(raw, recipient)
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
        assert expected == hashes and prefix == f"BRAINSTORM/state/text-turn-{scope.source_id}"
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
    assert receipt.turn_digest == s.scope.turn_digest
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
    with pytest.raises(module.TextTurnProtectionError) as error:
        s.gate.protect(s.scope)
    assert error.value.__context__ is None
    assert s.backup_calls == 1
    assert s.reader.get_object(receipt.receipt_object) == before
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("field", ["lease", "admin"])
def test_unavailable_operator_or_target_lease_denies_before_backup(protected, field):
    s = protected
    setattr(s, field, False)
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)
    assert s.backup_calls == s.restores == 0
    assert s.p._lease_guard is None


def test_cleanup_failure_withholds_ack_even_with_retained_receipt(protected):
    s = protected
    s.admin_cleanup_failure = True
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)
    assert s.backup_calls == 1
    s.admin_cleanup_failure = False
    receipt = s.gate.protect(s.scope)
    assert s.backup_calls == 1
    s.admin_cleanup_failure = True
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("status,wrong_run", [("FAILED", False), ("SUCCEEDED", True)])
def test_backup_journal_requires_exact_successful_run_before_receipt(protected, status, wrong_run):
    s = protected
    s.journal_status, s.wrong_run = status, wrong_run
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)
    key = f"BRAINSTORM/state/text-turn-{s.scope.source_id}/receipt-{s.scope.turn_digest}.age"
    assert not s.reader.exists(key) and s.restores == 0


def test_failed_actual_restore_gate_withholds_receipt(protected):
    s = protected
    s.corrupt_restore = True
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)
    key = f"BRAINSTORM/state/text-turn-{s.scope.source_id}/receipt-{s.scope.turn_digest}.age"
    assert not s.reader.exists(key)


def test_lost_lease_during_restore_and_backwards_clock_deny(protected):
    s = protected
    s.after_restore = lambda: setattr(s, "lease", False)
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)
    s.lease = True
    s.after_restore = lambda: setattr(s, "now", s.scope.captured_at - timedelta(seconds=1))
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)


def test_retained_receipt_must_match_exact_host_pointer(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    changed = receipt.model_copy(update={"state_plaintext_hash": "f" * 64})
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.recheck(s.scope, changed)


@pytest.mark.parametrize(
    "prefix",
    ["contextual-packet", "contextual-attempt", "contextual-research", "work-choice", "text-turn"],
)
def test_namespace_guard_accepts_only_existing_families_and_turn_uuid(prefix):
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)

    def stop():
        raise LookupError("stop before actual DB or backup")

    p._assert_target = stop
    with pytest.raises(LookupError):
        p._protect_state({uuid4(): "a" * 64}, f"BRAINSTORM/state/{prefix}-{uuid4()}")


@pytest.mark.parametrize(
    "prefix",
    [
        "PERSONAL/state/text-turn-",
        "BRAINSTORM/state/other-",
        "BRAINSTORM/state/text-turn-../",
        "BRAINSTORM/state/text-turn-",
    ],
)
def test_namespace_guard_rejects_unknown_or_noncanonical_before_io(prefix):
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._assert_target = lambda: pytest.fail("must reject namespace before I/O")
    suffix = "bad-id" if prefix.endswith("turn-") else str(uuid4())
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
def test_inventory_exact_committed_turn_and_current_acl(monkeypatch, change):
    state = turn_fixture.__wrapped__(monkeypatch)
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
    gate = module.BrainstormTextTurnProtection(protector=p, clock=lambda: state.now)
    scope = TextTurnCheckpointScope(saved.source_id, saved.turn_digest, state.now)
    hashes = gate._hashes(scope)
    assert hashes[saved.source_id] == saved.turn_digest
    assert state.receipt.locator.packet_source_id in hashes
    source = next(iter(state.sources.values()))
    if change == "boundary":
        source.trust_boundary = B.PERSONAL
    elif change == "classification":
        source.data_classification = module.C.HIGHLY_RESTRICTED
    elif change == "external_ref":
        source.external_ref = "work-turn/another"
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
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)


def test_reencrypted_artifact_preserves_exact_plaintext_recovery_and_receipt(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    # Same fixed object key and plaintext, randomized independent encryption.
    s.objects.put_object(
        receipt.artifact_object, age_encrypt(b"invented canonical turn bytes", s.p._recipient)
    )
    assert (
        content_hash_of(s.reader.get_object(receipt.artifact_object))
        != receipt.artifact_ciphertext_hash
    )
    s.gate.recheck(s.scope, receipt)
    assert s.gate.protect(s.scope) == receipt
    assert s.reader.get_object(receipt.receipt_object) == before
    s.objects.put_object(
        receipt.artifact_object, age_encrypt(b"invented WRONG turn plaintext", s.p._recipient)
    )
    with pytest.raises(module.TextTurnProtectionError):
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
def test_journal_run_cannot_predate_turn_or_have_invalid_completion(protected, started, finished):
    s = protected
    s.run_started_offset, s.run_finished_offset = started, finished
    with pytest.raises(module.TextTurnProtectionError):
        s.gate.protect(s.scope)
    assert not s.reader.exists(module.text_turn_receipt_key(s.scope.source_id, s.scope.turn_digest))


def inventory_fixture(monkeypatch):
    """Invented canonical rows/bytes; no keys, SQL, networking or private data."""
    from zacai.interfaces import text_turn_capture

    state = turn_fixture.__wrapped__(monkeypatch)
    parent = state.client.capture(**state.inputs)
    state.now += timedelta(seconds=1)
    child = state.client.capture(
        **{**state.inputs, "request_id": uuid4(), "original_utf8": b"Invented follow-up?"},
        parent_references=(parent.reference,),
    )
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._approval_id = None
    base = state.client._factory

    class Session(base):
        def scalar(self, statement):
            if str(statement) == "SELECT current_database()":
                return "zacai_test"
            return super().scalar(statement)

    p._factory, p._artifacts = Session, state.client._artifacts
    p._engine = SimpleNamespace(url=SimpleNamespace(database="zacai_test"))
    monkeypatch.setattr(
        module,
        "get_effective_source_classification",
        text_turn_capture.get_effective_source_classification,
    )
    monkeypatch.setattr(module, "load_contextual_packet", lambda *args, **kwargs: state.packet)
    gate = module.BrainstormTextTurnProtection(protector=p, clock=lambda: state.now)
    scope = TextTurnCheckpointScope(child.source_id, child.turn_digest, child.turn.recorded_at)
    return state, parent, child, gate, scope


def test_inventory_retains_explicit_parent_and_packet_but_does_not_read_ancestors(monkeypatch):
    state, parent, child, gate, scope = inventory_fixture(monkeypatch)
    hashes = gate._hashes(scope)
    assert hashes[parent.source_id] == parent.turn_digest
    assert hashes[child.source_id] == child.turn_digest
    assert hashes[child.turn.packet_reference.source_id] == child.turn.packet_reference.content_hash
    assert set(hashes) == {
        parent.source_id,
        child.source_id,
        child.turn.packet_reference.source_id,
        *(item.reference.source_id for item in state.packet.task.context),
    }


@pytest.mark.parametrize(
    "change",
    [
        "subject",
        "issuer",
        "conversation",
        "packet",
        "receipt",
        "future",
        "kind",
        "parent_label",
        "parent_boundary",
        "parent_system",
    ],
)
def test_parent_account_context_kind_time_and_acl_mismatch_denied(monkeypatch, change):
    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.interfaces.text_turn_capture import TextTurn, encode_text_turn

    state, parent, child, gate, scope = inventory_fixture(monkeypatch)
    parent_source = next(s for s in state.sources.values() if s.id == parent.source_id)
    child_source = next(s for s in state.sources.values() if s.id == child.source_id)
    fields = parent.turn.model_dump(mode="json")
    if change == "subject":
        fields["subject"] = "invented-other-owner"
    elif change == "issuer":
        fields["issuer"] = "invented-other-issuer"
    elif change == "conversation":
        fields["conversation_id"] = str(uuid4())
    elif change == "packet":
        fields["packet_reference"]["source_id"] = str(uuid4())
    elif change == "receipt":
        fields["packet_receipt_digest"] = "f" * 64
    elif change == "future":
        parent_source.captured_at = child.turn.recorded_at + timedelta(seconds=1)
        fields["recorded_at"] = parent_source.captured_at.isoformat()
    elif change == "kind":
        fields["kind"] = "assistant_output"
    elif change == "parent_label":
        parent_source.data_classification = module.C.HIGHLY_RESTRICTED
    elif change == "parent_boundary":
        parent_source.trust_boundary = B.PERSONAL
    elif change == "parent_system":
        parent_source.system = module.SourceSystem.MANUAL
    if change not in {"parent_label", "parent_boundary", "parent_system"}:
        # Invented rows may be changed adversarially. Real Source rows are
        # append-only; here hashes are rebound to isolate semantic mismatch.
        raw = canonical_bytes(fields)
        parent_source.content_hash = parent_source.content_location = content_hash_of(raw)
        state.raw[parent_source.content_hash] = raw
        reference = parent.reference.model_copy(update={"content_hash": parent_source.content_hash})
        updated = TextTurn.model_validate(
            child.turn.model_copy(update={"parent_references": (reference,)})
        )
        encoded = encode_text_turn(updated)
        child_source.content_hash = child_source.content_location = content_hash_of(encoded)
        state.raw[child_source.content_hash] = encoded
        scope = TextTurnCheckpointScope(
            child.source_id, child_source.content_hash, child.turn.recorded_at
        )
    with pytest.raises(ValueError):
        gate._hashes(scope)


@pytest.mark.parametrize("operation", ["protect", "recheck"])
def test_retained_receipt_completion_to_final_clock_rollback_denies_without_rewrite(
    protected, monkeypatch, operation
):
    s = protected
    zero = s.scope.captured_at
    s.now = zero + timedelta(seconds=20)
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    s.now = zero + timedelta(seconds=60)
    s.after_restore = lambda: setattr(s, "now", zero + timedelta(seconds=100))
    verify = s.gate._verify

    def rollback(scope, retained):
        completed = verify(scope, retained)
        assert completed == zero + timedelta(seconds=100)
        s.now = zero + timedelta(seconds=90)
        return completed

    monkeypatch.setattr(s.gate, "_verify", rollback)
    with pytest.raises(module.TextTurnProtectionError):
        if operation == "protect":
            s.gate.protect(s.scope)
        else:
            s.gate.recheck(s.scope, receipt)
    assert s.backup_calls == 1
    assert s.reader.get_object(receipt.receipt_object) == before


@pytest.mark.parametrize("operation", ["protect", "recheck"])
def test_operation_start_to_verification_clock_rollback_denies(protected, monkeypatch, operation):
    s = protected
    zero = s.scope.captured_at
    s.now = zero + timedelta(seconds=20)
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    s.now = zero + timedelta(seconds=100)
    load = s.gate._load_receipt

    def rollback(key):
        retained = load(key)
        s.now = zero + timedelta(seconds=90)
        return retained

    monkeypatch.setattr(s.gate, "_load_receipt", rollback)
    with pytest.raises(module.TextTurnProtectionError):
        if operation == "protect":
            s.gate.protect(s.scope)
        else:
            s.gate.recheck(s.scope, receipt)
    assert s.reader.get_object(receipt.receipt_object) == before
    assert s.backup_calls == 1


@pytest.mark.parametrize("operation", ["protect", "recheck"])
def test_transient_inventory_clock_ahead_of_verify_cannot_be_forgotten(
    protected, monkeypatch, operation
):
    s = protected
    zero = s.scope.captured_at
    s.now = zero + timedelta(seconds=20)
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        # Initial operation80, initial inventory100, then verify starts90.
        seconds = {1: 80, 2: 100}.get(calls, 90)
        return zero + timedelta(seconds=seconds)

    monkeypatch.setattr(s.gate, "_clock", clock)
    inventory = s.gate._hashes

    def observe_inventory(scope):
        # This fixture inventories synthetic rows without SQL. The production
        # _hashes also observes _now before its actual canonical Source reads.
        s.gate._now()
        return inventory(scope)

    monkeypatch.setattr(s.gate, "_hashes", observe_inventory)
    with pytest.raises(module.TextTurnProtectionError):
        if operation == "protect":
            s.gate.protect(s.scope)
        else:
            s.gate.recheck(s.scope, receipt)
    assert calls == 3 and s.backup_calls == 1
    assert s.reader.get_object(receipt.receipt_object) == before
