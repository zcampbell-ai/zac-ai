"""Actual age/local encrypted object readback; SQL and restore are invented mocks.

No production state, network, credentials or real disposable database is used.
These tests prove adapter bindings/order, not a completed live recovery receipt.
"""

import csv
import io
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_fireflies_protection import keypair
from zacai import backup
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import followup_authority_recovery as module
from zacai.interfaces.host_clock import HostObservedClock
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Base


@pytest.fixture
def protected(tmp_path, monkeypatch):
    identity = tmp_path / "throwaway.agekey"
    recipient = keypair(identity)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    raw = b"invented canonical authority bytes"
    reference = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    scope = module.FollowupAuthoritySubject(
        kind="consent",
        reference=reference,
        consent_reference=reference,
        scope_digest="a" * 64,
        captured_at=datetime(2026, 10, 5, tzinfo=UTC),
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
    # Real local age crypto and proof pin; operator escrow/off-device flags are
    # invented assertions, not a real password-manager/off-device exercise.
    proof_plain = b"invented independent recovered checkpoint"
    proof_cipher = age_encrypt(proof_plain, recipient)
    proof_hash = content_hash_of(proof_cipher)
    proof_key = f"BRAINSTORM/state/{uuid4()}/{proof_hash}.age"
    objects.put_object(proof_key, proof_cipher)
    proof = {
        "format": "zac-existing-state-recovery-v1",
        "boundary": "BRAINSTORM",
        "state_object": proof_key,
        "ciphertext_hash": proof_hash,
        "plaintext_hash": content_hash_of(proof_plain),
        "full_row_field_comparison": "passed",
        "target_cleaned": True,
        "off_device_retrieval": True,
        "recovered_identity_from_password_manager": True,
        "temporary_recovered_key_removed": True,
    }
    proof_path = tmp_path / "invented-recovered-proof.json"
    proof_path.write_bytes(json.dumps(proof).encode())
    proof_path.chmod(0o600)
    gate = module.BrainstormFollowupAuthorityRecovery(
        protector=p,
        clock=HostObservedClock(lambda: state.now),
        refresh=lambda: None,
        owner=lambda: None,
        recovered_key_receipt=proof_path,
        expected_key_proof_digest=content_hash_of(proof_path.read_bytes()),
    )
    gate._fresh_subject = lambda subject: (
        None
    )  # Invented host snapshot; separately exercised below.
    state.proof_path, state.proof, state.raw = proof_path, proof, raw
    hashes = {scope.reference.source_id: scope.reference.content_hash}

    def inventory(request):
        assert request == scope
        if state.now < scope.captured_at:
            raise ValueError("invented future turn")
        return hashes.copy()

    gate._hashes = inventory
    objects.put_object(
        backup_object_key_for(B.BRAINSTORM, scope.reference.content_hash),
        age_encrypt(raw, recipient),
    )

    def verify(plain, expected, *, current_selected_sources, operational_journal):
        assert state.active and p._lease_guard is not None
        p._lease_guard()
        assert plain == b"invented final canonical state " + str(scope.reference.source_id).encode()
        assert expected == hashes and current_selected_sources is p._engine
        assert backup._csv_columns("artifact_backup_run", operational_journal)
        state.restores += 1
        if state.corrupt_restore:
            raise ValueError("invented exact restored row mismatch")
        if state.after_restore:
            state.after_restore()

    p._restoration = SimpleNamespace(verify=verify)

    def protect_state(expected, prefix):
        assert (
            expected == hashes
            and prefix == f"BRAINSTORM/state/followup-authority-{scope.reference.source_id}"
        )
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
        plain = b"invented final canonical state " + str(scope.reference.source_id).encode()
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
    assert receipt.subject.reference.source_id == s.scope.reference.source_id
    assert receipt.subject.reference.content_hash == s.scope.reference.content_hash
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
    with pytest.raises(module.FollowupAuthorityRecoveryError) as error:
        s.gate.protect(s.scope)
    assert error.value.__context__ is None
    assert s.backup_calls == 1
    assert s.reader.get_object(receipt.receipt_object) == before
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("field", ["lease", "admin"])
def test_unavailable_operator_or_target_lease_denies_before_backup(protected, field):
    s = protected
    setattr(s, field, False)
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    assert s.backup_calls == s.restores == 0
    assert s.p._lease_guard is None


def test_cleanup_failure_withholds_ack_even_with_retained_receipt(protected):
    s = protected
    s.admin_cleanup_failure = True
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    assert s.backup_calls == 1
    s.admin_cleanup_failure = False
    receipt = s.gate.protect(s.scope)
    assert s.backup_calls == 1
    s.admin_cleanup_failure = True
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("status,wrong_run", [("FAILED", False), ("SUCCEEDED", True)])
def test_backup_journal_requires_exact_successful_run_before_receipt(protected, status, wrong_run):
    s = protected
    s.journal_status, s.wrong_run = status, wrong_run
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    key = f"BRAINSTORM/state/followup-authority-{s.scope.reference.source_id}/receipt-{s.scope.reference.content_hash}.age"
    assert not s.reader.exists(key) and s.restores == 0


def test_failed_actual_restore_gate_withholds_receipt(protected):
    s = protected
    s.corrupt_restore = True
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    key = f"BRAINSTORM/state/followup-authority-{s.scope.reference.source_id}/receipt-{s.scope.reference.content_hash}.age"
    assert not s.reader.exists(key)


def test_lost_lease_during_restore_and_backwards_clock_deny(protected):
    s = protected
    s.after_restore = lambda: setattr(s, "lease", False)
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    s.lease = True
    s.after_restore = lambda: setattr(s, "now", s.scope.captured_at - timedelta(seconds=1))
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)


def test_retained_receipt_must_match_exact_host_pointer(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    changed = receipt.model_copy(update={"state_plaintext_hash": "f" * 64})
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.recheck(s.scope, changed)


@pytest.mark.parametrize(
    "prefix",
    [
        "contextual-packet",
        "contextual-attempt",
        "contextual-research",
        "work-choice",
        "text-turn",
        "text-reply",
        "followup-authority",
    ],
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
        "PERSONAL/state/followup-authority-",
        "BRAINSTORM/state/other-",
        "BRAINSTORM/state/followup-authority-../",
        "BRAINSTORM/state/followup-authority-",
    ],
)
def test_namespace_guard_rejects_unknown_or_noncanonical_before_io(prefix):
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._assert_target = lambda: pytest.fail("must reject namespace before I/O")
    suffix = "bad-id" if prefix.endswith("authority-") else str(uuid4())
    with pytest.raises(ValueError):
        p._protect_state({uuid4(): "a" * 64}, prefix + suffix)


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
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)


def test_reencrypted_artifact_preserves_exact_plaintext_recovery_and_receipt(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    # Same fixed object key and plaintext, randomized independent encryption.
    s.objects.put_object(
        receipt.artifact_object, age_encrypt(b"invented canonical authority bytes", s.p._recipient)
    )
    assert (
        content_hash_of(s.reader.get_object(receipt.artifact_object))
        != receipt.artifact_ciphertext_hash
    )
    s.gate.recheck(s.scope, receipt)
    assert s.gate.protect(s.scope) == receipt
    assert s.reader.get_object(receipt.receipt_object) == before
    s.objects.put_object(
        receipt.artifact_object, age_encrypt(b"invented WRONG authority plaintext", s.p._recipient)
    )
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.recheck(s.scope, receipt)
    assert s.reader.get_object(receipt.receipt_object) == before


def test_verified_timestamp_records_completed_restore(protected):
    s = protected
    began = s.now
    s.after_restore = lambda: setattr(s, "now", began + timedelta(seconds=45))
    receipt = s.gate.protect(s.scope)
    assert receipt.verified_at == began + timedelta(seconds=45)
    assert receipt.subject.captured_at == began


@pytest.mark.parametrize("started,finished", [(-1, 0), (1, 0), (0, 1)])
def test_journal_run_cannot_predate_turn_or_have_invalid_completion(protected, started, finished):
    s = protected
    s.run_started_offset, s.run_finished_offset = started, finished
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    assert not s.reader.exists(
        module.followup_authority_receipt_key(
            s.scope.reference.source_id, s.scope.reference.content_hash
        )
    )


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
    with pytest.raises(module.FollowupAuthorityRecoveryError):
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
    with pytest.raises(module.FollowupAuthorityRecoveryError):
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
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        if operation == "protect":
            s.gate.protect(s.scope)
        else:
            s.gate.recheck(s.scope, receipt)
    assert calls == 3 and s.backup_calls == 1
    assert s.reader.get_object(receipt.receipt_object) == before


@pytest.fixture
def canonical(monkeypatch, tmp_path):
    from tests.test_followup_authorization import fixture as authority_fixture
    from zacai.state import Source

    s = authority_fixture.__wrapped__(monkeypatch)
    # Canonical ledger setup uses explicit invented recovery hooks; no actual
    # authority durability claim is made by this mock-SQL inventory fixture.
    s.authority._recovery.protect_consent = lambda **kwargs: None
    s.authority._recovery.protect_claim = lambda **kwargs: None
    approval = s.authority.record(s.consent)
    s.claimed = s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    s.subjects = {
        "consent": module.consent_subject(s.consent, s.claimed.claim.consent_reference),
        "consumed_claim": module.claim_subject(s.claimed, s.request),
    }
    p = BrainstormContextualProtector.__new__(BrainstormContextualProtector)
    p._approval_id = None
    base = s.client._factory

    class Session(base):
        def scalar(self, statement):
            if str(statement) == "SELECT current_database()":
                return getattr(s, "database", "zacai_test")
            return super().scalar(statement)

    p._factory, p._artifacts = Session, s.client._artifacts
    p._engine = SimpleNamespace(url=SimpleNamespace(database="zacai_test"))
    monkeypatch.setattr(
        module,
        "get_effective_source_classification",
        lambda session, source_id: session.get(Source, source_id).data_classification,
    )
    s.gate = module.BrainstormFollowupAuthorityRecovery(
        protector=p,
        clock=HostObservedClock(lambda: s.now),
        refresh=s.authority._refresh,
        owner=lambda: s.owner,
        recovered_key_receipt=tmp_path / "unused-proof",
        expected_key_proof_digest="a" * 64,
    )
    s.session = Session
    return s


@pytest.mark.parametrize("kind", ["consent", "consumed_claim"])
def test_exact_canonical_inventory_and_refresh_outside_sql(canonical, kind):
    s = canonical
    subject = s.subjects[kind]
    s.gate._fresh_subject(subject)  # Actual fixture refresh asserts zero open sessions.
    hashes = s.gate._hashes(subject)
    declared = s.scope
    expected = {
        s.claimed.claim.consent_reference.source_id: s.claimed.claim.consent_reference.content_hash,
        declared.packet_reference.source_id: declared.packet_reference.content_hash,
        **{ref.source_id: ref.content_hash for ref in declared.context_references},
    }
    if kind == "consumed_claim":
        expected[s.claimed.reference.source_id] = s.claimed.reference.content_hash
    assert hashes == expected
    assert s.active_sessions == 0
    # Expiry/revocation is not historical Source-read authorization. Current
    # actor/grant/ACL and original immutable chronology still apply.
    s.now += timedelta(minutes=16)
    s.authority.revoke(
        approval_id=s.claimed.claim.consent_reference.source_id,
        human_reference="invented explicit cancellation",
    )
    s.gate._fresh_subject(subject)
    assert s.gate._hashes(subject) == expected
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        module.claim_subject(s.claimed, SimpleNamespace())


@pytest.mark.parametrize("kind", ["consent", "consumed_claim"])
@pytest.mark.parametrize(
    "change",
    [
        "subject_kind",
        "subject_hash",
        "consent_prefix",
        "consent_hash",
        "consent_role",
        "user_role",
        "user_actor",
        "user_parent",
        "packet_role",
        "classification",
        "database",
        "isolation",
        "future_source",
        "scope_digest",
    ],
)
def test_inventory_refuses_wrong_canonical_bindings(canonical, kind, change):
    from zacai.interfaces.text_turn_capture import decode_text_turn, encode_text_turn
    from zacai.review_authorization import ReviewAuthorizationError
    from zacai.state import Source, SourceSystem

    s = canonical
    subject = s.subjects[kind]
    with s.session() as session:
        row = session.get(Source, subject.reference.source_id)
        consent = session.get(Source, subject.consent_reference.source_id)
        user = session.get(Source, s.scope.user_reference.source_id)
        if change == "subject_kind":
            row.system = SourceSystem.MANUAL if kind == "consent" else SourceSystem.USER_INSTRUCTION
        elif change == "subject_hash":
            row.content_hash = "f" * 64
        elif change == "consent_prefix":
            consent.external_ref = "other/consent"
        elif change == "consent_hash":
            consent.content_hash = "f" * 64
        elif change == "consent_role":
            consent.system = SourceSystem.MANUAL
        elif change == "user_role":
            user.system = SourceSystem.MANUAL
        elif change in ("user_actor", "user_parent"):
            original = decode_text_turn(s.raw[user.content_hash])
            fields = (
                {"subject": "other-owner"} if change == "user_actor" else {"parent_references": ()}
            )
            if change == "user_parent":
                # This fixture has no parents: invent one to break exact scope.
                fields = {"parent_references": (subject.reference,)}
            altered = original.model_copy(update=fields)
            raw = encode_text_turn(altered)
            # Keep original reference/hash: canonical artifact hash mismatch must
            # be denied before altered plaintext can be accepted.
            s.raw[user.content_hash] = raw
        elif change == "packet_role":
            session.get(
                Source, s.scope.packet_reference.source_id
            ).system = SourceSystem.USER_INSTRUCTION
        elif change == "classification":
            user.data_classification = C.HIGHLY_RESTRICTED
        elif change == "database":
            s.database = "unapproved"
        elif change == "isolation":
            s.isolation = "repeatable read"
        elif change == "future_source":
            user.captured_at = s.now + timedelta(seconds=1)
        elif change == "scope_digest":
            subject = subject.model_copy(update={"scope_digest": "f" * 64})
    with pytest.raises((ValueError, ReviewAuthorizationError)):
        s.gate._hashes(subject)


@pytest.mark.parametrize(
    "change", ["route", "model", "owner", "original_observed", "original_request", "scope_digest"]
)
def test_fresh_protected_snapshot_exact_bindings(canonical, change):
    from dataclasses import replace

    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    s = canonical
    subject = s.subjects["consumed_claim"]
    if change == "route":
        s.route = s.route.model_copy(update={"available": False})
    elif change == "model":
        original = s.gate._refresh
        s.gate._refresh = lambda: replace(original(), model_digest="f" * 64)
    elif change == "owner":
        s.owner = OwnerGrant(Identity(s.owner.identity.issuer, "other-owner"), s.owner.scopes)
    elif change == "original_observed":
        subject = subject.model_copy(update={"original_observed_at": s.now - timedelta(seconds=1)})
    elif change == "original_request":
        subject = subject.model_copy(update={"original_request_digest": "f" * 64})
    elif change == "scope_digest":
        subject = subject.model_copy(update={"scope_digest": "f" * 64})
    with pytest.raises(ValueError):
        s.gate._fresh_subject(subject)
    assert s.active_sessions == 0


@pytest.mark.parametrize("change", ["pin", "proof_flag", "mode", "identity", "receipt_pin"])
def test_independent_keyproof_is_required_on_each_operation(protected, change):
    s = protected
    receipt = s.gate.protect(s.scope)
    before = s.reader.get_object(receipt.receipt_object)
    if change == "pin":
        s.gate._key_proof_digest = "f" * 64
    elif change == "proof_flag":
        s.proof["target_cleaned"] = False
        s.proof_path.write_bytes(json.dumps(s.proof).encode())
    elif change == "mode":
        s.proof_path.chmod(0o644)
    elif change == "identity":
        s.p._identity = s.proof_path  # Not an age identity; no real key read.
    elif change == "receipt_pin":
        receipt = receipt.model_copy(update={"key_proof_digest": "f" * 64})
    with pytest.raises(module.FollowupAuthorityRecoveryError) as error:
        s.gate.recheck(s.scope, receipt)
    assert error.value.__context__ is None
    assert s.reader.get_object(receipt.receipt_object) == before
    assert s.backup_calls == 1


def test_receipt_inventory_subject_and_proof_pins_cannot_be_substituted(protected):
    s = protected
    receipt = s.gate.protect(s.scope)
    for fields in (
        {"inventory_digest": "f" * 64},
        {"subject": s.scope.model_copy(update={"scope_digest": "f" * 64})},
    ):
        with pytest.raises(module.FollowupAuthorityRecoveryError):
            s.gate.recheck(s.scope, receipt.model_copy(update=fields))
    assert receipt.processing_authorized is receipt.execution_authorized is False
    assert "FollowupAuthoritySubject" not in repr(receipt)


def test_preflight_requires_keyproof_and_fresh_recovered_scope_without_consent_source(
    canonical, monkeypatch
):
    s = canonical
    s.sources = {
        key: source for key, source in s.sources.items() if not key.startswith("packet-followup-")
    }
    # The fixture Session closes over the original mapping; remove in place too.
    # This test deliberately supplies a separate invented key gate, while the
    # local-age fixture above exercises the actual key-helper implementation.
    calls = []
    monkeypatch.setattr(s.gate, "_key_check", lambda: calls.append("key"))
    assert s.gate.preflight(s.consent) is None
    assert calls == ["key"] and s.active_sessions == 0
    s.route = s.route.model_copy(update={"available": False})
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.preflight(s.consent)


@pytest.mark.parametrize("kind", ["consent", "consumed_claim"])
@pytest.mark.parametrize(
    "returned", ["valid", "truthy", "changed_subject", "changed_proof", "failure"]
)
def test_postcommit_entrypoints_require_exact_protected_receipt(
    canonical, protected, monkeypatch, kind, returned
):
    s = canonical
    subject = s.subjects[kind]
    template = protected.gate.protect(protected.scope)
    s.gate._key_proof_digest = template.key_proof_digest
    receipt = template.model_copy(update={"subject": subject})
    calls = []

    def protect(actual):
        assert actual == subject
        calls.append(actual)
        if returned == "failure":
            raise RuntimeError("INVENTED PRIVATE RECOVERY")
        if returned == "truthy":
            return True
        if returned == "changed_subject":
            return receipt.model_copy(
                update={"subject": subject.model_copy(update={"scope_digest": "f" * 64})}
            )
        if returned == "changed_proof":
            return receipt.model_copy(update={"key_proof_digest": "f" * 64})
        return receipt

    monkeypatch.setattr(s.gate, "protect", protect)
    call = lambda: (
        s.gate.protect_consent(consent=s.consent, reference=subject.reference)
        if kind == "consent"
        else s.gate.protect_claim(claimed=s.claimed, request=s.request)
    )
    if returned == "valid":
        assert call() is None
    else:
        with pytest.raises(module.FollowupAuthorityRecoveryError) as error:
            call()
        assert error.value.__context__ is None
    assert calls == [subject]


def test_wrong_retained_subject_is_denied_before_any_receipt_object_read(protected, monkeypatch):
    s = protected
    receipt = s.gate.protect(s.scope)
    other = s.scope.model_copy(update={"scope_digest": "f" * 64})
    monkeypatch.setattr(
        s.gate,
        "_load_receipt",
        lambda key: pytest.fail("wrong subject must deny before receipt read"),
    )
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.recheck(s.scope, receipt.model_copy(update={"subject": other}))


@pytest.mark.parametrize("kind", ["consent", "consumed_claim"])
def test_valid_hash_rewritten_user_actor_is_still_denied(canonical, kind):
    from zacai.interfaces.followup_authorization import _raw, followup_scope_digest
    from zacai.interfaces.text_turn_capture import decode_text_turn, encode_text_turn
    from zacai.state import Source

    s = canonical
    subject = s.subjects[kind]
    with s.session() as session:
        user_source = session.get(Source, s.scope.user_reference.source_id)
        original = decode_text_turn(s.raw[user_source.content_hash])
        user_raw = encode_text_turn(
            original.model_copy(update={"subject": "wrong-canonical-actor"})
        )
        user_digest = content_hash_of(user_raw)
        user_source.content_hash = user_source.content_location = user_digest
        s.raw[user_digest] = user_raw
        user_ref = s.scope.user_reference.model_copy(update={"content_hash": user_digest})
        declared = s.scope.model_copy(
            update={
                "user_reference": user_ref,
                "context_references": (user_ref, *s.scope.context_references[1:]),
            }
        )
        consent = s.consent.model_copy(update={"scope": declared})
        consent_raw = _raw(consent)
        consent_digest = content_hash_of(consent_raw)
        consent_source = session.get(Source, subject.consent_reference.source_id)
        consent_source.content_hash = consent_source.content_location = consent_digest
        s.raw[consent_digest] = consent_raw
        consent_ref = subject.consent_reference.model_copy(update={"content_hash": consent_digest})
        fields = {"consent_reference": consent_ref, "scope_digest": followup_scope_digest(declared)}
        if kind == "consent":
            fields["reference"] = consent_ref
        else:
            altered_claim = s.claimed.claim.model_copy(
                update={"run_scope": declared, "consent_reference": consent_ref}
            )
            claim_raw = _raw(altered_claim)
            claim_digest = content_hash_of(claim_raw)
            claim_source = session.get(Source, subject.reference.source_id)
            claim_source.content_hash = claim_source.content_location = claim_digest
            s.raw[claim_digest] = claim_raw
            fields["reference"] = subject.reference.model_copy(
                update={"content_hash": claim_digest}
            )
        subject = subject.model_copy(update=fields)
    with pytest.raises(ValueError, match="user context mismatch"):
        s.gate._hashes(subject)


def test_claim_canonical_original_window_is_not_current_expiry(canonical):
    from zacai.interfaces.followup_authorization import _raw
    from zacai.state import Source

    s = canonical
    subject = s.subjects["consumed_claim"]
    # Matching canonical bytes and references, but consent approval postdates
    # the consumed attempt: historical repair must reject, even after expiry.
    consent = s.consent.model_copy(
        update={"approved_at": s.claimed.claim.claimed_at + timedelta(seconds=1)}
    )
    raw = _raw(consent)
    digest = content_hash_of(raw)
    ref = subject.consent_reference.model_copy(update={"content_hash": digest})
    altered_claim = s.claimed.claim.model_copy(update={"consent_reference": ref})
    claim_raw = _raw(altered_claim)
    claim_digest = content_hash_of(claim_raw)
    with s.session() as session:
        row = session.get(Source, ref.source_id)
        row.content_hash = row.content_location = digest
        row.captured_at = consent.approved_at
        row = session.get(Source, subject.reference.source_id)
        row.content_hash = row.content_location = claim_digest
    s.raw[digest], s.raw[claim_digest] = raw, claim_raw
    subject = subject.model_copy(
        update={
            "consent_reference": ref,
            "reference": subject.reference.model_copy(update={"content_hash": claim_digest}),
        }
    )
    s.now += timedelta(minutes=16)
    with pytest.raises(ValueError, match="original window mismatch"):
        s.gate._hashes(subject)


def test_current_snapshot_change_after_restore_withholds_ack(protected, monkeypatch):
    s = protected
    checks = []

    def fresh(subject):
        assert not s.active  # No nested recovery or SQL lease during host refresh.
        checks.append(subject)
        if len(checks) == 2:
            raise ValueError("invented fresh owner/context changed")

    monkeypatch.setattr(s.gate, "_fresh_subject", fresh)
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        s.gate.protect(s.scope)
    assert checks == [s.scope, s.scope]
    assert s.backup_calls == s.restores == 1
    assert s.reader.exists(
        module.followup_authority_receipt_key(
            s.scope.reference.source_id, s.scope.reference.content_hash
        )
    )
    assert not s.active and s.p._lease_guard is None


@pytest.fixture
def public_canonical(canonical, protected, monkeypatch):
    """Actual canonical freshness/inventory + age receipt, mocked restore/state.

    This fixture deliberately replaces only checkpoint creation/full restoration;
    it must never bypass _fresh_subject, _fresh or canonical _hashes. Tests prove
    callback/lease order and final acknowledgement denial, not SQL/off-device DR.
    """
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    s, local = canonical, protected
    subject = s.subjects["consumed_claim"]
    p = local.p
    p._factory, p._artifacts = s.session, s.client._artifacts
    s.mutate_at = None
    s.owner_calls = 0
    s.changed_owner = OwnerGrant(
        Identity(s.owner.identity.issuer, "changed-during-recovery"), s.owner.scopes
    )

    def owner():
        assert s.active_sessions == 0
        assert not local.active
        assert p._lease_guard is None
        s.owner_calls += 1
        return s.owner

    gate = module.BrainstormFollowupAuthorityRecovery(
        protector=p, clock=s.authority._clock, refresh=s.authority._refresh,
        owner=owner, recovered_key_receipt=local.proof_path,
        expected_key_proof_digest=content_hash_of(local.proof_path.read_bytes()),
    )
    subject_raw = s.raw[subject.reference.content_hash]
    local.objects.put_object(
        backup_object_key_for(B.BRAINSTORM, subject.reference.content_hash),
        age_encrypt(subject_raw, p._recipient),
    )

    def protect_state(hashes, prefix):
        assert local.active and p._lease_guard is not None
        assert subject.reference.source_id in hashes
        local.backup_calls += 1
        if s.mutate_at == "backup":
            s.owner = s.changed_owner
        return ProtectedState(
            uuid4(), f"{prefix}/{'1' * 64}.age", "1" * 64, "2" * 64,
            f"{prefix}/journal-{'3' * 64}.age", "3" * 64, "4" * 64,
        )

    def verify(actual, receipt):
        assert actual == subject and local.active and p._lease_guard is not None
        # Simulate owner change in a long restoration; actual freshness after
        # releasing the lease must still deny, not a fake _fresh callback.
        if s.mutate_at == "restore":
            s.owner = s.changed_owner
        return gate._now()

    monkeypatch.setattr(p, "_protect_state", protect_state)
    monkeypatch.setattr(gate, "_verify", verify)
    s.public_gate, s.public_subject, s.local = gate, subject, local
    return s


def test_public_owner_callbacks_are_outside_sql_and_restore_lease(public_canonical):
    s = public_canonical
    receipt = s.public_gate.protect(s.public_subject)
    assert s.public_gate.recheck(s.public_subject, receipt) is None
    assert s.owner_calls >= 4
    assert s.active_sessions == 0 and not s.local.active
    assert s.local.p._lease_guard is None


@pytest.mark.parametrize("operation,mutation", [
    ("protect", "backup"), ("protect", "restore"), ("recheck", "restore"),
])
def test_public_owner_change_during_recovery_holds_ack_without_bypassing_freshness(
    public_canonical, operation, mutation
):
    s = public_canonical
    receipt = s.public_gate.protect(s.public_subject) if operation == "recheck" else None
    s.mutate_at = mutation
    with pytest.raises(module.FollowupAuthorityRecoveryError):
        if operation == "protect":
            s.public_gate.protect(s.public_subject)
        else:
            s.public_gate.recheck(s.public_subject, receipt)
    assert s.owner == s.changed_owner
    assert s.active_sessions == 0 and not s.local.active
    assert s.local.p._lease_guard is None


def test_inventory_owner_authentication_is_only_public_freshness(canonical):
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    s = canonical
    subject = s.subjects["consumed_claim"]
    s.owner = OwnerGrant(Identity(s.owner.identity.issuer, "changed-owner"), s.owner.scopes)
    # Inventory checks canonical provenance/ACL; arbitrary owner callbacks must
    # be outside this transaction. Public freshness remains owner-gated.
    assert s.gate._hashes(subject)
    with pytest.raises(ValueError):
        s.gate._fresh_subject(subject)
