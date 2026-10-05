"""Actual local age; invented canonical inventory, SQL/restore and host session.

No real SQL, cloud, credentials, private decisions or processing permissions.
"""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.test_followup_authority_recovery import protected as protected  # noqa: PLC0414
from zacai.backup_artifacts import age_encrypt
from zacai.interfaces import named_decision_recovery as module
from zacai.interfaces.named_decision_capture import NamedDecisionCheckpointScope


@pytest.fixture
def decision(protected):
    s = protected
    old_scope, p = s.scope, s.p
    scope = NamedDecisionCheckpointScope(
        old_scope.reference.source_id, old_scope.reference.content_hash, old_scope.captured_at
    )
    state = SimpleNamespace(active_owner=True, fresh_calls=0, callback_value=None)

    def fresh(value, now):
        assert p._lease_guard is None and not s.active
        assert value.admitted_at == scope.captured_at
        assert now >= value.bound_at
        state.fresh_calls += 1
        if not state.active_owner:
            raise ValueError("invented private owner revoked")
        return state.callback_value

    gate = module.BrainstormNamedDecisionRecovery(
        protector=p,
        clock=s.gate.host_clock,
        fresh=fresh,
        recovered_key_receipt=s.proof_path,
        expected_key_proof_digest=s.gate._key_proof_digest,
    )

    def inventory(selected):
        assert selected == scope
        return SimpleNamespace(
            decision=SimpleNamespace(admitted_at=scope.captured_at, bound_at=scope.captured_at),
            hashes=((scope.source_id, scope.decision_digest),),
        )

    gate._inventory = inventory
    original_protect = p._protect_state

    def protect(hashes, prefix):
        assert prefix == f"BRAINSTORM/state/named-decision-{scope.source_id}"
        previous = original_protect(
            hashes, f"BRAINSTORM/state/followup-authority-{scope.source_id}"
        )
        state_key = f"{prefix}/{previous.state_ciphertext_hash}.age"
        journal_key = f"{prefix}/journal-{previous.journal_ciphertext_hash}.age"
        p._put(state_key, p._read(previous.state_object, 65_000_000))
        p._put(journal_key, p._read(previous.journal_object, 4_100_000))
        return replace(previous, state_object=state_key, journal_object=journal_key)

    p._protect_state = protect
    state.gate, state.scope, state.underlying = gate, scope, s
    return state


def test_actual_age_immutable_receipt_recheck_and_historical_repair(decision):
    s = decision
    receipt = s.gate.protect(s.scope)
    assert receipt.source_id == s.scope.source_id
    assert receipt.decision_digest == s.scope.decision_digest
    assert receipt.inventory_digest == module._inventory_digest(
        {s.scope.source_id: s.scope.decision_digest}
    )
    assert receipt.key_proof_digest == s.gate._key_proof_digest
    assert "named-decision-" in receipt.receipt_object
    old = s.underlying.p._read(receipt.receipt_object, 64_000)
    s.underlying.now += timedelta(days=1)
    assert s.gate.protect(s.scope) == receipt
    assert s.underlying.p._read(receipt.receipt_object, 64_000) == old
    assert s.gate.recheck(s.scope, receipt) is None
    assert s.underlying.backup_calls == 1 and s.underlying.restores == 3
    assert s.fresh_calls == 6
    assert not s.underlying.active and s.underlying.p._lease_guard is None


@pytest.mark.parametrize(
    "object_name", ["receipt_object", "state_object", "journal_object", "artifact_object"]
)
def test_corruption_held_no_receipt_overwrite(decision, object_name):
    s = decision
    receipt = s.gate.protect(s.scope)
    key = getattr(receipt, object_name)
    s.underlying.p._put(key, b"invented corrupt private bytes")
    original = s.underlying.p._read(receipt.receipt_object, 64_000)
    with pytest.raises(module.NamedDecisionRecoveryError) as error:
        s.gate.protect(s.scope)
    assert "private" not in str(error.value) and error.value.__context__ is None
    assert s.underlying.p._read(receipt.receipt_object, 64_000) == original
    assert s.underlying.backup_calls == 1


@pytest.mark.parametrize("operation", ["protect", "recheck"])
def test_owner_session_revoked_during_restore_holds_ack_outside_lease(decision, operation):
    s = decision
    receipt = s.gate.protect(s.scope)
    s.underlying.after_restore = lambda: setattr(s, "active_owner", False)
    with pytest.raises(module.NamedDecisionRecoveryError):
        if operation == "protect":
            s.gate.protect(s.scope)
        else:
            s.gate.recheck(s.scope, receipt)
    assert s.fresh_calls == 4
    assert not s.underlying.active and s.underlying.p._lease_guard is None


@pytest.mark.parametrize("callback_value", [True, False, 0, "approved"])
def test_no_permissive_callback_ack(decision, callback_value):
    s = decision
    s.callback_value = callback_value
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.protect(s.scope)
    assert s.underlying.backup_calls == 0


@pytest.mark.parametrize(
    "field", ["inventory_digest", "key_proof_digest", "decision_digest", "state_plaintext_hash"]
)
def test_shaped_receipt_is_not_actual_retained_proof(decision, field):
    s = decision
    receipt = s.gate.protect(s.scope)
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.recheck(s.scope, receipt.model_copy(update={field: "f" * 64}))


def test_dependency_reencryption_keeps_exact_plaintext_receipt(decision):
    s = decision
    receipt = s.gate.protect(s.scope)
    s.underlying.p._put(
        receipt.artifact_object, age_encrypt(s.underlying.raw, s.underlying.p._recipient)
    )
    assert s.gate.recheck(s.scope, receipt) is None


def test_independent_key_proof_changed_holds_before_backup(decision):
    s = decision
    s.underlying.proof_path.write_bytes(b"invented modified keyproof")
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.protect(s.scope)
    assert s.underlying.backup_calls == 0


def test_rollback_in_final_owner_callback_held(decision):
    s = decision
    initial = s.gate._fresh_binding

    def fresh(value, now):
        initial(value, now)
        if s.fresh_calls == 2:
            s.underlying.now -= timedelta(seconds=1)

    s.gate._fresh_binding = fresh
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.protect(s.scope)
    assert s.underlying.backup_calls == 1


def test_invalid_scope_fails_before_proof_or_objects(decision):
    s = decision
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.protect(replace(s.scope, decision_digest="../private"))
    assert s.fresh_calls == s.underlying.backup_calls == 0


def test_actual_rows_inventory_seam_and_callback_outside_sql(decision, monkeypatch):
    from contextlib import contextmanager

    s = decision
    gate, p = s.gate, s.underlying.p
    inventory = gate._inventory(s.scope)
    del gate._inventory
    state = SimpleNamespace(session_open=False, calls=0)

    class Session:
        def scalar(self, statement):
            assert str(statement) == "SELECT current_database()"
            return p._engine.url.database

    @contextmanager
    def factory():
        state.session_open = True
        try:
            yield Session()
        finally:
            state.session_open = False

    def rows(session, *, artifacts, reference, as_of):
        assert state.session_open and reference.source_id == s.scope.source_id
        assert reference.content_hash == s.scope.decision_digest
        assert as_of == s.underlying.now
        state.calls += 1
        return inventory

    p._factory, p._artifacts = factory, object()
    monkeypatch.setattr(module, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(module, "load_named_decision_inventory", rows)
    original = gate._fresh_binding

    def fresh(record, now):
        assert not state.session_open
        return original(record, now)

    gate._fresh_binding = fresh
    receipt = gate.protect(s.scope)
    gate.recheck(s.scope, receipt)
    assert state.calls >= 8 and not state.session_open


def test_bound_decision_time_after_receipt_is_denied(decision):
    s = decision
    receipt = s.gate.protect(s.scope)
    previous = s.gate._inventory
    s.underlying.now += timedelta(seconds=1)

    def inventory(scope):
        found = previous(scope)
        found.decision.bound_at = s.underlying.now
        return found

    s.gate._inventory = inventory
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.recheck(s.scope, receipt)


@pytest.mark.parametrize("flag", ["lease", "admin", "corrupt_restore", "admin_cleanup_failure"])
def test_existing_checkpoint_safety_failures_hold_ack(decision, flag):
    s = decision
    setattr(s.underlying, flag, flag in ("corrupt_restore", "admin_cleanup_failure"))
    with pytest.raises(module.NamedDecisionRecoveryError):
        s.gate.protect(s.scope)
    assert s.underlying.p._lease_guard is None and not s.underlying.active
