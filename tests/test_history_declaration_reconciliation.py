"""Genuine invented signed sessions/artifacts; canonical SQL explicitly simulated."""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_a2_precommit_owner import (  # noqa: F401
    capture_case,
    case,
    declaration_case,
    factory_case,
    host,
    installed,
    loader_case,
    post_case,
    setup,
    simulated_commit_driver,
)
from zacai.intelligence import history_declaration_reconciliation as m
from zacai.intelligence import history_review_retention as retention
from zacai.intelligence.history_generation_review_declaration import decode_history_consent
from zacai.interfaces.named_session_binding import NamedSessionOperation


@pytest.fixture
def reconciled_case(capture_case, monkeypatch):  # noqa: F811
    s = capture_case
    retained = s.capture()
    s.events.clear()
    s.reads.clear()
    # Use the existing capture fixture's documented simulated SQL seams;
    # actual complete body codec/filesystem and signed owner remain genuine.
    for name in ("_physical", "_same", "_ids", "_fragment_rows"):
        monkeypatch.setattr(m, name, getattr(retention, name))
    s.reconcile = lambda: m.reconcile_history_declaration_custody(
        factory=s.f.c.factory,
        artifacts=s.f.c.artifacts,
        context=retention.HistoryDeclarationContext(
            s.f.c.expected_root, s.f.c.expected_account_ref, s.f.c.expected_exported_at
        ),
        expected_declaration=retained.declaration,
        operation=s.f.operation,
    )
    return s


def test_existing_exact_committed_custody_is_read_without_writes(reconciled_case):
    s = reconciled_case
    rows = {ident: dict(row) for ident, row in s.rows.items()}
    value = s.reconcile()
    assert value == s.out.retained
    assert value.owner_admitted is value.processing_authorized is False
    assert s.rows == rows
    assert "commit" not in s.events and "canonical record simulated" not in s.events
    assert "actual artifact put" not in s.events and len(s.reads) == 1


def test_preservation_read_does_not_renew_expired_processing_window(reconciled_case):
    s = reconciled_case
    declaration = s.out.retained.declaration
    consent = decode_history_consent(declaration.generation_consent_json.encode())
    original_expiry = consent.expires_at
    s.f.s.f.now[0] = original_expiry + timedelta(seconds=1)
    value = s.reconcile()
    assert value.declaration == declaration
    assert decode_history_consent(value.declaration.generation_consent_json.encode()).expires_at == original_expiry
    assert value.processing_authorized is value.owner_admitted is False
    assert "commit" not in s.events


@pytest.mark.parametrize("fault", ["absent", "duplicate", "wrong_hash"])
def test_missing_conflicting_or_changed_custody_holds_before_body(reconciled_case, fault):
    s = reconciled_case
    if fault == "absent":
        s.ids = ()
    elif fault == "duplicate":
        s.ids = (*s.ids, uuid4())
    else:
        s.rows[s.out.retained.reference.source_id]["content_hash"] = "f" * 64
    with pytest.raises(m.HistoryDeclarationReconciliationError):
        s.reconcile()
    assert s.reads == []
    assert "commit" not in s.events and "actual artifact put" not in s.events


def test_revoked_owner_holds_before_body(reconciled_case):
    s = reconciled_case
    s.f.s.inputs.owners.revoke()
    with pytest.raises(m.HistoryDeclarationReconciliationError):
        s.reconcile()
    assert s.reads == [] and "open" not in s.events


def test_body_callback_owner_revocation_withholds_read_result(reconciled_case, monkeypatch):
    s = reconciled_case
    read_clock = s.f.s.inputs.clock._read
    fired = []

    def read():
        if s.reads and not fired:
            fired.append(True)
            s.f.s.inputs.owners.revoke()
        return read_clock()

    monkeypatch.setattr(s.f.s.inputs.clock, "_read", read)
    with pytest.raises(m.HistoryDeclarationReconciliationError):
        s.reconcile()
    assert fired == [True] and len(s.reads) == 1
    assert "commit" not in s.events


def test_final_owner_callback_source_drift_withholds_result(reconciled_case, monkeypatch):
    s = reconciled_case
    read_clock = s.f.s.inputs.clock._read
    fired = []

    def read():
        if s.reads and not fired:
            fired.append(True)
            s.rows[s.out.retained.reference.source_id]["captured_at"] += timedelta(seconds=1)
        return read_clock()

    monkeypatch.setattr(s.f.s.inputs.clock, "_read", read)
    with pytest.raises(m.HistoryDeclarationReconciliationError):
        s.reconcile()
    assert fired == [True] and "commit" not in s.events


def test_actual_owner_callbacks_run_outside_canonical_leases(reconciled_case, monkeypatch):
    s = reconciled_case
    establish = NamedSessionOperation.establish
    receipt = NamedSessionOperation.receipt_only
    seen = []

    def first(operation):
        assert s.events.count("open") == s.events.count("close")
        seen.append("establish")
        return establish(operation)

    def final(operation, principal):
        assert s.events.count("open") == s.events.count("close")
        seen.append("receipt")
        return receipt(operation, principal)

    monkeypatch.setattr(NamedSessionOperation, "establish", first)
    monkeypatch.setattr(NamedSessionOperation, "receipt_only", final)
    assert s.reconcile() == s.out.retained
    assert seen == ["establish", "receipt"] and "commit" not in s.events


def test_advancing_clock_observation_does_not_refresh_signed_session(reconciled_case, monkeypatch):
    s = reconciled_case
    read_clock = s.f.s.inputs.clock._read
    base = read_clock()
    observations = []

    def read():
        observations.append(True)
        return base + timedelta(milliseconds=len(observations))

    monkeypatch.setattr(s.f.s.inputs.clock, "_read", read)
    assert s.reconcile() == s.out.retained
    assert len(observations) > 1 and "commit" not in s.events
