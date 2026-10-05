"""Invented admission, memory ledger and proof only; no HTTP, SQL or recovery."""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_named_followup_decision import fixture as named_fixture
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import named_decision_capture as m
from zacai.interfaces import named_decision_inventory
from zacai.interfaces.named_followup_decision import decode_named_decision, encode_named_decision
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.state import SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    s = named_fixture.__wrapped__(monkeypatch)
    s.now = s.decision.bound_at
    s.capture_owner = s.client._owner()
    s.admission_error = s.binding_error = s.session_error = False
    s.admission_result = s.binding_result = None
    s.after_fresh = s.after_protection = s.after_decision_recheck = s.after_session = None
    s.decision_receipts = {}
    s.decision_protects = 0
    old = s.client._capture if hasattr(s.client, "_capture") else s.client
    # Existing nested invented fixtures retain the original canonical turn store.
    while not hasattr(old, "_factory"):
        old = old._assembler._capture
    from zacai.interfaces.host_clock import HostObservedClock
    s.host_clock = HostObservedClock(lambda: s.now)

    class Admission:
        def resolve(self, handle, principal, request, now):
            assert s.active_sessions == 0 and handle == "invented-handle"
            if s.admission_error:
                raise RuntimeError("PRIVATE admission failure")
            return s.decision

        def recheck(self, handle, principal, decision, now):
            assert s.active_sessions == 0 and handle == "invented-handle"
            if s.session_error:
                raise RuntimeError("PRIVATE session failure")
            assert decision == s.decision.model_copy(update={"bound_at": decision.bound_at})
            if s.after_session:
                s.after_session()
            return s.admission_result

        def recheck_session(self, principal, decision, now):
            assert s.active_sessions == 0
            if s.session_error:
                raise RuntimeError("PRIVATE session failure")
            return s.admission_result

    class Binding:
        def verify_fresh(self, decision, now):
            assert s.active_sessions == 0
            if s.binding_error:
                raise RuntimeError("PRIVATE recovery/runtime failure")
            if s.after_fresh:
                s.after_fresh()
            return s.binding_result

        def verify_rows(self, session, decision, now):
            assert s.active_sessions == 1
            if s.binding_error:
                raise RuntimeError("PRIVATE rows failure")
            return s.binding_result

    class Protection:
        @property
        def host_clock(self):
            return s.host_clock

        def protect(self, scope):
            assert s.active_sessions == 0
            assert any(source.id == scope.source_id for source in s.sources.values())
            s.decision_protects += 1
            if s.fail_protect:
                raise RuntimeError("PRIVATE backup failure")
            if scope.source_id not in s.decision_receipts:
                s.decision_receipts[scope.source_id] = m.NamedDecisionRecoveryReceipt(
                    source_id=scope.source_id, decision_digest=scope.decision_digest,
                    captured_at=scope.captured_at, verified_at=s.now,
                    inventory_digest="a"*64, key_proof_digest="b"*64,
                    artifact_backup_run_id=uuid4(), artifact_ciphertext_hash="1"*64,
                    state_ciphertext_hash="2"*64, state_plaintext_hash="3"*64,
                    journal_ciphertext_hash="4"*64, journal_plaintext_hash="5"*64,
                )
            if s.after_protection:
                s.after_protection()
            return s.decision_receipts[scope.source_id].model_copy(update=s.bad_receipt or {})

        def recheck(self, scope, receipt):
            assert s.active_sessions == 0
            if s.fail_recheck:
                raise RuntimeError("PRIVATE proof failure")
            if s.after_decision_recheck:
                s.after_decision_recheck()
            return s.recheck_result

    def find(session, ref):
        return s.sources.get(ref)

    def write(session, store, ref, system, raw, at):
        prior = s.sources.get(ref)
        if prior:
            assert s.raw[prior.content_hash] == raw
            return prior.id
        from types import SimpleNamespace
        digest = content_hash_of(raw)
        location = store.put(m.B.BRAINSTORM, digest, raw)
        source = SimpleNamespace(id=uuid4(), external_ref=ref, system=system,
                                 trust_boundary=m.B.BRAINSTORM, data_classification=C.CONFIDENTIAL,
                                 content_hash=digest, content_location=location, captured_at=at)
        session.pending[ref] = source
        return source.id

    def memory_rows(session, binding, decision, now):
        # The memory seam has no ORM transaction/events. Actual flush/commit
        # veto and transaction retention are covered by the SQL composition.
        if binding.verify_rows(session, decision, now) is not None:
            raise ValueError("invented row gate held")

    monkeypatch.setattr(m, "_checked_rows", memory_rows)
    monkeypatch.setattr(m, "_require_request_lock", lambda session, request_id: None)
    monkeypatch.setattr(m, "_find_named", find)
    monkeypatch.setattr(m, "_write", write)
    # Existing fixture patches actual _bytes ACL helper in review_authorization.
    monkeypatch.setattr(m, "get_effective_source_classification", lambda session, source_id:
                        session.get(None, source_id).data_classification)
    monkeypatch.setattr(named_decision_inventory, "get_effective_source_classification",
                        lambda session, source_id: session.get(None, source_id).data_classification)
    s.capture = m.CanonicalNamedDecisionCapture(factory=old._factory, artifacts=old._artifacts,
        owner=lambda: s.capture_owner, admission=Admission(), binding=Binding(), protection=Protection(),
        clock=s.host_clock)
    s.capture_inputs = {"principal": s.reply_inputs["principal"],
                        "admission_handle": "invented-handle", "original_request": s.reply_inputs["request"]}
    return s


def saved_source(s):
    return s.sources[f"packet-followup-named-decision/{s.decision.manifest.request_id}"]


def load(s, saved):
    return s.capture.load(principal=s.capture_inputs["principal"], admission_handle="invented-handle",
                          source_id=saved.reference.source_id,
                          expected_decision_digest=saved.reference.content_hash,
                          recovery_receipt=saved.recovery_receipt)


def test_actual_committed_reference_then_protected_ack_not_permission(fixture):
    s = fixture
    saved = s.capture.capture(**s.capture_inputs)
    source = saved_source(s)
    assert source.system is SourceSystem.USER_INSTRUCTION
    assert source.captured_at == s.decision.admitted_at
    assert decode_named_decision(s.raw[source.content_hash]) == s.decision
    assert saved.reference.source_id == source.id and saved.reference.content_hash == source.content_hash
    assert saved.recovery_receipt.decision_digest == source.content_hash
    assert saved.recovery_receipt.receipt_object.startswith(f"BRAINSTORM/state/named-decision-{source.id}/")
    assert not saved.processing_authorized and not saved.execution_authorized
    assert s.decision.manifest.actor_subject not in repr(saved)
    assert s.decision_protects == 1 and load(s, saved) == saved


def test_replay_preserves_original_bound_observation_expiry(fixture):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    original_raw = s.raw[first.reference.content_hash]
    s.now += timedelta(seconds=10)
    s.decision = s.decision.model_copy(update={"bound_at": s.now})
    second = s.capture.capture(**s.capture_inputs)
    assert second == first and encode_named_decision(second.decision) == original_raw
    assert second.decision.original_observed_at == first.decision.original_observed_at
    assert second.decision.processing_expires_at == first.decision.processing_expires_at


@pytest.mark.parametrize("field", ["session_binding_digest", "original_utf8_digest", "original_observed_at"])
def test_replay_changed_original_binding_denied(fixture, field):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    update = s.now if field == "original_observed_at" else "0" * 64
    s.decision = s.decision.model_copy(update={field: update})
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)
    assert saved_source(s).content_hash == first.reference.content_hash


@pytest.mark.parametrize("flag", ["admission_error", "binding_error", "session_error"])
def test_failed_required_host_gate_never_records(fixture, flag):
    s = fixture
    setattr(s, flag, True)
    with pytest.raises(m.NamedDecisionCaptureError) as error:
        s.capture.capture(**s.capture_inputs)
    assert error.value.__context__ is None
    assert f"packet-followup-named-decision/{s.decision.manifest.request_id}" not in s.sources
    assert s.decision_protects == 0


@pytest.mark.parametrize("field", ["admission_result", "binding_result", "recheck_result"])
def test_boolean_gate_not_permission(fixture, field):
    setattr(fixture, field, True)
    with pytest.raises(m.NamedDecisionCaptureError):
        fixture.capture.capture(**fixture.capture_inputs)


def test_failed_protection_pending_repair_after_expiry_returns_receipt_only(fixture):
    s = fixture
    s.fail_protect = True
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)
    source = saved_source(s)
    s.now = s.decision.processing_expires_at + timedelta(seconds=1)
    s.fail_protect = False
    receipt = s.capture.protect_pending(principal=s.capture_inputs["principal"], source_id=source.id,
                                       expected_decision_digest=source.content_hash)
    assert type(receipt) is m.NamedDecisionRecoveryReceipt
    assert receipt.captured_at == s.decision.admitted_at and receipt.verified_at == s.now
    assert not hasattr(receipt, "decision")
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.load(principal=s.capture_inputs["principal"], admission_handle="invented-handle",
                       source_id=source.id, expected_decision_digest=source.content_hash, recovery_receipt=receipt)


@pytest.mark.parametrize("stage", ["after_fresh", "after_protection", "after_decision_recheck"])
def test_owner_change_during_external_work_withholds_ack(fixture, stage):
    s = fixture
    def change():
        s.capture_owner = OwnerGrant(Identity("https://accounts.google.com", "other-owner"), s.capture_owner.scopes)
    setattr(s, stage, change)
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)


@pytest.mark.parametrize("update", [{"source_id": uuid4()}, {"decision_digest": "0"*64},
                                    {"verified_at": None}, {"format": "zac-text-turn-recovery-v1"}])
def test_wrong_receipt_held(fixture, update):
    fixture.bad_receipt = update
    with pytest.raises(m.NamedDecisionCaptureError):
        fixture.capture.capture(**fixture.capture_inputs)


def test_current_acl_and_source_bytes_after_recovery(fixture):
    s = fixture
    def relabel():
        saved_source(s).data_classification = C.HIGHLY_RESTRICTED
    s.after_decision_recheck = relabel
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)


def test_read_committed_required_and_clock_rollback(fixture):
    s = fixture
    s.isolation = "repeatable read"
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)
    assert s.decision_protects == 0
    s.isolation = "read committed"
    s.after_protection = lambda: setattr(s, "now", s.decision.admitted_at - timedelta(seconds=1))
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)


def test_serial_request_lock_invoked_before_write(fixture):
    s = fixture
    previous = s.locks
    s.capture.capture(**s.capture_inputs)
    assert s.locks == previous + 1
    # The memory fixture is not PostgreSQL concurrency proof; root owns SQL tests.


@pytest.mark.parametrize("callback", ["session", "owner"])
def test_expiry_during_last_external_auth_callback_denies(fixture, callback):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    if callback == "session":
        s.after_session = lambda: setattr(s, "now", s.decision.processing_expires_at)
    else:
        def owner():
            s.now = s.decision.processing_expires_at
            return s.capture_owner
        s.capture._owner = owner
    with pytest.raises(m.NamedDecisionCaptureError):
        load(s, first)


def test_protection_outlasts_deadline_no_active_ack_but_history_recoverable(fixture):
    s = fixture
    s.after_protection = lambda: setattr(s, "now", s.decision.processing_expires_at)
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.capture(**s.capture_inputs)
    source = saved_source(s)
    s.after_protection = None
    receipt = s.capture.protect_pending(principal=s.capture_inputs["principal"], source_id=source.id,
                                       expected_decision_digest=source.content_hash)
    assert type(receipt) is m.NamedDecisionRecoveryReceipt


@pytest.mark.parametrize("field,value", [
    ("system", SourceSystem.MANUAL), ("external_ref", "text-turn/other"),
    ("content_hash", "0"*64), ("captured_at", None), ("data_classification", C.HIGHLY_RESTRICTED),
])
def test_source_kind_provenance_hash_acl_repair_hold(fixture, field, value):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    source = saved_source(s)
    setattr(source, field, value)
    with pytest.raises(m.NamedDecisionCaptureError):
        load(s, first)
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.protect_pending(principal=s.capture_inputs["principal"], source_id=first.reference.source_id,
                                 expected_decision_digest=first.reference.content_hash)


def test_wrong_principal_denied_before_private_session_read(fixture):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    old_opens = s.session_opens
    s.capture_owner = OwnerGrant(Identity("https://accounts.google.com", "other"), s.capture_owner.scopes)
    with pytest.raises(m.NamedDecisionCaptureError):
        load(s, first)
    assert s.session_opens == old_opens


def test_recheck_session_failure_withholds_pending_ack(fixture):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    s.now = s.decision.processing_expires_at
    s.session_error = True
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.protect_pending(principal=s.capture_inputs["principal"], source_id=first.reference.source_id,
                                 expected_decision_digest=first.reference.content_hash)


@pytest.mark.parametrize("handle", ["", True, "x"*257, "with space", "\n", "café"])
def test_raw_or_invalid_handle_no_record(fixture, handle):
    with pytest.raises(m.NamedDecisionCaptureError):
        fixture.capture.capture(**{**fixture.capture_inputs, "admission_handle": handle})


def test_future_verified_receipt_holds(fixture):
    fixture.bad_receipt = {"verified_at": fixture.now + timedelta(seconds=1)}
    with pytest.raises(m.NamedDecisionCaptureError):
        fixture.capture.capture(**fixture.capture_inputs)


@pytest.mark.parametrize("field", ["inventory_digest", "key_proof_digest"])
def test_required_recovery_inventory_and_independent_key_proof(fixture, field):
    from pydantic import ValidationError
    saved = fixture.capture.capture(**fixture.capture_inputs)
    fields = saved.recovery_receipt.model_dump()
    del fields[field]
    with pytest.raises(ValidationError):
        m.NamedDecisionRecoveryReceipt(**fields)


def test_malformed_historical_window_cannot_be_repaired(fixture):
    import json

    from zacai.ingestion.artifact_store import canonical_bytes
    s = fixture
    saved = s.capture.capture(**s.capture_inputs)
    source = saved_source(s)
    fields = json.loads(s.raw[source.content_hash])
    fields["bound_at"] = fields["processing_expires_at"]
    raw = canonical_bytes(fields)
    source.content_hash = content_hash_of(raw)
    source.content_location = source.content_hash
    s.raw[source.content_hash] = raw
    s.now = s.decision.processing_expires_at + timedelta(seconds=1)
    with pytest.raises(m.NamedDecisionCaptureError):
        s.capture.protect_pending(principal=s.capture_inputs["principal"], source_id=saved.reference.source_id,
                                 expected_decision_digest=source.content_hash)


def test_final_session_callback_source_relabel_withholds_ack(fixture):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    calls = 0

    def relabel_during_final_check():
        nonlocal calls
        calls += 1
        if calls == 5:
            saved_source(s).data_classification = C.HIGHLY_RESTRICTED

    s.after_session = relabel_during_final_check
    with pytest.raises(m.NamedDecisionCaptureError):
        load(s, first)
    assert calls == 5



def test_final_row_adapter_source_relabel_withholds_ack(fixture):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    calls = 0
    original = s.capture._binding.verify_rows

    def relabel_in_final_rows(session, decision, now):
        nonlocal calls
        original(session, decision, now)
        calls += 1
        if calls == 2:
            saved_source(s).data_classification = C.HIGHLY_RESTRICTED

    s.capture._binding.verify_rows = relabel_in_final_rows
    with pytest.raises(m.NamedDecisionCaptureError):
        load(s, first)
    assert calls == 2



@pytest.mark.parametrize("dependency", ["question", "packet", "evidence"])
def test_final_row_adapter_dependency_relabel_withholds_ack(fixture, dependency):
    s = fixture
    first = s.capture.capture(**s.capture_inputs)
    calls = 0
    original = s.capture._binding.verify_rows
    ref = {"question": s.decision.question_reference, "packet": s.decision.manifest.packet_reference,
           "evidence": s.decision.manifest.evidence_references[0]}[dependency]

    def relabel_in_final_rows(session, decision, now):
        nonlocal calls
        original(session, decision, now)
        calls += 1
        if calls == 2:
            session.get(None, ref.source_id).data_classification = C.HIGHLY_RESTRICTED

    s.capture._binding.verify_rows = relabel_in_final_rows
    with pytest.raises(m.NamedDecisionCaptureError):
        load(s, first)
    assert calls == 2
