"""Actual decoder/assembler and invented canonical memory plus temp tokenizer.

No canonical SQL/backup/model/network/provider session. Trusted callbacks here
are synthetic; passing these tests is not actual live host/runtime readiness.
"""

from datetime import timedelta

import pytest

from tests.test_local_followup_runtime import route
from tests.test_named_followup_decision import fixture as declared_fixture
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.intelligence.followup_prompt_counter import OllamaQwenFollowupTokenCounter
from zacai.interfaces import named_candidate_rows as rows
from zacai.interfaces import named_decision_binding as module
from zacai.interfaces.followup_authorization import FollowupHostSnapshot, scope_from_snapshot
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_decision_admission import QuestionRecoveryInputs
from zacai.interfaces.named_followup_decision import named_manifest_digest
from zacai.interfaces.named_runtime_binding import FixedLocalNamedRuntimeBinding
from zacai.policy import DataClassification as C


@pytest.fixture
def fixture(monkeypatch, installed):
    s = declared_fixture.__wrapped__(monkeypatch)
    s.client._clock = HostObservedClock(lambda: s.now)
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    s.metadata_calls = []
    s.after_metadata = None

    def transport(method, path, body=None):
        assert s.active_sessions == 0
        s.metadata_calls.append((method, path, body))
        if s.after_metadata:
            s.after_metadata()
        if path == "/api/version":
            return {"version": "0.35.1"}
        if path == "/api/tags":
            return {"models": [{"name": route().identity.model_id, "digest": installed[2]}]}
        if path == "/api/show":
            return {}
        pytest.fail("generation called")

    runtime = FixedLocalNamedRuntimeBinding(
        route=route(),
        model_digest=installed[2],
        counter=counter,
        transport_factory=lambda request, started: transport,
    )
    pins = runtime.pins()

    def snapshot(assembled, principal):
        assert s.active_sessions == 0
        return FollowupHostSnapshot(
            assembled, principal, s.client._owner(), runtime.route, runtime.model_digest
        )

    inputs = QuestionRecoveryInputs(s.receipt, s.reply_inputs["text_receipt"])
    assembled = s.assembler.assemble(
        principal=s.reply_inputs["principal"],
        source_id=s.decision.question_reference.source_id,
        expected_turn_digest=s.decision.question_reference.content_hash,
        retained_receipt=s.receipt,
        expected_receipt_digest=s.manifest.packet_receipt_digest,
        recovery_receipt=inputs.question_receipt,
    )
    scope = scope_from_snapshot(
        snapshot(assembled, s.reply_inputs["principal"]),
        run_id=s.manifest.run_id,
        builder_id=s.manifest.builder_id,
    )
    manifest = s.manifest.model_copy(
        update={
            "route": runtime.route,
            "model_digest": runtime.model_digest,
            "tokenizer_digest": pins.tokenizer_digest,
            "request_template_digest": pins.request_template_digest,
        }
    )
    s.decision = s.decision.model_copy(
        update={
            "manifest": manifest,
            "manifest_digest": named_manifest_digest(manifest),
            "run_scope": scope,
        }
    )
    s.now = s.decision.bound_at
    s.labels = {}
    monkeypatch.setattr(rows, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(
        rows,
        "get_effective_source_classification",
        lambda session, source_id: s.labels.get(
            source_id, session.get(rows.Source, source_id).data_classification
        ),
    )

    def recovery(decision):
        assert s.active_sessions == 0
        assert decision == s.decision
        return inputs

    s.binding = module.CanonicalNamedDecisionBinding(
        assembler=s.assembler,
        clock=s.client._clock,
        recovery_inputs=recovery,
        snapshot_builder=snapshot,
        runtime=runtime,
    )
    s.runtime = runtime
    return s


def test_fresh_actual_assembly_sharedclock_and_rows_before_decision_commit(fixture):
    s = fixture
    assert s.binding.host_clock is s.client._clock
    assert s.binding.verify_fresh(s.decision, s.now) is None
    assert [x[1] for x in s.metadata_calls] == ["/api/version", "/api/tags", "/api/show"]
    assert not any(
        x.external_ref.startswith("packet-followup-named-decision/") for x in s.sources.values()
    )
    with s.client._factory() as session:
        assert s.binding.verify_rows(session, s.decision, s.now) is None


def test_expired_history_checks_integrity_without_renewal(fixture):
    s = fixture
    s.now += timedelta(minutes=16)
    assert s.binding.verify_fresh(s.decision, s.now) is None
    assert s.decision.processing_expires_at < s.now
    assert s.decision.processing_authorized is False


def test_row_verifier_never_calls_recovery_runtime_or_clock(fixture, monkeypatch):
    s = fixture
    monkeypatch.setattr(
        s.binding, "_recovery_inputs", lambda *a: pytest.fail("recovery inside SQL")
    )
    monkeypatch.setattr(s.binding, "_snapshot_builder", lambda *a: pytest.fail("owner inside SQL"))
    monkeypatch.setattr(s.runtime, "verify", lambda *a, **kw: pytest.fail("runtime inside SQL"))
    monkeypatch.setattr(s.binding, "_clock", lambda: pytest.fail("clock inside SQL"))
    with s.client._factory() as session:
        s.binding.verify_rows(session, s.decision, s.now)
    assert not s.metadata_calls


def test_post_runtime_acl_elevation_holds(fixture):
    s = fixture
    s.after_metadata = lambda: s.labels.update(
        {s.decision.question_reference.source_id: C.HIGHLY_RESTRICTED}
    )
    with pytest.raises(module.CanonicalNamedDecisionBindingError):
        s.binding.verify_fresh(s.decision, s.now)


def test_row_content_change_after_last_callback_holds(fixture):
    s = fixture

    def alter():
        s.raw[s.decision.question_reference.content_hash] += b" "

    s.after_metadata = alter
    with pytest.raises(module.CanonicalNamedDecisionBindingError):
        s.binding.verify_fresh(s.decision, s.now)


def test_row_prepared_digest_mismatch_holds(fixture):
    s = fixture
    altered = s.decision.model_copy(update={"prepared_request_digest": "e" * 64})
    with s.client._factory() as session, pytest.raises(rows.NamedDecisionInventoryError):
        s.binding.verify_rows(session, altered, s.now)


def test_snapshot_runtime_change_before_metadata_holds(fixture):
    s = fixture
    original = s.binding._snapshot_builder

    def wrong(assembled, principal):
        from dataclasses import replace

        return replace(original(assembled, principal), model_digest="e" * 64)

    s.binding._snapshot_builder = wrong
    with pytest.raises(module.CanonicalNamedDecisionBindingError):
        s.binding.verify_fresh(s.decision, s.now)
    assert not s.metadata_calls


@pytest.mark.parametrize("target", ["question", "evidence", "packet"])
def test_actual_dependency_acl_holds_without_recovery_in_rows(fixture, target):
    s = fixture
    references = {
        "question": s.decision.question_reference,
        "evidence": s.decision.manifest.evidence_references[0],
        "packet": s.decision.manifest.packet_reference,
    }
    s.labels[references[target].source_id] = C.HIGHLY_RESTRICTED
    with s.client._factory() as session, pytest.raises(rows.NamedDecisionInventoryError):
        s.binding.verify_rows(session, s.decision, s.now)
    assert not s.metadata_calls


def test_original_observation_is_not_silently_refreshed(fixture):
    s = fixture
    original = s.decision.original_observed_at
    s.now += timedelta(minutes=1)
    assert s.binding.verify_fresh(s.decision, s.now) is None
    assert s.decision.original_observed_at == original
    changed = s.decision.model_copy(
        update={"original_observed_at": original + timedelta(microseconds=1)}
    )
    with s.client._factory() as session, pytest.raises(rows.NamedDecisionInventoryError):
        s.binding.verify_rows(session, changed, s.now)


def test_final_owner_callback_cannot_replace_runtime_pin(fixture, monkeypatch):
    s = fixture
    original_principal = s.client._principal
    original_pins = s.runtime.pins
    metadata_finished = False

    def mark():
        nonlocal metadata_finished
        metadata_finished = True

    s.after_metadata = mark

    def principal(actual, now):
        original_principal(actual, now)
        if metadata_finished:
            from dataclasses import replace

            monkeypatch.setattr(
                s.runtime, "pins", lambda: replace(original_pins(), tokenizer_digest="e" * 64)
            )

    monkeypatch.setattr(s.client, "_principal", principal)
    with pytest.raises(module.CanonicalNamedDecisionBindingError):
        s.binding.verify_fresh(s.decision, s.now)


def test_historical_record_survives_runtime_unavailability_without_processing(fixture, monkeypatch):
    s = fixture
    original = s.decision
    s.now = original.processing_expires_at + timedelta(seconds=1)

    def unavailable(*args, **kwargs):
        raise RuntimeError('invented current runtime unavailable')

    monkeypatch.setattr(s.runtime, 'pins', unavailable)
    monkeypatch.setattr(s.runtime, 'verify', unavailable)
    s.binding._snapshot_builder = unavailable
    assert s.binding.verify_historical(original, s.now) is None
    assert s.decision == original and not s.metadata_calls
    assert not original.processing_authorized and not original.execution_authorized
    with pytest.raises(module.CanonicalNamedDecisionBindingError):
        s.binding.verify_fresh(original, s.now)


def test_historical_record_retains_final_acl_check_after_owner_callback(fixture, monkeypatch):
    s = fixture
    original = s.client._principal

    def relabel(actual, now):
        original(actual, now)
        s.labels[s.decision.question_reference.source_id] = C.HIGHLY_RESTRICTED

    monkeypatch.setattr(s.client, '_principal', relabel)
    with pytest.raises(module.CanonicalNamedDecisionBindingError):
        s.binding.verify_historical(s.decision, s.now)
    assert not s.metadata_calls
