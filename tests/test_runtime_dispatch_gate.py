"""Actual generate flow and mocked loopback boundary; no live model/SQL authority."""

import pytest

from tests.test_final_dispatch_rows import fixture as row_fixture
from tests.test_local_followup_runtime import setup as runtime_setup
from zacai.intelligence import local_followup_runtime as local
from zacai.policy import DataClassification as C


@pytest.mark.parametrize('callback', ['tokenizer', 'version', 'model'])
def test_prechat_callback_acl_mutation_is_held_at_actual_transport_boundary(monkeypatch, callback):
    s = row_fixture.__wrapped__(monkeypatch)
    runtime, _, _, counter, calls, _ = runtime_setup(monkeypatch)
    request = s.request
    runtime.preflight(request)
    selected = next(iter(s.sources.values()))
    original_count = counter.count_prompt_tokens
    original_factory = local._deadline_transport
    if callback == 'tokenizer':
        def count(body):
            selected.data_classification = C.HIGHLY_RESTRICTED
            return original_count(body)
        counter.count_prompt_tokens = count
    else:
        def factory(actual, started):
            transport = original_factory(actual, started)
            def call(method, path, body=None):
                result = transport(method, path, body)
                if path == ('/api/version' if callback == 'version' else '/api/show'):
                    selected.data_classification = C.HIGHLY_RESTRICTED
                return result
            return call
        monkeypatch.setattr(local, "_deadline_transport", factory)
    checks = []
    def final_gate(actual):
        assert actual is request
        checks.append(actual)
        s.check(s.claimed, actual)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request, before_dispatch=final_gate)
    assert len(checks) == 1
    assert not any(path == '/api/chat' for _, path, _ in calls)
    assert runtime._attempted and runtime.usage is None
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request, before_dispatch=final_gate)
    assert len(checks) == 1 and not any(path == '/api/chat' for _, path, _ in calls)


def named_runtime(monkeypatch):
    from zacai.interfaces.named_runtime_binding import FixedLocalNamedRuntimeBinding

    legacy, request, draft, counter, calls, _ = runtime_setup(monkeypatch)
    # Exact concrete profile fixture only: no actual tokenizer inventory proof.
    profile = object.__new__(FixedLocalNamedRuntimeBinding)
    profile.route, profile.model_digest, profile._counter = legacy.route, legacy.model_digest, counter
    from zacai.interfaces.named_runtime_binding import NamedRuntimePins
    profile._transport_factory = local._deadline_transport
    monkeypatch.setattr(FixedLocalNamedRuntimeBinding, 'pins', lambda self: NamedRuntimePins('a' * 64, 'b' * 64))
    runtime = local.NamedLocalFollowupRuntime(profile=profile)
    return runtime, request, draft, calls


def test_named_lane_cannot_omit_final_gate_legacy_remains_compatible(monkeypatch):
    runtime, request, _, calls = named_runtime(monkeypatch)
    runtime.preflight(request)
    with pytest.raises(TypeError):
        runtime.generate(request)
    assert not any(path == '/api/chat' for _, path, _ in calls)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request, before_dispatch=None)
    assert runtime._attempted
    legacy, request, draft, _, _, _ = runtime_setup(monkeypatch)
    legacy.preflight(request)
    assert legacy.generate(request) == draft


def test_named_lane_exact_gate_runs_before_only_chat(monkeypatch):
    runtime, request, draft, calls = named_runtime(monkeypatch)
    runtime.preflight(request)
    def gate(actual):
        assert actual is request
        assert not any(path == '/api/chat' for _, path, _ in calls)
    assert runtime.generate(request, before_dispatch=gate) == draft
    assert sum(path == '/api/chat' for _, path, _ in calls) == 1


@pytest.mark.parametrize('field', ['instruction', 'digest', 'evidence_json'])
def test_final_gate_request_mutation_never_dispatches_stale_prepared_body(monkeypatch, field):
    runtime, request, _, calls = named_runtime(monkeypatch)
    runtime.preflight(request)
    def gate(actual):
        value = getattr(actual, field)
        object.__setattr__(actual, field, value + (b' ' if type(value) is bytes else ' '))
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request, before_dispatch=gate)
    assert not any(path == '/api/chat' for _, path, _ in calls)
    assert runtime._attempted and runtime.usage is None


def test_final_gate_nested_task_budget_mutation_holds_without_chat(monkeypatch):
    runtime, request, _, calls = named_runtime(monkeypatch)
    runtime.preflight(request)
    def gate(actual):
        object.__setattr__(actual.context.task, 'max_output_tokens', actual.context.task.max_output_tokens + 1)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request, before_dispatch=gate)
    assert not any(path == '/api/chat' for _, path, _ in calls)


def test_final_gate_recovery_time_consumes_original_total_budget(monkeypatch):
    runtime, request, _, calls = named_runtime(monkeypatch)
    ticks = [0.0]
    monkeypatch.setattr(local.time, 'perf_counter', lambda: ticks[0])
    runtime.preflight(request)
    def gate(actual):
        ticks[0] = actual.context.task.max_latency_ms / 1000
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request, before_dispatch=gate)
    assert error.value.code == local.F.TOTAL_LATENCY
    assert not any(path == '/api/chat' for _, path, _ in calls)
    assert runtime._attempted and runtime.usage is None


def test_named_preflight_and_generate_share_original_sixty_percent_budget(monkeypatch):
    runtime, request, _, calls = named_runtime(monkeypatch)
    ticks = [0.0]
    monkeypatch.setattr(local.time, 'perf_counter', lambda: ticks[0])
    count = runtime._token_counter.count_prompt_tokens
    def slow_count(body):
        ticks[0] += request.context.task.max_latency_ms / 1000 * 0.6
        return count(body)
    runtime._token_counter.count_prompt_tokens = slow_count
    runtime.preflight(request)
    assert ticks[0] < request.context.task.max_latency_ms / 1000
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request, before_dispatch=lambda actual: None)
    assert error.value.code == local.F.TOTAL_LATENCY
    assert not any(path == '/api/chat' for _, path, _ in calls)
    assert runtime._attempted


def test_named_runtime_uses_same_exact_profile_transport_seam(monkeypatch):
    runtime, request, draft, calls = named_runtime(monkeypatch)
    legacy_factory = local._deadline_transport
    transport = legacy_factory(request, 0)
    issued = []
    def profile_factory(actual, started):
        assert actual is request
        issued.append(started + actual.context.task.max_latency_ms / 1000)
        return transport
    runtime._profile._transport_factory = profile_factory
    runtime = local.NamedLocalFollowupRuntime(profile=runtime._profile)
    monkeypatch.setattr(local, '_deadline_transport', lambda *args: (_ for _ in ()).throw(AssertionError('wrong transport seam')))
    runtime.preflight(request)
    assert runtime.generate(request, before_dispatch=lambda actual: None) == draft
    assert len(issued) == 2 and issued[0] == issued[1]
    assert sum(path == '/api/chat' for _, path, _ in calls) == 1


@pytest.mark.parametrize('pin', ['tokenizer', 'serializer', 'transport'])
def test_named_runtime_changed_pins_after_metadata_hold_before_final_gate(monkeypatch, pin):
    from zacai.interfaces.named_runtime_binding import (
        FixedLocalNamedRuntimeBinding,
        NamedRuntimePins,
    )
    runtime, request, _, calls = named_runtime(monkeypatch)
    runtime.preflight(request)
    check = runtime._token_counter.verify_runtime_with_transport
    def changed(transport):
        check(transport)
        if pin == 'transport':
            runtime._profile._transport_factory = lambda **kwargs: None
        else:
            monkeypatch.setattr(FixedLocalNamedRuntimeBinding, 'pins', lambda self:
                NamedRuntimePins('f' * 64 if pin == 'tokenizer' else 'a' * 64,
                                 'f' * 64 if pin == 'serializer' else 'b' * 64))
    runtime._token_counter.verify_runtime_with_transport = changed
    gates = []
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request, before_dispatch=lambda actual: gates.append(actual))
    assert not gates
    assert not any(path == '/api/chat' for _, path, _ in calls)
