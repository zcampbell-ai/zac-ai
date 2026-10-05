"""Invented requests and mocked metadata/chat; no actual private/model calls."""

import asyncio
import json
from dataclasses import replace

import pytest

from tests.test_review_generation import route as base_route
from tests.test_text_followup import setup as declared_context
from zacai.intelligence import local_followup_runtime as local
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F
from zacai.policy import Destination


def route():
    base = base_route()
    return base.model_copy(update={
        'identity': base.identity.model_copy(update={
            'model_id': 'qwen3.8:27b-mlx',
            'runtime_id': 'mac-loopback-packet-followup-16k',
        }),
        'capabilities': frozenset({'packet_followup'}),
        'max_input_characters': 60_000,
    })


class Counter:
    model_digest = 'a' * 64
    count = 100
    checks = 0

    def verify_runtime(self):
        self.checks += 1

    def count_prompt_tokens(self, body):
        return self.count


def setup(monkeypatch):
    context, draft = declared_context()
    request = prepare_followup_request(context)
    selected_route = route()
    calls = []
    reply = {
        'model': selected_route.identity.model_id,
        'done': True,
        'done_reason': 'stop',
        'prompt_eval_count': 100,
        'eval_count': 100,
        'message': {'role': 'assistant', 'content': draft.model_dump_json()},
    }

    def transport(method, path, body=None):
        calls.append((method, path, body))
        if path == '/api/tags':
            return {'models': [{'name': selected_route.identity.model_id, 'digest': 'a' * 64}]}
        if path == '/api/show':
            return {}
        assert (method, path) == ('POST', '/api/chat')
        return reply

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: transport)
    counter = Counter()
    runtime = local.LocalFollowupRuntime(route=selected_route, model_digest='a' * 64, token_counter=counter)
    return runtime, request, draft, counter, calls, reply


def test_metadata_preflight_one_call_and_usage(monkeypatch):
    runtime, request, draft, counter, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    assert [c[1] for c in calls] == ['/api/tags', '/api/show']
    assert all(request.evidence_json not in (c[2] or b'') for c in calls)
    result = runtime.generate(request)
    assert result == draft
    assert runtime.usage.input_tokens == 100
    assert runtime.usage.cost_usd == 0
    assert counter.checks == 3
    assert [c[1] for c in calls].count('/api/chat') == 1
    body = json.loads(next(c[2] for c in calls if c[1] == '/api/chat'))
    assert body['options']['num_ctx'] == 16384
    assert body['truncate'] is False and body['shift'] is False and body['think'] is False
    assert [m['role'] for m in body['messages']] == ['system', 'user']
    assert json.loads(body['messages'][1]['content']) == json.loads(request.evidence_json)
    recorded = runtime.usage
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request)
    assert runtime.usage == recorded
    assert [c[1] for c in calls].count('/api/chat') == 1


@pytest.mark.parametrize('change', ['missing', 'digest', 'evidence', 'task'])
def test_missing_or_changed_preflight_no_dispatch(monkeypatch, change):
    runtime, request, _, _, calls, _ = setup(monkeypatch)
    if change != 'missing':
        runtime.preflight(request)
        calls.clear()
    if change == 'digest':
        request = replace(request, digest='f' * 64)
    elif change == 'evidence':
        request = replace(request, evidence_json=b'{}')
    elif change == 'task':
        request = prepare_followup_request(declared_context()[0])
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request)
    assert calls == []


@pytest.mark.parametrize('updates', [
    {'destination': Destination.EXTERNAL},
    {'capabilities': frozenset({'contextual_meeting_review'})},
    {'capabilities': frozenset({'packet_followup', 'contextual_meeting_review'})},
    {'available': False},
    {'estimated_cost_usd': 0.1},
    {'max_output_tokens': 1},
])
def test_other_routes_and_scopes_denied_before_http(monkeypatch, updates):
    _, request, _, counter, calls, _ = setup(monkeypatch)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime = local.LocalFollowupRuntime(route=route().model_copy(update=updates), model_digest='a' * 64, token_counter=counter)
        runtime.preflight(request)
    assert calls == []


@pytest.mark.parametrize('location', ['model', 'runtime'])
def test_other_profile_denied(monkeypatch, location):
    _, request, _, counter, calls, _ = setup(monkeypatch)
    selected = route()
    identity = selected.identity.model_copy(update={f'{location}_id': 'other'})
    runtime = local.LocalFollowupRuntime(route=selected.model_copy(update={'identity': identity}), model_digest='a' * 64, token_counter=counter)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.preflight(request)
    assert calls == []


@pytest.mark.parametrize('count', [True, -1, 0, 16_000])
def test_real_token_capacity_no_http(monkeypatch, count):
    runtime, request, _, counter, calls, _ = setup(monkeypatch)
    counter.count = count
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.preflight(request)
    assert calls == []


@pytest.mark.parametrize('changes', [
    {'model': 'other'}, {'done': False}, {'done_reason': 'length'},
    {'prompt_eval_count': True}, {'eval_count': 801}, {'prompt_eval_count': 16_380},
    {'message': {'role': 'assistant', 'content': '{}', 'tool_calls': [{'name': 'run'}]}},
    {'message': {'role': 'assistant', 'content': '{}', 'thinking': 'private'}},
    {'message': {'role': 'user', 'content': '{}'}},
    {'message': {'role': 'assistant', 'content': 'not json'}},
])
def test_bad_reply_consumes_single_attempt_and_never_usage(monkeypatch, changes):
    runtime, request, _, _, calls, reply = setup(monkeypatch)
    runtime.preflight(request)
    reply.update(changes)
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.__context__ is None
    assert runtime.usage is None
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request)
    assert [c[1] for c in calls].count('/api/chat') == 1


def test_reported_prompt_count_must_match_tokenizer(monkeypatch):
    runtime, request, _, _, _, reply = setup(monkeypatch)
    runtime.preflight(request)
    reply['prompt_eval_count'] = 101
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.code == F.PROMPT_COUNT_MISMATCH
    assert runtime.usage is None


@pytest.mark.parametrize('phase', ['before', 'after'])
def test_pin_change_denies_without_retry(monkeypatch, phase):
    runtime, request, _, _, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    calls.clear()
    original = local._deadline_transport(request, 0)
    chat_seen = False

    def changed(method, path, body=None):
        nonlocal chat_seen
        if path == '/api/chat':
            chat_seen = True
        result = original(method, path, body)
        if path == '/api/tags' and (phase == 'before' or chat_seen):
            return {'models': [{'name': runtime.route.identity.model_id, 'digest': 'b' * 64}]}
        return result

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: changed)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request)
    assert [c[1] for c in calls].count('/api/chat') == (0 if phase == 'before' else 1)
    assert runtime.usage is None


@pytest.mark.parametrize('kind', [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_interruption_sanitized_and_consumed(monkeypatch, kind):
    runtime, request, _, _, _, _ = setup(monkeypatch)
    runtime.preflight(request)
    original = local._deadline_transport(request, 0)

    def interrupted(method, path, body=None):
        if path == '/api/chat':
            raise kind('PRIVATE diagnostic')
        return original(method, path, body)

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: interrupted)
    with pytest.raises(kind) as error:
        runtime.generate(request)
    assert 'PRIVATE' not in str(error.value)
    assert error.value.__context__ is None
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request)
    assert runtime.usage is None


@pytest.mark.parametrize(('times', 'code'), [([0, 0, 61], F.RESPONSE_LATENCY), ([0, 0, 0.005, 61], F.TOTAL_LATENCY)])
def test_dispatch_and_total_latency_hold_output(monkeypatch, times, code):
    runtime, request, _, _, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    ticks = iter(times)
    monkeypatch.setattr(local.time, 'perf_counter', lambda: next(ticks))
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.code == code
    assert runtime.usage is None
    assert [c[1] for c in calls].count('/api/chat') == 1


def test_changed_token_count_after_preflight_denies_before_metadata(monkeypatch):
    runtime, request, _, counter, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    calls.clear()
    counter.count = 101
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.code == F.PREFLIGHT_BINDING
    assert calls == []


def test_remote_model_metadata_denies_no_chat(monkeypatch):
    runtime, request, _, _, calls, _ = setup(monkeypatch)
    original = local._deadline_transport(request, 0)

    def remote(method, path, body=None):
        reply = original(method, path, body)
        if path == '/api/show':
            return {'remote_host': 'https://outside.invalid'}
        return reply

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: remote)
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.preflight(request)
    assert [c[1] for c in calls] == ['/api/tags', '/api/show']


@pytest.mark.parametrize('phase', ['before', 'after'])
def test_metadata_connection_failure_reports_transport_not_pin(monkeypatch, phase):
    runtime, request, _, _, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    original = local._deadline_transport(request, 0)
    chat_seen = False

    def failed(method, path, body=None):
        nonlocal chat_seen
        if path == '/api/chat':
            chat_seen = True
        if path == '/api/tags' and (phase == 'before' or chat_seen):
            raise OSError('PRIVATE backend diagnostics')
        return original(method, path, body)

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: failed)
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.code == F.TRANSPORT
    assert [c[1] for c in calls].count('/api/chat') == (0 if phase == 'before' else 1)
    assert error.value.__context__ is None
    assert runtime.usage is None


def test_clean_system_exit_code_preserved(monkeypatch):
    runtime, request, _, _, _, _ = setup(monkeypatch)
    runtime.preflight(request)

    def interrupted(*args):
        raise SystemExit(None)

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: interrupted)
    with pytest.raises(SystemExit) as error:
        runtime.generate(request)
    assert error.value.code is None
    assert error.value.__context__ is None


@pytest.mark.parametrize('error', [GeneratorExit('PRIVATE'), BaseExceptionGroup('PRIVATE', [KeyboardInterrupt('PRIVATE')])])
def test_other_base_interruptions_not_swallowed(monkeypatch, error):
    runtime, request, _, _, _, _ = setup(monkeypatch)
    runtime.preflight(request)

    def interrupted(*args):
        raise error

    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: interrupted)
    expected = GeneratorExit if isinstance(error, GeneratorExit) else KeyboardInterrupt
    with pytest.raises(expected) as caught:
        runtime.generate(request)
    assert 'PRIVATE' not in str(caught.value)
    assert caught.value.__context__ is None
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.generate(request)


@pytest.mark.parametrize(('prompt', 'output', 'expected'), [
    (100, 800, F.OUTPUT_LIMIT),
    (15_584, 800, F.RESPONSE_LENGTH),
    (100, 799, F.RESPONSE_LENGTH),
    (100, 801, F.RESPONSE_USAGE),
])
def test_length_completion_diagnostic_is_specific(monkeypatch, prompt, output, expected):
    runtime, request, _, _, calls, reply = setup(monkeypatch)
    runtime.preflight(request)
    reply.update(done_reason='length', prompt_eval_count=prompt, eval_count=output)
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.code == expected
    assert runtime.usage is None
    assert [c[1] for c in calls].count('/api/chat') == 1


def test_failed_repreflight_clears_prior_binding(monkeypatch):
    runtime, request, _, counter, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    counter.count = 0
    with pytest.raises(local.LocalFollowupRuntimeError):
        runtime.preflight(request)
    counter.count = 100
    calls.clear()
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.generate(request)
    assert error.value.code == F.PREFLIGHT_BINDING
    assert calls == []


def test_preflight_cannot_renew_consumed_attempt(monkeypatch):
    runtime, request, _, _, calls, _ = setup(monkeypatch)
    runtime.preflight(request)
    runtime.generate(request)
    calls.clear()
    recorded = runtime.usage
    with pytest.raises(local.LocalFollowupRuntimeError) as error:
        runtime.preflight(request)
    assert error.value.code == F.PREFLIGHT_BINDING
    assert calls == []
    assert runtime.usage == recorded


def test_deadline_factory_uses_exact_operation_budget_and_clock_basis(monkeypatch):
    factory_under_test = local._deadline_transport
    _, request, _, _, _, _ = setup(monkeypatch)
    captured = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return lambda method, path, body=None: {}

    monkeypatch.setattr(local, 'FollowupLoopbackTransport', factory)
    # Call actual production factory despite setup's mock transport.
    deadline = 123.5 + request.context.task.max_latency_ms / 1000
    factory_under_test(request, 123.5)
    assert captured == {'deadline': deadline, 'monotonic': local.time.perf_counter}


def test_separate_operation_factories_and_shared_generation_transport(monkeypatch):
    runtime, request, _, _, _, _ = setup(monkeypatch)
    base = local._deadline_transport(request, 0)
    groups = []

    def factory(request, started):
        group = []
        groups.append((started, group))

        def call(method, path, body=None):
            group.append(path)
            return base(method, path, body)

        return call

    monkeypatch.setattr(local, '_deadline_transport', factory)
    runtime.preflight(request)
    runtime.generate(request)
    assert len(groups) == 2 and groups[1][0] >= groups[0][0]
    assert groups[0][1] == ['/api/tags', '/api/show']
    assert groups[1][1] == ['/api/tags', '/api/show', '/api/chat', '/api/tags', '/api/show']


@pytest.mark.parametrize('phase', ['preflight', 'chat', 'post_metadata'])
def test_total_deadline_diagnostic_survives_wrappers_without_usage(monkeypatch, phase):
    from zacai.intelligence.followup_transport import FollowupTransportError

    runtime, request, _, _, _, _ = setup(monkeypatch)
    base = local._deadline_transport(request, 0)
    sent = False

    def call(method, path, body=None):
        nonlocal sent
        if phase == 'preflight' or (phase == 'chat' and path == '/api/chat') or (phase == 'post_metadata' and sent):
            raise FollowupTransportError('invented deadline', code=F.TOTAL_LATENCY)
        result = base(method, path, body)
        if path == '/api/chat':
            sent = True
        return result

    if phase != 'preflight':
        runtime.preflight(request)
    monkeypatch.setattr(local, '_deadline_transport', lambda request, started: call)
    with pytest.raises(local.LocalFollowupRuntimeError) as exc:
        if phase == 'preflight':
            runtime.preflight(request)
        else:
            runtime.generate(request)
    assert exc.value.code == F.TOTAL_LATENCY
    assert runtime.usage is None
    assert exc.value.__context__ is None


def test_late_return_tokenizer_preflight_cannot_retain_successful_binding(monkeypatch):
    runtime, request, _, counter, _, _ = setup(monkeypatch)
    observed = [0.0]
    monkeypatch.setattr(local.time, 'perf_counter', lambda: observed[0])

    def late_tokens(body):
        observed[0] = request.context.task.max_latency_ms / 1000 + 1
        return 100

    monkeypatch.setattr(counter, 'count_prompt_tokens', late_tokens)
    with pytest.raises(local.LocalFollowupRuntimeError) as exc:
        runtime.preflight(request)
    assert exc.value.code == F.TOTAL_LATENCY
    assert runtime._prepared is None
    assert runtime.usage is None
