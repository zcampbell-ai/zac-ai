"""Invented requests and mocked loopback; no actual model/private content."""

from dataclasses import replace

import pytest

from tests.test_review_generation import (
    install_fake_http,
    route,
    synthetic_context,
)
from zacai.intelligence import local_review_benchmark as benchmark
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence.review_generation import prepare_review_request


class TokenCounter:
    model_digest = "a" * 64
    count = 100

    def verify_runtime(self):
        pass

    def count_prompt_tokens(self, body):
        return self.count


def setup(monkeypatch, **changes):
    calls = install_fake_http(monkeypatch, **changes)
    monkeypatch.setattr(local, "_http", benchmark._http)
    runtime = local.LocalReviewRuntime(
        route=route(), model_digest="a" * 64, token_counter=TokenCounter()
    )
    return runtime, prepare_review_request(synthetic_context()), calls


def test_metadata_only_preflight_then_one_generation(monkeypatch):
    runtime, request, calls = setup(monkeypatch)
    runtime.preflight(request)
    assert [c[1] for c in calls] == ["/api/tags", "/api/show"]
    assert all(request.evidence_json.encode() not in (c[2] or b"") for c in calls)
    result = runtime.generate(request)
    assert result.summary
    assert runtime.usage.output_tokens == 100
    assert [c[1] for c in calls].count("/api/chat") == 1
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert [c[1] for c in calls].count("/api/chat") == 1
    assert runtime.usage is None


@pytest.mark.parametrize("failure", ["missing", "modified", "different_task"])
def test_missing_or_changed_preflight_rejects_without_network(monkeypatch, failure):
    runtime, request, calls = setup(monkeypatch)
    if failure != "missing":
        runtime.preflight(request)
        calls.clear()
    if failure == "modified":
        request = replace(request, instruction="Invented extra instruction")
    elif failure == "different_task":
        # Same messages/prose, different canonical task/source identity.
        request = prepare_review_request(synthetic_context())
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert calls == []
    assert runtime.usage is None


@pytest.mark.parametrize("phase", ["before", "after"])
def test_pin_changes_reject_without_retry(monkeypatch, phase):
    runtime, request, calls = setup(monkeypatch)
    runtime.preflight(request)
    original = local._http
    seen_chat = False

    def changed(method, path, body=None):
        nonlocal seen_chat
        if path == "/api/chat":
            seen_chat = True
        value = original(method, path, body)
        if path == "/api/tags" and (phase == "before" or seen_chat):
            value["models"][0]["digest"] = "b" * 64
        return value

    monkeypatch.setattr(local, "_http", changed)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    count = sum(c[1] == "/api/chat" for c in calls)
    assert count == (0 if phase == "before" else 1)
    assert runtime.usage is None
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert sum(c[1] == "/api/chat" for c in calls) == count


def test_failed_new_preflight_clears_previous_binding(monkeypatch):
    runtime, request, calls = setup(monkeypatch)
    runtime.preflight(request)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.preflight(replace(request, evidence_json="modified"))
    calls.clear()
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"done": False},
        {"done_reason": "length"},
        {"model": "foreign"},
        {"eval_count": True},
        {"prompt_eval_count": 8192},
        {"eval_count": 1601},
        {"message": {"role": "assistant", "tool_calls": ["send"]}},
        {"message": {"role": "assistant", "content": '{"summary":NaN}'}},
    ],
)
def test_bad_generation_consumes_attempt(monkeypatch, changes):
    runtime, request, calls = setup(monkeypatch, reply_changes=changes)
    runtime.preflight(request)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert sum(c[1] == "/api/chat" for c in calls) == 1
    assert runtime.usage is None


def test_backend_exception_sanitized(monkeypatch):
    runtime, request, calls = setup(monkeypatch)
    runtime.preflight(request)

    def broken(*args):
        raise ValueError("invented-private-marker")

    monkeypatch.setattr(local, "_http", broken)
    with pytest.raises(local.LocalReviewRuntimeError) as error:
        runtime.generate(request)
    assert "invented-private-marker" not in str(error.value)
    assert sum(c[1] == "/api/chat" for c in calls) == 0


def test_ambiguous_model_registration_rejected(monkeypatch):
    runtime, request, calls = setup(monkeypatch)
    original = local._http

    def duplicate(method, path, body=None):
        value = original(method, path, body)
        if path == "/api/tags":
            value["models"].append({"name": "synthetic:local", "digest": "b" * 64})
        return value

    monkeypatch.setattr(local, "_http", duplicate)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.preflight(request)
    assert sum(c[1] == "/api/chat" for c in calls) == 0


@pytest.mark.parametrize("count", [True, -1, 0, 6593])
def test_invalid_or_overflowing_token_count_rejected_before_network(monkeypatch, count):
    calls = install_fake_http(monkeypatch)
    monkeypatch.setattr(local, "_http", benchmark._http)
    counter = TokenCounter()
    counter.count = count
    runtime = local.LocalReviewRuntime(route=route(), model_digest="a" * 64, token_counter=counter)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.preflight(prepare_review_request(synthetic_context()))
    assert calls == []


def test_prompt_usage_mismatch_discards_possible_clipping(monkeypatch):
    runtime, request, calls = setup(monkeypatch, reply_changes={"prompt_eval_count": 99})
    runtime.preflight(request)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert sum(c[1] == "/api/chat" for c in calls) == 1
    assert runtime.usage is None


def test_tokenizer_pin_mismatch_before_network(monkeypatch):
    calls = install_fake_http(monkeypatch)
    monkeypatch.setattr(local, "_http", benchmark._http)
    counter = TokenCounter()
    counter.model_digest = "b" * 64
    runtime = local.LocalReviewRuntime(route=route(), model_digest="a" * 64, token_counter=counter)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.preflight(prepare_review_request(synthetic_context()))
    assert calls == []


def test_total_adapter_latency_includes_pin_rechecks(monkeypatch):
    runtime, request, calls = setup(monkeypatch)
    runtime.preflight(request)
    ticks = iter([0.0, 0.0, 1.0, 121.0])
    monkeypatch.setattr(local.time, "perf_counter", lambda: next(ticks))
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert sum(c[1] == "/api/chat" for c in calls) == 1
    assert runtime.usage is None


@pytest.mark.parametrize("failure", ["compression", "oversize", "malformed"])
def test_transport_limits_and_connection_close(monkeypatch, failure):
    observed = []

    class Response:
        status = 200

        def getheader(self, *args):
            return "gzip" if failure == "compression" else "identity"

        def read(self, limit):
            assert limit == 2_000_001
            return b"x" * limit if failure == "oversize" else b'{"x":NaN}'

    class Connection:
        def __init__(self, host, port, timeout):
            observed.append((host, port, timeout))

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            observed.append("closed")

    monkeypatch.setattr(local.http.client, "HTTPConnection", Connection)
    with pytest.raises(ValueError):
        local._http("GET", "/api/tags")
    assert observed == [("127.0.0.1", 11434, 120), "closed"]


def test_external_route_constructor_rejected():
    from zacai.policy import Destination

    external = route().model_copy(update={"destination": Destination.EXTERNAL})
    with pytest.raises(local.LocalReviewRuntimeError):
        local.LocalReviewRuntime(
            route=external, model_digest="a" * 64, token_counter=TokenCounter()
        )


def test_route_output_capacity_rejected_before_network(monkeypatch):
    calls = install_fake_http(monkeypatch)
    monkeypatch.setattr(local, "_http", benchmark._http)
    smaller = route().model_copy(update={"max_output_tokens": 1599})
    runtime = local.LocalReviewRuntime(
        route=smaller, model_digest="a" * 64, token_counter=TokenCounter()
    )
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.preflight(prepare_review_request(synthetic_context()))
    assert calls == []


@pytest.mark.parametrize("phase", ["before", "after"])
def test_tokenizer_runtime_incompatibility_blocks_release(monkeypatch, phase):
    runtime, request, calls = setup(monkeypatch)
    runtime.preflight(request)
    checks = 0

    def verify():
        nonlocal checks
        checks += 1
        if checks == (1 if phase == "before" else 2):
            raise ValueError("invented backend private marker")

    monkeypatch.setattr(runtime._token_counter, "verify_runtime", verify)
    with pytest.raises(local.LocalReviewRuntimeError) as failure:
        runtime.generate(request)
    assert "private marker" not in str(failure.value)
    assert sum(c[1] == "/api/chat" for c in calls) == (0 if phase == "before" else 1)
    assert runtime.usage is None
