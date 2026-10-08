"""Invented complete packet; all metadata, counter and HTTP are explicitly mocked.

PASS judgments are structural fixture data, never review quality/authentication.
"""

from dataclasses import replace

import pytest

from tests.test_fragment_review_preparation import case as original_case
from tests.test_fragment_review_wire import reply
from tests.test_fragment_review_wire import wire_case as original_wire_case
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_review_runtime as m
from zacai.intelligence import fragment_review_wire as wire


@pytest.fixture
def selected():
    return original_wire_case.__wrapped__(original_case.__wrapped__())


class Counter:
    model_digest = "a" * 64
    tokenizer_digest = "b" * 64
    template_digest = "c" * 64
    renderer_digest = "d" * 64

    def __init__(self):
        self.count = 100
        self.callback = lambda: None
        self.verify_callback = lambda: None
        self.calls = []

    def count_prompt_tokens(self, raw):
        self.calls.append("count")
        self.callback()
        return self.count

    def verify_runtime(self):
        self.calls.append("runtime")
        self.verify_callback()


@pytest.fixture
def setup(selected):
    (raw, _, args), p = selected
    c = Counter()
    c.model_digest = p.model_digest
    profile = m.FragmentReviewRuntimeProfile(
        wire.RUNTIME,
        m.fragment_review_runtime_digest(),
        c.model_digest,
        c.tokenizer_digest,
        c.template_digest,
        c.renderer_digest,
    )
    clock = [0.0]
    calls = []
    post_callback = [lambda: None]
    metadata_callback = [lambda: None]
    response = [reply()]

    def transport(method, path, body, remaining):
        calls.append((method, path, body, remaining))
        if path == "/api/version":
            return canonical_bytes({"version": "0.35.1"})
        if path == "/api/tags":
            return canonical_bytes({"models": [{"name": wire.MODEL, "digest": c.model_digest}]})
        if path == "/api/show":
            metadata_callback[0]()
            return canonical_bytes({"details": {"family": "qwen"}})
        assert path == "/api/chat"
        post_callback[0]()
        return canonical_bytes(response[0])

    engine = m._LocalFragmentReviewRuntime(
        profile=profile, token_counter=c, _transport=transport, _clock=lambda: clock[0]
    )
    kwargs = {
        "packet_raw": raw,
        "rubric_utf8": args["rubric_utf8"],
        "template_utf8": args["template_utf8"],
    }
    return engine, p, kwargs, c, clock, calls, post_callback, metadata_callback, response


def preflight(s):
    engine, p, kwargs, *_ = s
    return engine.preflight(p, **kwargs, deadline_monotonic=p.max_latency_ms / 1000)


def posts(s):
    return [c for c in s[5] if c[1] == "/api/chat"]


def test_internal_positive_exact_wire_one_post_and_no_authority(setup):
    descriptor = preflight(setup)
    e, p, kw, c, _, calls, *_ = setup
    assert not posts(setup)
    assert not hasattr(e, "generate")
    result = e._attempt_mechanical(p, **kw)
    assert len(posts(setup)) == 1
    assert posts(setup)[0][2] == wire.serialize_fragment_review_wire(p, **kw)
    assert result.descriptor == descriptor
    assert result.usage.input_tokens == 100 and result.usage.output_tokens == 12
    assert result.processing_authorized is False and result.reviewer_authenticated is False
    assert [call[1] for call in calls] == [
        "/api/version",
        "/api/tags",
        "/api/show",
        "/api/version",
        "/api/tags",
        "/api/show",
        "/api/chat",
        "/api/version",
        "/api/tags",
        "/api/show",
    ]
    assert c.calls == ["count", "runtime", "count", "runtime", "runtime", "count"]


def test_successful_usage_survives_denied_replay(setup):
    preflight(setup)
    e, p, kw, *_ = setup
    result = e._attempt_mechanical(p, **kw)
    with pytest.raises(m.FragmentReviewRuntimeError):
        e._attempt_mechanical(p, **kw)
    assert e.usage == result.usage and len(posts(setup)) == 1


def test_missing_preflight_burns_without_post(setup):
    e, p, kw, *_ = setup
    with pytest.raises(m.FragmentReviewRuntimeError):
        e._attempt_mechanical(p, **kw)
    with pytest.raises(m.FragmentReviewRuntimeError):
        preflight(setup)
    assert not posts(setup) and e.did_transport_attempt is False


@pytest.mark.parametrize("count", [0, -1, True, 1.5, 16384 - 128 + 1])
def test_invalid_or_overbudget_count_before_post(setup, count):
    preflight(setup)
    setup[3].count = count
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert not posts(setup)


def test_exact_context_boundary_keeps_original_output_reservation(setup):
    setup[3].count = 16384 - setup[1].max_output_tokens
    setup[8][0]["prompt_eval_count"] = setup[3].count
    preflight(setup)
    result = setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert result.descriptor.requested_output_tokens == 128
    assert result.usage.input_tokens + 128 == 16384


@pytest.mark.parametrize(
    "field", ["model_digest", "tokenizer_digest", "template_digest", "renderer_digest"]
)
def test_each_counter_pin_change_holds_before_post(setup, field):
    preflight(setup)
    setattr(setup[3], field, "f" * 64)
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert not posts(setup)


@pytest.mark.parametrize("callback", ["count", "runtime", "metadata"])
def test_callback_body_mutation_holds_before_post_with_milestone(setup, callback):
    preflight(setup)
    milestones = []

    def mutation():
        milestones.append(callback)
        object.__setattr__(setup[1], "body", b"changed")

    if callback == "count":
        setup[3].callback = mutation
    elif callback == "runtime":
        setup[3].verify_callback = mutation
    else:
        setup[7][0] = mutation
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert milestones and not posts(setup)


def test_changed_model_metadata_fingerprint_before_post(setup):
    preflight(setup)
    original = setup[0]._transport

    def altered(method, path, body, remaining):
        result = original(method, path, body, remaining)
        return canonical_bytes({"details": {"family": "other"}}) if path == "/api/show" else result

    setup[0]._transport = altered
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert not posts(setup)


def test_original_deadline_not_renewed_includes_callbacks(setup):
    descriptor = preflight(setup)
    setup[3].verify_callback = lambda: setup[4].__setitem__(0, descriptor.deadline_monotonic + 0.1)
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert not posts(setup)


@pytest.mark.parametrize("deadline", [0.0, float("inf"), True, 1000000.0])
def test_no_widened_or_nonfinite_deadline(setup, deadline):
    e, p, kw, *_ = setup
    with pytest.raises(m.FragmentReviewRuntimeError):
        e.preflight(p, **kw, deadline_monotonic=deadline)
    assert not setup[5]


@pytest.mark.parametrize(
    "fault", ["zero", "mismatch", "tool", "thinking", "model", "unknown", "late"]
)
def test_after_post_parser_usage_and_time_faults_burn(setup, fault):
    preflight(setup)
    r = setup[8][0]
    if fault == "zero":
        r["eval_count"] = 0
    elif fault == "mismatch":
        r["prompt_eval_count"] = 101
    elif fault == "tool":
        r["message"]["tool_calls"] = []
    elif fault == "thinking":
        r["message"]["thinking"] = "not allowed"
    elif fault == "model":
        r["model"] = "other"
    elif fault == "unknown":
        r["reviewer_authenticated"] = True
    else:
        setup[6][0] = lambda: setup[4].__setitem__(0, setup[1].max_latency_ms / 1000 + 1)
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert len(posts(setup)) == 1 and setup[0].did_transport_attempt is True
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert len(posts(setup)) == 1 and setup[0].usage is None


def test_transport_exception_cause_free_and_one_attempt(setup):
    preflight(setup)

    def hostile():
        raise RuntimeError("invented confidential error")

    setup[6][0] = hostile
    with pytest.raises(m.FragmentReviewRuntimeError) as exc:
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert (
        str(exc.value) == "fragment review operation unavailable" and exc.value.__context__ is None
    )
    assert exc.value.__cause__ is None and len(posts(setup)) == 1


def test_reentrant_counter_busy_does_not_deadlock_or_consume_outer(setup):
    preflight(setup)
    outcomes = []

    def recurse():
        try:
            setup[0]._attempt_mechanical(setup[1], **setup[2])
        except m.FragmentReviewRuntimeError:
            outcomes.append("busy")

    setup[3].callback = recurse
    result = setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert (
        outcomes == ["busy", "busy"] and result.usage.input_tokens == 100 and len(posts(setup)) == 1
    )


def test_release_callback_mutation_withholds_after_exactly_one_post(setup):
    preflight(setup)
    mutations = []

    def change():
        mutations.append(True)
        object.__setattr__(setup[1], "body", b"changed")

    setup[6][0] = change
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert mutations == [True] and len(posts(setup)) == 1


def test_bad_constructor_has_fixed_cause_free_error(setup):
    p = replace(setup[0].profile, tokenizer_digest="bad")
    with pytest.raises(m.FragmentReviewRuntimeError) as exc:
        m._LocalFragmentReviewRuntime(profile=p, token_counter=setup[3])
    assert (
        str(exc.value) == "fragment review configuration unavailable"
        and exc.value.__context__ is None
    )


def test_loopback_fixed_endpoint_timeout_response_bound_and_close(monkeypatch):
    calls = []

    class Response:
        status = 200

        def getheader(self, *args):
            return "identity"

        def read(self, n):
            calls.append(("read", n))
            return b"{}"

    class Connection:
        def __init__(self, host, port, timeout):
            calls.append(("connection", host, port, timeout))

        def request(self, *args):
            calls.append(("request", *args))

        def getresponse(self):
            return Response()

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(m.http.client, "HTTPConnection", Connection)
    assert m._loopback("POST", "/api/chat", b"invented", 1.25) == b"{}"
    assert calls[0] == ("connection", "127.0.0.1", 11434, 1.25)
    assert ("read", wire.MAX_REPLY_BYTES + 1) in calls and calls[-1] == ("close",)
    with pytest.raises(ValueError):
        m._loopback("POST", "/api/pull", b"", 1)
    assert len([c for c in calls if c[0] == "connection"]) == 1


def test_successful_preflight_cannot_extend_original_window(setup):
    first = preflight(setup)
    setup[4][0] = 1.0
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0].preflight(setup[1], **setup[2], deadline_monotonic=first.deadline_monotonic + 1)
    assert len(setup[5]) == 3 and not posts(setup)


def test_failed_preflight_cannot_renew_or_repair(setup):
    setup[3].count = 0
    with pytest.raises(m.FragmentReviewRuntimeError):
        preflight(setup)
    setup[3].count = 100
    setup[4][0] = 1.0
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0].preflight(
            setup[1], **setup[2], deadline_monotonic=setup[1].max_latency_ms / 1000 + 1
        )
    assert not posts(setup)


def test_terminal_clock_at_deadline_holds_after_post(setup):
    bound = preflight(setup)
    milestones = []
    original = setup[0]._describe

    def observe(*args, **kwargs):
        result = original(*args, **kwargs)
        if posts(setup):
            milestones.append("terminal binding reconstructed")
            setup[4][0] = bound.deadline_monotonic
        return result

    setup[0]._describe = observe
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert milestones == ["terminal binding reconstructed"] and len(posts(setup)) == 1
    assert setup[0].usage is None


def test_single_terminal_clock_observation_no_late_second_sample(setup):
    bound = preflight(setup)
    original = setup[0]._describe
    observations = []

    def terminal_clock():
        observations.append(True)
        return (
            bound.deadline_monotonic - 0.1
            if len(observations) == 1
            else bound.deadline_monotonic + 1
        )

    def observe(*args, **kwargs):
        result = original(*args, **kwargs)
        if posts(setup):
            setup[0]._clock = terminal_clock
        return result

    setup[0]._describe = observe
    result = setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert observations == [True]
    assert result.usage.latency_ms == (bound.deadline_monotonic - 0.1) * 1000


def test_usage_includes_preflight_and_wait_without_deadline_renewal(setup):
    setup[7][0] = lambda: setup[4].__setitem__(0, 0.1)
    preflight(setup)
    setup[4][0] = 0.2
    setup[7][0] = lambda: None
    result = setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert result.usage.latency_ms == 200.0


def test_postflight_actual_counter_drift_holds_after_post(setup):
    preflight(setup)
    milestones = []

    def change():
        milestones.append("POST returned")
        setup[3].count = 101

    setup[6][0] = change
    with pytest.raises(m.FragmentReviewRuntimeError):
        setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert milestones == ["POST returned"] and len(posts(setup)) == 1


def test_common_complete_wire_positive_preserves_structural_judgments(setup):
    preflight(setup)
    result = setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert len(posts(setup)) == 1 and len(result.judgments.assessments) == 10
    assert result.processing_authorized is False and result.reviewer_authenticated is False


@pytest.mark.parametrize("phase", ["preflight", "before_post", "after_post"])
def test_reported_server_version_change_holds_in_exact_phase(setup, phase):
    if phase != "preflight":
        preflight(setup)
    original = setup[0]._transport
    milestones = []

    def version_drift(method, path, body, remaining):
        raw = original(method, path, body, remaining)
        if path == "/api/version" and (phase != "after_post" or posts(setup)):
            milestones.append("changed reported version")
            return canonical_bytes({"version": "0.35.2"})
        return raw

    setup[0]._transport = version_drift
    with pytest.raises(m.FragmentReviewRuntimeError):
        if phase == "preflight":
            preflight(setup)
        else:
            setup[0]._attempt_mechanical(setup[1], **setup[2])
    assert milestones == ["changed reported version"]
    assert len(posts(setup)) == (1 if phase == "after_post" else 0)
