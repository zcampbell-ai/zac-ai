"""Actual synthetic tokenizer files, metadata transport mocked, no inference/SQL."""

from dataclasses import replace

import pytest

from tests.test_fragment_review_prompt_counter import counter
from tests.test_ollama_token_counter import installed as original_installed
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_review_runtime as m


@pytest.fixture
def readiness(tmp_path, monkeypatch):
    installed = original_installed.__wrapped__(tmp_path)
    c = counter(installed)
    profile = m.FragmentReviewRuntimeProfile(
        m.wire.RUNTIME,
        m.fragment_review_runtime_digest(),
        c.model_digest,
        c.tokenizer_digest,
        c.template_digest,
        c.renderer_digest,
    )
    now = [100.0]
    monkeypatch.setattr(m.time, "monotonic", lambda: now[0])
    calls = []
    callback = [lambda: None]

    def metadata(method, path, body, remaining):
        calls.append((method, path, body, remaining))
        assert path != "/api/chat"
        if path == "/api/version":
            return canonical_bytes({"version": "0.35.1"})
        if path == "/api/tags":
            return canonical_bytes({"models": [{"name": m.wire.MODEL, "digest": c.model_digest}]})
        assert path == "/api/show"
        callback[0]()
        return canonical_bytes({"details": {"family": "qwen"}})

    monkeypatch.setattr(m, "_loopback", metadata)

    def forbidden(*args, **kwargs):
        raise AssertionError("No fake whole-answer count/runtime callback")

    monkeypatch.setattr(c, "count_prompt_tokens", forbidden)
    monkeypatch.setattr(c, "verify_runtime", forbidden)
    kwargs = {
        "profile": profile,
        "token_counter": c,
        "deadline_monotonic": 160.0,
        "max_latency_ms": 60000,
    }
    return kwargs, installed, c, calls, now, callback


def test_real_synthetic_file_readiness_without_packet_or_count(readiness):
    kw, _, c, calls, _, _ = readiness
    result = m.inspect_fragment_review_readiness(**kw)
    assert result.profile == kw["profile"]
    assert result.observed_monotonic == 100 and result.deadline_monotonic == 160
    assert [call[:2] for call in calls] == [
        ("GET", "/api/version"),
        ("GET", "/api/tags"),
        ("POST", "/api/show"),
    ]
    assert (
        result.processing_authorized
        is result.reviewer_authenticated
        is result.full_answer_fit_measured
        is False
    )
    assert len(result.model_metadata_digest) == 64
    assert c.model_digest == kw["profile"].model_digest


@pytest.mark.parametrize("which", ["manifest", "tokenizer", "config"])
def test_actual_file_drift_before_metadata_zero_calls(readiness, which):
    kw, installed, c, calls, _, _ = readiness
    path = installed[1] if which == "manifest" else c._files[1 if which == "tokenizer" else 0][0]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(m.FragmentReviewRuntimeError):
        m.inspect_fragment_review_readiness(**kw)
    assert calls == []


@pytest.mark.parametrize("which", ["file", "pin"])
def test_last_metadata_callback_drift_causally_holds(readiness, which):
    kw, _, c, calls, _, callback = readiness
    milestones = []

    def drift():
        milestones.append("show completed")
        if which == "file":
            p = c._files[1][0]
            p.write_bytes(p.read_bytes() + b" ")
        else:
            c._digest = "f" * 64

    callback[0] = drift
    with pytest.raises(m.FragmentReviewRuntimeError):
        m.inspect_fragment_review_readiness(**kw)
    assert milestones == ["show completed"] and len(calls) == 3


@pytest.mark.parametrize(
    "field",
    [
        "implementation_digest",
        "model_digest",
        "tokenizer_digest",
        "template_digest",
        "renderer_digest",
        "reported_server_version",
    ],
)
def test_every_declared_profile_pin_mismatch_zero_metadata(readiness, field):
    kw, _, _, calls, _, _ = readiness
    kw = kw | {
        "profile": replace(
            kw["profile"], **{field: "0.35.2" if field == "reported_server_version" else "f" * 64}
        )
    }
    with pytest.raises(m.FragmentReviewRuntimeError):
        m.inspect_fragment_review_readiness(**kw)
    assert calls == []


@pytest.mark.parametrize(
    "deadline,budget",
    [(100, 60000), (161, 60000), (float("inf"), 60000), (160, 0), (160, True), (160, 60001)],
)
def test_original_window_cannot_be_widened(readiness, deadline, budget):
    kw, _, _, calls, _, _ = readiness
    with pytest.raises(m.FragmentReviewRuntimeError):
        m.inspect_fragment_review_readiness(
            **(kw | {"deadline_monotonic": deadline, "max_latency_ms": budget})
        )
    assert calls == []


def test_callback_consumes_original_expiry_no_renewal(readiness):
    kw, _, _, calls, now, callback = readiness
    milestones = []

    def expire():
        milestones.append("expired during show")
        now[0] = 160

    callback[0] = expire
    with pytest.raises(m.FragmentReviewRuntimeError):
        m.inspect_fragment_review_readiness(**kw)
    assert milestones == ["expired during show"] and len(calls) == 3


def test_exact_concrete_counter_required_not_none_or_fake(readiness):
    kw, _, _, calls, _, _ = readiness
    with pytest.raises(m.FragmentReviewRuntimeError):
        m.inspect_fragment_review_readiness(**(kw | {"token_counter": None}))
    assert calls == []


def test_hostile_metadata_error_fixed_without_private_chain(readiness):
    kw, _, _, calls, _, callback = readiness

    def hostile():
        raise RuntimeError("invented private backend data")

    callback[0] = hostile
    with pytest.raises(m.FragmentReviewRuntimeError) as caught:
        m.inspect_fragment_review_readiness(**kw)
    assert str(caught.value) == "fragment review readiness unavailable"
    assert caught.value.__cause__ is caught.value.__context__ is None and len(calls) == 3
