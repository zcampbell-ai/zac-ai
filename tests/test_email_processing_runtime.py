"""Invented offline wire/runtime mechanics only; mocked host is NOT authority evidence."""

import json
import time
from uuid import uuid4

import pytest

from tests.test_email_generation import req as source_req
from tests.test_ollama_token_counter import installed as source_installed
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.email_local_wire import prepare_email_local_payload
from zacai.intelligence.email_processing_runtime import (
    EmailLoopbackTransport,
    EmailProcessingRuntimeError,
    FixedLocalEmailRuntimeV1,
)
from zacai.intelligence.followup_transport import FollowupLoopbackTransport
from zacai.intelligence.ollama_token_counter import OllamaQwenEmailTokenCounter
from zacai.interfaces.email_input import EmailInputRecoveryReceiptV1
from zacai.interfaces.email_processing import (
    _ATTEMPT_KEY,
    CanonicalBrainstormEmailProcessing,
    _EmailAttempt,
)
from zacai.interfaces.email_processing_contracts import (
    ACTION,
    EmailProcessingClaimV1,
    EmailProcessingConsentV1,
    EmailProcessingManifestV1,
    request_digest,
)
from zacai.interfaces.host_clock import HostObservedClock


@pytest.fixture
def case(tmp_path):
    from datetime import timedelta

    installed = source_installed.__wrapped__(tmp_path)
    req = source_req.__wrapped__()
    route = ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "qwen3.8:27b-mlx",
            "runtime_id": "mac-loopback-email-8k",
        },
        destination="LOCAL",
        capabilities=frozenset({"email_draft"}),
        available=True,
        max_input_characters=64000,
        max_output_tokens=2048,
        estimated_latency_ms=0.0,
        estimated_cost_usd=0.0,
    )
    counter = OllamaQwenEmailTokenCounter(models_root=installed[0], model_digest=installed[2])
    runtime = FixedLocalEmailRuntimeV1(route=route, model_digest=installed[2], counter=counter)
    body, count, pins = runtime.prepare(req)
    ref = req.specification.task().context[0].reference
    at = req.specification.task().event.observed_at
    receipt = EmailInputRecoveryReceiptV1(
        source_id=ref.source_id,
        instruction_digest=ref.content_hash,
        captured_at=at,
        verified_at=at,
        artifact_backup_run_id=uuid4(),
        artifact_ciphertext_hash="a" * 64,
        state_ciphertext_hash="a" * 64,
        state_plaintext_hash="a" * 64,
        journal_ciphertext_hash="a" * 64,
        journal_plaintext_hash="a" * 64,
    )
    manifest = EmailProcessingManifestV1(
        action_id=uuid4(),
        builder_id=uuid4(),
        input_reference=ref,
        input_receipt=receipt,
        specification=req.specification,
        source_preimages_json="{}",
        route=route,
        model_digest=installed[2],
        tokenizer_digest=pins.tokenizer_digest,
        implementation_digest=pins.implementation_digest,
        request_digest=request_digest(req.specification),
        body_digest=content_hash_of(body),
        schema_digest=content_hash_of(req.schema_json.encode()),
        full_prompt_tokens=count,
    )
    consent = EmailProcessingConsentV1(
        manifest=manifest,
        action_text=ACTION,
        issuer="invented",
        subject="invented",
        session_binding="a" * 64,
        original_session_issued_at=at - timedelta(minutes=1),
        original_session_expires_at=at + timedelta(hours=1),
        approved_at=at,
        expires_at=at + timedelta(minutes=5),
    )
    claim = EmailProcessingClaimV1(
        consent_reference=ref, manifest_digest=manifest.digest(), attempt_id=uuid4(), claimed_at=at
    )
    # Exact host type with no DB fields; class gate methods are mocked solely to
    # isolate runtime call ordering. SQL tests use the complete concrete composition.
    host = object.__new__(CanonicalBrainstormEmailProcessing)
    host._runtime = runtime
    host._clock = HostObservedClock(lambda: at)
    host._clock()
    attempt = _EmailAttempt(
        consent, ref, None, claim, ref, None, time.perf_counter(), "{}", _ATTEMPT_KEY
    )
    host._attempt = attempt
    return host, runtime, attempt, req, body, count, installed


def probes(monkeypatch, case, callback=None):
    _host, runtime, _attempt, _req, body, count, _installed = case
    calls = []
    monkeypatch.setattr(
        CanonicalBrainstormEmailProcessing, "_gate", lambda self, a: calls.append("GATE")
    )
    monkeypatch.setattr(
        CanonicalBrainstormEmailProcessing, "_final_rows", lambda self, a: calls.append("ROWS")
    )

    def transport(self, method, path, payload=None):
        self._validate_request(method, path, payload)
        calls.append(path)
        if callback:
            callback(path)
        if path == "/api/version":
            return {"version": "0.35.1"}
        if path == "/api/tags":
            return {
                "models": [
                    {"name": runtime.route.identity.model_id, "digest": runtime.model_digest}
                ]
            }
        if path == "/api/show":
            return {}
        assert path == "/api/chat" and payload == body
        assert count == runtime._counter.count_prompt_tokens(payload)
        return {"invented_transport_response": "not represented as a candidate"}

    monkeypatch.setattr(EmailLoopbackTransport, "__call__", transport)
    return calls


def test_actual_email_transport_exact_admitted_body_count_pins_and_gate_order(case, monkeypatch):
    calls = probes(monkeypatch, case)
    host, runtime, attempt, _, _, _, _ = case
    assert (
        runtime._invoke(host, attempt)
        == b'{"invented_transport_response":"not represented as a candidate"}'
    )
    assert calls == [
        "/api/version",
        "/api/tags",
        "/api/show",
        "GATE",
        "ROWS",
        "/api/chat",
        "/api/version",
        "/api/tags",
        "/api/show",
        "GATE",
    ]
    with pytest.raises(EmailProcessingRuntimeError) as error:
        runtime._invoke(host, attempt)
    assert error.value.__context__ is None
    assert calls.count("/api/chat") == 1


@pytest.mark.parametrize("change", ["count", "body", "model", "tokenizer"])
def test_metadata_callback_change_prevents_chat(case, monkeypatch, change):
    host, runtime, attempt, _req, _, _, installed = case

    def mutation(path):
        if path != "/api/show":
            return
        if change == "count":
            object.__setattr__(
                attempt.consent.manifest,
                "full_prompt_tokens",
                attempt.consent.manifest.full_prompt_tokens + 1,
            )
        elif change == "body":
            object.__setattr__(
                attempt.consent.manifest.specification, "task_json", "PRIVATE_MARKER"
            )
        elif change == "model":
            runtime.model_digest = "f" * 64
        else:
            installed[1].write_bytes(b"PRIVATE_MARKER")

    calls = probes(monkeypatch, case, mutation)
    with pytest.raises(
        EmailProcessingRuntimeError, match="^email generation held; attempt consumed$"
    ) as error:
        runtime._invoke(host, attempt)
    assert error.value.__context__ is None
    assert "/api/chat" not in calls
    assert "PRIVATE_MARKER" not in str(error.value)


@pytest.mark.parametrize("flag", ["think", "stream", "truncate", "shift"])
def test_closed_email_transport_retains_legacy_protocol_guards(case, flag):
    _, _, _, _, body, _, _ = case
    email = EmailLoopbackTransport(deadline=time.perf_counter() + 1)
    followup = FollowupLoopbackTransport(deadline=time.perf_counter() + 1)
    email._validate_request("POST", "/api/chat", body)
    with pytest.raises(ValueError):
        followup._validate_request("POST", "/api/chat", body)
    data = json.loads(body)
    data[flag] = True
    with pytest.raises(ValueError):
        email._validate_request("POST", "/api/chat", json.dumps(data).encode())


def test_transport_schema_and_model_are_email_specific(case):
    _, _, _, req, body, _, _ = case
    transport = EmailLoopbackTransport(deadline=time.perf_counter() + 1)
    for key, bad in (("format", {}), ("model", "wrong:local")):
        data = json.loads(body)
        data[key] = bad
        with pytest.raises(ValueError):
            transport._validate_request("POST", "/api/chat", json.dumps(data).encode())
    assert prepare_email_local_payload(req, case[1].route, case[1].model_digest) == body


def test_schema_boolean_integer_substitution_rejected(case):
    body = case[4]
    data = json.loads(body)
    assert data["format"]["additionalProperties"] is False
    original = json.loads(body)["format"]
    data["format"]["additionalProperties"] = 0
    assert data["format"] == original  # Python equality is the predecessor's causal false positive.
    with pytest.raises(ValueError):
        EmailLoopbackTransport(deadline=time.perf_counter() + 1)._validate_request(
            "POST", "/api/chat", json.dumps(data).encode()
        )


@pytest.mark.parametrize("kind", ["custom", "cancelled", "system_exit"])
def test_private_interruption_sanitized_and_attempt_remains_consumed(case, monkeypatch, kind):
    import asyncio

    class PrivateStop(BaseException):
        def __init__(self, private):
            super().__init__(private)

    failure = {
        "custom": PrivateStop("PRIVATE_MARKER"),
        "cancelled": asyncio.CancelledError("PRIVATE_MARKER"),
        "system_exit": SystemExit("PRIVATE_MARKER"),
    }[kind]

    def stop(path):
        if path == "/api/chat":
            raise failure

    calls = probes(monkeypatch, case, stop)
    host, runtime, attempt = case[:3]
    expected = {
        "custom": KeyboardInterrupt,
        "cancelled": asyncio.CancelledError,
        "system_exit": SystemExit,
    }[kind]
    with pytest.raises(expected) as error:
        runtime._invoke(host, attempt)
    assert "PRIVATE_MARKER" not in str(error.value)
    assert error.value.__context__ is None
    with pytest.raises(EmailProcessingRuntimeError):
        runtime._invoke(host, attempt)
    assert calls.count("/api/chat") == 1


def test_included_shared_implementation_pin_change_after_admission_holds_chat(case, monkeypatch):
    from pathlib import Path

    from zacai.intelligence import followup_prompt_counter

    included = Path(followup_prompt_counter.__file__)
    read = Path.read_bytes
    changed = [False]

    def bytes_after_change(path):
        raw = read(path)
        return (
            raw + b"\n# invented changed implementation\n"
            if path == included and changed[0]
            else raw
        )

    monkeypatch.setattr(Path, "read_bytes", bytes_after_change)

    def change(path):
        if path == "/api/show":
            changed[0] = True

    calls = probes(monkeypatch, case, change)
    host, runtime, attempt = case[:3]
    with pytest.raises(EmailProcessingRuntimeError):
        runtime._invoke(host, attempt)
    assert changed[0] and "/api/chat" not in calls


def test_arbitrary_transport_subclass_is_not_actual_email_transport(case, monkeypatch):
    class Permissive(EmailLoopbackTransport):
        def _validate_request(self, *args):
            return None

    calls = probes(monkeypatch, case)
    host, runtime, attempt = case[:3]
    monkeypatch.setattr(runtime, "_transport", lambda deadline: Permissive(deadline=deadline))
    with pytest.raises(EmailProcessingRuntimeError):
        runtime._invoke(host, attempt)
    assert calls == []


def test_fresh_permission_observation_holds_even_when_old_watermark_and_latency_are_valid(case):
    from datetime import timedelta

    host, _, attempt = case[:3]
    old = attempt.consent.approved_at
    assert host._clock._last == old
    host._clock._read = lambda: attempt.consent.expires_at + timedelta(microseconds=1)
    with pytest.raises(ValueError, match="^original email attempt deadline exhausted$"):
        host._deadline(attempt)
    assert host._clock._last > attempt.consent.expires_at


def test_permission_socket_cap_pairs_wall_and_monotonic_without_renewal(case, monkeypatch):
    from datetime import timedelta

    from zacai.interfaces import email_processing

    host, _, attempt = case[:3]
    now = attempt.consent.expires_at - timedelta(milliseconds=200)
    host._clock._read = lambda: now
    object.__setattr__(attempt, "started", 10.0)
    samples = iter((10.1, 10.15))
    monkeypatch.setattr(email_processing.time, "perf_counter", lambda: next(samples))
    # Original operation deadline is 11.0; permission ends at paired10.1+0.2.
    cap = host._deadline(attempt)
    assert cap == pytest.approx(10.3)
    transport = EmailLoopbackTransport(deadline=11.0, monotonic=lambda: 10.2)
    transport._restrict_deadline(cap)
    assert transport._deadline == cap
    transport._restrict_deadline(99.0)
    assert transport._deadline == cap


def test_near_permission_expiry_caps_actual_connection_and_read_waits(case, monkeypatch):
    from tests.test_followup_transport import fixture as source_socket_fixture
    from zacai.intelligence.followup_transport import FollowupTransportError
    from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F

    s = source_socket_fixture.__wrapped__(monkeypatch)
    s.now = 10.0
    transport = EmailLoopbackTransport(deadline=11.0, monotonic=lambda: s.now)
    transport._restrict_deadline(10.2)
    s.after_read = lambda: setattr(s, "now", 10.201)
    with pytest.raises(FollowupTransportError) as error:
        transport("POST", "/api/chat", case[4])
    assert error.value.code == F.TOTAL_LATENCY
    assert s.constructed[0][2] == pytest.approx(0.2)
    assert all(t <= 0.2 + 1e-9 for t in s.sockets[0].timeouts)
    assert len(s.requests) == 1 and s.closed == 1
