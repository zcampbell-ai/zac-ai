"""Actual runtime/canonical gate classes; SQL, owner, recovery and HTTP simulated."""
# ruff: noqa: F401, F811, PLC0414
import json
import time
from datetime import timedelta

import pytest

from tests.test_fragment_publication_generation import (
    authority,
    baseline_authority,
    case,
    declaration_case,
    installed,
    issuer,
    publication_issuer,
)
from tests.test_fragment_publication_generation import consent_case as consent_case
from tests.test_fragment_publication_generation import packet_case as packet_base
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.intelligence import contextual_generation as catalog
from zacai.intelligence import fragment_publication_generation as parent_module
from zacai.intelligence import local_contextual_runtime as runtime_module


@pytest.fixture
def packet_case(packet_base, consent_case, monkeypatch):
    f = packet_base
    _, original_consent, _ = consent_case
    # Unchanged original full180s+ declaration window, late preparation clock.
    # This observation occurs BEFORE exact parent/runtime binding, not reminted.
    monkeypatch.setattr(f.p._clock, "_read", lambda: original_consent.expires_at - timedelta(seconds=30))
    return f


def wire(f, monkeypatch):
    r, q = f.runtime, f.q
    events = []
    monkeypatch.setattr(r._token_counter, "verify_runtime", lambda: None)
    monkeypatch.setattr(runtime_module, "verify_model", lambda *a: None)
    quote = catalog._prepare_contextual_catalog(q.context()).quotes[0][0]
    draft = {"format": "zac-contextual-draft-v2", "overview": [{"text": "Dated uncertain evidence.", "evidence_ids": [quote], "inferred": False}], "background": [], "continuity": [], "items": [], "conflicts": [], "clarifications": []}

    def post(body, timeout):
        events.append(timeout)
        return {"model": q.route.identity.model_id, "done": True, "done_reason": "stop", "message": {"role": "assistant", "content": json.dumps(draft)}, "prompt_eval_count": r._token_counter.count_prompt_tokens(body), "eval_count": 2}

    monkeypatch.setattr(runtime_module, "_fragment_http_post", post)
    r.preflight_fragment(q)
    return events


def test_actual_post_timeout_is_capped_by_original_consent(publication_issuer, monkeypatch):
    f = publication_issuer
    posts = wire(f, monkeypatch)
    f.runtime.generate_fragment(f.q)
    assert len(posts) == 1
    # Task is120s, original signed consent has30s left at late binding. No budget reset.
    assert 0 < posts[0] <= 30 < f.q.task.max_latency_ms / 1000
    assert f.gate._phase == "RELEASED" and f.runtime.usage is not None


def test_actual_pre_gate_expiry_zero_post_and_burned(publication_issuer, monkeypatch):
    f = publication_issuer
    posts = wire(f, monkeypatch)
    # Explicit simulated canonical gate callback advances elapsed real time;
    # immutable expiry remains original. Start with that same original bound.
    original = f.gate._final_claim
    milestones = []
    original_bound = time.monotonic() + (f.consent.expires_at - f.p._clock()).total_seconds()

    def terminal(receipt):
        original(receipt)
        milestones.append("actual-final-claim-returned")
        # Trustworthy native monotonic cannot be replaced by caller fake clock.
        remaining = original_bound - time.monotonic()
        time.sleep(max(0, remaining) + 0.01)

    monkeypatch.setattr(f.gate, "_final_claim", terminal)
    with pytest.raises(runtime_module.FragmentLocalContextualRuntimeError):
        f.runtime.generate_fragment(f.q)
    assert milestones == ["actual-final-claim-returned"]
    assert posts == [] and not f.runtime.did_transport_attempt
    assert f.runtime._attempted and f.runtime.usage is None and len(f.ledger) == 1
    with pytest.raises(runtime_module.FragmentLocalContextualRuntimeError):
        f.runtime.generate_fragment(f.q)
    assert posts == []


@pytest.mark.parametrize("phase", ["PRE", "RELEASE"])
def test_actual_generation_gate_cleanup_uncertainty_survives(publication_issuer, monkeypatch, phase):
    f = publication_issuer
    posts = wire(f, monkeypatch)
    milestones = []
    method = "protect_publication_claim" if phase == "PRE" else "recheck_publication_claim"

    def uncertain(*args, **kwargs):
        assert f.gate._claim_reference is not None
        milestones.append(phase)
        raise PersonalFragmentCleanupUncertain("invented private diagnostic")

    monkeypatch.setattr(parent_module, method, uncertain)
    with pytest.raises(PersonalFragmentCleanupUncertain) as caught:
        f.runtime.generate_fragment(f.q)
    assert str(caught.value) == "PERSONAL recovery cleanup uncertain; operator review required"
    assert caught.value.__cause__ is caught.value.__context__ is None
    assert milestones == [phase] and len(posts) == (0 if phase == "PRE" else 1)
    assert f.runtime._attempted and f.runtime.usage is None and f.gate._phase == "HELD"
    assert len(f.ledger) == 1
