"""Real signed owner/clock/codecs; canonical capture and recovery seams simulated."""
# ruff: noqa: F401, F811
from datetime import timedelta

import pytest

from tests.test_personal_fragment_factory import (
    case,
    controller,
    declaration_case,
    factory_case,
    installed,
    invoke,
    owner_case,
    post_case,
)
from zacai.intelligence.fragment_review_retention import _parts
from zacai.interfaces import personal_fragment_factory as factory


@pytest.mark.parametrize("margin_ms", [-1, 0, 1])
def test_final_owner_observation_requires_original_combined_window(
    factory_case, monkeypatch, margin_ms
):
    f = factory_case
    original_expiry = f.c.expires_at
    real = factory.prepare_fragment_generation_review_declaration
    milestones = []

    def advance_after_preparation(*args, **kwargs):
        declaration = real(*args, **kwargs)
        _, generation, request = _parts(declaration)
        assert declaration.review is not None
        required = request.task.max_latency_ms + declaration.review.max_latency_ms
        f.s.f.now[0] = original_expiry - timedelta(milliseconds=required + margin_ms)
        milestones.append((required, generation.approved_at, f.s.f.now[0]))
        return declaration

    monkeypatch.setattr(factory, "prepare_fragment_generation_review_declaration", advance_after_preparation)
    puts = []
    monkeypatch.setattr(f.c.artifacts, "put", lambda *args: puts.append(args))
    outcome = None
    result = None
    try:
        result = invoke(f)
    except factory.PersonalFragmentFactoryError as error:
        outcome = error
    assert len(milestones) == 1
    assert milestones[0][1] < milestones[0][2] < original_expiry
    with f.s.inputs.clock._lock:
        assert f.s.inputs.clock._last == f.s.f.now[0]
    assert f.c.expires_at == original_expiry and not f.active
    if margin_ms < 0:
        assert isinstance(outcome, factory.PersonalFragmentFactoryError)
        assert outcome.__context__ is None
        assert result is None and f.retained == [] and puts == []
        assert "capture committed closed" not in f.events
        assert "genuine protector join substituted" not in f.events
    else:
        assert outcome is None and result is not None and len(f.retained) == 1
        assert "genuine protector join substituted" in f.events
        _, generation, _ = _parts(f.retained[0].declaration)
        assert generation.expires_at == original_expiry
        assert generation.approved_at == milestones[0][1]
        assert f.events[-1] == "final scalar"
