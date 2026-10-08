"""Real concrete gate/runtime; inherited fixture mocks owner/SQL/age/transport."""

# ruff: noqa: F811, I001 - fixture imports preserve shared test graph
import pytest
from tests.test_fragment_publication_review_integration import (  # noqa: F401
    baseline_authority, authority, case, consent_case, declaration_case, installed,
    issuer, packet_case, publication_issuer, review_case,
)
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.intelligence import fragment_publication_review as gate_module


@pytest.mark.parametrize("phase", ["PRE", "RELEASE"])
def test_real_gate_cleanup_uncertainty_preserved_and_attempt_held(review_case, monkeypatch, phase):
    f = review_case
    milestones = []
    name = "protect_publication_review_claim" if phase == "PRE" else "recheck_publication_review_claim"

    def uncertain(*args, **kwargs):
        assert f.review_gate._claim_reference is not None
        milestones.append(phase + "-actual-gate-checkpoint-entered")
        raise PersonalFragmentCleanupUncertain("invented sensitive detail must be removed")

    monkeypatch.setattr(gate_module, name, uncertain)
    with pytest.raises(PersonalFragmentCleanupUncertain) as failure:
        gate_module.invoke_personal_fragment_publication_review(f.review_gate, runtime=f.review_runtime)
    assert type(failure.value) is PersonalFragmentCleanupUncertain
    assert str(failure.value) == "PERSONAL reviewer cleanup uncertain; operator review required"
    assert failure.value.__cause__ is failure.value.__context__ is None
    assert milestones == [phase + "-actual-gate-checkpoint-entered"]
    assert len(f.review_transport.posts) == (0 if phase == "PRE" else 1)
    assert f.review_runtime._attempted and f.review_runtime._authenticated_held
    assert f.review_runtime.usage is None and f.review_runtime._authenticated_result is None
    assert f.review_gate._phase == "HELD" and f.review_gate._observed_result is None
