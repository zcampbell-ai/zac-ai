"""Concrete complete producer and independent reviewer; operational I/O simulated."""

# ruff: noqa: F401,F811
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_history_generation_runtime import (
    action_case,
    base_factory_case,
    canonical_case,
    case,
    declaration_case,
    dispatch_case,
    host,
    installed,
    loader_case,
    observed_case,
    post_case,
    producer_case,
    released_case,
    setup,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_publication_generation as generation
from zacai.intelligence import history_publication_review as review
from zacai.intelligence import history_review_runtime as runtime
from zacai.intelligence import history_review_wire as wire
from zacai.intelligence import ollama_token_counter as base_counter
from zacai.intelligence.contextual_evaluation import (
    ContextualAssessment,
    ContextualCriterion,
    ContextualOutcome,
)
from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

RUBRIC = b"Review all ten criteria against the full retained answer and original dated context."
TEMPLATE = b"Independently judge exact factual support, instruction adherence and uncertainty."


@pytest.fixture
def factory_case(base_factory_case, installed):
    f = base_factory_case
    counter = OllamaQwenHistoryReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )
    profile = f.c.review_profile.model_copy(
        update={
            "model_digest": counter.model_digest,
            "tokenizer_digest": counter.tokenizer_digest,
            "renderer_digest": counter.renderer_digest,
            "runtime_digest": runtime.history_review_runtime_digest(),
            "rubric_digest": content_hash_of(RUBRIC),
            "template_digest": content_hash_of(TEMPLATE),
            "reviewer_wire_digest": runtime.history_review_wire_digest(),
            "body_derivation_digest": runtime.history_review_derivation_digest(),
            "max_latency_ms": 60000,
            "route": f.c.review_profile.route.model_copy(
                update={
                    "max_input_characters": 64000,
                    "identity": f.c.review_profile.route.identity.model_copy(
                        update={"runtime_id": wire.RUNTIME}
                    ),
                }
            ),
        }
    )
    from zacai.intelligence.history_contextual_runtime import history_contextual_runtime_digest

    f.c = replace(
        f.c, review_profile=profile, generation_runtime_digest=history_contextual_runtime_digest()
    )
    f.review_counter = counter
    return f


@pytest.fixture
def review_inputs(released_case, monkeypatch):
    p = released_case
    output = generation.retain_personal_history_publication_output(
        p.gate, runtime=p.runtime, request=p.s.q, draft=p.draft
    )
    r = runtime.LocalHistoryReviewRuntime(counter=p.f.review_counter)
    state = SimpleNamespace(posts=[], metadata=[], judgment=ReviewJudgment.UNREVIEWED, cancel=False, gate=None)
    monkeypatch.setattr(
        r._counter, "verify_runtime", lambda: state.metadata.append("counter runtime simulated")
    )

    def transport(method, path, body, remaining):
        assert remaining > 0
        state.metadata.append(path)
        if path == "/api/version":
            return canonical_bytes({"version": base_counter._VERSION})
        if path == "/api/tags":
            return canonical_bytes(
                {"models": [{"name": wire.MODEL, "digest": r._counter.model_digest}]}
            )
        if path == "/api/show":
            return canonical_bytes({"template": "invented verified backend metadata"})
        assert method == "POST" and path == "/api/chat"
        assert state.gate._phase == "CLAIMED" and state.gate._claim_reference.source_id in p.s.c.a.s.rows
        state.posts.append(body)
        payload = {
            "format": "zac-history-complete-review-judgments-v1",
            "assessments": [
                ContextualAssessment(criterion=value, judgment=state.judgment).model_dump(
                    mode="json"
                )
                for value in ContextualCriterion
            ],
        }
        if state.cancel:
            p.s.c.cancelled = True
        return canonical_bytes(
            {
                "model": wire.MODEL,
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(payload)},
                "prompt_eval_count": r._counter.count_prompt_tokens(body),
                "eval_count": 100,
            }
        )

    r._transport = transport
    r._original_transport = transport
    monkeypatch.setattr(review, "_physical", generation._physical)
    monkeypatch.setattr(review, "_same", generation._same)
    monkeypatch.setattr(review, "_same_commit", generation._same_commit)
    monkeypatch.setattr(review, "_lock", generation._lock)
    monkeypatch.setattr(
        review,
        "_assert_personal_custody_append_capacity",
        generation._assert_personal_custody_append_capacity,
    )
    monkeypatch.setattr(review, "_fragment_rows", generation._fragment_rows)
    monkeypatch.setattr(review, "record_source", generation.record_source)
    return SimpleNamespace(p=p, output=output, runtime=r, state=state)


@pytest.fixture
def review_case(review_inputs):
    c = review_inputs
    child = review.CanonicalPersonalHistoryReviewAuthorization(
        generation_authorization=c.p.gate,
        output=c.output,
        runtime=c.runtime,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    c.state.gate = child
    c.gate = child
    return c


def test_actual_complete_child_claim_before_mock_post_and_unreviewed_withheld(review_case):
    c = review_case
    observed = c.gate.invoke()
    assert observed is c.runtime._result and c.gate._observed is observed
    assert len(c.state.posts) == 1 and len(c.p.state.commits) == 4 and c.gate._phase == "RELEASED"
    retained = review.capture_history_publication_assessment(c.gate, observed=observed)
    assert len(c.p.state.commits) == 5 and c.gate._result is retained
    assert retained.outcome is ContextualOutcome.NEEDS_REVIEW and not retained.ready_to_deliver
    assert len(retained.recovery_receipt.full_boundary_source_hashes) == len(c.p.s.c.a.s.rows)
    assert review.release_history_reviewed_text(c.gate, expected=retained) is None
    assert c.gate._phase == "DELIVERY_RELEASED"
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert len(c.state.posts) == 1 and len(c.p.state.commits) == 5


def test_actual_complete_ten_pass_observation_recovery_before_one_text_release(review_case):
    c = review_case
    c.state.judgment = ReviewJudgment.PASS
    observed = c.gate.invoke()
    retained = review.capture_history_publication_assessment(c.gate, observed=observed)
    assert retained.outcome is ContextualOutcome.REVIEWED_PASS
    text = review.release_history_reviewed_text(c.gate, expected=retained)
    assert type(text) is str and text and len(c.state.posts) == 1
    assert (
        retained.assessment.evaluation.packet_digest
        == c.output.association.packet_reference.content_hash
    )
    with pytest.raises(review.HistoryPublicationReviewError):
        review.release_history_reviewed_text(c.gate, expected=retained)
    assert len(c.state.posts) == 1 and len(c.p.state.commits) == 5


def test_actual_review_cancellation_after_post_burns_with_no_assessment(review_case):
    c = review_case
    c.state.cancel = True
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert len(c.state.posts) == 1 and len(c.p.state.commits) == 4 and c.gate._phase == "HELD"
    assert c.runtime._result is None and c.gate._result is None
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert len(c.state.posts) == 1
