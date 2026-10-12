"""Root-only real signed admission/SQL/age with invented model observations.

Independent concrete reviewer claim, parser/checker, custody and full recovery
are actual code. Scripted PASS never establishes real model quality/usefulness.
"""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_complete_generation_producer_sql import (
    actual_case as actual_case,  # noqa: PLC0414
)
from tests.test_complete_generation_producer_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_complete_generation_producer_sql import (
    generate,
    retain,
)
from tests.test_complete_generation_producer_sql import (
    history_factory_case as history_factory_case,  # noqa: PLC0414
)
from tests.test_complete_generation_producer_sql import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_complete_generation_producer_sql import (
    producer_case as producer_case,  # noqa: PLC0414
)
from tests.test_history_publication_admission_sql import (
    admission_case as base_admission_case,  # noqa: F401
)
from tests.test_personal_history_factory_sql import all_sources
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence import history_publication_generation as generation
from zacai.intelligence import history_publication_protection as protection
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
from zacai.policy import TrustBoundary as B
from zacai.state import Source

RUBRIC = b"Review all ten criteria against the full retained answer and original dated context."
TEMPLATE = b"Independently judge exact factual support, instruction adherence and uncertainty."


@pytest.fixture
def admission_case(base_admission_case, installed):  # noqa: F811 - pytest fixture dependency
    f = base_admission_case
    counter = OllamaQwenHistoryReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )
    # Every reviewer pin/budget declared BEFORE producer fixture captures approval.
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
    f.c = replace(f.c, review_profile=profile)
    f.review_counter = counter
    return f


@pytest.fixture
def review_case(producer_case, monkeypatch):
    p = producer_case
    output = retain(p, generate(p))
    r = runtime.LocalHistoryReviewRuntime(counter=p.f.review_counter)
    state = SimpleNamespace(posts=[], judgment=ReviewJudgment.UNREVIEWED, fault=None)
    monkeypatch.setattr(r._counter, "verify_runtime", lambda: None)  # Model metadata only.
    child = None

    def transport(method, path, body, remaining):
        assert remaining > 0
        if path == "/api/version":
            return canonical_bytes({"version": base_counter._VERSION})
        if path == "/api/tags":
            return canonical_bytes(
                {"models": [{"name": wire.MODEL, "digest": r._counter.model_digest}]}
            )
        if path == "/api/show":
            return canonical_bytes({"template": "invented verified backend metadata"})
        assert method == "POST" and path == "/api/chat" and child._phase == "CLAIMED"
        # Actual committed reviewer claim, not a simulated SQL callback.
        with p.f.c.factory() as session:
            assert generation._ids(session, review._review_prefix(p.g.id)) == (
                child._claim_reference.source_id,
            )
        state.posts.append(body)
        if state.fault == "transport":
            raise ValueError("invented reviewer transport failure")
        payload = {
            "format": "zac-history-complete-review-judgments-v1",
            "assessments": [
                ContextualAssessment(criterion=v, judgment=state.judgment).model_dump(mode="json")
                for v in ContextualCriterion
            ],
        }
        if state.fault == "owner":
            p.f.inputs.owners.revoke()
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
    child = review.CanonicalPersonalHistoryReviewAuthorization(
        generation_authorization=p.gate,
        output=output,
        runtime=r,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    return SimpleNamespace(p=p, output=output, gate=child, runtime=r, state=state)


def subject(c, result=None):
    p = c.p
    with p.f.c.factory() as session, session.begin():
        return review.load_history_publication_review_subject(
            session,
            artifacts=LocalFilesystemArtifactStore(p.f.c.artifacts.root),
            context=p.gate._context,
            declaration=p.d,
            admission=p.gate._admission,
            admission_reference=p.gate._admission_reference,
            generation_claim=p.gate._claim,
            generation_claim_reference=p.gate._claim_reference,
            association=c.output.association,
            association_reference=c.output.association_reference,
            review_claim=c.gate._claim,
            review_claim_reference=c.gate._claim_reference,
            assessment=None if result is None else result.assessment,
            assessment_reference=None if result is None else result.reference,
        )


@pytest.mark.parametrize("judgment", [ReviewJudgment.PASS, ReviewJudgment.UNREVIEWED])
def test_actual_seven_source_chain_cold_assessment_recovery_original_once_release(
    review_case, judgment
):
    c = review_case
    c.state.judgment = judgment
    observed = c.gate.invoke()
    assert observed is c.runtime._result and observed is c.gate._observed
    retained = review.capture_history_publication_assessment(c.gate, observed=observed)
    assert subject(c, retained) == retained.assessment
    p = c.p
    after = all_sources(p.f)
    assert len(after) == len(p.before) + 7
    assert dict(retained.recovery_receipt.full_boundary_source_hashes) == after
    assert set(dict(retained.recovery_receipt.full_boundary_source_fingerprints)) == set(after)
    assert (
        retained.assessment.evaluation.packet_digest
        == c.output.association.packet_reference.content_hash
    )
    assert p.g.expires_at == p.d.expires_at == c.gate._claim.expires_at
    assert c.gate._claim.original_deadline_monotonic <= p.gate._deadline_monotonic
    assert (
        protection.protect_history_assessment(c.gate, read_existing=True)
        == retained.recovery_receipt
    )
    assert all_sources(p.f) == after
    with pytest.raises(
        ValueError, match="PERSONAL complete admission checkpoint unavailable or mismatched"
    ):
        protection.protect_history_review_claim(c.gate, read_existing=True)
    text = review.release_history_reviewed_text(c.gate, expected=retained)
    if judgment is ReviewJudgment.PASS:
        assert retained.outcome is ContextualOutcome.REVIEWED_PASS and text
    else:
        assert retained.outcome is ContextualOutcome.NEEDS_REVIEW and text is None
        assert not retained.ready_to_deliver
    assert c.gate._phase == "DELIVERY_RELEASED"
    assert len(p.posts) == len(c.state.posts) == 1
    with pytest.raises(review.HistoryPublicationReviewError):
        review.release_history_reviewed_text(c.gate, expected=retained)
    with pytest.raises(review.HistoryPublicationReviewError):
        review.capture_history_publication_assessment(c.gate, observed=observed)
    assert all_sources(p.f) == after and len(c.state.posts) == 1


@pytest.mark.parametrize("fault", ["transport", "owner"])
def test_actual_committed_reviewer_claim_failure_or_owner_revoke_withholds_no_retry(
    review_case, fault
):
    c = review_case
    c.state.fault = fault
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert len(c.state.posts) == 1 and c.gate._phase == "HELD"
    assert c.runtime._result is c.gate._observed is c.gate._result is None
    assert len(all_sources(c.p.f)) == len(c.p.before) + 6
    assert subject(c) == c.gate._claim  # Custody load is not a new processing grant.
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert len(c.state.posts) == 1


def test_actual_corrupted_assessment_holds_loader_recovery_and_text_without_repair(review_case):
    c = review_case
    c.state.judgment = ReviewJudgment.PASS
    retained = review.capture_history_publication_assessment(c.gate, observed=c.gate.invoke())
    before = all_sources(c.p.f)
    with c.p.f.c.factory() as session:
        location = session.get(Source, retained.reference.source_id).content_location
    path = c.p.f.c.artifacts.root / B.PERSONAL.value / location
    corrupted = path.read_bytes() + b" "
    path.write_bytes(corrupted)
    with pytest.raises(review.HistoryPublicationReviewError):
        subject(c, retained)
    with pytest.raises(
        ValueError, match="PERSONAL complete admission checkpoint unavailable or mismatched"
    ):
        protection.protect_history_assessment(c.gate, read_existing=True)
    with pytest.raises(review.HistoryPublicationReviewError):
        review.release_history_reviewed_text(c.gate, expected=retained)
    assert c.gate._phase == "HELD" and c.gate._result is None
    assert path.read_bytes() == corrupted and all_sources(c.p.f) == before
    assert len(c.state.posts) == 1
