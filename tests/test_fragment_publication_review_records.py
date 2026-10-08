"""Invented declared codecs only; no owner/SQL/model/recovery authentication."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_publication_review as m
from zacai.intelligence.contextual_evaluation import ContextualCriterion, ContextualEvaluation
from zacai.intelligence.contracts import (
    EvidenceReference,
    ModelRoute,
    RouteIdentity,
    UsageObservation,
)
from zacai.intelligence.fragment_review_declaration import (
    FragmentReviewPurposeProfileV1,
    fragment_review_profile_digest,
)
from zacai.intelligence.fragment_review_preparation import FragmentReviewJudgments
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B


def uid(value):
    return UUID(int=value)


def claim():
    refs = tuple(
        EvidenceReference(
            source_id=uid(i),
            content_hash=str(i) * 64,
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        for i in range(1, 6)
    )
    route = ModelRoute(
        identity=RouteIdentity(
            provider_id="ollama",
            model_id="qwen3.8:27b-mlx",
            runtime_id="mac-loopback-packet-followup-16k",
        ),
        destination=Destination.LOCAL,
        capabilities=frozenset({"history_fragment_independent_review"}),
        max_input_characters=64000,
        max_output_tokens=2048,
        estimated_latency_ms=60000.0,
        estimated_cost_usd=0.0,
        available=True,
    )
    profile = FragmentReviewPurposeProfileV1(
        reviewer_id=uid(20),
        run_id=uid(21),
        route=route,
        model_digest="a" * 64,
        tokenizer_digest="b" * 64,
        runtime_digest="c" * 64,
        template_digest="d" * 64,
        renderer_digest="e" * 64,
        rubric_digest="f" * 64,
        reviewer_wire_digest="0" * 64,
        body_derivation_digest="1" * 64,
        context_window_tokens=16384,
        max_output_tokens=2048,
        max_latency_ms=60000,
        max_estimated_cost_usd=0.0,
    )
    now = datetime(2026, 10, 8, tzinfo=UTC)
    return m.FragmentPublicationReviewClaimV1(
        generation_id=uid(22),
        run_id=profile.run_id,
        reviewer_id=profile.reviewer_id,
        attempt_id=uid(23),
        task_id=uid(24),
        builder_id=uid(25),
        association_reference=refs[0],
        association_digest=refs[0].content_hash,
        packet_reference=refs[1],
        publication_reference=refs[2],
        publication_digest="a" * 64,
        admission_reference=refs[3],
        admission_digest=refs[3].content_hash,
        generation_claim_reference=refs[4],
        generation_claim_digest=refs[4].content_hash,
        review_profile=profile,
        review_profile_digest=fragment_review_profile_digest(profile),
        prepared_request_digest="b" * 64,
        prepared_body_digest="c" * 64,
        wire_body_digest="d" * 64,
        route_digest="e" * 64,
        runtime_profile_digest="f" * 64,
        authorization_graph_digest="0" * 64,
        model_metadata_digest="1" * 64,
        mechanical_descriptor_digest="2" * 64,
        original_deadline_monotonic=1000.0,
        measured_input_tokens=1000,
        requested_output_tokens=2048,
        original_session_binding="3" * 64,
        original_approved_at=now,
        expires_at=now + timedelta(minutes=10),
        consumed_at=now + timedelta(seconds=1),
        selected_references=refs,
    )


def assessment():
    c = claim()
    judgments = FragmentReviewJudgments(
        format="zac-history-fragment-review-judgments-v1",
        assessments=tuple(
            {"criterion": v, "judgment": ReviewJudgment.UNREVIEWED} for v in ContextualCriterion
        ),
    )
    usage = UsageObservation(
        input_tokens=c.measured_input_tokens, output_tokens=100, latency_ms=1.0, cost_usd=0.0
    )
    at = c.consumed_at + timedelta(seconds=1)
    evaluation = ContextualEvaluation(
        format="zac-contextual-evaluation-v1",
        evaluation_id=c.run_id,
        task_id=c.task_id,
        builder_id=c.builder_id,
        reviewer_id=c.reviewer_id,
        evaluated_at=at,
        packet_digest=c.packet_reference.content_hash,
        assessments=judgments.assessments,
    )
    return m.FragmentPublicationAssessmentV1(
        evaluation=evaluation,
        review_claim=c,
        review_claim_reference=EvidenceReference(
            source_id=uid(30),
            content_hash=content_hash_of(m.encode_fragment_publication_review_claim(c)),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        ),
        released_judgments_digest=content_hash_of(
            canonical_bytes(judgments.model_dump(mode="json"))
        ),
        released_usage_digest=content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
        usage=usage,
        captured_at=at,
    )


def test_declared_roundtrips_are_not_authentication():
    c = claim()
    a = assessment()
    assert (
        m.decode_fragment_publication_review_claim(m.encode_fragment_publication_review_claim(c))
        == c
    )
    assert (
        m.decode_fragment_publication_assessment(m.encode_fragment_publication_assessment(a)) == a
    )
    assert a.processing_authorized is False and a.reviewer_authenticated is False


@pytest.mark.parametrize(
    "change",
    [
        {"requested_output_tokens": 1024},
        {"run_id": uid(80)},
        {"reviewer_id": uid(25)},
        {"association_digest": "a" * 64},
        {"admission_digest": "b" * 64},
        {"generation_claim_digest": "c" * 64},
        {"selected_references": ()},
        {"measured_input_tokens": 15000},
        {"original_deadline_monotonic": 0.0},
        {"original_deadline_monotonic": float("inf")},
    ],
)
def test_constructed_claim_revalidates(change):
    forged = claim().model_copy(update=change)
    with pytest.raises(
        m.FragmentPublicationReviewError, match="^PERSONAL review claim unavailable$"
    ):
        m.encode_fragment_publication_review_claim(forged)


def test_missing_association_holds_even_with_other_valid_refs():
    c = claim()
    with pytest.raises(m.FragmentPublicationReviewError):
        m.encode_fragment_publication_review_claim(
            c.model_copy(update={"selected_references": c.selected_references[1:]})
        )


@pytest.mark.parametrize(
    "change",
    [
        {"released_judgments_digest": "0" * 64},
        {"released_usage_digest": "1" * 64},
        {"captured_at": datetime(2026, 10, 9, tzinfo=UTC)},
    ],
)
def test_assessment_exact_release_binding(change):
    with pytest.raises(m.FragmentPublicationReviewError):
        m.encode_fragment_publication_assessment(assessment().model_copy(update=change))


def test_changed_usage_coherent_digest_still_holds_count_or_zero_output():
    a = assessment()
    for usage in (
        a.usage.model_copy(update={"input_tokens": 999}),
        a.usage.model_copy(update={"output_tokens": 0}),
    ):
        forged = a.model_copy(
            update={
                "usage": usage,
                "released_usage_digest": content_hash_of(
                    canonical_bytes(usage.model_dump(mode="json"))
                ),
            }
        )
        with pytest.raises(m.FragmentPublicationReviewError):
            m.encode_fragment_publication_assessment(forged)


def test_safe_errors_have_no_private_cause_or_context():
    for decoder in (
        m.decode_fragment_publication_review_claim,
        m.decode_fragment_publication_assessment,
    ):
        with pytest.raises(m.FragmentPublicationReviewError) as error:
            decoder(b'{"private body":"invented secret"}')
        assert error.value.__cause__ is None and error.value.__context__ is None
        assert "invented secret" not in str(error.value)
