"""Root-only actual child reviewer claim+assessment complete recovery.

Invented signed owner/attendance and local metadata/model response. Actual
canonical Source writes/commit/reopen, synthetic-file tokenizer, native age and
full disposable State/journal are real. Judgments UNREVIEWED are fixture data,
not independent semantic review or live owner/private processing permission.
"""

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_fragment_publication_generation_output_sql import (
    actual_case as actual_case,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    generation_case as generation_case,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    http_case as http_case,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    installed as installed,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    original_fixture_budget as original_fixture_budget,  # noqa: PLC0414 - actual pytest fixture export
)
from tests.test_fragment_publication_generation_output_sql import (
    released as released,  # noqa: PLC0414 - actual pytest fixture export
)
from zacai import contextual_authorization as auth
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_publication_generation as generation
from zacai.intelligence import fragment_publication_review as review
from zacai.intelligence import fragment_review_declaration as declaration
from zacai.intelligence import fragment_review_preparation as preparation
from zacai.intelligence import fragment_review_prompt_counter as counter_module
from zacai.intelligence import fragment_review_runtime as engine
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence import local_review_runtime as local_review
from zacai.intelligence.contextual_evaluation import (
    ContextualCriterion,
    check_history_fragment_contextual_evaluation,
)
from zacai.intelligence.contextual_storage import _fragment_request_provenance
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem

RUBRIC = (
    b"Review all ten criteria against full dated evidence. Quote presence alone is not support."
)
TEMPLATE = (
    b"Independently assess the unchanged complete answer. Return only ten criterion judgments."
)


@pytest.fixture
def declaration_case(actual_case, installed):
    make, _, _, q, writer, calls, active, sessions, cookie, leases = actual_case
    p = make("declaration-first-cold")
    owner = p._operation.establish()
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    pins = local.fragment_contextual_counter_pins(counter)
    now = p._clock()
    g = auth.HistoryFragmentConsentV1(
        id=uuid4(),
        builder_id=uuid4(),
        task_id=q.task.task_id,
        request_digest=content_hash_of(encode_history_fragment_contextual_request(q)),
        provenance=_fragment_request_provenance(q),
        owner_issuer=owner.principal.identity.issuer,
        owner_subject=owner.principal.identity.subject,
        original_session_binding=owner.binding_digest,
        original_session_issued_at=owner.issued_at,
        original_session_expires_at=owner.effective_expires_at,
        approved_at=now,
        expires_at=min(now + timedelta(minutes=10), owner.effective_expires_at),
        human_reference="declaration-fixture-data-no-human-action-observed",
        route=q.route,
        model_digest=installed[2],
        tokenizer_digest=pins[0],
        template_digest=pins[1],
        renderer_digest=pins[2],
        runtime_digest=local.fragment_contextual_runtime_digest(),
        body_digest=content_hash_of(q.prompt_body.encode()),
        prompt_tokens=counter.count_prompt_tokens(q.prompt_body.encode()),
        max_output_tokens=q.task.max_output_tokens,
    )
    review_counter = counter_module.OllamaQwenFragmentReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )
    profile = declaration.FragmentReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=q.route.model_copy(
            update={
                "identity": q.route.identity.model_copy(update={"runtime_id": wire.RUNTIME}),
                "capabilities": frozenset({declaration.PURPOSE}),
                "max_input_characters": 64000,
                "max_output_tokens": 8192,
                "estimated_latency_ms": 60000,
                "estimated_cost_usd": 0.0,
            }
        ),
        model_digest=installed[2],
        tokenizer_digest=review_counter.tokenizer_digest,
        runtime_digest=engine.fragment_review_runtime_digest(),
        template_digest=content_hash_of(TEMPLATE),
        renderer_digest=review_counter.renderer_digest,
        rubric_digest=content_hash_of(RUBRIC),
        reviewer_wire_digest=content_hash_of(Path(wire.__file__).read_bytes()),
        body_derivation_digest=content_hash_of(Path(preparation.__file__).read_bytes()),
        context_window_tokens=16384,
        max_output_tokens=1024,
        max_latency_ms=60000,
        max_estimated_cost_usd=0.0,
    )
    d = declaration.prepare_fragment_generation_review_declaration(g, q, review=profile)
    return SimpleNamespace(
        p=p,
        make=make,
        q=q,
        g=g,
        d=d,
        writer=writer,
        calls=calls,
        active=active,
        sessions=sessions,
        cookie=cookie,
        leases=leases,
        review_counter=review_counter,
    )


def child_rows(f, prefix):
    with f.p._factory() as session:
        return tuple(
            session.scalars(
                select(Source.id).where(
                    Source.trust_boundary == B.PERSONAL,
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.like(prefix),
                )
            )
        )


@pytest.fixture
def associated(released):
    f = released
    f.associated = generation.retain_personal_fragment_publication_output(
        f.gate, runtime=f.runtime, request=f.q, draft=f.draft
    )
    return f


@pytest.fixture
def reviewer_case(associated, monkeypatch):
    f = associated
    gate = review.CanonicalFragmentPublicationReviewAuthorization(
        generation_authorization=f.gate,
        associated_output=f.associated,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    prepared = gate.prepare_review()
    counter = f.review_counter
    metadata = []
    posts = []
    milestones = []

    def observed_version(method, path, body):
        assert (method, path, body) == ("GET", "/api/version", None)
        metadata.append("counter-reported-version")
        return {"version": "0.35.1"}

    monkeypatch.setattr(local_review, "_http", observed_version)

    def transport(method, path, body, remaining):
        assert remaining > 0
        metadata.append(path)
        if path == "/api/version":
            return canonical_bytes({"version": "0.35.1"})
        if path == "/api/tags":
            return canonical_bytes(
                {"models": [{"name": wire.MODEL, "digest": counter.model_digest}]}
            )
        if path == "/api/show":
            assert json.loads(body) == {"model": wire.MODEL}
            return canonical_bytes({"details": {"family": "qwen"}})
        assert (method, path) == ("POST", "/api/chat")
        assert f.active == {"canonical": 0, "admin": 0}
        assert gate._phase == "DISPATCHED"
        assert child_rows(f, review._review_prefix(f.g.id) + "%") == (
            gate._claim_reference.source_id,
        )
        assert gate._receipt.kind == "CLAIM"
        assert gate._claim_reference in gate._receipt.selected_references
        # Child append invalidates the earlier output whole-boundary proof.
        with pytest.raises(protection.ContextualProtectionError):
            f.p.recheck(
                source_id=f.associated.retained.source_id,
                expected_digest=f.associated.retained.packet_digest,
                expected_request=f.q,
            )
        milestones.append("real-child-committed-protected-before-one-post-old-output-proof-held")
        posts.append(body)
        expected = wire.serialize_fragment_review_wire(
            prepared, packet_raw=gate._packet_raw, rubric_utf8=RUBRIC, template_utf8=TEMPLATE
        )
        assert body == expected
        count = counter.count_prompt_tokens(body)
        return canonical_bytes(
            {
                "model": wire.MODEL,
                "done": True,
                "done_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "format": "zac-history-fragment-review-judgments-v1",
                            "assessments": [
                                {"criterion": criterion.value, "judgment": "UNREVIEWED"}
                                for criterion in ContextualCriterion
                            ],
                        }
                    ),
                },
                "prompt_eval_count": count,
                "eval_count": 100,
            }
        )

    runtime = engine._LocalFragmentReviewRuntime(
        profile=engine.FragmentReviewRuntimeProfile(
            wire.RUNTIME,
            engine.fragment_review_runtime_digest(),
            counter.model_digest,
            counter.tokenizer_digest,
            counter.template_digest,
            counter.renderer_digest,
        ),
        token_counter=counter,
        _transport=transport,
    )
    gate.bind_review_runtime(runtime)
    f.review_gate, f.review_runtime = gate, runtime
    f.review_prepared, f.review_posts, f.review_milestones = prepared, posts, milestones
    return f


def test_actual_review_child_assessment_commit_reopen_full_cold_once(reviewer_case):
    f = reviewer_case
    gate, runtime = f.review_gate, f.review_runtime
    posts, milestones = f.review_posts, f.review_milestones
    result = review.invoke_personal_fragment_publication_review(gate, runtime=runtime)
    assert gate._phase == "RELEASED" and result is gate._observed_result
    assert result is runtime._authenticated_result and len(posts) == 1
    assert milestones == ["real-child-committed-protected-before-one-post-old-output-proof-held"]
    with f.p._factory() as session:
        session.begin()
        own = review.load_fragment_publication_review_claim(
            session, authorization=gate, reference=gate._claim_reference, expected=gate._claim
        )
    assert own == gate._claim
    claim_receipt = gate._receipt
    retained = review.capture_fragment_publication_assessment(gate, runtime=runtime, result=result)
    assert gate._phase == "ASSESSMENT_RETAINED" and gate._observed_result is None
    assert child_rows(f, review._assessment_prefix(f.g.id) + "%") == (retained.reference.source_id,)
    assert retained.assessment.evaluation.assessments == result.judgments.assessments
    assert retained.assessment.released_usage_digest == result.usage_digest
    with f.p._factory() as session:
        session.begin()
        reopened = review.load_fragment_publication_assessment(
            session, authorization=gate, reference=retained.reference, expected=retained.assessment
        )
    assert reopened == retained.assessment
    receipt = retained.recovery_receipt
    hashes = dict(receipt.full_boundary_source_hashes)
    fingerprints = dict(receipt.full_boundary_source_fingerprints)
    for reference in (
        f.parent.reference,
        f.admitted.reference,
        f.gate._claim_reference,
        f.associated.association.packet_reference,
        f.associated.association_reference,
        gate._claim_reference,
        retained.reference,
    ):
        assert hashes[reference.source_id] == reference.content_hash
        assert reference.source_id in fingerprints
    assert (
        receipt.kind == "ASSESSMENT" and receipt.full_plan_digest != claim_receipt.full_plan_digest
    )
    assert (
        receipt.processing_authorized
        is receipt.reviewer_authenticated
        is receipt.recovery_verified
        is False
    )
    # Concrete reviewer graph pins its original protector. Its actual verifier
    # restores complete State into the existing disjoint disposable target; a
    # separately constructed protector is intentionally not this owned graph.
    cold = review.recheck_publication_assessment(
        f.p,
        authorization=gate,
        reference=retained.reference,
        expected_assessment=retained.assessment,
    )
    assert cold == receipt
    check_history_fragment_contextual_evaluation(retained.assessment.evaluation, gate._packet_raw)
    with pytest.raises(review.FragmentPublicationReviewError):
        review.capture_fragment_publication_assessment(gate, runtime=runtime, result=result)
    assert len(posts) == 1
    assert child_rows(f, review._review_prefix(f.g.id) + "%") == (gate._claim_reference.source_id,)
    assert child_rows(f, review._assessment_prefix(f.g.id) + "%") == (retained.reference.source_id,)
    assert f.active == {"canonical": 0, "admin": 0}
