"""Concrete producers/codecs/files/runtime; SQL/owner/age/HTTP explicitly mocked.

No genuine signed owner, canonical commit, recovery or model judgment quality.
"""

# ruff: noqa: PLC0414
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.authenticated_review_runtime_support import configured_runtime
from tests.test_fragment_publication_generation import (
    authority as authority,
)
from tests.test_fragment_publication_generation import (
    baseline_authority as baseline_authority,
)
from tests.test_fragment_publication_generation import (
    case as case,
)
from tests.test_fragment_publication_generation import (
    consent_case as consent_case,
)
from tests.test_fragment_publication_generation import (
    installed as installed,
)
from tests.test_fragment_publication_generation import (
    issuer as issuer,
)
from tests.test_fragment_publication_generation import (
    packet_case as packet_case,
)
from tests.test_fragment_publication_generation import (
    publication_issuer as publication_issuer,
)
from tests.test_fragment_publication_generation import (
    test_full_output_new_checkpoint_contains_publication_admission_claim as produce_output,
)
from zacai import backup_artifacts, state_repository
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_publication_generation as generation
from zacai.intelligence import fragment_publication_review as m
from zacai.intelligence import fragment_review_preparation as preparation
from zacai.intelligence import fragment_review_runtime as engine
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence.fragment_review_declaration import FragmentReviewPurposeProfileV1
from zacai.intelligence.fragment_review_prompt_counter import OllamaQwenFragmentReviewTokenCounter
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import ArtifactBackupRunStatus, SourceSystem

RUBRIC = b"Judge all ten criteria against this complete answer and dated evidence."
TEMPLATE = b"Independently review the entire answer. Return only exact ten criterion judgments."


@pytest.fixture
def declaration_case(case, installed):
    q, consent, _ = case
    counter = OllamaQwenFragmentReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )
    route = q.route.model_copy(
        update={
            "identity": q.route.identity.model_copy(
                update={"model_id": wire.MODEL, "runtime_id": wire.RUNTIME}
            ),
            "capabilities": frozenset({preparation.PURPOSE}),
            "max_input_characters": 64000,
            "max_output_tokens": 2048,
            "estimated_latency_ms": 60000.0,
            "estimated_cost_usd": 0.0,
        }
    )
    profile = FragmentReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=route,
        model_digest=installed[2],
        tokenizer_digest=counter.tokenizer_digest,
        runtime_digest=engine.fragment_review_runtime_digest(),
        template_digest=content_hash_of(TEMPLATE),
        renderer_digest=counter.renderer_digest,
        rubric_digest=content_hash_of(RUBRIC),
        reviewer_wire_digest=content_hash_of(Path(wire.__file__).read_bytes()),
        body_derivation_digest=content_hash_of(Path(preparation.__file__).read_bytes()),
        context_window_tokens=16384,
        max_output_tokens=128,
        max_latency_ms=60000,
        max_estimated_cost_usd=0.0,
    )
    return q, consent, profile


@pytest.fixture
def review_case(publication_issuer, installed, monkeypatch):
    f = publication_issuer
    # Existing real publication producer returns its exact object. Its fixture
    # explicitly mocks canonical SQL and cryptographic recovery, never authority.
    produce_output(f, monkeypatch)
    output = f.gate._associated_result
    assert output is not None and f.gate._phase == "OUTPUT_RETAINED"
    gate = m.CanonicalFragmentPublicationReviewAuthorization(
        generation_authorization=f.gate,
        associated_output=output,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    monkeypatch.setattr(m, "_physical", lambda s: ("simulated", None, None, None))
    monkeypatch.setattr(m, "_same", lambda *a: None)
    monkeypatch.setattr(m, "_fragment_rows", generation._fragment_rows)
    monkeypatch.setattr(m, "_fragment_profile_lineage", lambda *a: None)
    monkeypatch.setattr(
        m, "prepare_personal_encrypted_custody_backup_plan", lambda s: f.current_plan["value"]
    )

    def ids(s, prefix, system=SourceSystem.MANUAL):
        return tuple(
            v.id for v in (*f.ledger, *f.pending) if f.rows[v.id]["external_ref"].startswith(prefix)
        )

    monkeypatch.setattr(m, "_ids", ids)
    original = state_repository.record_source

    def record(s, **kwargs):
        if not kwargs["external_ref"].startswith(
            (m._review_prefix(f.consent.id), m._assessment_prefix(f.consent.id))
        ):
            return original(s, **kwargs)
        raw = f.p._artifacts.get_bounded(B.PERSONAL, kwargs["content_location"], max_bytes=16000)
        if kwargs["external_ref"].startswith(m._review_prefix(f.consent.id)):
            value = m.decode_fragment_publication_review_claim(raw)
            assert kwargs["external_ref"] == m._claim_namespace(value)
            f.events.append("review-record")
        else:
            value = m.decode_fragment_publication_assessment(raw)
            assert kwargs["external_ref"] == m._assessment_namespace(value)
            f.events.append("assessment-record")
        source = SimpleNamespace(id=uuid4(), supersedes_source_id=None)
        f.pending.append(source)
        f.rows[source.id] = dict(
            kwargs, id=source.id, supersedes_source_id=None, lineage_id=source.id
        )
        rows = json.loads(f.current_plan["value"].rows)
        rows.append({"id": str(source.id), "content_hash": kwargs["content_hash"]})
        f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
        return source, True

    monkeypatch.setattr(state_repository, "record_source", record)

    def backup(*a, **kw):
        f.events.append("review-backup")
        return SimpleNamespace(id=f.run, status=ArtifactBackupRunStatus.SUCCEEDED)

    monkeypatch.setattr(backup_artifacts, "run_artifact_backup", backup)
    prepared = gate.prepare_review()
    counter = OllamaQwenFragmentReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )
    runtime, _kwargs, transport = configured_runtime(
        prepared, gate._packet_raw, RUBRIC, TEMPLATE, counter, monkeypatch
    )
    gate.bind_review_runtime(runtime)
    f.review_gate, f.review_runtime, f.review_transport = gate, runtime, transport
    f.events.clear()
    return f


def invoke(f):
    return m.invoke_personal_fragment_publication_review(f.review_gate, runtime=f.review_runtime)


def test_actual_join_positive_once_includes_claim_then_assessment(review_case):
    f = review_case
    result = invoke(f)
    assert f.review_gate._phase == "RELEASED"
    assert result is f.review_runtime._authenticated_result
    assert len(f.review_transport.posts) == 1
    assert f.events.index("commit") < f.events.index("review-backup")
    claim = f.review_gate._claim
    assert claim.original_deadline_monotonic == f.review_gate._deadline_monotonic
    retained = m.capture_fragment_publication_assessment(
        f.review_gate, runtime=f.review_runtime, result=result
    )
    assert f.review_gate._phase == "ASSESSMENT_RETAINED"
    assert retained.assessment.evaluation.assessments == result.judgments.assessments
    assert {
        retained.reference,
        f.review_gate._claim_reference,
        f.gate._associated_result.association_reference,
    } <= set(retained.recovery_receipt.selected_references)
    assert len(f.review_transport.posts) == 1 and f.events.count("review-record") == 1
    with pytest.raises(m.FragmentPublicationReviewError):
        m.capture_fragment_publication_assessment(
            f.review_gate, runtime=f.review_runtime, result=result
        )
    assert f.events.count("assessment-record") == 1


def test_foreign_equal_producer_result_denied_before_callbacks(review_case):
    f = review_case
    before = list(f.events)
    clone = replace(f.gate._associated_result)
    with pytest.raises(m.FragmentPublicationReviewError):
        m.CanonicalFragmentPublicationReviewAuthorization(
            generation_authorization=f.gate,
            associated_output=clone,
            rubric_utf8=RUBRIC,
            template_utf8=TEMPLATE,
        )
    assert f.events == before and not f.review_transport.posts


def test_pre_withdrawal_before_post_is_permanently_held(review_case):
    f = review_case
    f.withdrawn = True
    with pytest.raises(m.FragmentPublicationReviewError):
        invoke(f)
    assert f.review_gate._phase == "HELD" and f.events.count("review-record") == 0
    assert not f.review_transport.posts


def test_release_withdrawal_withholds_actual_one_post_result(review_case):
    f = review_case
    milestones = []

    def changed():
        f.withdrawn = True
        milestones.append("chat-reply-before-release")

    f.review_transport.callback = changed
    with pytest.raises(m.FragmentPublicationReviewError):
        invoke(f)
    assert milestones == ["chat-reply-before-release"]
    assert len(f.review_transport.posts) == 1 and f.events.count("review-record") == 1
    assert f.review_gate._phase == "HELD" and f.review_runtime._authenticated_result is None


def test_protection_failure_after_commit_burns_fresh_instance(review_case, monkeypatch):
    f = review_case
    milestones = []

    def fault(*a, **kw):
        milestones.append("own-claim-protect-after-commit")
        assert f.events.count("review-record") == 1 and "commit" in f.events
        raise ValueError("invented private error")

    monkeypatch.setattr(m, "protect_publication_review_claim", fault)
    with pytest.raises(m.FragmentPublicationReviewError):
        invoke(f)
    assert milestones == ["own-claim-protect-after-commit"] and not f.review_transport.posts
    assert f.review_gate._phase == "HELD" and f.events.count("review-record") == 1
    fresh = m.CanonicalFragmentPublicationReviewAuthorization(
        generation_authorization=f.gate,
        associated_output=f.gate._associated_result,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    # Original output checkpoint is now stale because the committed child remains.
    with pytest.raises(m.FragmentPublicationReviewError):
        fresh.prepare_review()
    assert f.events.count("review-record") == 1 and not f.review_transport.posts


def test_reentrant_pre_caught_by_owner_stays_held(review_case, monkeypatch):
    f = review_case
    gate, runtime = f.review_gate, f.review_runtime
    original = f.p._operation._read
    milestones = []

    def owner():
        if gate._phase == "ENTERED" and not milestones:
            bound = runtime._prepared
            assert bound is not None
            body, mechanical = runtime._describe(
                gate._prepared,
                packet_raw=gate._packet_raw,
                rubric_utf8=RUBRIC,
                template_utf8=TEMPLATE,
                count=bound.measured_input_tokens,
                deadline=bound.deadline_monotonic,
                metadata_digest=bound.model_metadata_digest,
            )
            nested = engine.AuthenticatedFragmentReviewDispatchDescriptor(
                "PRE_DISPATCH",
                gate._profile.run_id,
                runtime._authenticated_attempt_id,
                mechanical,
                body,
                m.fragment_publication_review_graph_digest(),
            )
            with pytest.raises(m.FragmentPublicationReviewError):
                gate.recheck_review_dispatch(gate._prepared, nested)
            milestones.append("caught-nested-pre-hold")
        return original()

    monkeypatch.setattr(f.p._operation, "_read", owner)
    f.p._operation_settings = (owner, f.p._operation._host_clock)
    with pytest.raises(m.FragmentPublicationReviewError):
        invoke(f)
    assert milestones == ["caught-nested-pre-hold"]
    assert gate._phase == "HELD" and not f.review_transport.posts
    assert f.events.count("review-record") == 0


def test_equal_copy_of_actual_result_burns_capture_without_writes(review_case):
    f = review_case
    result = invoke(f)
    clone = replace(result)
    assert clone == result and clone is not result
    with pytest.raises(m.FragmentPublicationReviewError):
        m.capture_fragment_publication_assessment(
            f.review_gate, runtime=f.review_runtime, result=clone
        )
    assert f.review_gate._phase == "HELD" and f.events.count("assessment-record") == 0
    with pytest.raises(m.FragmentPublicationReviewError):
        m.capture_fragment_publication_assessment(
            f.review_gate, runtime=f.review_runtime, result=result
        )
    assert f.events.count("assessment-record") == 0 and len(f.review_transport.posts) == 1


def add_sibling(f, kind):
    prefix = (
        m._review_prefix(f.consent.id) if kind == "CLAIM" else m._assessment_prefix(f.consent.id)
    )
    sid = uuid4()
    f.rows[sid] = {
        "id": sid,
        "content_hash": "f" * 64,
        "external_ref": prefix + str(uuid4()),
        "system": SourceSystem.MANUAL,
        "trust_boundary": B.PERSONAL,
        "data_classification": C.HIGHLY_RESTRICTED,
        "captured_at": f.consent.approved_at,
        "supersedes_source_id": None,
        "lineage_id": sid,
        "content_location": "invented-sibling",
    }
    f.ledger.append(SimpleNamespace(id=sid))
    rows = json.loads(f.current_plan["value"].rows)
    rows.append({"id": str(sid), "content_hash": "f" * 64})
    f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))


@pytest.mark.parametrize("kind", ["CLAIM", "ASSESSMENT"])
def test_sibling_after_exact_subject_body_is_detected_by_repeated_namespace(
    review_case, monkeypatch, kind
):
    f = review_case
    result = invoke(f)
    if kind == "ASSESSMENT":
        retained = m.capture_fragment_publication_assessment(
            f.review_gate, runtime=f.review_runtime, result=result
        )
        expected, reference = retained.assessment, retained.reference
        raw = m.encode_fragment_publication_assessment(expected)
    else:
        expected, reference = f.review_gate._claim, f.review_gate._claim_reference
        raw = m.encode_fragment_publication_review_claim(expected)
    original = f.p._artifacts.get_bounded
    milestones = []

    def changed(*a, **kw):
        body = original(*a, **kw)
        if body == raw and not milestones:
            add_sibling(f, kind)
            milestones.append("actual-own-body-returned-then-sibling")
        return body

    monkeypatch.setattr(f.p._artifacts, "get_bounded", changed)
    with f.p._factory() as session:
        session.begin()
        outcome = None
        try:
            if kind == "CLAIM":
                m.load_fragment_publication_review_claim(
                    session, authorization=f.review_gate, reference=reference, expected=expected
                )
            else:
                m.load_fragment_publication_assessment(
                    session, authorization=f.review_gate, reference=reference, expected=expected
                )
        except m.FragmentPublicationReviewError as error:
            outcome = error
    assert milestones == ["actual-own-body-returned-then-sibling"]
    assert type(outcome) is m.FragmentPublicationReviewError
    assert len(f.review_transport.posts) == 1
