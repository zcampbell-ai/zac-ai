"""Pure nominal renderer fixtures only; no authenticated/SQL/recovery success claim."""

import ast
from dataclasses import replace
from html import escape
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_history_contextual_codec import host as host  # noqa: PLC0414
from tests.test_history_contextual_codec import prepared as prepared  # noqa: PLC0414
from tests.test_history_contextual_codec import review_for
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import (
    ContextualAssessment,
    ContextualCriterion,
    ContextualEvaluation,
    ContextualOutcome,
)
from zacai.intelligence.contextual_review import Clarification, EvidenceConflict
from zacai.intelligence.history_contextual_codec import encode_history_contextual_packet
from zacai.intelligence.history_publication_review import (
    CanonicalPersonalHistoryReviewAuthorization,
    HistoryPublicationAssessmentV1,
    PersonalHistoryRetainedAssessment,
)
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.interfaces import history_publication_web as web


@pytest.fixture
def render_case(prepared):
    request = prepared[-1]
    review = review_for(request)
    quote = review.overview[0].quotes[0]
    gap = Clarification(
        text="Project attribution needs confirmation.",
        quotes=(quote,),
        question="Which <img src=x onerror=alert(1)> project?",
        reason="Attribution changes the answer & next step.",
    )
    second = gap.model_copy(update={"question": "SECOND HIDDEN QUESTION?"})
    review = review.model_copy(update={"clarifications": (gap, second)})
    builder = uuid4()
    raw = encode_history_contextual_packet(
        review, request, builder_id=builder, created_at=request.task.event.observed_at
    )
    evaluation = ContextualEvaluation(
        format="zac-contextual-evaluation-v1",
        evaluation_id=uuid4(),
        task_id=request.task.task_id,
        reviewer_id=uuid4(),
        builder_id=builder,
        evaluated_at=request.task.event.observed_at,
        packet_digest=content_hash_of(raw),
        assessments=tuple(
            ContextualAssessment(criterion=c, judgment=ReviewJudgment.PASS)
            for c in ContextualCriterion
        ),
    )
    # Only the pure renderer's nominal input shape is constructed. These objects
    # have never passed source/owner/claim/recovery gates and cannot authorize work.
    assessed = HistoryPublicationAssessmentV1.model_construct(evaluation=evaluation)
    retained = PersonalHistoryRetainedAssessment(
        reference=None,
        assessment=assessed,
        recovery_receipt=None,
        outcome=ContextualOutcome.NEEDS_CLARIFICATION,
    )
    gate = object.__new__(CanonicalPersonalHistoryReviewAuthorization)
    gate._phase = "DELIVERY_RELEASED"
    gate._packet_raw = raw
    gate._generation = SimpleNamespace(_request=request)
    gate._result = retained
    gate._assessment = assessed
    return SimpleNamespace(
        gate=gate,
        retained=retained,
        evaluation=evaluation,
        raw=raw,
        request=request,
        overview=review.overview[0].text,
        gap_text=gap.text,
        quote_text=quote.text,
        review=review,
        builder=builder,
    )


def replace_evaluation(f, evaluation):
    assessed = f.retained.assessment.model_copy(update={"evaluation": evaluation})
    f.retained = replace(f.retained, assessment=assessed)
    f.gate._result = f.retained
    f.gate._assessment = assessed
    return f.retained


def test_first_reviewed_question_escaped_full_reply_held_no_authority_controls(render_case):
    f = render_case
    html = web._reviewed_result_html(f.gate, f.retained, None)
    assert "One quick question" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html and "<img" not in html
    assert "Why it matters: Attribution changes the answer &amp; next step." in html
    assert "additional questions" not in html
    assert "SECOND HIDDEN" not in html and f.overview not in html
    assert (
        "The full answer is still on hold." in html
        and "current details may need an update." in html
    )
    assert all(
        hidden not in html
        for hidden in (
            f.gap_text,
            escape(f.gap_text),
            f.quote_text,
            escape(f.quote_text),
            f.raw.decode(),
            escape(f.raw.decode()),
        )
    )
    assert all(
        marker not in html
        for marker in (
            "<form",
            "<input",
            "<button",
            "<details",
            "action=",
            "href=",
            "Reviewed historical-context reply",
        )
    )


@pytest.mark.parametrize("judgment", [ReviewJudgment.FAIL, ReviewJudgment.UNREVIEWED])
def test_failed_or_unreviewed_criterion_hides_question_even_if_outcome_claims_clarification(
    render_case, judgment
):
    f = render_case
    judgments = list(f.evaluation.assessments)
    judgments[0] = judgments[0].model_copy(update={"judgment": judgment})
    replace_evaluation(f, f.evaluation.model_copy(update={"assessments": tuple(judgments)}))
    html = web._reviewed_result_html(f.gate, f.retained, None)
    assert "Reply withheld" in html and "project?" not in html and "Why it matters" not in html


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_gate",
        "wrong_result",
        "wrong_assessment",
        "held_phase",
        "wrong_context",
        "packet_hash",
        "missing_criterion",
        "supplied_reply",
    ],
)
def test_only_original_bound_delivery_result_and_validated_packet_can_show_gap(render_case, fault):
    f = render_case
    gate, retained, text = f.gate, f.retained, None
    if fault == "wrong_gate":
        gate = SimpleNamespace(**vars(f.gate))
    elif fault == "wrong_result":
        retained = replace(f.retained)
    elif fault == "wrong_assessment":
        gate._assessment = HistoryPublicationAssessmentV1.model_construct(evaluation=f.evaluation)
    elif fault == "held_phase":
        gate._phase = "HELD"
    elif fault == "wrong_context":
        gate._generation._request = f.request.model_copy(
            update={"task": f.request.task.model_copy(update={"task_id": uuid4()})}
        )
    elif fault == "packet_hash":
        retained = replace_evaluation(
            f, f.evaluation.model_copy(update={"packet_digest": "0" * 64})
        )
    elif fault == "missing_criterion":
        retained = replace_evaluation(
            f, f.evaluation.model_copy(update={"assessments": f.evaluation.assessments[:-1]})
        )
    else:
        text = "SENSITIVE HELD FULL REPLY<script>bad</script>"
    html = web._reviewed_result_html(gate, retained, text)
    assert (
        "Reply withheld" in html
        and "project?" not in html
        and "SENSITIVE" not in html
        and "<script>" not in html
    )


@pytest.mark.parametrize(
    "outcome",
    [
        v
        for v in ContextualOutcome
        if v not in (ContextualOutcome.REVIEWED_PASS, ContextualOutcome.NEEDS_CLARIFICATION)
    ],
)
def test_other_outcomes_never_display_retained_question_or_full_text(render_case, outcome):
    f = render_case
    html = web._reviewed_result_html(
        f.gate, replace(f.retained, outcome=outcome), "SENSITIVE FULL REPLY"
    )
    assert "Reply withheld" in html and "project?" not in html and "SENSITIVE" not in html


def test_untrusted_clarification_outcome_alone_is_no_display_grant(render_case):
    html = web._reviewed_result_html(
        None, SimpleNamespace(outcome=ContextualOutcome.NEEDS_CLARIFICATION), None
    )
    assert "Reply withheld" in html and "project?" not in html


def test_staging_only_handlers_and_protected_current_result_paths_ast_unchanged():
    stage = Path(__file__).parent.parent
    source = "src/zacai/interfaces/history_publication_web.py"
    base = Path("/private/tmp/caz-compact-recovery-window-20261013")
    if not (base / source).is_file():
        pytest.skip("staging-only comparison requires the frozen local baseline")

    def definitions(path):
        return {
            node.name: ast.dump(node, include_attributes=False)
            for node in ast.parse(path.read_text()).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name != "_reviewed_result_html"
        }

    assert definitions(stage / source) == definitions(base / source)


def test_conflict_accounts_quotes_and_later_gap_text_are_not_rendered(render_case):
    f = render_case
    quote = f.review.clarifications[0].quotes[0]
    split = len(quote.text) // 2
    first = quote.model_copy(update={"end": quote.start + split, "text": quote.text[:split]})
    second = quote.model_copy(update={"start": quote.start + split, "text": quote.text[split:]})
    conflict = EvidenceConflict(
        text="FIRST CONFLICT ACCOUNT versus SECOND CONFLICT ACCOUNT.",
        quotes=(first, second),
        question="Which dated account should guide the answer?",
        reason="The accounts imply different next steps.",
    )
    review = f.review.model_copy(update={"conflicts": (conflict,)})
    raw = encode_history_contextual_packet(
        review, f.request, builder_id=f.builder, created_at=f.request.task.event.observed_at
    )
    f.gate._packet_raw = raw
    retained = replace_evaluation(
        f, f.evaluation.model_copy(update={"packet_digest": content_hash_of(raw)})
    )
    html = web._reviewed_result_html(f.gate, retained, None)
    assert conflict.question in html and conflict.reason in html
    for hidden in (
        "FIRST CONFLICT ACCOUNT",
        "SECOND CONFLICT ACCOUNT",
        f.gap_text,
        f.quote_text,
        escape(f.quote_text),
        first.text,
        escape(first.text),
        second.text,
        escape(second.text),
        "SECOND HIDDEN QUESTION",
        f.overview,
    ):
        assert hidden not in html
    assert "Which &lt;img" not in html
    assert "<details" not in html and "<form" not in html
