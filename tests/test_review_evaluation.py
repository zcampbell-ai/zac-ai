"""Independent-review binding tests using invented evidence, no inference."""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_review_generation import draft, synthetic_context
from zacai.intelligence.review_evaluation import (
    CriterionAssessment,
    EvaluationOutcome,
    ReviewCriterion,
    ReviewEvaluation,
    ReviewJudgment,
    check_review_evaluation,
    review_evaluation_digests,
)
from zacai.intelligence.review_generation import prepare_review_request, resolve_review_draft


def packet(judgment=ReviewJudgment.UNREVIEWED):
    context = synthetic_context()
    review = resolve_review_draft(draft(), prepare_review_request(context))
    output_digest, context_digest = review_evaluation_digests(review, context)
    evaluation = ReviewEvaluation(
        evaluation_id=uuid4(),
        task_id=context.task.task_id,
        reviewer_id=uuid4(),
        builder_id=uuid4(),
        evaluated_at=context.task.event.observed_at + timedelta(seconds=1),
        review_digest=output_digest,
        context_digest=context_digest,
        assessments=tuple(
            CriterionAssessment(criterion=c, judgment=judgment) for c in ReviewCriterion
        ),
    )
    return context, review, evaluation


@pytest.mark.parametrize(
    "judgment,outcome",
    [
        (ReviewJudgment.PASS, EvaluationOutcome.REVIEWED_PASS),
        (ReviewJudgment.FAIL, EvaluationOutcome.NEEDS_REVISION),
        (ReviewJudgment.UNREVIEWED, EvaluationOutcome.NEEDS_REVIEW),
    ],
)
def test_exact_complete_review_reports_judgments_without_authority(judgment, outcome):
    context, review, evaluation = packet(judgment)
    assert check_review_evaluation(evaluation, review, context) == outcome
    assert not hasattr(evaluation, "approved")


def test_fail_precedes_unreviewed():
    context, review, evaluation = packet()
    data = evaluation.model_dump()
    data["assessments"][0]["judgment"] = ReviewJudgment.FAIL
    revised = ReviewEvaluation.model_validate(data)
    assert check_review_evaluation(revised, review, context) == EvaluationOutcome.NEEDS_REVISION


@pytest.mark.parametrize("change", ["missing", "duplicate", "same_reviewer", "extra_authority"])
def test_incomplete_duplicate_or_nonindependent_inventory_rejects(change):
    _, _, evaluation = packet()
    data = evaluation.model_dump()
    if change == "missing":
        data["assessments"] = data["assessments"][:-1]
    elif change == "duplicate":
        data["assessments"] = (data["assessments"][0],) * 8
    elif change == "same_reviewer":
        data["reviewer_id"] = data["builder_id"]
    else:
        data["approved"] = True
    with pytest.raises(ValueError):
        ReviewEvaluation.model_validate(data)


@pytest.mark.parametrize("field", ["task_id", "context_digest", "review_digest", "evaluated_at"])
def test_mismatched_evaluation_is_not_reused(field):
    context, review, evaluation = packet(ReviewJudgment.PASS)
    changes = {
        "task_id": uuid4(),
        "context_digest": "f" * 64,
        "review_digest": "f" * 64,
        "evaluated_at": context.task.event.observed_at - timedelta(seconds=1),
    }
    bad = evaluation.model_copy(update={field: changes[field]})
    with pytest.raises(ValueError, match="unavailable or mismatched"):
        check_review_evaluation(bad, review, context)


def test_edited_draft_invalidates_previous_pass():
    context, review, evaluation = packet(ReviewJudgment.PASS)
    data = review.model_dump()
    data["summary"][0]["text"] = "The reporting fix is complete."
    altered = type(review).model_validate(data)
    # Structurally valid exact quotes cannot prove this semantic overstatement.
    with pytest.raises(ValueError):
        check_review_evaluation(evaluation, altered, context)


def test_changed_context_invalidates_previous_pass():
    context, review, evaluation = packet(ReviewJudgment.PASS)
    data = context.task.model_dump()
    data["instruction"] = "Different trusted instruction."
    from dataclasses import replace

    altered = replace(context, task=type(context.task).model_validate(data))
    with pytest.raises(ValueError):
        check_review_evaluation(evaluation, review, altered)


def test_invalid_private_prose_error_is_sanitized():
    context, review, evaluation = packet()
    bad = review.model_copy(update={"summary": ({"text": "PRIVATE unrelated secret prose"},)})
    with pytest.raises(ValueError) as error:
        check_review_evaluation(evaluation, bad, context)
    assert str(error.value) == "meeting review evaluation unavailable or mismatched"
    assert error.value.__suppress_context__
