"""Invented exact contextual packets; supplied judgments are never authority."""

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_contextual_review import fixture
from zacai.intelligence.contextual_evaluation import (
    ContextualAssessment,
    ContextualCriterion,
    ContextualEvaluation,
    ContextualOutcome,
    check_contextual_evaluation,
    decode_contextual_packet,
)
from zacai.intelligence.contextual_evaluation import (
    encode_contextual_packet as _encode,
)
from zacai.intelligence.contextual_review import Clarification, EvidenceConflict
from zacai.intelligence.review_evaluation import ReviewJudgment


def encode_contextual_packet(review, context):
    return _encode(
        review,
        context,
        builder_id=context.task.task_id,
        created_at=context.task.event.observed_at + timedelta(seconds=1),
    )


def evaluation(payload, context, judgment=ReviewJudgment.UNREVIEWED):
    return ContextualEvaluation(
        format="zac-contextual-evaluation-v1",
        evaluation_id=uuid4(),
        task_id=context.task.task_id,
        reviewer_id=uuid4(),
        builder_id=context.task.task_id,
        evaluated_at=context.task.event.observed_at + timedelta(seconds=1),
        packet_digest=hashlib.sha256(payload).hexdigest(),
        assessments=tuple(
            ContextualAssessment(criterion=c, judgment=judgment) for c in ContextualCriterion
        ),
    )


def test_exact_round_trip_preserves_context_and_visible_preview():
    context, review, _, _ = fixture()
    payload = encode_contextual_packet(review, context)
    restored = decode_contextual_packet(payload)
    assert restored.review == review
    assert restored.context() == context
    assert restored.rendered_preview.startswith("Contextual overview")
    assert encode_contextual_packet(restored.review, restored.context()) == payload


@pytest.mark.parametrize(
    "judgment,outcome",
    [
        (ReviewJudgment.PASS, ContextualOutcome.REVIEWED_PASS),
        (ReviewJudgment.FAIL, ContextualOutcome.NEEDS_REVISION),
        (ReviewJudgment.UNREVIEWED, ContextualOutcome.NEEDS_REVIEW),
    ],
)
def test_reports_supplied_independent_judgments_without_permission(judgment, outcome):
    context, review, _, _ = fixture()
    payload = encode_contextual_packet(review, context)
    record = evaluation(payload, context, judgment)
    assert check_contextual_evaluation(record, payload) == outcome
    assert not hasattr(record, "approved")


@pytest.mark.parametrize("gap_field", ["clarifications", "conflicts"])
def test_unresolved_question_cannot_become_pass_even_with_all_pass_judgments(gap_field):
    context, review, current, earlier = fixture()
    gap_type = Clarification if gap_field == "clarifications" else EvidenceConflict
    gap = gap_type(
        text="Project is uncertain.",
        quotes=(current,) if gap_field == "clarifications" else (current, earlier),
        question="Which project?",
        reason="This changes the relevant history.",
    )
    payload = encode_contextual_packet(review.model_copy(update={gap_field: (gap,)}), context)
    restored = decode_contextual_packet(payload)
    assert restored.rendered_preview.startswith("Context clarification needed")
    assert (
        check_contextual_evaluation(evaluation(payload, context, ReviewJudgment.PASS), payload)
        == ContextualOutcome.NEEDS_CLARIFICATION
    )


@pytest.mark.parametrize("unreviewed_criterion", list(ContextualCriterion))
@pytest.mark.parametrize("gap_field", ["clarifications", "conflicts"])
def test_unreviewed_question_waits_for_every_review_criterion(unreviewed_criterion, gap_field):
    context, review, current, earlier = fixture()
    gap_type = Clarification if gap_field == "clarifications" else EvidenceConflict
    gap = gap_type(
        text="Project is uncertain.",
        quotes=(current,) if gap_field == "clarifications" else (current, earlier),
        question="Which project?",
        reason="This changes the relevant history.",
    )
    payload = encode_contextual_packet(review.model_copy(update={gap_field: (gap,)}), context)
    record = evaluation(payload, context, ReviewJudgment.PASS)
    record = record.model_copy(
        update={
            "assessments": tuple(
                item.model_copy(update={"judgment": ReviewJudgment.UNREVIEWED})
                if item.criterion == unreviewed_criterion
                else item
                for item in record.assessments
            )
        }
    )
    assert check_contextual_evaluation(record, payload) == ContextualOutcome.NEEDS_REVIEW


@pytest.mark.parametrize("gap_field", ["clarifications", "conflicts"])
def test_failed_question_still_precedes_unfinished_review(gap_field):
    context, review, current, earlier = fixture()
    gap_type = Clarification if gap_field == "clarifications" else EvidenceConflict
    gap = gap_type(
        text="Project is uncertain.",
        quotes=(current,) if gap_field == "clarifications" else (current, earlier),
        question="Which project?",
        reason="This changes the relevant history.",
    )
    payload = encode_contextual_packet(review.model_copy(update={gap_field: (gap,)}), context)
    record = evaluation(payload, context)
    record = record.model_copy(
        update={
            "assessments": (
                record.assessments[0].model_copy(update={"judgment": ReviewJudgment.FAIL}),
                *record.assessments[1:],
            )
        }
    )
    assert check_contextual_evaluation(record, payload) == ContextualOutcome.NEEDS_REVISION


@pytest.mark.parametrize(
    "field", ["review", "context", "roles", "preview", "renderer", "version", "format"]
)
def test_component_tampering_and_version_defaulting_reject(field):
    context, review, _, _ = fixture()
    data = json.loads(encode_contextual_packet(review, context))
    if field == "review":
        data["review"]["overview"][0]["text"] = "Private sentinel."
    elif field == "context":
        data["task"]["instruction"] = "Private sentinel."
    elif field == "roles":
        data["related_source_ids"] = []
    elif field == "preview":
        data["rendered_preview"] = "Private sentinel."
    elif field == "renderer":
        data["renderer_version"] = True
    elif field == "version":
        del data["task"]["event"]["contract_version"]
    else:
        del data["format"]
    with pytest.raises(ValueError, match="^contextual packet unavailable or invalid$") as error:
        decode_contextual_packet(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    assert error.value.__context__ is None
    assert "Private sentinel" not in str(error.value)


def test_edited_and_rehashed_packet_cannot_reuse_independently_retained_evaluation():
    context, review, _, _ = fixture()
    payload = encode_contextual_packet(review, context)
    record = evaluation(payload, context, ReviewJudgment.PASS)
    changed = review.model_copy(
        update={
            "overview": (
                review.overview[0].model_copy(
                    update={"text": "Different supported draft wording."}
                ),
            )
        }
    )
    revised = encode_contextual_packet(changed, context)
    assert decode_contextual_packet(revised).review == changed
    with pytest.raises(ValueError):
        check_contextual_evaluation(record, revised)


@pytest.mark.parametrize(
    "change", ["missing", "duplicate", "same_reviewer", "builder", "task", "early"]
)
def test_invalid_or_mismatched_evaluation_rejects(change):
    context, review, _, _ = fixture()
    payload = encode_contextual_packet(review, context)
    record = evaluation(payload, context)
    if change == "missing":
        record = record.model_copy(update={"assessments": record.assessments[:-1]})
    elif change == "duplicate":
        record = record.model_copy(update={"assessments": (record.assessments[0],) * 10})
    elif change == "same_reviewer":
        record = record.model_copy(update={"reviewer_id": record.builder_id})
    elif change == "builder":
        record = record.model_copy(update={"builder_id": uuid4()})
    elif change == "task":
        record = record.model_copy(update={"task_id": uuid4()})
    else:
        record = record.model_copy(
            update={"evaluated_at": context.task.event.observed_at - timedelta(seconds=1)}
        )
    with pytest.raises(
        ValueError, match="^contextual evaluation unavailable or mismatched$"
    ) as error:
        check_contextual_evaluation(record, payload)
    assert error.value.__context__ is None


def test_noncanonical_and_duplicate_json_rejects():
    context, review, _, _ = fixture()
    payload = encode_contextual_packet(review, context)
    for bad in (
        b" " + payload,
        payload.replace(b'"renderer_version":1', b'"renderer_version":1,"renderer_version":1'),
    ):
        with pytest.raises(ValueError):
            decode_contextual_packet(bad)


def test_mutable_payload_rejected_and_capture_time_bound():
    context, review, _, _ = fixture()
    payload = encode_contextual_packet(review, context)
    with pytest.raises(ValueError):
        decode_contextual_packet(bytearray(payload))
    with pytest.raises(ValueError):
        check_contextual_evaluation(evaluation(payload, context), bytearray(payload))
    with pytest.raises(ValueError):
        _encode(
            review,
            context,
            builder_id=context.task.task_id,
            created_at=context.task.event.observed_at - timedelta(seconds=1),
        )
    record = evaluation(payload, context).model_copy(
        update={"evaluated_at": context.task.event.observed_at}
    )
    with pytest.raises(ValueError):
        check_contextual_evaluation(record, payload)


def test_fail_precedes_held_status():
    context, review, current, _ = fixture()
    gap = Clarification(
        text="Project unclear.",
        quotes=(current,),
        question="Which project?",
        reason="Project choice changes context.",
    )
    payload = encode_contextual_packet(
        review.model_copy(update={"overview": (), "clarifications": (gap,)}), context
    )
    assert (
        check_contextual_evaluation(evaluation(payload, context, ReviewJudgment.FAIL), payload)
        == ContextualOutcome.NEEDS_REVISION
    )


def fixed_packet(monkeypatch):
    from uuid import UUID

    from tests import test_review_evaluation, test_review_generation

    counter = iter(range(1, 100))

    def fixed_uuid():
        return UUID(int=next(counter))

    monkeypatch.setattr(test_review_generation, "uuid4", fixed_uuid)
    monkeypatch.setattr(test_review_evaluation, "uuid4", fixed_uuid)
    context, review, _, _ = fixture()
    return encode_contextual_packet(review, context)


def test_fixed_packet_digest_and_preview_require_explicit_version_review(monkeypatch):
    payload = fixed_packet(monkeypatch)
    assert (
        hashlib.sha256(payload).hexdigest()
        == "ec0ec819dafbf8f41c99a8d0aae700501fc56df77e138d85f82f4463cefdb59e"
    )
    assert decode_contextual_packet(payload).rendered_preview == (
        "Contextual overview\n"
        "Reporting validation remains underway.\n"
        "Candidate context: Earlier work reproduced the failure.\n"
        "Possible: This may continue the reporting investigation.\n"
        "\nDecisions and commitments\n"
        "- Commitment: Alex will test the reporting fix. (proposed owner: Alex)\n"
        "\nRisks and follow-ups\n"
        "None recorded in this draft; completeness still needs review."
    )


def test_packet_decodes_across_process_hash_seeds():
    import base64
    import os
    import subprocess
    import sys

    context, review, _, _ = fixture()
    task = context.task.model_copy(
        update={"required_capabilities": frozenset({"context", "review"})}
    )
    context = type(context)(task, context.meeting_source_id, context.related_source_ids)
    payload = encode_contextual_packet(review, context)
    script = (
        "import base64,hashlib,sys; "
        "from zacai.intelligence.contextual_evaluation import decode_contextual_packet,encode_contextual_packet; "
        "p=decode_contextual_packet(base64.b64decode(sys.argv[1])); "
        "print(hashlib.sha256(encode_contextual_packet(p.review,p.context(),"
        "builder_id=p.builder_id,created_at=p.created_at)).hexdigest())"
    )
    for seed in ("1", "99"):
        result = subprocess.run(
            [sys.executable, "-c", script, base64.b64encode(payload).decode()],
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.stdout.strip() == hashlib.sha256(payload).hexdigest()
