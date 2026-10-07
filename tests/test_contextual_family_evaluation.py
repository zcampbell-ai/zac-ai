"""Invented structural supplied judgments, never authenticated semantic review."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_history_contextual_codec import prepared as history_prepared  # noqa: F401
from tests.test_history_contextual_codec import review_for
from tests.test_history_fragment_contextual_codec import request as fragment_request
from tests.test_native_context_sidecar import fixture as native_fixture  # noqa: F401
from tests.test_native_context_sidecar import request as native_request
from tests.test_native_context_sidecar import retained_project
from tests.test_native_context_sidecar import review as native_review
from tests.test_native_evidence_context import choice
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import contextual_evaluation as m
from zacai.intelligence import history_contextual_codec as h
from zacai.intelligence import history_fragment_contextual_codec as f
from zacai.intelligence.contextual_generation import prepare_native_contextual_request
from zacai.intelligence.contextual_review import Clarification, EvidenceConflict
from zacai.intelligence.meeting_review import Quote
from zacai.intelligence.review_evaluation import ReviewJudgment as J


@pytest.fixture(params=["native", "history", "fragment"])
def family(request):
    kind = request.param
    if kind == "native":
        native = request.getfixturevalue("native_fixture")
        value = prepare_native_contextual_request(
            retained_project(native, (choice(native[2][-1], "Invented private body"),))
        )
        context, review = value.context, native_review(value)
        encoder, decoder, checker = (
            m.encode_native_contextual_packet,
            m.decode_native_contextual_packet,
            m.check_native_contextual_evaluation,
        )
    elif kind == "history":
        value = request.getfixturevalue("history_prepared")[-1]
        context, review = value.context(), review_for(value)
        encoder, decoder, checker = (
            h.encode_history_contextual_packet,
            h.decode_history_contextual_packet,
            m.check_history_contextual_evaluation,
        )
    else:
        value = fragment_request(True)
        context, review = value.context(), review_for(value)
        encoder, decoder, checker = (
            f.encode_history_fragment_contextual_packet,
            f.decode_history_fragment_contextual_packet,
            m.check_history_fragment_contextual_evaluation,
        )

    def encode(review=review, builder=None, created=None):
        return encoder(
            review,
            value,
            builder_id=builder or uuid4(),
            created_at=created or context.task.event.observed_at + timedelta(seconds=1),
        )

    raw = encode()
    packet = decoder(raw)
    return kind, value, context, review, encode, decoder, checker, raw, packet


def assessment(family, judgment=J.UNREVIEWED):
    _, _, context, _, _, _, _, raw, packet = family
    return m.ContextualEvaluation(
        format="zac-contextual-evaluation-v1",
        evaluation_id=uuid4(),
        task_id=context.task.task_id,
        reviewer_id=uuid4(),
        builder_id=packet.builder_id,
        evaluated_at=packet.created_at,
        packet_digest=content_hash_of(raw),
        assessments=tuple(
            m.ContextualAssessment(criterion=c, judgment=judgment) for c in m.ContextualCriterion
        ),
    )


def held(checker, record, raw):
    with pytest.raises(ValueError) as caught:
        checker(record, raw)
    assert caught.value.__cause__ is caught.value.__context__ is None
    assert str(caught.value).endswith("contextual evaluation unavailable or mismatched")


@pytest.mark.parametrize(
    "judgment,outcome",
    [
        (J.PASS, m.ContextualOutcome.REVIEWED_PASS),
        (J.FAIL, m.ContextualOutcome.NEEDS_REVISION),
        (J.UNREVIEWED, m.ContextualOutcome.NEEDS_REVIEW),
    ],
)
def test_each_family_reports_supplied_judgments_only(family, judgment, outcome):
    assert family[6](assessment(family, judgment), family[7]) is outcome
    assert family[5](family[7]) == family[8]
    with pytest.raises(ValueError):
        m.check_contextual_evaluation(assessment(family, judgment), family[7])


@pytest.mark.parametrize("gap", ["clarifications", "conflicts"])
@pytest.mark.parametrize(
    "judgment,outcome",
    [
        (J.PASS, m.ContextualOutcome.NEEDS_CLARIFICATION),
        (J.FAIL, m.ContextualOutcome.NEEDS_REVISION),
        (J.UNREVIEWED, m.ContextualOutcome.NEEDS_REVIEW),
    ],
)
def test_exact_conflict_precedence(family, gap, judgment, outcome):
    kind, value, context, review, encode, decoder, checker, _, packet = family
    meeting = review.overview[0].quotes[0]
    quotes = (meeting,)
    if gap == "conflicts":
        tail = context.task.context[-1]
        if kind == "history":
            e = value.sidecar.entries[0]
            start, end = e.context_character_start, e.context_character_end
        else:
            start, end = 0, len(tail.untrusted_text)
        quotes += (
            Quote(
                source_id=tail.reference.source_id,
                start=start,
                end=end,
                text=tail.untrusted_text[start:end],
            ),
        )
    cls = Clarification if gap == "clarifications" else EvidenceConflict
    issue = cls(
        text="A material relationship requires confirmation.",
        quotes=quotes,
        question="Which interpretation applies?",
        reason="The answer changes this task.",
    )
    altered = encode(review.model_copy(update={gap: (issue,)}), builder=packet.builder_id)
    replacement = (*family[:7], altered, decoder(altered))
    assert checker(assessment(replacement, judgment), altered) is outcome


@pytest.mark.parametrize("fault", ["metadata", "header"])
def test_stale_components_metadata_or_header_target(family, fault):
    kind, _, _, _, _, decoder, checker, raw, _ = family
    data = json.loads(raw)
    if fault == "header":
        data["rendered_preview"] += "\nInvented altered attribution."
    elif kind == "native":
        data["noncitable_metadata"]["entries"][0]["relevance_reason"] += " changed"
    else:
        request_data = json.loads(data["request_json"])
        if kind == "history":
            request_data["sidecar"]["entries"][0]["historical_role"] = "ASSISTANT"
        else:
            request_data["observation"]["full_decoded_text_hash"] = "0" * 64
        data["request_json"] = canonical_bytes(request_data).decode()
    changed = canonical_bytes(data)
    assert changed != raw
    with pytest.raises(ValueError):
        decoder(changed)
    held(checker, assessment(family), changed)


def test_fully_canonical_changed_packet_cannot_reuse_old_assessment(family):
    _, _, _, _, encode, decoder, checker, raw, packet = family
    changed = encode(
        builder=packet.builder_id, created=packet.created_at + timedelta(microseconds=1)
    )
    assert changed != raw and decoder(changed).created_at > packet.created_at
    # Chronology is valid for BOTH packets; only old exact-byte digest is stale.
    record = assessment(family).model_copy(update={"evaluated_at": decoder(changed).created_at})
    assert record.builder_id == decoder(changed).builder_id
    held(checker, record, changed)


@pytest.mark.parametrize(
    "fault", ["task", "builder", "digest", "date", "reviewer", "missing", "duplicate"]
)
def test_malformed_or_mismatched_assessment_model_copy_revalidated(family, fault):
    record = assessment(family)
    changes = {}
    if fault in {"task", "builder"}:
        changes[fault + "_id"] = uuid4()
    elif fault == "digest":
        changes["packet_digest"] = "0" * 64
    elif fault == "date":
        changes["evaluated_at"] = record.evaluated_at - timedelta(microseconds=1)
    elif fault == "reviewer":
        changes["reviewer_id"] = record.builder_id
    elif fault == "missing":
        changes["assessments"] = record.assessments[:-1]
    else:
        changes["assessments"] = (record.assessments[0],) * 10
    held(family[6], record.model_copy(update=changes), family[7])


@pytest.mark.parametrize("fault", ["bytearray", "oversize", "duplicate-json", "noncanonical"])
def test_closed_byte_resource_and_json_inputs(family, fault):
    raw = family[7]
    changed = {
        "bytearray": lambda: bytearray(raw),
        "oversize": lambda: b" " * (8 * 1024 * 1024 + 1),
        "duplicate-json": lambda: b'{"format":"wrong",' + raw[1:],
        "noncanonical": lambda: json.dumps(json.loads(raw)).encode(),
    }[fault]()
    held(family[6], assessment(family), changed)


def test_wrong_family_explicit_functions_never_dispatch_any_decoder(family):
    for checker in (
        m.check_contextual_evaluation,
        m.check_native_contextual_evaluation,
        m.check_history_contextual_evaluation,
        m.check_history_fragment_contextual_evaluation,
    ):
        if checker is family[6]:
            continue
        with pytest.raises(ValueError):
            checker(assessment(family), family[7])


def test_native_rebuilt_metadata_still_binds_exact_full_packet(native_fixture):  # noqa: F811
    first = native_request(native_fixture)
    second = native_request(native_fixture, relevance_reason="A different explicit host relevance.")
    assert first.sidecar_json != second.sidecar_json

    def raw(value):
        return m.encode_native_contextual_packet(
            native_review(value),
            value,
            builder_id=uuid4(),
            created_at=value.context.task.event.observed_at + timedelta(seconds=1),
        )

    a, b = raw(first), raw(second)
    pa, pb = m.decode_native_contextual_packet(a), m.decode_native_contextual_packet(b)
    assert pa.noncitable_metadata != pb.noncitable_metadata
    record = m.ContextualEvaluation(
        format="zac-contextual-evaluation-v1",
        evaluation_id=uuid4(),
        task_id=pb.task.task_id,
        reviewer_id=uuid4(),
        builder_id=pb.builder_id,
        evaluated_at=pb.created_at,
        packet_digest=content_hash_of(a),
        assessments=tuple(
            m.ContextualAssessment(criterion=c, judgment=J.UNREVIEWED)
            for c in m.ContextualCriterion
        ),
    )
    held(m.check_native_contextual_evaluation, record, b)


@pytest.mark.parametrize("fault", ["task", "context"])
def test_packet_component_mutations_reach_closed_codec(family, fault):
    kind, _, _, _, _, decoder, checker, raw, _ = family
    data = json.loads(raw)
    request_data = data if kind == "native" else json.loads(data["request_json"])
    if fault == "task":
        request_data["task"]["task_id"] = str(uuid4())
    else:
        request_data["task"]["context"][0]["untrusted_text"] += " changed"
    if kind != "native":
        data["request_json"] = canonical_bytes(request_data).decode()
    changed = canonical_bytes(data)
    assert changed != raw
    with pytest.raises(ValueError):
        decoder(changed)
    held(checker, assessment(family), changed)


def test_mixed_failed_and_unreviewed_criteria_failure_wins(family):
    record = assessment(family, J.PASS)
    values = list(record.assessments)
    values[0] = values[0].model_copy(update={"judgment": J.FAIL})
    values[1] = values[1].model_copy(update={"judgment": J.UNREVIEWED})
    record = record.model_copy(update={"assessments": tuple(values)})
    assert family[6](record, family[7]) is m.ContextualOutcome.NEEDS_REVISION


def test_junk_assessment_has_fixed_no_private_chain(family):
    held(family[6], None, family[7])
