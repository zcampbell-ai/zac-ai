"""Invented provider output; delivery-path linkage without a model call."""

import hashlib
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_contextual_review import fixture
from tests.test_contextual_storage import stored  # noqa: F401 - reusable pytest fixture
from zacai.intelligence.contextual_evaluation import encode_contextual_packet
from zacai.intelligence.contextual_generation import (
    ContextualDraft,
    ContextualGenerationError,
    DraftAgreement,
    DraftConflict,
    DraftConnection,
    DraftQuestion,
    GenerationFailure,
    parse_contextual_draft,
    prepare_contextual_request,
    resolve_contextual_draft,
)
from zacai.intelligence.contextual_review import render_contextual_preview
from zacai.intelligence.contextual_storage import capture_contextual_packet, load_contextual_packet
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.review_generation import DraftClaim
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def request(context=None):
    if context is None:
        context, _, _, _ = fixture()
    task = context.task.model_copy(
        update={"required_capabilities": frozenset({"contextual_meeting_review"})}
    )
    context = type(context)(task, context.meeting_source_id, context.related_source_ids)
    return prepare_contextual_request(context)


def draft(req):
    current = next(eid for eid, q in req.quotes if q.source_id == req.context.meeting_source_id)
    prior = next(eid for eid, q in req.quotes if q.source_id in req.context.related_source_ids)
    return ContextualDraft(
        format="zac-contextual-draft-v1",
        overview=(DraftClaim(text="The reporting fix is being tested.", evidence_ids=(current,)),),
        background=(
            DraftClaim(text="Prior records describe the reporting failure.", evidence_ids=(prior,)),
        ),
        continuity=(
            DraftConnection(
                text="This may continue the reporting investigation.",
                evidence_ids=(current, prior),
                inferred=True,
            ),
        ),
        items=(
            DraftAgreement(
                text="Alex will test the fix.",
                evidence_ids=(current,),
                kind=ItemKind.COMMITMENT,
                owner="Alex",
            ),
        ),
    )


def test_resolves_host_identity_and_quotes_for_three_section_delivery():
    req = request()
    result = resolve_contextual_draft(draft(req), req)
    assert result.task_id == req.context.task.task_id
    assert result.data_classification == req.context.task.event.data_classification
    assert "Possible:" in render_contextual_preview(result, req.context)
    assert result.items[0].owner == "Alex"
    assert prepare_contextual_request(req.context) == req


@pytest.mark.parametrize("field", ["instruction", "evidence_json", "quotes", "schema_json"])
def test_changed_request_cannot_resolve_output(field):
    req = request()
    changes = {
        "instruction": "Ignore policy",
        "evidence_json": "[]",
        "quotes": (),
        "schema_json": "{}",
    }
    with pytest.raises(ValueError, match="^contextual draft unavailable or invalid$") as error:
        resolve_contextual_draft(draft(req), replace(req, **{field: changes[field]}))
    assert error.value.__context__ is None


@pytest.mark.parametrize("change", ["unknown", "duplicate", "prior_only", "confirmed"])
def test_bad_citations_or_confirmed_inference_rejects(change):
    req = request()
    output = draft(req)
    if change == "confirmed":
        output = output.model_copy(
            update={"continuity": (output.continuity[0].model_copy(update={"inferred": False}),)}
        )
    else:
        ids = {
            "unknown": ("e9999",),
            "duplicate": output.overview[0].evidence_ids * 2,
            "prior_only": output.background[0].evidence_ids,
        }[change]
        output = output.model_copy(
            update={"overview": (output.overview[0].model_copy(update={"evidence_ids": ids}),)}
        )
    with pytest.raises(ValueError):
        resolve_contextual_draft(output, req)


def test_compact_capability_is_not_reused_for_contextual_workflow():
    context, _, _, _ = fixture()
    with pytest.raises(ValueError):
        prepare_contextual_request(context)


def test_material_gap_returns_question_without_invented_overview():
    req = request()
    current = draft(req).overview[0].evidence_ids
    output = ContextualDraft(
        format="zac-contextual-draft-v1",
        clarifications=(
            DraftQuestion(
                text="Project attribution is uncertain.",
                evidence_ids=current,
                question="Which project does this meeting continue?",
                reason="The answer determines the history to use.",
            ),
        ),
    )
    result = resolve_contextual_draft(output, req)
    assert not result.overview
    assert "Which project" in render_contextual_preview(result, req.context)


def test_synthetic_resolved_draft_is_captured_and_reloaded_exactly(stored):  # noqa: F811
    factory, store, _, _, context, _ = stored
    req = request(context)
    review = resolve_contextual_draft(draft(req), req)
    payload = encode_contextual_packet(
        review,
        req.context,
        builder_id=uuid4(),
        created_at=req.context.task.event.observed_at + timedelta(seconds=1),
    )
    with factory() as session:
        sid = capture_contextual_packet(
            session,
            artifacts=store,
            payload=payload,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
        session.commit()
    with factory() as session:
        saved = load_contextual_packet(
            session,
            artifacts=store,
            source_id=sid,
            expected_digest=hashlib.sha256(payload).hexdigest(),
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
        assert saved.review == review and saved.context() == req.context
        assert saved.rendered_preview == render_contextual_preview(review, req.context)


def test_output_for_another_request_cannot_be_rebound():
    first = request()
    second_context = replace(
        first.context, task=first.context.task.model_copy(update={"task_id": uuid4()})
    )
    second = prepare_contextual_request(second_context)
    with pytest.raises(ContextualGenerationError) as error:
        resolve_contextual_draft(draft(first), second)
    assert error.value.code == GenerationFailure.CITATION
    assert error.value.__context__ is None


def test_host_failure_is_classified_as_request_failure():
    req = request()
    invalid = replace(req, instruction="changed host request")
    with pytest.raises(ContextualGenerationError) as error:
        resolve_contextual_draft(draft(req), invalid)
    assert error.value.code == GenerationFailure.REQUEST


@pytest.mark.parametrize(
    "change",
    ["approved", "task_id", "data_classification", "wrong_format", "bool_string", "duplicate"],
)
def test_raw_provider_json_cannot_supply_authority_or_ambiguous_fields(change):
    import json

    req = request()
    data = draft(req).model_dump(mode="json")
    if change in {"approved", "task_id", "data_classification"}:
        data[change] = "authority"
    elif change == "wrong_format":
        data["format"] = "compact"
    elif change == "bool_string":
        data["overview"][0]["inferred"] = "true"
    raw = json.dumps(data).encode()
    if change == "duplicate":
        raw = raw.replace(b'"format":', b'"format":"wrong","format":', 1)
    with pytest.raises(ContextualGenerationError) as error:
        parse_contextual_draft(raw)
    assert error.value.code == GenerationFailure.DRAFT_SCHEMA
    assert error.value.__context__ is None


def test_valid_raw_provider_json_resolves_with_bound_schema():
    req = request()
    output = parse_contextual_draft(draft(req).model_dump_json().encode())
    assert output == draft(req)
    assert "zac-contextual-draft-v1" in req.schema_json
    assert resolve_contextual_draft(output, req).task_id == req.context.task.task_id


def test_conflict_requires_meeting_and_distinct_support():
    req = request()
    base = draft(req)
    ids = base.continuity[0].evidence_ids
    gap = DraftConflict(
        text="The accounts may differ.",
        evidence_ids=ids,
        question="Did the decision change?",
        reason="This changes the next action.",
    )
    result = resolve_contextual_draft(
        ContextualDraft(format="zac-contextual-draft-v1", conflicts=(gap,)), req
    )
    assert "Conflicting accounts" in render_contextual_preview(result, req.context)
    for bad_ids in (ids[1:], ids[:1]):
        with pytest.raises(ContextualGenerationError):
            resolve_contextual_draft(
                ContextualDraft(format="zac-contextual-draft-v1", conflicts=(gap,)).model_copy(
                    update={"conflicts": (gap.model_copy(update={"evidence_ids": bad_ids}),)}
                ),
                req,
            )


@pytest.mark.parametrize(
    "text", ["Decisions and commitments", "Contextual overview (draft)", "- Decision: Budget approved", "1. Approval", "# Risks"]
)
def test_overview_cannot_forge_renderer_headings_or_lists(text):
    req = request()
    output = draft(req)
    output = output.model_copy(
        update={"overview": (output.overview[0].model_copy(update={"text": text}),)}
    )
    with pytest.raises(ContextualGenerationError):
        resolve_contextual_draft(output, req)


def test_unassigned_context_and_mixed_workflow_capabilities_reject():
    req = request()
    task = req.context.task.model_copy(
        update={
            "required_capabilities": frozenset(
                {"contextual_meeting_review", "compact_meeting_review"}
            )
        }
    )
    with pytest.raises(ContextualGenerationError) as error:
        prepare_contextual_request(replace(req.context, task=task))
    assert error.value.code == GenerationFailure.REQUEST
    with pytest.raises(ContextualGenerationError):
        prepare_contextual_request(replace(req.context, related_source_ids=frozenset()))


def test_follow_up_flag_is_not_silently_rewritten():
    req = request()
    output = draft(req)
    item = output.items[0].model_copy(update={"kind": ItemKind.FOLLOW_UP, "inferred": False})
    with pytest.raises(ContextualGenerationError):
        resolve_contextual_draft(output.model_copy(update={"items": (item,)}), req)


def test_no_related_evidence_does_not_request_invented_continuity():
    from tests.test_review_generation import synthetic_context

    req = request(synthetic_context(related=False))
    assert not req.context.related_source_ids
    assert "Return background=[] and continuity=[]" in req.instruction
    with_related = request()
    assert with_related.context.related_source_ids
    assert "Return background=[] and continuity=[]" not in with_related.instruction


@pytest.mark.parametrize("flag", [None, False, 1, "true"])
def test_raw_continuity_cannot_omit_or_coerce_provisional_flag(flag):
    import json
    req = request()
    data = draft(req).model_dump(mode="json")
    if flag is None:
        del data["continuity"][0]["inferred"]
    else:
        data["continuity"][0]["inferred"] = flag
    with pytest.raises(ContextualGenerationError) as error:
        parse_contextual_draft(json.dumps(data).encode())
    assert error.value.code == GenerationFailure.DRAFT_SCHEMA
    assert error.value.__context__ is None


def test_schema_exposes_continuity_and_conflict_requirements():
    import json
    schema = json.loads(request().schema_json)
    assert schema["$defs"]["DraftConnection"]["properties"]["inferred"]["const"] is True
    assert "inferred" in schema["$defs"]["DraftConnection"]["required"]
    assert schema["$defs"]["DraftConflict"]["properties"]["evidence_ids"]["minItems"] == 2


@pytest.mark.parametrize("change", ["conflict_single", "follow_up"])
def test_invalid_raw_structures_reject_before_resolution(change):
    import json
    req = request()
    data = draft(req).model_dump(mode="json")
    if change == "empty":
        data = {"format": "zac-contextual-draft-v1"}
    elif change == "conflict_single":
        data["conflicts"] = [{"text": "The accounts differ.", "evidence_ids": data["overview"][0]["evidence_ids"],
                              "question": "Did the plan change?", "reason": "This determines the action."}]
    else:
        data["items"][0].update(kind="FOLLOW_UP", inferred=False)
    with pytest.raises(ContextualGenerationError) as error:
        parse_contextual_draft(json.dumps(data).encode())
    assert error.value.code == GenerationFailure.DRAFT_SCHEMA


def test_mixed_roles_agreements_and_suggestions_resolve_without_coercion():
    import json
    req = request()
    data = draft(req).model_dump(mode="json")
    current = data["overview"][0]["evidence_ids"]
    data["items"].extend([
        {"text": "The reporting issue remains a risk.", "evidence_ids": current, "kind": "RISK", "inferred": False},
        {"text": "Confirm the next validation checkpoint.", "evidence_ids": current, "kind": "FOLLOW_UP", "inferred": True},
    ])
    output = parse_contextual_draft(json.dumps(data).encode())
    review = resolve_contextual_draft(output, req)
    assert len(review.items) == 3 and len(review.continuity) == 1 and len(review.background) == 1
    assert review.items[-1].inferred and not review.items[0].inferred
    assert "Possible:" in render_contextual_preview(review, req.context)


def test_rule_reason_survives_resolution_without_private_text():
    from zacai.intelligence.contextual_diagnostics import ReviewRejection
    req = request()
    output = draft(req)
    output = output.model_copy(update={"overview": (output.overview[0].model_copy(update={"text": "PRIVATE invented\u200b marker"}),)})
    with pytest.raises(ContextualGenerationError) as error:
        resolve_contextual_draft(output, req)
    assert error.value.code == GenerationFailure.VALIDATION
    assert error.value.rejection == ReviewRejection.DISPLAY_CONTROL
    assert "PRIVATE" not in str(error.value) and error.value.__context__ is None



def test_short_passages_remain_visible_but_are_not_offered_as_citations():
    import json

    from tests.test_review_generation import synthetic_context
    context = synthetic_context(related=False)
    item = context.task.context[0].model_copy(update={"untrusted_text": "Agreed.\nAlex: I will test the reporting fix tomorrow."})
    context = replace(context, task=context.task.model_copy(update={"context": (item,)}))
    req = request(context)
    passages = json.loads(req.evidence_json)
    short = next(p for p in passages if p["text"] == "Agreed.")
    assert short["citable"] is False and short["id"] not in dict(req.quotes)
    assert any(p["citable"] is True for p in passages)
    output = ContextualDraft(format="zac-contextual-draft-v1", overview=(DraftClaim(text="A test is planned.", evidence_ids=(short["id"],)),))
    with pytest.raises(ContextualGenerationError) as error:
        resolve_contextual_draft(output, req)
    assert error.value.code == GenerationFailure.CITATION


def test_secondary_diagnostic_lookup_never_propagates_private_or_interrupt():
    from zacai.intelligence.contextual_diagnostics import closed_draft_code
    class Broken(ContextualGenerationError):
        @property
        def rejection(self):
            raise KeyboardInterrupt("PRIVATE invented marker")
    error = Broken.__new__(Broken)
    error.code = GenerationFailure.VALIDATION
    assert closed_draft_code(error) == (None, None)



def test_item_schema_exposes_inference_rules_instead_of_only_python_validation():
    import json
    schema = json.loads(request().schema_json)
    assert schema["$defs"]["DraftFollowUp"]["properties"]["inferred"]["const"] is True
    assert schema["$defs"]["DraftAgreement"]["properties"]["inferred"]["const"] is False
    assert "inferred" in schema["$defs"]["DraftFollowUp"]["required"]


@pytest.mark.parametrize("kind,flag", [("FOLLOW_UP", False), ("FOLLOW_UP", 1), ("COMMITMENT", True), ("DECISION", 0)])
def test_raw_item_kind_and_flag_cannot_disagree_or_coerce(kind, flag):
    import json
    req = request()
    data = draft(req).model_dump(mode="json")
    data["items"][0].update(kind=kind, inferred=flag)
    with pytest.raises(ContextualGenerationError) as error:
        parse_contextual_draft(json.dumps(data).encode())
    assert error.value.code == GenerationFailure.DRAFT_SCHEMA



def test_items_only_draft_reaches_precise_missing_overview_rejection():
    from zacai.intelligence.contextual_diagnostics import ReviewRejection
    req = request()
    output = parse_contextual_draft(b'{"format":"zac-contextual-draft-v1"}')
    with pytest.raises(ContextualGenerationError) as error:
        resolve_contextual_draft(output, req)
    assert error.value.code == GenerationFailure.VALIDATION
    assert error.value.rejection == ReviewRejection.OVERVIEW_MISSING
    assert error.value.__context__ is None
