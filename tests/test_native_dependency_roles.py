"""Causal native structure checks, invented retained SQLite fixture, no permission."""

import json
from uuid import uuid4, uuid5

import pytest

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_derivation_admission import projection
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import contextual_generation as g
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext


def derived(p, r, *, original=None, provenance=None):
    original = original or p.original_task
    if provenance is None:
        provenance = (
            *original.event.provenance,
            *r.context.task.event.provenance[len(p.original_task.event.provenance) :],
        )
    data = original.model_dump(mode="json")
    data["required_capabilities"] = sorted(data["required_capabilities"])
    original_json = canonical_bytes(data).decode()
    tail = r.context.task.context[len(p.original_task.context) :]
    derivation = canonical_bytes(
        {
            "format": "zac-native-evidence-projection-v1",
            "original_task": json.loads(original_json),
            "metadata": [m.model_dump(mode="json") for m in r.sidecar.entries],
            "provenance": [ref.model_dump(mode="json") for ref in provenance],
            "selected_text": [i.untrusted_text for i in tail],
            "native_dependency_roles": g._native_dependency_roles(
                r.batch_reference, r.approval_reference, r.proposal_reference, r.artifact_references
            ),
        }
    )
    data = original.model_dump()
    data["context"] = (*original.context, *tail)
    data["event"] = r.context.task.event.model_dump()
    data["event"]["provenance"] = provenance
    data["event"]["data_classification"] = original.event.data_classification
    data["event"]["event_id"] = uuid5(
        original.event.event_id, "native-evidence-projection/" + content_hash_of(derivation)
    )
    data["task_id"] = uuid5(
        original.task_id, "native-evidence-projection-task/" + content_hash_of(derivation)
    )
    context = ReviewContext(
        IntelligenceTask.model_validate(data),
        r.context.meeting_source_id,
        frozenset(
            i.reference.source_id
            for i in data["context"]
            if i.reference.source_id != r.context.meeting_source_id
        ),
    )
    return context, original_json


def test_proposal_role_cannot_swap_to_nonquoted_batch(fixture, prepared):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    quoted = {i.reference.source_id for i in r.context.task.context}
    other = next(
        ref
        for ref in r.context.task.event.provenance
        if ref.source_id not in quoted
        and ref != r.proposal_reference
        and ref not in p.original_task.event.provenance
    )
    with pytest.raises(ValueError):
        g.rebuild_native_contextual_request(
            r.context,
            r.sidecar,
            original_task_json=r.original_task_json,
            proposal_reference=other,
            batch_reference=r.batch_reference,
            approval_reference=r.approval_reference,
            artifact_references=r.artifact_references,
        )


def test_recomputed_tail_order_is_not_projector_dependency_order(fixture, prepared):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    count = len(p.original_task.event.provenance)
    refs = (
        *r.context.task.event.provenance[:count],
        *reversed(r.context.task.event.provenance[count:]),
    )
    context, original = derived(p, r, provenance=refs)
    with pytest.raises(ValueError):
        g.rebuild_native_contextual_request(
            context,
            r.sidecar,
            original_task_json=original,
            proposal_reference=r.proposal_reference,
            batch_reference=r.batch_reference,
            approval_reference=r.approval_reference,
            artifact_references=r.artifact_references,
        )


def test_original_seventeen_items_cannot_enter_native_codec(fixture, prepared):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    data = p.original_task.model_dump()
    items = list(p.original_task.context)
    while len(items) < 17:
        ref = p.original_task.context[0].reference.model_copy(update={"source_id": uuid4()})
        items.append(p.original_task.context[0].model_copy(update={"reference": ref}))
    data["context"] = tuple(items)
    data["event"]["provenance"] = tuple(i.reference for i in items)
    original = IntelligenceTask.model_validate(data)
    context, raw = derived(p, r, original=original)
    assert len(context.task.context) == 19
    with pytest.raises(ValueError):
        g.rebuild_native_contextual_request(
            context,
            r.sidecar,
            original_task_json=raw,
            proposal_reference=r.proposal_reference,
            batch_reference=r.batch_reference,
            approval_reference=r.approval_reference,
            artifact_references=r.artifact_references,
        )


def test_highly_restricted_original_is_not_native_fixed_scope(fixture, prepared):
    from zacai.policy import DataClassification

    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    data = p.original_task.model_dump()
    data["event"]["data_classification"] = DataClassification.HIGHLY_RESTRICTED
    original = IntelligenceTask.model_validate(data)
    context, raw = derived(p, r, original=original)
    with pytest.raises(ValueError):
        g.rebuild_native_contextual_request(
            context,
            r.sidecar,
            original_task_json=raw,
            proposal_reference=r.proposal_reference,
            batch_reference=r.batch_reference,
            approval_reference=r.approval_reference,
            artifact_references=r.artifact_references,
        )


def test_contract_already_rejects_lower_classification(fixture, prepared):
    from zacai.policy import DataClassification

    p = projection(fixture, prepared)
    data = p.original_task.model_dump()
    data["event"]["data_classification"] = DataClassification.INTERNAL
    with pytest.raises(ValueError, match="weaker than its evidence"):
        IntelligenceTask.model_validate(data)


def test_full_prepared_digest_pins_exact_canonical_role_bytes(fixture, prepared):
    from zacai.contextual_authorization import prepared_native_contextual_digest

    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    assert prepared_native_contextual_digest(r) == content_hash_of(
        canonical_bytes(
            {
                "format": "zac-native-contextual-prepared-v2",
                "exact_retained_request_digest": content_hash_of(
                    g.encode_native_contextual_request(r)
                ),
            }
        )
    )


@pytest.mark.parametrize("field", ["batch_reference", "approval_reference", "artifact_references"])
def test_decode_requires_exact_role_fields(fixture, prepared, field):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    data = json.loads(g.encode_native_contextual_request(r))
    del data[field]
    with pytest.raises(ValueError):
        g.decode_native_contextual_request(canonical_bytes(data))


@pytest.mark.parametrize("fault", ["nested", "rollback", "quoted_proposal"])
def test_v2_eligible_projection_denies_before_private_artifact_reads(
    fixture, prepared, monkeypatch, fault
):
    from datetime import timedelta

    from tests.test_native_evidence_context import choice, project

    sql, args, sources, raw, source = fixture
    base = args["context"]
    data = base.task.model_dump()
    related = base.related_source_ids
    observed = args["observed_at"]
    proposal = prepared[5]
    if fault == "nested":
        data["event"]["producer"] = "native-evidence-projection-v1"
        data["event"]["event_type"] = "native.evidence.selected"
    elif fault == "rollback":
        observed = base.task.event.observed_at - timedelta(microseconds=1)
    elif fault == "quoted_proposal":
        proposal = base.task.context[0].reference
    original = ReviewContext(IntelligenceTask.model_validate(data), base.meeting_source_id, related)
    changed = (sql, {**args, "context": original}, sources, raw, source)
    actual_get = args["artifacts"].get
    reads = []

    def get(*args):
        reads.append(args)
        return actual_get(*args)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(ValueError):
        project(
            changed,
            (choice(sources[-1], "Invented private body", start=9, end=16),),
            proposal_reference=proposal,
            observed_at=observed,
        )
    assert reads == []


def test_optional_projection_only_derivation_ids_are_unchanged(fixture, prepared):
    # Preserve the existing None-proposal pure projection API, no V2 admission.
    p = projection(fixture, prepared, retained=False)
    original = p.original_task.model_dump(mode="json")
    original["required_capabilities"] = sorted(original["required_capabilities"])
    raw = canonical_bytes(
        {
            "format": "zac-native-evidence-projection-v1",
            "original_task": original,
            "metadata": [m.model_dump(mode="json") for m in p.metadata],
            "provenance": [r.model_dump(mode="json") for r in p.context.task.event.provenance],
            "selected_text": [
                i.untrusted_text for i in p.context.task.context[len(p.original_task.context) :]
            ],
        }
    )
    assert p.context.task.task_id == uuid5(
        p.original_task.task_id, "native-evidence-projection-task/" + content_hash_of(raw)
    )
    assert p.context.task.event.event_id == uuid5(
        p.original_event.event_id, "native-evidence-projection/" + content_hash_of(raw)
    )
    with pytest.raises(ValueError):
        g.prepare_native_contextual_request(p)


def test_contract_already_rejects_missing_original_context_provenance(fixture, prepared):
    base = fixture[1]["context"]
    data = base.task.model_dump()
    data["event"]["provenance"] = (prepared[5],)
    with pytest.raises(ValueError, match="context reference must exactly match event provenance"):
        IntelligenceTask.model_validate(data)


def test_context_already_rejects_meeting_in_related_roles(fixture, prepared):
    base = fixture[1]["context"]
    with pytest.raises(ValueError, match="context roles must name distinct supplied evidence"):
        ReviewContext(
            base.task, base.meeting_source_id, base.related_source_ids | {base.meeting_source_id}
        )


def test_role_preimage_binds_even_when_dedup_keeps_provenance_union_unchanged(fixture, prepared):
    base = fixture[1]["context"]
    data = base.task.model_dump()
    data["event"]["provenance"] = (
        *base.task.event.provenance,
        fixture[1]["batch_reference"],
        fixture[1]["approval_reference"],
        prepared[5],
    )
    fixture[1]["context"] = ReviewContext(
        IntelligenceTask.model_validate(data), base.meeting_source_id, base.related_source_ids
    )
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    swapped = g._native_dependency_roles(
        r.approval_reference, r.batch_reference, r.proposal_reference, r.artifact_references
    )
    original = g._native_dependency_roles(
        r.batch_reference, r.approval_reference, r.proposal_reference, r.artifact_references
    )
    assert swapped != original
    # Both controls already occur in original prefix, so exact dedup union remains identical.
    refs = {ref.source_id: ref for ref in p.original_task.event.provenance}
    for ref in (
        r.approval_reference,
        r.batch_reference,
        r.proposal_reference,
        *(ref for group in r.artifact_references for ref in group),
    ):
        refs[ref.source_id] = ref
    assert tuple(refs.values()) == r.context.task.event.provenance
    with pytest.raises(ValueError):
        g.rebuild_native_contextual_request(
            r.context,
            r.sidecar,
            original_task_json=r.original_task_json,
            proposal_reference=r.proposal_reference,
            batch_reference=r.approval_reference,
            approval_reference=r.batch_reference,
            artifact_references=r.artifact_references,
        )
