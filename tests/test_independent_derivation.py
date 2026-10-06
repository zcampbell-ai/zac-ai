"""Actual retained proposal/projection/SQLite; no SQL server/model/approval proof."""
import json
from uuid import uuid5

import pytest

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_derivation_admission import projection
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import contextual_generation as g
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext


def test_actual_projection_retains_existing_nonquoted_proposal_provenance(fixture, prepared):
    original = fixture[1]["context"]
    data = original.task.model_dump()
    data["event"]["provenance"] = (*original.task.event.provenance, prepared[5])
    fixture[1]["context"] = ReviewContext(
        IntelligenceTask.model_validate(data), original.meeting_source_id,
        original.related_source_ids,
    )
    p = projection(fixture, prepared)
    assert prepared[5] in p.original_task.event.provenance
    assert prepared[5] not in [i.reference for i in p.context.task.context]
    # Real projector permits this exact merge used by the actual project13 graph.
    g.prepare_native_contextual_request(p)


def test_recomputed_derivation_must_preserve_original_provenance_prefix(fixture, prepared):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    prefix = p.original_task.event.provenance
    original_ids = {ref.source_id for ref in prefix}
    rest = tuple(ref for ref in r.context.task.event.provenance if ref.source_id not in original_ids)
    reordered = (*rest, *prefix)
    assert reordered != r.context.task.event.provenance
    derivation = canonical_bytes({
        "format": "zac-native-evidence-projection-v1",
        "original_task": json.loads(r.original_task_json),
        "metadata": [entry.model_dump(mode="json") for entry in r.sidecar.entries],
        "provenance": [ref.model_dump(mode="json") for ref in reordered],
        "selected_text": [i.untrusted_text for i in r.context.task.context[len(p.original_task.context):]],
        "native_dependency_roles":g._native_dependency_roles(r.batch_reference,r.approval_reference,r.proposal_reference,r.artifact_references),
    })
    data = r.context.task.model_dump()
    data["event"]["provenance"] = reordered
    data["event"]["event_id"] = uuid5(p.original_event.event_id, "native-evidence-projection/" + content_hash_of(derivation))
    data["task_id"] = uuid5(p.original_task.task_id, "native-evidence-projection-task/" + content_hash_of(derivation))
    context = ReviewContext(IntelligenceTask.model_validate(data), r.context.meeting_source_id,
                            r.context.related_source_ids)
    # New UUID hashes recomputed, but actual projector always emits original prefix first.
    with pytest.raises(ValueError):
        g.rebuild_native_contextual_request(context, r.sidecar,
            original_task_json=r.original_task_json, proposal_reference=r.proposal_reference, batch_reference=r.batch_reference, approval_reference=r.approval_reference, artifact_references=r.artifact_references)
