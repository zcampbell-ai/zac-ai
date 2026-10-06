"""Genuine retained-proposal projection over invented SQLite, no active grant."""
import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import choice, project
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import contextual_generation as g
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.native_context_metadata import NativeContextSidecar, encode_native_sidecar
from zacai.intelligence.review_evaluation import review_context_digest


def projection(fixture, prepared, *, retained=True):
    _, _, sources, raw, _ = fixture
    selections = (choice(sources[2], raw.decode(), 'rfc822_utf8', 0, 10),
                  choice(sources[-1], 'Invented private body', 'text', 9, 16))
    return project(fixture, selections, **({'proposal_reference': prepared[5]} if retained else {}))


def rebuild(context, sidecar, projection, prepared):
    data = projection.original_task.model_dump(mode='json')
    data['required_capabilities'] = sorted(data['required_capabilities'])
    return g.rebuild_native_contextual_request(context, sidecar,
        original_task_json=canonical_bytes(data).decode(), proposal_reference=prepared[5],
        batch_reference=projection.batch_reference, approval_reference=projection.approval_reference,
        artifact_references=projection.artifact_references)


def forged_raw(request, context, sidecar):
    before, after = review_context_digest(request.context)[:32], review_context_digest(context)[:32]
    catalog = g._prepare_contextual_catalog(context)
    forged = replace(request, context=context, quotes=catalog.quotes,
                     instruction=request.instruction.replace(before, after),
                     evidence_json=catalog.evidence_json, schema_json=catalog.schema_json,
                     sidecar=sidecar, sidecar_json=encode_native_sidecar(sidecar).decode())
    # Raw test forgery deliberately bypasses public encoder validation; decoder must hold.
    return g._native_request_bytes(forged)


def test_actual_retained_projection_positive(fixture, prepared):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    assert g.decode_native_contextual_request(g.encode_native_contextual_request(r)) == r
    assert prepared[5] in r.context.task.event.provenance


@pytest.mark.parametrize('entry', ['rebuild','decode'])
def test_subset_sidecar_is_not_full_native_tail(fixture, prepared, entry):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    subset = NativeContextSidecar(format=r.sidecar.format, entries=r.sidecar.entries[:1])
    assert len(p.metadata) == 2
    with pytest.raises(ValueError):
        if entry == 'rebuild':
            rebuild(r.context, subset, p, prepared)
        else:
            g.decode_native_contextual_request(forged_raw(r, r.context, subset))


@pytest.mark.parametrize('field', ['task_id','event_id','causation_id','markers'])
@pytest.mark.parametrize('entry', ['rebuild','decode'])
def test_derived_identity_cannot_be_replaced(fixture, prepared, field, entry):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    data = r.context.task.model_dump()
    if field == 'task_id':
        data[field] = uuid4()
    elif field == 'markers':
        data['event']['event_type'] = 'meeting.completed'
        data['event']['producer'] = 'invented.legacy'
    else:
        data['event'][field] = uuid4()
    context = ReviewContext(IntelligenceTask.model_validate(data), r.context.meeting_source_id,
                            r.context.related_source_ids)
    with pytest.raises(ValueError):
        if entry == 'rebuild':
            rebuild(context, r.sidecar, p, prepared)
        else:
            g.decode_native_contextual_request(forged_raw(r, context, r.sidecar))


def test_v2_projection_requires_retained_proposal_reference(fixture, prepared):
    p = projection(fixture, prepared, retained=False)
    with pytest.raises(ValueError):
        g.prepare_native_contextual_request(p)


def test_packet_retains_original_task_and_proposal_exactly(fixture, prepared):
    from datetime import timedelta
    from uuid import UUID

    from tests.test_native_context_sidecar import review
    from zacai.intelligence.contextual_evaluation import (
        decode_native_contextual_packet,
        encode_native_contextual_packet,
    )
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    raw = encode_native_contextual_packet(review(r), r, builder_id=UUID(int=5),
        created_at=r.context.task.event.observed_at + timedelta(seconds=1))
    packet = decode_native_contextual_packet(raw)
    assert packet.request() == r
    assert packet.original_task_json == r.original_task_json
    assert packet.proposal_reference == prepared[5]


@pytest.mark.parametrize('field', ['original_task_json', 'proposal_reference'])
def test_decode_requires_original_and_proposal_fields(fixture, prepared, field):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    data = json.loads(g.encode_native_contextual_request(r))
    # Baseline request lacks these fields, exactly the missing-binding defect.
    del data[field]
    with pytest.raises(ValueError):
        g.decode_native_contextual_request(canonical_bytes(data))

@pytest.mark.parametrize('entry', ['rebuild', 'decode'])
def test_sidecar_order_cannot_differ_from_native_appended_tail(fixture, prepared, entry):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    reordered = NativeContextSidecar(format=r.sidecar.format, entries=tuple(reversed(r.sidecar.entries)))
    with pytest.raises(ValueError):
        if entry == 'rebuild':
            rebuild(r.context, reordered, p, prepared)
        else:
            g.decode_native_contextual_request(forged_raw(r, r.context, reordered))


def test_original_task_bytes_cannot_be_noncanonical_or_changed(fixture, prepared):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    original = json.loads(r.original_task_json)
    changed = dict(original)
    changed['task_id'] = str(uuid4())
    for raw in (json.dumps(original, indent=2), canonical_bytes(changed).decode()):
        with pytest.raises(ValueError):
            g.rebuild_native_contextual_request(r.context, r.sidecar,
                original_task_json=raw, proposal_reference=prepared[5], batch_reference=r.batch_reference, approval_reference=r.approval_reference, artifact_references=r.artifact_references)


def test_retained_proposal_already_in_original_provenance_is_preserved(fixture, prepared):
    # Real project base can already cite its retained MANUAL confirmation.
    sql, args, sources, raw, source = fixture
    task = args['context'].task.model_dump()
    task['event']['provenance'] = (*task['event']['provenance'], prepared[5].model_dump())
    original = ReviewContext(IntelligenceTask.model_validate(task), args['context'].meeting_source_id,
                             args['context'].related_source_ids)
    actual = (sql, {**args, 'context': original}, sources, raw, source)
    p = projection(actual, prepared)
    r = g.prepare_native_contextual_request(p)
    assert tuple(r.context.task.event.provenance[:len(original.task.event.provenance)]) == original.task.event.provenance
    assert r.context.task.event.provenance.count(prepared[5]) == 1
    assert g.decode_native_contextual_request(g.encode_native_contextual_request(r)) == r
