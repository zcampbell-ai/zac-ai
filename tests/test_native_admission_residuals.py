"""Invented structural codec controls, no Source/authentication claims."""

from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_native_contextual_assembly import (
    prepared as prepared,  # noqa: PLC0414 - export actual pytest fixture
)
from tests.test_native_dependency_roles import derived
from tests.test_native_derivation_admission import projection
from tests.test_native_evidence_context import (
    fixture as fixture,  # noqa: PLC0414 - export actual pytest fixture
)
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import contextual_generation as g
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.native_context_metadata import NativeContextSidecar, NativeEvidenceMetadata
from zacai.policy import DataClassification as C


def rebuild(r, context, original):
    return g.rebuild_native_contextual_request(
        context,
        r.sidecar,
        original_task_json=original,
        proposal_reference=r.proposal_reference,
        batch_reference=r.batch_reference,
        approval_reference=r.approval_reference,
        artifact_references=r.artifact_references,
    )


@pytest.mark.parametrize("classification", [C.CONFIDENTIAL, C.INTERNAL, C.PUBLIC])
def test_original_nonquoted_reference_classification_admission(fixture, prepared, classification):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    extra = p.original_task.event.provenance[0].model_copy(
        update={"source_id": uuid4(), "effective_classification": classification}
    )
    data = p.original_task.model_dump()
    data["event"]["provenance"] = (*p.original_task.event.provenance, extra)
    original = IntelligenceTask.model_validate(data)
    context, raw = derived(p, r, original=original)
    if classification is C.CONFIDENTIAL:
        result = rebuild(r, context, raw)
        assert result.context.task.event.provenance[len(original.event.provenance) - 1] == extra
    else:
        with pytest.raises(ValueError):
            rebuild(r, context, raw)


@pytest.mark.parametrize(
    "value",
    ["\n".join(["a" * 999] * 4), "\n".join(["😀" * 999] * 4), "a" * 1501],
    ids=["ascii-permitted", "utf8-over-cap", "line-over-cap"],
)
def test_selected_text_byte_and_line_admission(fixture, prepared, value):
    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    data = r.context.task.model_dump()
    data["context"][len(p.original_task.context)]["untrusted_text"] = value
    context = ReviewContext(
        IntelligenceTask.model_validate(data),
        r.context.meeting_source_id,
        r.context.related_source_ids,
    )
    meta = r.sidecar.entries[0].model_dump()
    meta.update(
        field_text_hash=content_hash_of(value.encode()),
        source_span={"start": 0, "end": len(value)},
        field_length_codepoints=len(value),
        omitted_before_codepoints=0,
        omitted_after_codepoints=0,
    )
    sidecar = NativeContextSidecar(
        format=r.sidecar.format,
        entries=(NativeEvidenceMetadata.model_validate(meta), *r.sidecar.entries[1:]),
    )
    changed = replace(r, context=context, sidecar=sidecar)
    context, raw = derived(p, changed)
    if len(value.splitlines()[0]) > 1500 or len(value.encode("utf-8")) > 12000:
        with pytest.raises(ValueError):
            rebuild(changed, context, raw)
    else:
        result = rebuild(changed, context, raw)
        assert result.context.task.context[len(p.original_task.context)].untrusted_text == value
        if "😀" in value:
            assert len(value.encode()) > 12000


@pytest.mark.parametrize("field", ["batch_reference", "approval_reference"])
def test_inventory_control_return_is_checked_before_proposal_read(
    fixture, prepared, monkeypatch, field
):
    from tests.test_native_evidence_context import choice, project
    from zacai.intelligence import native_evidence_context as native

    actual = native.load_native_batch_inventory
    returned = []
    proposal_reads = []

    def inventory(*args, **kwargs):
        value = actual(*args, **kwargs)
        ref = getattr(value, field).model_copy(update={"source_id": uuid4()})
        returned.append(value)
        return replace(value, **{field: ref})

    def proposal(*args, **kwargs):
        proposal_reads.append(True)
        raise AssertionError("proposal read after incompatible control return")

    monkeypatch.setattr(native, "load_native_batch_inventory", inventory)
    monkeypatch.setattr(native, "load_retained_native_proposal", proposal)
    with pytest.raises(ValueError):
        project(
            fixture,
            (choice(fixture[2][-1], "Invented private body", start=9, end=16),),
            proposal_reference=prepared[5],
        )
    assert len(returned) == 1
    assert proposal_reads == []


def test_retained_request_capacity_holds_without_truncating_original(
    fixture, prepared, monkeypatch
):
    from zacai.ingestion.artifact_store import canonical_bytes

    p = projection(fixture, prepared)
    r = g.prepare_native_contextual_request(p)
    original = p.original_task.model_dump()
    text = "\n".join(["Invented evidence " + '"' * 1470] * 32)
    assert len(text.encode()) <= 48000
    original["context"] = (p.original_task.context[0].model_copy(update={"untrusted_text": text}),)
    changed_original = IntelligenceTask.model_validate(original)
    context, raw = derived(p, r, original=changed_original)
    assert len(canonical_bytes(changed_original.model_dump(mode="json"))) < 256000
    measured = []
    actual = g._native_request_bytes

    def encode(value):
        result = actual(value)
        measured.append(len(result))
        return result

    monkeypatch.setattr(g, "_native_request_bytes", encode)
    with pytest.raises(ValueError):
        rebuild(r, context, raw)
    assert measured and max(measured) > 256000
    assert changed_original.context[0].untrusted_text == text
