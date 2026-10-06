"""Synthetic real projection and closed metadata UTC identity controls."""

from datetime import UTC, timedelta, timezone

from tests.test_native_evidence_context import choice, project
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.native_evidence_context import NativeEvidenceMetadata


def test_every_metadata_date_normalizes_equivalent_offset(fixture):
    _, _, sources, _, _ = fixture
    result = project(fixture, (choice(sources[-1], "Invented private body"),))
    data = result.metadata[0].model_dump()
    dates = (
        "provider_occurred_at",
        "source_captured_at",
        "batch_observed_at",
        "projection_observed_at",
    )
    offset = timezone(timedelta(hours=5, minutes=30))
    for name in dates:
        data[name] = data[name].astimezone(offset)
    equivalent = NativeEvidenceMetadata.model_validate(data)
    assert all(getattr(equivalent, name).tzinfo is UTC for name in dates)
    assert canonical_bytes(equivalent.model_dump(mode="json")) == canonical_bytes(
        result.metadata[0].model_dump(mode="json")
    )


def test_actual_projection_equivalent_observation_offset_keeps_both_ids(fixture):
    _, args, sources, _, _ = fixture
    selections = (choice(sources[-1], "Invented private body"),)
    first = project(fixture, selections)
    later_representation = args["observed_at"].astimezone(timezone(timedelta(hours=-7)))
    second = project(fixture, selections, observed_at=later_representation)
    assert first.context.task.task_id == second.context.task.task_id
    assert first.context.task.event.event_id == second.context.task.event.event_id
    assert first.metadata == second.metadata
    assert first.original_task == second.original_task == args["context"].task


def test_actual_serializer_250_catalog_boundary_only(fixture):
    """Standalone declarations test serializer limits, not reachable native intake capacity."""
    from uuid import uuid4

    import pytest

    from zacai.intelligence.contextual_generation import (
        ContextualGenerationError,
        prepare_contextual_request,
    )
    from zacai.intelligence.contracts import ContextItem, IntelligenceTask
    from zacai.intelligence.meeting_review import ReviewContext

    _, args, _, _, _ = fixture
    original = args["context"]
    ref = original.task.context[0].reference
    refs = tuple(ref.model_copy(update={"source_id": uuid4()}) for _ in range(5))

    def context(last_count):
        items = [original.task.context[0]]
        for position, reference in enumerate(refs):
            count = last_count if position == 4 else 50
            items.append(
                ContextItem(reference=reference, untrusted_text="\n".join(["x" * 1500] * count))
            )
        data = original.task.model_dump()
        data["context"] = [item.model_dump() for item in items]
        data["event"]["provenance"] = [item.reference.model_dump() for item in items]
        return ReviewContext(
            IntelligenceTask.model_validate(data),
            original.meeting_source_id,
            frozenset(r.source_id for r in refs),
        )

    assert len(prepare_contextual_request(context(49)).quotes) == 250
    with pytest.raises(ContextualGenerationError):
        prepare_contextual_request(context(50))
