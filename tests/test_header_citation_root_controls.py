from tests.test_native_evidence_context import choice, run
from tests.test_native_evidence_context import (
    fixture as fixture,  # noqa: PLC0414 - pytest fixture export
)
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog


def test_host_relevance_is_not_provider_evidence(fixture):
    _, _, sources, _, _ = fixture
    selected = choice(sources[-1], "Invented private body")
    result = run(fixture, (selected,))
    prepared = _prepare_contextual_catalog(result)
    quoted = [q.text for _, q in prepared.quotes if q.source_id == selected.source_id]
    assert quoted, "Actual selected provider evidence must remain citable"
    assert all(
        "Host-selected relevance" not in q and selected.relevance_reason not in q for q in quoted
    ), "Host relevance was offered as a provider quote"


def test_original_event_identity_not_rewritten(fixture):
    _, args, sources, _, _ = fixture
    original = args["context"].task.event
    result = run(fixture, (choice(sources[-1], "Invented private body"),))
    assert result.task.event == original or result.task.event.event_id != original.event_id, (
        "Changed event content retained original canonical identity"
    )
