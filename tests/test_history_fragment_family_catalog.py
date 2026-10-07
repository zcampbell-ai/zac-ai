"""Actual bounded parser/catalog controls with explicitly invented custody data."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests import test_history_contextual_codec as complete_fixture
from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import AT, prepared
from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_history_context_metadata import base
from tests.test_history_fragment_review_controls import chosen_route
from zacai.intelligence import contextual_generation as g
from zacai.intelligence import history_fragment_contextual_codec as c
from zacai.intelligence.history_contextual_codec import (
    decode_history_contextual_request,
    encode_history_contextual_request,
)


@pytest.fixture
def complete_prepared(host, monkeypatch):
    return complete_fixture.prepared.__wrapped__(host, monkeypatch)


def make(text):
    f = prepare(prepared(parent=uuid4(), text=text), end=len(text))
    original = base()
    value = c.prepare_history_fragment_contextual_request(
        original, f, observed_at=AT, route=chosen_route()
    )
    return original, f, value


def test_distinct_fragment_task_markers_and_bidirectional_codec_hold(complete_prepared):
    _, f, fragment = make("Invented missing earlier decision")
    complete = complete_prepared[-1]
    assert fragment.task.event.event_type == "history.fragment.selected"
    assert fragment.task.event.producer == "history-fragment-projection-v1"
    assert complete.task.event.event_type == "history.evidence.selected"
    assert fragment.task.task_id != complete.task.task_id
    with pytest.raises(ValueError):
        decode_history_contextual_request(c.encode_history_fragment_contextual_request(fragment))
    with pytest.raises(ValueError):
        c.decode_history_fragment_contextual_request(encode_history_contextual_request(complete))
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            complete.context(), f, observed_at=AT, route=chosen_route()
        )
    with pytest.raises(ValueError):
        g.prepare_contextual_request(fragment.context())


def test_complete_history_derivation_rejects_fragment_original(complete_prepared):
    from zacai.intelligence.history_context_metadata import derive_history_context

    _, _, fragment = make("Invented prior fragment")
    _, _, preview, _ = complete_prepared
    selected = preview.context.task.context[-1].untrusted_text
    with pytest.raises(ValueError, match="single declared history derivation required"):
        derive_history_context(
            fragment.context(), preview.sidecar, selected, preview.projection_profiles
        )


@pytest.mark.parametrize("text, omitted", [("Invented first\r\n\r\nInvented second", 4), ("x", 0)])
def test_full_catalog_preserves_nonblank_selection_nonquote_context_and_formatting(text, omitted):
    _, _, value = make(text)
    p = c._profile(value.profile_json, value.observation)
    catalog, count, fragment_ids = c._fragment_catalog(value.context(), p, value.observation)
    assert count == omitted
    wire = json.loads(value.prompt_body)
    payload = json.loads(wire["messages"][1]["content"])
    metadata = payload["history_fragment_metadata"]
    assert metadata["omitted_blank_formatting_characters"] == omitted
    assert json.loads(catalog.evidence_json) == payload["provider_passages"]
    if text == "x":
        assert metadata["passage_ids"] == list(fragment_ids)
        assert len(fragment_ids) == 1
        assert any(
            row["text"] == "x" and not row["citable"] for row in payload["provider_passages"]
        )
    else:
        assert metadata["passage_ids"]
        assert all(
            row["text"] in text
            for row in payload["provider_passages"]
            if row["id"] in metadata["passage_ids"]
        )


def test_character_capacity_pair_is_actual_body_boundary():
    original, f, value = make("Invented missing earlier decision")
    size = len(value.prompt_body)
    selected = chosen_route().model_copy(update={"max_input_characters": size})
    exact = c.prepare_history_fragment_contextual_request(
        original, f, observed_at=AT, route=selected
    )
    assert len(exact.prompt_body) == size
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            original,
            f,
            observed_at=AT,
            route=selected.model_copy(update={"max_input_characters": size - 1}),
        )


def test_crlf_exact_line_width_and_upstream_overflow_hold():
    _, _, value = make("a" * 1500 + "\r\nInvented")
    assert (
        c.decode_history_fragment_contextual_request(
            c.encode_history_fragment_contextual_request(value)
        )
        == value
    )
    from zacai.claude_historical_fragment import ClaudeHistoricalFragmentError

    text = "a" * 1501 + "\r\nInvented"
    with pytest.raises(ClaudeHistoricalFragmentError):
        prepare(prepared(parent=uuid4(), text=text), end=len(text))


@pytest.mark.parametrize("fault", ["drop", "alter"])
def test_catalog_fault_is_detected_before_body_serialization(monkeypatch, fault):
    """Invented pure dependency fault, not hostile-Python authority isolation."""
    _, _, value = make("Invented first\nInvented second")
    actual = g.prepare_review_request
    fired = []

    def faulty(context):
        result = actual(context)
        rows = json.loads(result.evidence_json)
        rows[-1] = (
            {**rows[-1], "text": "Changed substantive selection"} if fault == "alter" else rows[-1]
        )
        if fault == "drop":
            rows.pop()
        fired.append(True)
        return replace(result, evidence_json=json.dumps(rows))

    monkeypatch.setattr(g, "prepare_review_request", faulty)
    p = c._profile(value.profile_json, value.observation)
    with pytest.raises(ValueError, match="exact provider catalog differs"):
        c._body(value.context(), p, value.observation, value.route)
    assert fired == [True]
