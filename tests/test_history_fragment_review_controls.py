"""Actual invented upstream preparation; no Source/owner/processing authority."""

from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import AT, prepared
from tests.test_history_context_metadata import base
from tests.test_history_contextual_codec import review_for
from tests.test_history_fragment_contextual_codec import request
from tests.test_local_contextual_runtime import route
from zacai.intelligence import history_fragment_contextual_codec as c
from zacai.intelligence.contracts import ContextItem, IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C


def chosen_route():
    return route().model_copy(update={"max_input_characters": 32000})


def test_companion_cannot_already_be_provider_context():
    read = prepared(parent=uuid4())
    f = prepare(read)
    original = base()
    c.prepare_history_fragment_contextual_request(original, f, observed_at=AT, route=chosen_route())
    task = IntelligenceTask.model_validate(
        {
            **original.task.model_dump(),
            "event": {
                **original.task.event.model_dump(),
                "provenance": (*original.task.event.provenance, read.companion_reference),
            },
            "context": (
                *original.task.context,
                ContextItem(
                    reference=read.companion_reference,
                    untrusted_text="Invented companion manifest text",
                ),
            ),
        }
    )
    altered = ReviewContext(
        task,
        original.meeting_source_id,
        original.related_source_ids | {read.companion_reference.source_id},
    )
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            altered, f, observed_at=AT, route=chosen_route()
        )


def test_binding_reference_survives_actual_current_classification_raise():
    read = prepared(parent=uuid4())
    current = read.original_reference.model_copy(
        update={"effective_classification": C.HIGHLY_RESTRICTED}
    )
    read = replace(
        read, original_reference=current, joint_output_classification=C.HIGHLY_RESTRICTED
    )
    f = prepare(read)
    assert f.fragment.reference == read.original_binding_reference
    assert f.profile.current_original_reference == current
    value = c.prepare_history_fragment_contextual_request(
        base(), f, observed_at=AT, route=chosen_route()
    )
    assert value.task.event.data_classification == C.HIGHLY_RESTRICTED
    assert (
        c.decode_history_fragment_contextual_request(
            c.encode_history_fragment_contextual_request(value)
        )
        == value
    )


def test_packet_retains_updated_anomaly_revision_and_omissions():
    value = request()
    raw = c.encode_history_fragment_contextual_packet(
        review_for(value), value, builder_id=uuid4(), created_at=AT
    )
    text = c.decode_history_fragment_contextual_packet(raw).rendered_preview
    p = c._profile(value.profile_json, value.observation)
    assert p.reported_updated_at.isoformat() in text
    assert "Omitted characters" in text
    assert str(value.observation.omitted_suffix_characters) in text
    assert "Reported dates after declared acquisition: no" in text
    assert "Superseded at read: no" in text


def test_wrong_fragment_and_nested_are_pre_body_guards(monkeypatch):
    f = prepare(prepared(parent=uuid4()))
    original = base()
    value = c.prepare_history_fragment_contextual_request(
        original, f, observed_at=AT, route=chosen_route()
    )
    body_calls = []
    actual = c._body

    def body(*args):
        body_calls.append(True)
        return actual(*args)

    monkeypatch.setattr(c, "_body", body)
    changed = replace(f, fragment=replace(f.fragment, parent_id=uuid4()))
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            original, changed, observed_at=AT, route=chosen_route()
        )
    assert body_calls == []
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(
            value.context(), f, observed_at=AT, route=chosen_route()
        )
    assert body_calls == []


def test_contract_revalidates_forged_instance():
    value = request()
    forged = value.model_copy(update={"prompt_body": "forged"})
    with pytest.raises(c.HistoryContextualCodecError):
        c.encode_history_fragment_contextual_request(forged)


def test_cross_boundary_contract_holds_and_placeholder_is_not_wire_pin():
    from zacai.intelligence.contracts import ZacEvent
    from zacai.policy import TrustBoundary as B

    original = base()
    altered = original.task.event.model_copy(update={"trust_boundary": B.BRAINSTORM})
    with pytest.raises(ValueError):
        ZacEvent.model_validate(altered)
    value = request()
    wire = __import__("json").loads(value.prompt_body)
    assert wire["model"] == value.route.identity.model_id
    assert "0" * 64 not in value.prompt_body


def test_route_subclass_is_not_admitted_as_exact_route():
    from zacai.intelligence.contracts import ModelRoute

    class OtherRoute(ModelRoute):
        pass

    f = prepare(prepared(parent=uuid4()))
    selected = chosen_route()
    c.prepare_history_fragment_contextual_request(base(), f, observed_at=AT, route=selected)
    shaped = OtherRoute.model_validate(selected.model_dump())
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_fragment_contextual_request(base(), f, observed_at=AT, route=shaped)


def test_profile_selected_text_is_same_upstream_acceptance_set():
    import json

    from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of

    value = request()
    p = json.loads(value.profile_json)
    text = " Invented "
    p["character_end"] = len(text)
    p["selected_text_hash"] = content_hash_of(text.encode())
    observation = value.observation.model_copy(
        update={
            "selected_text": text,
            "decoded_utf8_end": len(text),
            "omitted_suffix_characters": value.observation.full_decoded_characters - len(text),
        }
    )
    with pytest.raises(ValueError):
        c._profile(canonical_bytes(p).decode(), observation)


def test_actual_future_reported_date_and_revision_observations_survive_packet():
    read = prepared(parent=uuid4(), reported_date="2026-10-07T12:00:00Z", exported_at=None)
    read = replace(read, original_tip_id=uuid4(), superseded_at_read=True)
    f = prepare(read, start=1, end=8)
    assert f.profile.selected_dates_after_acquired_at is True
    assert f.profile.custody_selected_dates_after_acquired_at is True
    value = c.prepare_history_fragment_contextual_request(
        base(), f, observed_at=AT, route=chosen_route()
    )
    raw = c.encode_history_fragment_contextual_packet(
        review_for(value), value, builder_id=uuid4(), created_at=AT
    )
    text = c.decode_history_fragment_contextual_packet(raw).rendered_preview
    assert "Reported dates after declared acquisition: yes" in text
    assert "custody selected dates after acquisition: yes" in text
    assert "Superseded at read: yes" in text
    assert "prefix 1" in text
    assert "Current facts and owner preferences unconfirmed" in text


def test_legacy_hold_is_marker_guard_before_catalog(monkeypatch):
    from zacai.intelligence import contextual_generation as generation

    value = request()
    calls = []
    actual = generation._prepare_contextual_catalog

    def catalog(context):
        calls.append(True)
        return actual(context)

    monkeypatch.setattr(generation, "_prepare_contextual_catalog", catalog)
    with pytest.raises(generation.ContextualGenerationError) as error:
        generation.prepare_contextual_request(value.context())
    assert error.value.code is generation.GenerationFailure.REQUEST
    assert calls == []
