"""Small declared-invariant controls; actual invented parser/catalog, no authority."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_history_contextual_codec import prepared as prepared  # noqa: PLC0414
from tests.test_history_contextual_codec import review_for
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_context_metadata as m
from zacai.intelligence import history_contextual_codec as c
from zacai.intelligence.contextual_review import validate_contextual_review
from zacai.intelligence.meeting_review import Claim, Quote


def forged_declared_preview(original, preview, request, fault):
    entries, profiles = [], []
    new_tip = str(uuid4())
    for entry, raw in zip(preview.sidecar.entries, preview.projection_profiles, strict=True):
        e, p = entry.model_dump(mode="json"), json.loads(raw)
        if fault == "created_after_updated":
            value = (
                (entry.reported_updated_at + timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z")
            )
            e["reported_created_at"] = p["selection"]["reported_at"] = value
        elif fault == "acquired_after_capture":
            value = (
                (entry.host_declared_captured_at + timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z")
            )
            e["host_declared_acquired_at"] = p["declared_acquired_at"] = value
        elif fault == "export_after_acquisition":
            value = (
                (entry.host_declared_acquired_at + timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z")
            )
            e["host_declared_exported_at"] = p["declared_exported_at"] = value
        elif fault == "wrong_own_date_flag":
            e["reported_dates_after_acquired_at"] = p[
                "selected_dates_after_acquired_at"
            ] = not entry.reported_dates_after_acquired_at
            e["custody_selected_dates_after_acquired_at"] = p[
                "custody_selected_dates_after_acquired_at"
            ] = True
        elif fault == "own_conflict_not_custody":
            value = (
                (entry.host_declared_acquired_at + timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z")
            )
            e["reported_created_at"] = p["selection"]["reported_at"] = value
            e["reported_updated_at"] = p["reported_updated_at"] = value
            e["reported_dates_after_acquired_at"] = p["selected_dates_after_acquired_at"] = True
            e["custody_selected_dates_after_acquired_at"] = p[
                "custody_selected_dates_after_acquired_at"
            ] = False
        else:
            e["original_tip_id"] = p["original_tip_id"] = new_tip
            e["superseded_at_read"] = p["superseded_at_read"] = False
        raw = canonical_bytes(p)
        e["profile_hash"] = content_hash_of(raw)
        profiles.append(raw)
        entries.append(m.ClaudeMessageMetadata.model_validate(e))
    sidecar = m.HistoryContextSidecar(
        format="zac-history-context-sidecar-v2", entries=tuple(entries)
    )
    context = m.derive_history_context(
        original, sidecar, preview.context.task.context[-1].untrusted_text, tuple(profiles)
    )
    body = m.render_history_context_body(context, tuple(entries), request.route)
    return m.PreparedHistoryContextPreview(original.task, context, sidecar, tuple(profiles), body)


@pytest.mark.parametrize(
    "fault",
    [
        "created_after_updated",
        "acquired_after_capture",
        "export_after_acquisition",
        "wrong_own_date_flag",
        "own_conflict_not_custody",
        "wrong_superseded_flag",
    ],
)
def test_coherent_declared_profile_forgery_holds(prepared, fault):
    original, _, preview, request = prepared
    assert (
        c.decode_history_contextual_request(c.encode_history_contextual_request(request)) == request
    )
    with pytest.raises(ValueError):
        declared = forged_declared_preview(original, preview, request, fault)
        forged = c.prepare_history_contextual_request(
            declared, original_context=original, route=request.route
        )
        assert (
            c.decode_history_contextual_request(c.encode_history_contextual_request(forged))
            == forged
        )
        assert forged != request


def test_foreign_preparation_properties_are_not_read(prepared, monkeypatch):
    original, read, preview, request = prepared
    reads = []

    class Foreign:
        @property
        def capture_binding_projection(self):
            reads.append("projection")
            raise RuntimeError("foreign property reached")

    monkeypatch.setattr(
        m, "prepare_claude_large_original_message", lambda *args, **kwargs: Foreign()
    )
    entry = preview.sidecar.entries[0]
    with pytest.raises(m.HistoryContextError):
        m.prepare_claude_history_context_preview(
            original,
            read,
            selections=(
                m.HistoryMessageSpan(
                    message_id=entry.message_id,
                    character_start=entry.character_start,
                    character_end=entry.character_end,
                ),
            ),
            observed_at=entry.projection_observed_at,
            route=request.route,
        )
    assert reads == []


def test_actual_valid_quote_crossing_history_messages_holds_renderer(prepared):
    request = prepared[-1]
    tail = request.context().task.context[-1]
    first, second = request.sidecar.entries[:2]
    quote = Quote(
        source_id=tail.reference.source_id,
        start=first.context_character_start,
        end=second.context_character_end,
        text=tail.untrusted_text[: second.context_character_end],
    )
    review = review_for(request).model_copy(
        update={"background": (Claim(text="Two dated reports.", quotes=(quote,)),)}
    )
    assert validate_contextual_review(review, request.context()) == review
    with pytest.raises(ValueError, match="exactly one metadata owner"):
        c.render_history_packet_preview(review, request)


def test_changed_updated_and_after_acquisition_claims_surface_as_unverified(prepared):
    original, _, preview, request = prepared
    entries, profiles = [], []
    for entry, raw in zip(preview.sidecar.entries, preview.projection_profiles, strict=True):
        p, e = json.loads(raw), entry.model_dump(mode="json")
        value = (
            (entry.host_declared_acquired_at + timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
        e["reported_updated_at"] = p["reported_updated_at"] = value
        e["reported_dates_after_acquired_at"] = p["selected_dates_after_acquired_at"] = True
        e["custody_selected_dates_after_acquired_at"] = p[
            "custody_selected_dates_after_acquired_at"
        ] = True
        raw = canonical_bytes(p)
        e["profile_hash"] = content_hash_of(raw)
        profiles.append(raw)
        entries.append(m.ClaudeMessageMetadata.model_validate(e))
    sidecar = m.HistoryContextSidecar(
        format="zac-history-context-sidecar-v2", entries=tuple(entries)
    )
    context = m.derive_history_context(
        original, sidecar, preview.context.task.context[-1].untrusted_text, tuple(profiles)
    )
    declared = m.PreparedHistoryContextPreview(
        original.task,
        context,
        sidecar,
        tuple(profiles),
        m.render_history_context_body(context, tuple(entries), request.route),
    )
    updated = c.prepare_history_contextual_request(
        declared, original_context=original, route=request.route
    )
    quote = Quote(
        source_id=entries[0].current_original_reference.source_id,
        start=entries[0].context_character_start,
        end=entries[0].context_character_end,
        text=context.task.context[-1].untrusted_text[: entries[0].context_character_end],
    )
    review = review_for(updated).model_copy(
        update={"background": (Claim(text="Dated exported report.", quotes=(quote,)),)}
    )
    text = c.render_history_packet_preview(review, updated)
    assert "reported USER role, unverified author" in text
    assert "updated " in text and "reported date after declared acquisition" in text
    assert "Current facts and owner preferences unconfirmed" in text
    assert updated.current_facts_verified is False
