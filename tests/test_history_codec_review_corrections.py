"""Invented actual parser/catalog controls; no source or processing authority."""

import json
from uuid import uuid4

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_history_context_metadata import base, multi_read
from tests.test_history_contextual_codec import prepared as prepared  # noqa: PLC0414
from tests.test_history_contextual_codec import review_for
from tests.test_local_contextual_runtime import route
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_context_metadata as m
from zacai.intelligence import history_contextual_codec as c
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog
from zacai.intelligence.contextual_review import (
    render_contextual_preview,
    validate_contextual_review,
)
from zacai.intelligence.meeting_review import Claim


def test_packet_actual_assistant_citation_has_role_date_and_preference_caveat(prepared):
    request = prepared[-1]
    catalog = _prepare_contextual_catalog(request.context())
    quote = next(q for _, q in catalog.quotes if q.text == "Consider a long generic essay.")
    review = review_for(request).model_copy(
        update={"background": (Claim(text="User prefers essays.", quotes=(quote,)),)}
    )
    assert validate_contextual_review(review, request.context()) == review
    assert "Assistant suggestion" not in render_contextual_preview(review, request.context())
    packet = c.decode_history_contextual_packet(
        c.encode_history_contextual_packet(
            review, request, builder_id=uuid4(), created_at=request.task.event.observed_at
        )
    )
    assert "User prefers essays." in packet.rendered_preview
    assert "reported ASSISTANT role, unverified author" in packet.rendered_preview
    assert "Current facts and owner preferences unconfirmed" in packet.rendered_preview
    assert request.sidecar.entries[1].reported_created_at.isoformat() in packet.rendered_preview
    assert packet.review == review


def test_packet_user_citation_is_dated_not_current_fact(prepared):
    request = prepared[-1]
    quote = next(
        q
        for _, q in _prepare_contextual_catalog(request.context()).quotes
        if q.text == "Use short source-backed paragraphs."
    )
    review = review_for(request).model_copy(
        update={"background": (Claim(text="Historical user report.", quotes=(quote,)),)}
    )
    text = c.render_history_packet_preview(review, request)
    assert "reported USER role, unverified author" in text
    assert "Current facts and owner preferences unconfirmed" in text
    assert "Assistant suggestion" not in text


def test_direct_helpers_refuse_coherent_foreign_pair(prepared):
    original, _, preview, request = prepared
    entries = list(preview.sidecar.entries)
    data = entries[1].model_dump(mode="json")
    for keys in (
        ("current_original_reference", "original_binding_reference"),
        ("current_companion_reference", "companion_binding_reference"),
    ):
        sid = str(uuid4())
        for key in keys:
            data[key]["source_id"] = sid
    data["original_tip_id"] = data["original_binding_reference"]["source_id"]
    entries[1] = m.ClaudeMessageMetadata.model_validate(data)
    sidecar = m.HistoryContextSidecar(
        format="zac-history-context-sidecar-v2", entries=tuple(entries)
    )
    assert entries[1].current_original_reference != entries[0].current_original_reference
    with pytest.raises(ValueError, match="one original"):
        m.derive_history_context(
            original,
            sidecar,
            preview.context.task.context[-1].untrusted_text,
            preview.projection_profiles,
        )
    with pytest.raises(ValueError, match="one original"):
        m.render_history_context_body(preview.context, tuple(entries), request.route)


def test_codec_wrong_declared_file_capacity_flag_holds(prepared):
    original, _, preview, request = prepared
    entries, profiles = [], []
    for entry, raw in zip(preview.sidecar.entries, preview.projection_profiles, strict=True):
        profile = json.loads(raw)
        assert profile["original_file_bytes"] < 8000000
        profile["original_within_legacy_byte_limit"] = False
        raw = canonical_bytes(profile)
        profiles.append(raw)
        data = entry.model_dump(mode="json")
        data.update(original_within_legacy_byte_limit=False, profile_hash=content_hash_of(raw))
        entries.append(m.ClaudeMessageMetadata.model_validate(data))
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
    with pytest.raises(c.HistoryContextualCodecError):
        c.prepare_history_contextual_request(
            declared, original_context=original, route=request.route
        )
    assert (
        c.decode_history_contextual_request(c.encode_history_contextual_request(request)) == request
    )


@pytest.mark.parametrize("characters,accepted", [(2998, True), (2999, False)])
def test_two_unicode_passages_joined_utf8_cap(host, monkeypatch, characters, accepted):
    texts = tuple(
        "é" * 1000 + "\n" + "é" * 1000 + "\n" + "é" * (n - 2000) for n in (characters, 2999)
    )
    read, selections = multi_read(host, monkeypatch, [("human", texts[0]), ("assistant", texts[1])])
    assert sum(len(t.encode()) for t in texts) <= 12000
    original = base()
    selected_route = route().model_copy(update={"max_input_characters": 64000})
    if not accepted:
        with pytest.raises(m.HistoryContextError):
            m.prepare_claude_history_context_preview(
                original,
                read,
                selections=selections,
                observed_at=read.captured_at,
                route=selected_route,
            )
        return
    preview = m.prepare_claude_history_context_preview(
        original, read, selections=selections, observed_at=read.captured_at, route=selected_route
    )
    assert len(preview.context.task.context[-1].untrusted_text.encode()) == 11999
    request = c.prepare_history_contextual_request(
        preview, original_context=original, route=selected_route
    )
    assert (
        c.decode_history_contextual_request(c.encode_history_contextual_request(request)) == request
    )


def test_fragment_profile_cannot_replace_complete_profile_with_recomputed_hash(prepared):
    request = prepared[-1]
    data = json.loads(c.encode_history_contextual_request(request))
    from tests.test_claude_large_original_message import MID
    from tests.test_claude_large_original_message import prepared as fragment_read
    from zacai import claude_historical_fragment as f

    fragment = f.prepare_claude_historical_fragment(
        fragment_read(parent=uuid4()), message_id=MID, character_start=0, character_end=8
    )
    raw = fragment.profile_raw
    assert json.loads(raw)["format"] == "zac-claude-historical-literal-fragment-profile-v1"
    data["projection_profiles"][0] = raw.decode()
    data["sidecar"]["entries"][0]["profile_hash"] = content_hash_of(raw)
    assert data["sidecar"]["entries"][0]["profile_hash"] != request.sidecar.entries[0].profile_hash
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_request(canonical_bytes(data))


@pytest.mark.parametrize("fault", ["derived", "span", "time"])
def test_direct_derivation_guards_original_time_and_span(prepared, fault):
    from datetime import timedelta

    original, _, preview, _ = prepared
    sidecar = preview.sidecar
    text = preview.context.task.context[-1].untrusted_text
    if fault == "derived":
        original = preview.context
    elif fault == "span":
        text = "X" + text[1:]
    else:
        from zacai.intelligence.meeting_review import ReviewContext

        event = original.task.event.model_copy(
            update={"observed_at": sidecar.entries[0].projection_observed_at + timedelta(seconds=1)}
        )
        original = ReviewContext(
            original.task.model_copy(update={"event": event}),
            original.meeting_source_id,
            original.related_source_ids,
        )
    with pytest.raises(ValueError):
        m.derive_history_context(original, sidecar, text, preview.projection_profiles)


def test_fragment_result_is_not_accepted_as_complete_preview_input(monkeypatch):
    from tests.test_claude_large_original_message import MID
    from tests.test_claude_large_original_message import prepared as fragment_read
    from zacai import claude_historical_fragment as f

    read = fragment_read(parent=uuid4())
    fragment = f.prepare_claude_historical_fragment(
        read, message_id=MID, character_start=0, character_end=8
    )
    assert fragment.profile.lineage_complete is False
    calls = []

    def substituted(*args, **kwargs):
        calls.append(fragment)
        return fragment

    monkeypatch.setattr(m, "prepare_claude_large_original_message", substituted)
    with pytest.raises(m.HistoryContextError):
        m.prepare_claude_history_context_preview(
            base(),
            read,
            selections=(m.HistoryMessageSpan(message_id=MID, character_start=0, character_end=8),),
            observed_at=read.captured_at,
            route=route(),
        )
    assert calls == [fragment]


def test_packet_must_store_exact_validated_review(prepared, monkeypatch):
    request = prepared[-1]
    review = review_for(request)
    raw = c.encode_history_contextual_packet(
        review, request, builder_id=uuid4(), created_at=request.task.event.observed_at
    )
    data = json.loads(raw)
    changed = review.model_copy(
        update={
            "overview": (
                review.overview[0].model_copy(update={"text": "Different validated statement."}),
            )
        }
    )
    assert changed != review
    data["review_digest"] = content_hash_of(canonical_bytes(changed.model_dump(mode="json")))
    data["rendered_preview"] = c.render_history_packet_preview(changed, request)
    calls = []

    def substituted(value, context):
        calls.append(value)
        return changed

    monkeypatch.setattr(c, "validate_contextual_review", substituted)
    with pytest.raises(c.HistoryContextualCodecError):
        c.decode_history_contextual_packet(canonical_bytes(data))
    assert calls and calls[0] == review
