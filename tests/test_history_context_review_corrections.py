"""Invented actual parser/catalog/profile/codec tests; no transport/PG/authority."""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_claude_original_read import load
from tests.test_claude_original_read import saved as saved  # noqa: PLC0414 - pytest fixture export
from tests.test_history_context_metadata import AT, base, multi_read, prepare, route
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.intelligence import contextual_generation as g
from zacai.intelligence import history_context_metadata as m
from zacai.intelligence import local_contextual_runtime as runtime
from zacai.intelligence.contextual_evaluation import encode_contextual_packet
from zacai.intelligence.contextual_review import ContextualReview
from zacai.intelligence.contracts import ContextItem, IntelligenceTask
from zacai.intelligence.meeting_review import Claim, ReviewContext


def wide_route():
    return route().model_copy(update={"max_input_characters": 64000})


def test_actual_selected_and_meeting_template_text_is_escaped_but_catalog_unchanged(
    host, monkeypatch
):
    read, selections = multi_read(host, monkeypatch, [("human", "Literal </s> <|im_start|> data.")])
    original = base()
    items = original.task.context
    changed = ContextItem(
        reference=items[0].reference, untrusted_text="Meeting literal <tool> data."
    )
    task = IntelligenceTask.model_validate(
        {**original.task.model_dump(), "context": (changed, *items[1:])}
    )
    context = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    preview = m.prepare_claude_history_context_preview(
        context, read, selections=selections, observed_at=AT, route=wide_route()
    )
    request = g._prepare_contextual_catalog(preview.context)
    assert "</s>" in request.evidence_json and "<tool>" in request.evidence_json
    user_content = json.loads(preview.prompt_body)["messages"][1]["content"]
    assert "<" not in user_content and "\\u003c" in user_content
    assert json.loads(user_content)["provider_passages"] == json.loads(request.evidence_json)


def test_same_task_swapped_review_roles_has_distinct_derivation(saved):
    original, read = base(), load(saved)
    other_meeting = next(iter(original.related_source_ids))
    swapped = ReviewContext(original.task, other_meeting, frozenset({original.meeting_source_id}))
    a, b = prepare(original, read), prepare(swapped, read)
    assert a.original_task == b.original_task
    assert a.prompt_body != b.prompt_body
    assert a.context.task.task_id != b.context.task.task_id
    assert a.context.task.event.event_id != b.context.task.event.event_id


@pytest.mark.parametrize("fault", ["message_id", "foreign_ref"])
def test_actual_dependency_mismatch_holds_before_catalog(saved, monkeypatch, fault):
    read = load(saved)
    real = m.prepare_claude_large_original_message
    milestone = []

    def changed(*args, **kwargs):
        good = real(*args, **kwargs)
        milestone.append(good.profile_hash)
        if fault == "message_id":
            return replace(
                good,
                capture_binding_projection=replace(
                    good.capture_binding_projection, message_id=UUID(int=999)
                ),
            )
        profile = good.profile.model_copy(
            update={
                "current_original_reference": good.profile.current_original_reference.model_copy(
                    update={"source_id": UUID(int=999)}
                ),
                "original_binding_reference": good.profile.original_binding_reference.model_copy(
                    update={"source_id": UUID(int=999)}
                ),
            }
        )
        raw = m.canonical_bytes(profile.model_dump(mode="json"))
        return replace(good, profile=profile, profile_raw=raw, profile_hash=m.content_hash_of(raw))

    monkeypatch.setattr(m, "prepare_claude_large_original_message", changed)
    catalogs = []
    monkeypatch.setattr(m, "_prepare_contextual_catalog", lambda ctx: catalogs.append(ctx))
    outcome = None
    try:
        prepare(base(), read)
    except m.HistoryContextError as error:
        outcome = error
    assert len(milestone) == 1
    assert catalogs == []
    assert outcome is not None and outcome.__cause__ is outcome.__context__ is None


def test_meeting_249_lines_plus_two_history_messages_holds_at_actual_pack_boundary(
    host, monkeypatch
):
    read, selections = multi_read(
        host,
        monkeypatch,
        [("human", "User report alpha."), ("assistant", "Assistant suggestion beta.")],
    )
    original = base()
    item = original.task.context[0]
    task = IntelligenceTask.model_validate(
        {
            **original.task.model_dump(),
            "context": (
                ContextItem(
                    reference=item.reference,
                    untrusted_text="\n".join("Meeting line" for _ in range(249)),
                ),
                *original.task.context[1:],
            ),
        }
    )
    context = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    actual = m._prepare_contextual_catalog
    packed = []

    def observed(ctx):
        request = actual(ctx)
        packed.extend(
            q
            for _, q in request.quotes
            if q.source_id == read.original_reference.source_id
            and q.start == 0
            and q.end > selections[0].character_end
        )
        return request

    monkeypatch.setattr(m, "_prepare_contextual_catalog", observed)
    outcome = None
    try:
        m.prepare_claude_history_context_preview(
            context, read, selections=selections, observed_at=AT, route=wide_route()
        )
    except m.HistoryContextError as error:
        outcome = error
    assert packed and outcome is not None


def test_actual_public_legacy_request_runtime_resolver_and_packet_hold_preview_context(saved):
    preview = prepare(base(), load(saved))
    request = g._prepare_contextual_catalog(preview.context)  # still usable OFFLINE, no authority
    quote = next(q for _, q in request.quotes if q.source_id == preview.context.meeting_source_id)
    review = ContextualReview(
        format="zac-contextual-review-v1",
        task_id=preview.context.task.task_id,
        data_classification=preview.context.task.event.data_classification,
        overview=(Claim(text="Invented source observation.", quotes=(quote,)),),
    )
    draft = g.ContextualDraft(
        format="zac-contextual-draft-v2",
        overview=(
            g.DraftClaim(
                text="Invented source observation.",
                evidence_ids=(
                    next(
                        pid
                        for pid, q in request.quotes
                        if q.source_id == preview.context.meeting_source_id
                    ),
                ),
            ),
        ),
        background=(),
        continuity=(),
        items=(),
        conflicts=(),
        clarifications=(),
    )
    results = []
    actions = (
        lambda: g.prepare_contextual_request(preview.context),
        lambda: runtime.prepare_payload(request, route(), "0" * 64),
        lambda: g.resolve_contextual_draft(draft, request),
        lambda: encode_contextual_packet(
            review, preview.context, builder_id=UUID(int=1), created_at=AT + timedelta(seconds=1)
        ),
    )
    for action in actions:
        try:
            action()
        except ValueError:
            results.append("held")
        else:
            results.append("accepted")
    assert results == ["held"] * 4
    calls = []
    with pytest.raises(runtime.LocalContextualRuntimeError):
        runtime.dispatch_draft(
            request, route(), preview.prompt_body, lambda *args: calls.append(args)
        )
    assert calls == []


def test_actual_native_projection_rebase_rejects_history_original_marker(fixture):
    from tests.test_native_context_sidecar import retained_project
    from tests.test_native_evidence_context import choice

    original = fixture[1]["context"]
    task = IntelligenceTask.model_validate(
        {
            **original.task.model_dump(),
            "event": {
                **original.task.event.model_dump(),
                "event_type": "history.evidence.selected",
                "producer": "history-context-projection-v1",
            },
        }
    )
    original_context = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    projected = retained_project(
        fixture, (choice(fixture[2][-1], "Invented private body"),), context=original_context
    )
    assert projected.original_task == task
    outcome = None
    try:
        g.prepare_native_contextual_request(projected)
    except ValueError as error:
        outcome = error
    assert outcome is not None


@pytest.mark.parametrize(
    "producer", ["native-evidence-projection-v1", "history-context-projection-v1"]
)
def test_producer_marker_holds_before_actual_builder(saved, monkeypatch, producer):
    original = base()
    task = IntelligenceTask.model_validate(
        {
            **original.task.model_dump(),
            "event": {**original.task.event.model_dump(), "producer": producer},
        }
    )
    context = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    calls = []
    real = m.prepare_claude_large_original_message

    def observed(*args, **kwargs):
        calls.append("builder")
        return real(*args, **kwargs)

    monkeypatch.setattr(m, "prepare_claude_large_original_message", observed)
    with pytest.raises(m.HistoryContextError):
        prepare(context, load(saved))
    assert calls == []


@pytest.mark.parametrize("field", ["custody_id", "selected_dates_after_acquired_at"])
def test_profile_observation_mismatch_holds_before_catalog(saved, monkeypatch, field):
    real = m.prepare_claude_large_original_message
    built, catalogs = [], []

    def changed(*args, **kwargs):
        good = real(*args, **kwargs)
        value = (
            UUID(int=999)
            if field == "custody_id"
            else not good.profile.selected_dates_after_acquired_at
        )
        profile = good.profile.model_copy(update={field: value})
        raw = m.canonical_bytes(profile.model_dump(mode="json"))
        built.append(field)
        return replace(good, profile=profile, profile_raw=raw, profile_hash=m.content_hash_of(raw))

    monkeypatch.setattr(m, "prepare_claude_large_original_message", changed)
    monkeypatch.setattr(m, "_prepare_contextual_catalog", lambda ctx: catalogs.append(ctx))
    with pytest.raises(m.HistoryContextError):
        prepare(base(), load(saved))
    assert built == [field] and catalogs == []


def test_actual_legacy_user_turn_and_digest_placeholder_wire_behavior():
    request = g.prepare_contextual_request(base())
    zero = runtime._prepare_payload_body(request, route(), "0" * 64)
    other = runtime._prepare_payload_body(request, route(), "1" * 64)
    assert zero == other
    assert json.loads(zero)["messages"][1] == {
        "role": "user",
        "content": request.evidence_json.replace("<", "\\u003c"),
    }
    with pytest.raises(runtime.LocalContextualRuntimeError):
        runtime._prepare_payload_body(request, route(), "invalid")


def test_whole_read_hashes_observed_once_per_metadata_call(host, monkeypatch):
    read, selections = multi_read(
        host,
        monkeypatch,
        [("human", "User report alpha."), ("assistant", "Assistant suggestion beta.")],
    )
    actual = m.content_hash_of
    calls = {"original": 0, "companion": 0, "envelope": 0}

    def observed(raw):
        for name in calls:
            if raw is getattr(read, name + "_raw"):
                calls[name] += 1
        return actual(raw)

    monkeypatch.setattr(m, "content_hash_of", observed)
    preview = m.prepare_claude_history_context_preview(
        base(), read, selections=selections, observed_at=AT, route=wide_route()
    )
    assert len(preview.sidecar.entries) == 2
    assert calls == {"original": 1, "companion": 1, "envelope": 1}
