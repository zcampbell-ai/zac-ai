"""Actual parsers/filesystem and invented SQLite scalar rows, not protected intake.

Base fixture's PG isolation/timezone adaptation is explicit. No SQL model,
processing, private-account or recovery claim. Public native loader executes.
"""

import base64
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests import test_native_batch_inventory as base
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import native_evidence_context as m
from zacai.intelligence.contracts import ContextItem, Importance, IntelligenceTask, ZacEvent
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


@pytest.fixture
def fixture(tmp_path, monkeypatch, request):
    original_inputs = base.gmail_inputs
    original = "From: invented@example.test\r\nSubject: original\r\n\r\nEarlier café 😀e\u0301 decision.\r\nCorrection requires confirmation.".encode()

    if getattr(request, "param", None) == "binary":
        original = b"From: invented@example.test\r\n\r\nopaque\xff bytes"

    def gmail_inputs():
        args, _ = original_inputs()
        data = json.loads(args["message_response"])
        data["raw"] = base64.urlsafe_b64encode(original).decode().rstrip("=")
        args["message_response"] = json.dumps(data).encode()
        return args, original

    monkeypatch.setattr(base, "gmail_inputs", gmail_inputs)
    if getattr(request, "param", None) in {"utf8_capacity", "unicode_separator"}:
        original_slack = base.slack_inputs

        def long_slack():
            args = original_slack()
            page = json.loads(args["page_response"])
            page["messages"][0]["text"] = (
                "x" * 1500 + "\u2028" + "next"
                if request.param == "unicode_separator"
                else "\n".join(["😀" * 999] * 4)
            )
            args["page_response"] = json.dumps(page).encode()
            return args

        monkeypatch.setattr(base, "slack_inputs", long_slack)
    iterator = base.saved.__wrapped__(tmp_path)
    saved = next(iterator)
    sql, args, sources, _, _ = saved
    source = base.put_source(
        sql,
        args["artifacts"],
        SourceSystem.FIREFLIES,
        "invented-meeting",
        b"Original meeting quoted data",
    )
    sql.commit()
    ref = base.ref(source)
    task = IntelligenceTask(
        task_id=uuid4(),
        event=ZacEvent(
            event_id=uuid4(),
            event_type="meeting.completed",
            producer="invented.fixture",
            occurred_at=base.NOW,
            observed_at=base.NOW,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            provenance=(ref,),
            correlation_id=uuid4(),
            importance=Importance.IMPORTANT,
            confidence=1.0,
        ),
        required_capabilities=frozenset({"contextual_meeting_review"}),
        instruction="Original task instruction stays exact.",
        context=(ContextItem(reference=ref, untrusted_text="Original meeting quoted data"),),
        max_latency_ms=1234,
        max_estimated_cost_usd=0.0,
        max_output_tokens=222,
    )
    kwargs = {
        **args,
        "context": ReviewContext(task, source.id),
        "observed_at": args["as_of"],
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
    }
    kwargs.pop("as_of")
    yield sql, kwargs, sources, original, source
    try:
        next(iterator)
    except StopIteration:
        pass


def choice(row, value, field="text", start=0, end=None):
    return m.NativeEvidenceSelection(
        source_id=row.id,
        content_hash=row.content_hash,
        field=field,
        field_text_hash=content_hash_of(value.encode()),
        spans=(m.NativeEvidenceSpan(start=start, end=end or len(value)),),
        relevance_reason="Explicit host-selected earlier decision; relation unconfirmed.",
    )


def project(fixture, selections, **changes):
    sql, args, _, _, _ = fixture
    return m.append_native_evidence_context(sql, **{**args, "selections": selections, **changes})


def run(fixture, selections, **changes):
    return project(fixture, selections, **changes).context


def test_exact_slack_selected_field_only_and_original_bindings(fixture):
    sql, args, sources, _, _ = fixture
    selected = choice(sources[-1], "Invented private body", start=9, end=16)
    before = list(sql.execute(select(*Source.__table__.columns)))
    result = run(fixture, (selected,))
    text = result.task.context[-1].untrusted_text
    assert text == "private"
    meta = project(fixture, (selected,)).metadata[0]
    assert meta.source_span.start == 9 and meta.source_span.end == 16
    assert meta.provider_occurred_at.year == 1970 and meta.batch_observed_at == base.NOW
    assert result.task.context[-1].reference == base.ref(sources[-1])
    for name in (
        "instruction",
        "max_output_tokens",
        "max_latency_ms",
        "max_estimated_cost_usd",
        "required_capabilities",
    ):
        assert getattr(result.task, name) == getattr(args["context"].task, name)
    for name in (
        "occurred_at",
        "correlation_id",
        "related_entities",
        "importance",
    ):
        assert getattr(result.task.event, name) == getattr(args["context"].task.event, name)
    assert len(result.task.context) == 2 and len(result.task.event.provenance) == 9
    assert result.related_source_ids == frozenset({selected.source_id})
    assert (
        before == list(sql.execute(select(*Source.__table__.columns)))
        and not sql.new
        and not sql.dirty
    )


def test_exact_rfc_utf8_span_preserves_codepoints_and_hashes(fixture):
    _, _, sources, raw, _ = fixture
    value = raw.decode()
    start = value.index("café")
    result = run(fixture, (choice(sources[2], value, "rfc822_utf8", start, start + 8),))
    text = result.task.context[-1].untrusted_text
    assert text == value[start : start + 8]
    proof = project(fixture, (choice(sources[2], value, "rfc822_utf8", start, start + 8),))
    assert proof.metadata[0].field == "rfc822_utf8"
    assert proof.metadata[0].reference.content_hash == content_hash_of(raw)
    assert (
        not proof.metadata[0].authorship_verified and not proof.metadata[0].sent_approval_verified
    )


@pytest.mark.parametrize("fault", ["boundary", "classification"])
def test_caller_access_denies_before_any_inventory_get(fixture, fault):
    _, args, sources, _, _ = fixture
    store = CountingStore(args["artifacts"])
    changes = {"artifacts": store}
    changes["authorized_boundaries" if fault == "boundary" else "allowed_classifications"] = (
        frozenset({B.PERSONAL}) if fault == "boundary" else frozenset({C.PUBLIC})
    )
    with pytest.raises(m.NativeEvidenceContextError) as exc:
        run(fixture, (choice(sources[-1], "Invented private body"),), **changes)
    assert store.count == 0 and exc.value.__context__ is None


class CountingStore:
    def __init__(self, store, callback=None):
        self.store, self.callback, self.count = store, callback, 0

    def get(self, boundary, location):
        self.count += 1
        raw = self.store.get(boundary, location)
        if self.callback:
            self.callback(self.count, location)
        return raw

    def put(self, *args):
        raise AssertionError("projection must not write artifacts")


@pytest.mark.parametrize("fault", ["hash", "field_hash", "role", "span", "duplicate", "profile"])
def test_exact_selection_faults_hold(fixture, fault):
    _, _, sources, _, _ = fixture
    selected = choice(sources[-1], "Invented private body")
    data = selected.model_dump()
    if fault == "hash":
        data["content_hash"] = "f" * 64
    if fault == "field_hash":
        data["field_text_hash"] = "e" * 64
    if fault == "role":
        data["field"] = "rfc822_utf8"
    if fault == "span":
        data["spans"] = [{"start": 0, "end": 30}]
    if fault == "profile":
        data.update(
            source_id=sources[0].id, content_hash=sources[0].content_hash, field="rfc822_utf8"
        )
    selected = m.NativeEvidenceSelection.model_validate(data)
    selections = (selected, selected) if fault == "duplicate" else (selected,)
    with pytest.raises(m.NativeEvidenceContextError) as exc:
        run(fixture, selections)
    assert exc.value.__context__ is None and "Invented" not in str(exc.value)


@pytest.mark.parametrize("target", ["native", "old_context"])
def test_acl_changed_by_last_artifact_callback_holds_after_milestone(fixture, target):
    sql, args, sources, _, meeting = fixture
    # Determine exact callback sequence from a successful public method first.
    count = CountingStore(args["artifacts"])
    run(fixture, (choice(sources[-1], "Invented private body"),), artifacts=count)
    events = []
    sid = sources[-1].id if target == "native" else meeting.id

    def mutate(n, location):
        if n == count.count:
            sql.add(
                SourceClassificationElevation(
                    source_id=sid,
                    trust_boundary=B.BRAINSTORM,
                    previous_classification=C.CONFIDENTIAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    elevated_by="invented",
                    elevated_at=base.NOW,
                    reason="Invented elevation",
                )
            )
            sql.flush()
            events.append((n, location))

    with pytest.raises(m.NativeEvidenceContextError):
        run(
            fixture,
            (choice(sources[-1], "Invented private body"),),
            artifacts=CountingStore(args["artifacts"], mutate),
        )
    assert len(events) == 1 and not sql.new and not sql.dirty


def test_only_explicit_relevant_choice_changes_context_and_no_fact_promotion(fixture):
    _, _, sources, raw, _ = fixture
    mail = run(fixture, (choice(sources[2], raw.decode(), "rfc822_utf8", 0, 10),))
    slack = run(fixture, (choice(sources[-1], "Invented private body"),))
    assert mail.task.context[0] == slack.task.context[0]
    assert mail.task.context[-1].reference.source_id != slack.task.context[-1].reference.source_id
    assert mail.task.context[-1].untrusted_text == raw.decode()[:10]
    assert slack.task.context[-1].untrusted_text == "Invented private body"
    assert (
        project(fixture, (choice(sources[-1], "Invented private body"),)).metadata[0].project_link
        == "UNCONFIRMED"
    )
    assert mail.task.event.occurred_at == slack.task.event.occurred_at


def test_original_context_corruption_holds_before_native_body_read(fixture):
    sql, args, sources, _, meeting = fixture
    sql.execute(
        Source.__table__.update().where(Source.id == meeting.id).values(content_hash="f" * 64)
    )
    sql.commit()
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        run(fixture, (choice(sources[-1], "Invented private body"),), artifacts=store)
    assert store.count == 0


@pytest.mark.parametrize("fault", ["too_many", "empty", "naive", "dirty"])
def test_closed_capacity_inputs_hold_before_artifacts(fixture, fault):
    _sql, args, sources, _, meeting = fixture
    selected = choice(sources[-1], "Invented private body")
    selections = (selected,)
    changes = {}
    if fault == "too_many":
        selections = (selected,) * 5
    if fault == "empty":
        selections = ()
    if fault == "naive":
        changes["observed_at"] = args["observed_at"].replace(tzinfo=None)
    if fault == "dirty":
        meeting.excerpt = "Pending write"
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        run(fixture, selections, artifacts=store, **changes)
    assert store.count == 0


@pytest.mark.parametrize("fault", ["hash", "elevation", "role"])
def test_selected_source_integrity_denied_before_inventory_body(fixture, fault):
    sql, args, sources, _, _ = fixture
    selected = choice(sources[-1], "Invented private body")
    if fault == "hash":
        selected = selected.model_copy(update={"content_hash": "f" * 64})
    elif fault == "elevation":
        sql.add(
            SourceClassificationElevation(
                source_id=selected.source_id,
                trust_boundary=B.BRAINSTORM,
                previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED,
                elevated_at=base.NOW,
                elevated_by="invented",
                reason="Synthetic correction",
            )
        )
        sql.flush()
    else:
        selected = selected.model_copy(update={"field": "rfc822_utf8"})
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        run(fixture, (selected,), artifacts=store)
    assert store.count == 0


def test_later_revision_does_not_promote_dated_selected_evidence(fixture):
    sql, args, sources, _, _ = fixture
    old = sources[-1]
    corrected = base.put_source(
        sql,
        args["artifacts"],
        SourceSystem.SLACK,
        old.external_ref,
        b'{"ts":"150.123456","text":"Corrected later proposal, unconfirmed"}',
        at=base.NOW + timedelta(microseconds=1),
    )
    corrected.supersedes_source_id = old.id
    sql.commit()
    assert (
        sql.scalar(select(Source.supersedes_source_id).where(Source.id == corrected.id)) == old.id
    )
    historical = run(fixture, (choice(old, "Invented private body"),))
    text = historical.task.context[-1].untrusted_text
    assert historical.task.context[-1].reference.source_id == old.id
    assert text == "Invented private body" and "Corrected later proposal" not in text
    assert not project(fixture, (choice(old, "Invented private body"),)).metadata[0].current_fact
    with pytest.raises(m.NativeEvidenceContextError):
        run(fixture, (choice(corrected, "Corrected later proposal, unconfirmed"),))


@pytest.mark.parametrize("target", ["native", "old_context"])
def test_final_scalar_metadata_detects_sqlite_admin_corruption(fixture, target):
    sql, args, sources, _, meeting = fixture
    good_count = CountingStore(args["artifacts"])
    run(fixture, (choice(sources[-1], "Invented private body"),), artifacts=good_count)
    sid = sources[-1].id if target == "native" else meeting.id
    events = []

    def corrupt(n, _location):
        if n == good_count.count:
            sql.execute(
                Source.__table__.update()
                .where(Source.id == sid)
                .values(content_location="changed-admin-location")
            )
            assert (
                sql.scalar(select(Source.content_location).where(Source.id == sid))
                == "changed-admin-location"
            )
            events.append(n)

    with pytest.raises(m.NativeEvidenceContextError):
        run(
            fixture,
            (choice(sources[-1], "Invented private body"),),
            artifacts=CountingStore(args["artifacts"], corrupt),
        )
    assert events == [good_count.count]


@pytest.mark.parametrize("fault", ["multiple_spans", "too_long", "negative", "empty_reason"])
def test_closed_selector_validation(fixture, fault):
    _, _, sources, _, _ = fixture
    data = choice(sources[-1], "Invented private body").model_dump()
    if fault == "multiple_spans":
        data["spans"] = [{"start": 0, "end": 10}, {"start": 5, "end": 15}]
    elif fault == "too_long":
        data["spans"] = [{"start": 0, "end": 4001}]
    elif fault == "negative":
        data["spans"] = [{"start": -1, "end": 5}]
    else:
        data["relevance_reason"] = "  "
    with pytest.raises(ValueError):
        m.NativeEvidenceSelection.model_validate(data)


@pytest.mark.parametrize("fixture", ["binary"], indirect=True)
def test_non_utf8_rfc_is_retained_but_not_projected_as_text(fixture):
    _, _, sources, original, _ = fixture
    assert b"\xff" in original
    sibling = project(fixture, (choice(sources[-1], "Invented private body"),))
    assert sibling.context.task.context[-1].untrusted_text == "Invented private body"
    with pytest.raises(m.NativeEvidenceContextError) as exc:
        run(
            fixture,
            (choice(sources[2], original.decode("utf-8", errors="replace"), "rfc822_utf8"),),
        )
    assert exc.value.__context__ is None


def test_original_context_capacity_hold_before_artifact_reads(fixture):
    _, args, sources, _, _ = fixture
    original = args["context"]
    data = original.task.model_dump()
    data["context"][0]["untrusted_text"] = "x" * 48_001
    large = ReviewContext(IntelligenceTask.model_validate(data), original.meeting_source_id)
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        run(
            fixture, (choice(sources[-1], "Invented private body"),), artifacts=store, context=large
        )
    assert store.count == 0


def test_existing_contextual_serializer_uses_only_explicit_native_role(fixture):
    from zacai.intelligence.contextual_generation import _prepare_contextual_catalog

    _, args, sources, _, _ = fixture
    projected = run(fixture, (choice(sources[-1], "Invented private body"),))
    prepared = _prepare_contextual_catalog(projected)
    assert prepared.context.task.task_id != args["context"].task.task_id
    assert (
        project(fixture, (choice(sources[-1], "Invented private body"),)).original_task
        == args["context"].task
    )
    assert prepared.context.task.instruction == args["context"].task.instruction
    source_ids = {quote.source_id for _, quote in prepared.quotes}
    assert sources[-1].id in source_ids
    assert not {sources[0].id, sources[1].id, sources[2].id} & source_ids
    assert "Invented private body" in prepared.evidence_json
    reason = choice(sources[-1], "Invented private body").relevance_reason
    assert reason not in prepared.evidence_json and reason not in prepared.instruction
    assert "Host-selected" not in prepared.evidence_json
    assert "Provider occurrence" not in prepared.evidence_json


@pytest.mark.parametrize(
    "caps",
    [
        frozenset({"structured_extraction"}),
        frozenset({"contextual_meeting_review", "compact_meeting_review"}),
    ],
)
def test_no_silent_expansion_of_old_compact_capability(fixture, caps):
    _, args, sources, _, _ = fixture
    original = args["context"]
    data = original.task.model_dump()
    data["required_capabilities"] = caps
    other = ReviewContext(IntelligenceTask.model_validate(data), original.meeting_source_id)
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        run(
            fixture, (choice(sources[-1], "Invented private body"),), artifacts=store, context=other
        )
    assert store.count == 0


def test_multi_selection_is_exact_and_derivation_replays_without_original_mutation(fixture):
    _, args, sources, raw, _ = fixture
    original = args["context"].task.model_dump_json()
    selected = (
        choice(sources[2], raw.decode(), "rfc822_utf8", 0, 10),
        choice(sources[-1], "Invented private body"),
    )
    first = project(fixture, selected)
    second = project(fixture, selected)
    assert first.context.task == second.context.task
    assert first.original_task == args["context"].task
    assert first.context.task.task_id != first.original_task.task_id
    assert first.original_event == args["context"].task.event
    assert args["context"].task.model_dump_json() == original
    event = first.context.task.event
    assert event.event_id != first.original_event.event_id
    assert event.causation_id == first.original_event.event_id
    assert event.correlation_id == first.original_event.correlation_id
    assert (
        event.provenance[: len(first.original_event.provenance)] == first.original_event.provenance
    )
    assert [item.untrusted_text for item in first.context.task.context[-2:]] == [
        raw.decode()[:10],
        "Invented private body",
    ]
    assert len(first.metadata) == 2
    changed = selected[0].model_copy(
        update={"relevance_reason": "Different explicit selection basis"}
    )
    third = project(fixture, (changed, selected[1]))
    assert third.context.task.event.event_id != event.event_id
    assert third.context.task.task_id != first.context.task.task_id
    assert third.context.task.context == first.context.task.context
    assert (
        not first.processing_authorized
        and not first.recovery_verified
        and not first.facts_confirmed
    )


@pytest.mark.parametrize("target", ["batch", "approval", "unselected"])
def test_complete_dependency_access_is_checked_before_provider_read(fixture, target):
    sql, args, sources, _, _ = fixture
    selected = choice(sources[-1], "Invented private body")
    positive = CountingStore(args["artifacts"])
    project(fixture, (selected,), artifacts=positive)
    assert positive.count > 1
    sid = (
        args["batch_reference"].source_id
        if target == "batch"
        else args["approval_reference"].source_id
        if target == "approval"
        else sources[0].id
    )
    sql.add(
        SourceClassificationElevation(
            source_id=sid,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            elevated_by="invented",
            elevated_at=base.NOW,
            reason="Synthetic current access reduction",
        )
    )
    sql.flush()
    assert (
        sql.scalar(
            select(SourceClassificationElevation.source_id).where(
                SourceClassificationElevation.source_id == sid
            )
        )
        == sid
    )
    reads = []
    store = CountingStore(args["artifacts"], lambda n, location: reads.append(location))
    with pytest.raises(m.NativeEvidenceContextError):
        project(fixture, (selected,), artifacts=store)
    if target == "unselected":
        batch = sql.get(Source, args["batch_reference"].source_id)
        assert reads == [batch.content_location]
    else:
        assert reads == []


def test_multi_selection_late_acl_change_holds_after_actual_callback(fixture):
    sql, args, sources, raw, _ = fixture
    selections = (
        choice(sources[2], raw.decode(), "rfc822_utf8", 0, 10),
        choice(sources[-1], "Invented private body"),
    )
    positive = CountingStore(args["artifacts"])
    project(fixture, selections, artifacts=positive)
    milestones = []

    def elevate(n, _location):
        if n == positive.count:
            sql.add(
                SourceClassificationElevation(
                    source_id=sources[2].id,
                    trust_boundary=B.BRAINSTORM,
                    previous_classification=C.CONFIDENTIAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    elevated_by="invented",
                    elevated_at=base.NOW,
                    reason="Late access reduction",
                )
            )
            sql.flush()
            milestones.append(n)

    with pytest.raises(m.NativeEvidenceContextError):
        project(fixture, selections, artifacts=CountingStore(args["artifacts"], elevate))
    assert milestones == [positive.count]


@pytest.mark.parametrize("fixture", ["utf8_capacity"], indirect=True)
def test_utf8_item_bound_is_distinct_from_unicode_and_line_bounds(fixture):
    _, _, sources, _, _ = fixture
    value = "\n".join(["😀" * 999] * 4)
    assert len(value) == 3999 and len(value.encode()) > 12000
    assert all(len(line) <= 1500 for line in value.splitlines())
    sibling = project(fixture, (choice(sources[-1], value, start=0, end=999),))
    assert sibling.context.task.context[-1].untrusted_text == "😀" * 999
    # Genuine provider page/parser/retained field; one bounded exact span.
    with pytest.raises(m.NativeEvidenceContextError):
        project(fixture, (choice(sources[-1], value),))


def test_already_quoted_selected_source_does_not_duplicate_context(fixture):
    _, args, sources, _, _ = fixture
    first = project(fixture, (choice(sources[-1], "Invented private body"),))
    assert len(first.context.task.context) == 2
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        project(
            fixture,
            (choice(sources[-1], "Invented private body"),),
            context=first.context,
            artifacts=store,
        )
    assert store.count == 0
    assert len(args["context"].task.context) == 1


@pytest.mark.parametrize("fixture", ["unicode_separator"], indirect=True)
def test_exact_serializer_line_terminator_ceiling_with_positive_subspan(fixture):
    from zacai.intelligence.contextual_generation import _prepare_contextual_catalog

    _, _, sources, _, _ = fixture
    value = "x" * 1500 + "\u2028" + "next"
    good = project(fixture, (choice(sources[-1], value, end=1499),))
    assert _prepare_contextual_catalog(good.context).quotes
    # Serializer retains U+2028 in passage; 1500+terminator exceeds1500.
    assert len(value.splitlines()[0]) == 1500
    with pytest.raises(m.NativeEvidenceContextError):
        project(fixture, (choice(sources[-1], value),))
