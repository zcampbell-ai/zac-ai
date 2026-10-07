"""Invented SQLite scalar/real filesystem controls; PG isolation guard simulated.

SQLite has no canonical append-only triggers. Raw mutations below are deliberate
corruption injections, not claims that ordinary PostgreSQL permits Source edits.
"""

import copy
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import DateTime, create_engine, update
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence import research_context as module
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.research_context import (
    RenderedFirefliesSelection,
    ResearchRange,
    load_rendered_fireflies_literal,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.research_intake import prepare_rendered_fireflies_literal
from zacai.state import Source, SourceClassificationElevation, SourceSystem


class SQLiteAwareDate(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=UTC)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    # SQLite's naive datetime adapter is replaced solely to emulate PG timezone results.
    monkeypatch.setattr(Source.__table__.c.captured_at, "type", SQLiteAwareDate())
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    monkeypatch.setattr(module, "_assert_ledger_isolation", lambda session: None)
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    detail = canonical_bytes(
        {
            "request": {"transcriptId": "invented1"},
            "fetched_at": "2026-10-07T12:00:00Z",
            "response": {
                "content": [{"type": "text", "text": "Literal café 😀. Untrusted returned text."}],
                "isError": False,
            },
        }
    )
    record = {
        key: None
        for key in (
            "title",
            "duration",
            "organizerEmail",
            "meetingLink",
            "summary",
            "meetingAttendees",
            "meetingInfo",
            "participants",
        )
    }
    record.update(id="invented1", dateString="2026-07-01T10:00:00Z")
    metadata = canonical_bytes(
        {
            "request": {"format": "json", "limit": 50, "skip": 0, "mine": False},
            "fetched_at": "2026-10-07T13:00:00Z",
            "response": {
                "content": [{"type": "text", "text": json.dumps([record])}],
                "isError": False,
            },
        }
    )
    refs = [
        EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(raw),
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        for raw in (detail, metadata)
    ]
    derived = prepare_rendered_fireflies_literal(
        detail_raw=detail,
        metadata_raw=metadata,
        detail_reference=refs[0],
        metadata_reference=refs[1],
        block_index=0,
        start=0,
        end=15,
    ).envelope
    refs.append(
        EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(derived),
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
    )
    raws = (detail, metadata, derived)
    with Session(engine) as session, session.begin():
        for i, (ref, raw) in enumerate(zip(refs, raws)):
            location = store.put(B.BRAINSTORM, ref.content_hash, raw)
            session.add(
                Source(
                    id=ref.source_id,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    external_ref=f"invented/{i}",
                    captured_at=datetime(2026, 10, 7, tzinfo=UTC),
                    content_hash=ref.content_hash,
                    content_location=location,
                )
            )
    choice = RenderedFirefliesSelection(
        detail_reference=refs[0],
        metadata_reference=refs[1],
        derived_reference=refs[2],
        requested_transcript_id="invented1",
        block_index=0,
        span=ResearchRange(start=0, end=15),
    )
    session = Session(engine)
    session.begin()
    yield session, store, choice, raws
    session.close()
    engine.dispose()


class ObservedStore:
    """Test-only method spies on an exact concrete store, no fake reader."""

    def __new__(cls, store, callback=None, transform=None):
        observed = copy.copy(store)
        observed.gets = []
        observed.unbounded_gets = []
        original = store.get_bounded

        def get_bounded(boundary, location, *, max_bytes):
            observed.gets.append(location)
            value = original(boundary, location, max_bytes=max_bytes)
            if callback:
                callback(len(observed.gets))
            return transform(len(observed.gets), value) if transform else value

        def forbidden(*args, **kwargs):
            observed.unbounded_gets.append(True)
            raise AssertionError("unbounded get or put forbidden")

        observed.get_bounded = get_bounded
        observed.get = forbidden
        observed.put = forbidden
        return observed


def load(fixture, store=None, **changes):
    session, actual, choice, _ = fixture
    args = {
        "artifacts": store or actual,
        "selection": choice,
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
    }
    args.update(changes)
    return load_rendered_fireflies_literal(session, **args)


def test_real_files_and_three_current_scalar_sources(fixture):
    observed = ObservedStore(fixture[1])
    result = load(fixture, observed)
    assert len(observed.gets) == 3
    assert result.envelope == fixture[3][2]
    assert result.recovery_references == (
        fixture[2].detail_reference,
        fixture[2].metadata_reference,
        fixture[2].derived_reference,
    )
    assert (
        result.processing_authorized is False
        and result.recovery_verified is False
        and result.current_facts_verified is False
    )
    assert "café" not in repr(result)


@pytest.mark.parametrize("which", [0, 1, 2])
@pytest.mark.parametrize(
    "field,value",
    [
        ("trust_boundary", B.PERSONAL),
        ("data_classification", C.HIGHLY_RESTRICTED),
        ("content_hash", "0" * 64),
        ("system", SourceSystem.FIREFLIES),
    ],
)
def test_denied_original_or_derived_before_any_get(fixture, which, field, value):
    session, store, choice, _ = fixture
    refs = (choice.detail_reference, choice.metadata_reference, choice.derived_reference)
    session.execute(update(Source).where(Source.id == refs[which].source_id).values({field: value}))
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert observed.gets == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("trust_boundary", B.PERSONAL),
        ("content_location", "changed"),
        ("excerpt", "changed"),
        ("captured_at", datetime(2026, 10, 8, tzinfo=UTC)),
        ("external_ref", "changed"),
    ],
)
def test_final_callback_full_columns_hold(fixture, field, value):
    session, store, choice, _ = fixture
    fired = []

    def callback(count):
        if count == 3:
            session.execute(
                update(Source)
                .where(Source.id == choice.detail_reference.source_id)
                .values({field: value})
            )
            fired.append(True)

    observed = ObservedStore(store, callback)
    with pytest.raises(ValueError) as error:
        load(fixture, observed)
    assert fired == [True] and len(observed.gets) == 3
    assert str(error.value) == "rendered Fireflies research unavailable"
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("stage", [1, 3])
def test_callback_transaction_replacement_hold(fixture, stage):
    session, store, _, _ = fixture
    fired = []

    def callback(count):
        if count == stage:
            session.rollback()
            session.begin()
            fired.append(True)

    observed = ObservedStore(store, callback)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert fired == [True] and len(observed.gets) == stage


def test_changed_selection_does_not_reconstruct_old_derivative(fixture):
    choice = fixture[2].model_copy(update={"span": ResearchRange(start=1, end=15)})
    with pytest.raises(ValueError):
        load(fixture, selection=choice)


def test_current_revision_and_ambiguous_tip_hold_before_get(fixture):
    session, store, choice, _ = fixture
    session.add(
        Source(
            id=uuid4(),
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref="invented/0",
            captured_at=datetime(2026, 10, 7, tzinfo=UTC),
            content_hash="1" * 64,
            content_location="invented",
            supersedes_source_id=choice.detail_reference.source_id,
        )
    )
    session.flush()
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert observed.gets == []


@pytest.mark.parametrize("when", [0, 1, 3])
def test_effective_elevation_in_dependency_union(fixture, when):
    session, store, choice, _ = fixture
    fired = []

    def elevate():
        session.add(
            SourceClassificationElevation(
                id=uuid4(),
                source_id=choice.metadata_reference.source_id,
                trust_boundary=B.BRAINSTORM,
                previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented",
                elevated_by="invented",
                elevated_at=datetime(2026, 10, 7, tzinfo=UTC),
            )
        )
        session.flush()
        fired.append(True)

    if when == 0:
        elevate()
    observed = ObservedStore(store, lambda count: elevate() if count == when else None)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert fired == [True] and len(observed.gets) == when


def test_ambiguous_other_current_tip_holds(fixture):
    session, store, _, _ = fixture
    session.add(
        Source(
            id=uuid4(),
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref="invented/0",
            captured_at=datetime(2026, 10, 7, tzinfo=UTC),
            content_hash="2" * 64,
            content_location="invented",
        )
    )
    session.flush()
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert observed.gets == []


@pytest.mark.parametrize("index", [0, 1, 2])
def test_artifact_corruption_fires_exact_read(fixture, index):
    store = fixture[1]
    fired = []

    def transform(count, raw):
        if count == index + 1:
            fired.append(True)
            return b"corrupt invented"
        return raw

    observed = ObservedStore(store, transform=transform)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert fired == [True] and len(observed.gets) == index + 1


def test_hash_consistent_canonical_changed_derivative_holds_reconstruction(fixture):
    session, store, choice, raws = fixture
    body = json.loads(raws[2])
    body["reported_metadata_date"] = "2020-01-01T00:00:00+00:00"
    changed = canonical_bytes(body)
    digest = content_hash_of(changed)
    location = store.put(B.BRAINSTORM, digest, changed)
    session.execute(
        update(Source)
        .where(Source.id == choice.derived_reference.source_id)
        .values(content_hash=digest, content_location=location)
    )
    ref = choice.derived_reference.model_copy(update={"content_hash": digest})
    new = choice.model_copy(update={"derived_reference": ref})
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed, selection=new)
    assert len(observed.gets) == 3


def test_no_active_transaction_before_reads(fixture):
    fixture[0].rollback()
    observed = ObservedStore(fixture[1])
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert observed.gets == []


def test_late_revision_child_holds_after_all_reads(fixture):
    session, store, choice, _ = fixture
    fired = []

    def callback(count):
        if count == 3:
            session.add(
                Source(
                    id=uuid4(),
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    external_ref="invented/0",
                    captured_at=datetime(2026, 10, 7, tzinfo=UTC),
                    content_hash="3" * 64,
                    content_location="invented",
                    supersedes_source_id=choice.detail_reference.source_id,
                )
            )
            session.flush()
            fired.append(True)

    observed = ObservedStore(store, callback)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert fired == [True] and len(observed.gets) == 3


@pytest.mark.parametrize("argument", ["authorized_boundaries", "allowed_classifications"])
def test_caller_read_scope_denied_before_get(fixture, argument):
    observed = ObservedStore(fixture[1])
    with pytest.raises(ValueError):
        load(fixture, observed, **{argument: frozenset()})
    assert observed.gets == []


@pytest.mark.parametrize("boundary", [B.PERSONAL, B.BRAINSTORM])
def test_explicit_hr_current_read_with_three_exact_sources(fixture, boundary):
    session, store, choice, raws = fixture
    first = choice.detail_reference.model_copy(
        update={"trust_boundary": boundary, "effective_classification": C.HIGHLY_RESTRICTED}
    )
    second = choice.metadata_reference.model_copy(
        update={"trust_boundary": boundary, "effective_classification": C.HIGHLY_RESTRICTED}
    )
    derived = prepare_rendered_fireflies_literal(
        detail_raw=raws[0],
        metadata_raw=raws[1],
        detail_reference=first,
        metadata_reference=second,
        block_index=0,
        start=0,
        end=15,
    ).envelope
    third = choice.derived_reference.model_copy(
        update={
            "trust_boundary": boundary,
            "effective_classification": C.HIGHLY_RESTRICTED,
            "content_hash": content_hash_of(derived),
        }
    )
    new = RenderedFirefliesSelection(
        detail_reference=first,
        metadata_reference=second,
        derived_reference=third,
        requested_transcript_id="invented1",
        block_index=0,
        span=choice.span,
    )
    for ref, raw in zip((first, second, third), (raws[0], raws[1], derived)):
        location = store.put(boundary, ref.content_hash, raw)
        session.execute(
            update(Source)
            .where(Source.id == ref.source_id)
            .values(
                trust_boundary=boundary,
                data_classification=C.HIGHLY_RESTRICTED,
                content_hash=ref.content_hash,
                content_location=location,
            )
        )
    observed = ObservedStore(store)
    result = load(
        fixture,
        observed,
        selection=new,
        authorized_boundaries=frozenset({boundary}),
        allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
    )
    assert len(observed.gets) == 3
    assert result.recovery_references == (first, second, third)
    assert result.envelope == derived and result.recovery_verified is False
    denied = ObservedStore(store)
    with pytest.raises(ValueError):
        load(
            fixture,
            denied,
            selection=new,
            authorized_boundaries=frozenset({boundary}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
    assert denied.gets == []


def test_cross_boundary_or_shared_selection_rejected(fixture):
    choice = fixture[2]
    for boundary in (B.PERSONAL, B.SHARED):
        first = choice.detail_reference.model_copy(update={"trust_boundary": boundary})
        with pytest.raises(ValueError):
            RenderedFirefliesSelection.model_validate(
                choice.model_copy(update={"detail_reference": first})
            )


@pytest.mark.parametrize("index,limit", [(0, 2_000_000), (1, 2_000_000), (2, 32_000)])
def test_actual_oversize_file_holds_before_materialization(fixture, monkeypatch, index, limit):
    import os

    from zacai.ingestion import artifact_store as artifact_module

    session, store, choice, _ = fixture
    raw = b"x" * (limit + 1)
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    fields = ("detail_reference", "metadata_reference", "derived_reference")
    selected = getattr(choice, fields[index])
    changed = selected.model_copy(update={"content_hash": digest})
    new = choice.model_copy(update={fields[index]: changed})
    session.execute(
        update(Source)
        .where(Source.id == selected.source_id)
        .values(content_hash=digest, content_location=location)
    )
    fdopen = artifact_module.os.fdopen
    opened = []

    def spy(fd, *args, **kwargs):
        opened.append(os.fstat(fd).st_size)
        return fdopen(fd, *args, **kwargs)

    monkeypatch.setattr(artifact_module.os, "fdopen", spy)
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed, selection=new)
    assert len(observed.gets) == index + 1
    assert len(opened) == index and all(size <= 2_000_000 for size in opened)
    assert limit + 1 not in opened
    assert observed.unbounded_gets == []


def test_revocation_inside_actual_bounded_file_read_holds_before_next_get(fixture, monkeypatch):
    from zacai.ingestion import artifact_store as artifact_module

    session, store, choice, _ = fixture
    fired = []
    fdopen = artifact_module.os.fdopen

    class Stream:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def read(self, count):
            raw = self.inner.read(count)
            if not fired:
                session.execute(
                    update(Source)
                    .where(Source.id == choice.metadata_reference.source_id)
                    .values(trust_boundary=B.PERSONAL)
                )
                fired.append(True)
            return raw

    monkeypatch.setattr(artifact_module.os, "fdopen", lambda *a, **k: Stream(fdopen(*a, **k)))
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert fired == [True] and len(observed.gets) == 1


def test_get_only_shaped_store_refused_before_any_read(fixture):
    calls = []

    class GetOnly:
        def get(self, *args):
            calls.append(True)
            return b"invented"

    with pytest.raises(ValueError):
        load(fixture, GetOnly())
    assert calls == []


def hr_sources(fixture):
    session, store, choice, raws = fixture
    first = choice.detail_reference.model_copy(
        update={"effective_classification": C.HIGHLY_RESTRICTED}
    )
    second = choice.metadata_reference.model_copy(
        update={"effective_classification": C.HIGHLY_RESTRICTED}
    )
    derived = prepare_rendered_fireflies_literal(
        detail_raw=raws[0],
        metadata_raw=raws[1],
        detail_reference=first,
        metadata_reference=second,
        block_index=0,
        start=0,
        end=15,
    ).envelope
    third = choice.derived_reference.model_copy(
        update={
            "effective_classification": C.HIGHLY_RESTRICTED,
            "content_hash": content_hash_of(derived),
        }
    )
    updated = choice.model_copy(
        update={"detail_reference": first, "metadata_reference": second, "derived_reference": third}
    )
    for ref, raw in zip((first, second, third), (raws[0], raws[1], derived)):
        location = store.put(B.BRAINSTORM, ref.content_hash, raw)
        session.execute(
            update(Source)
            .where(Source.id == ref.source_id)
            .values(
                data_classification=C.HIGHLY_RESTRICTED,
                content_hash=ref.content_hash,
                content_location=location,
            )
        )
    return updated


@pytest.mark.parametrize("originals_hr", [True, False])
def test_derivative_different_effective_label_holds_both_directions(fixture, originals_hr):
    choice = hr_sources(fixture) if originals_hr else fixture[2]
    positive = load(
        fixture,
        selection=choice,
        allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
    )
    assert positive.selection == choice
    classification = C.CONFIDENTIAL if originals_hr else C.HIGHLY_RESTRICTED
    fixture[0].execute(
        update(Source)
        .where(Source.id == choice.derived_reference.source_id)
        .values(data_classification=classification)
    )
    ref = choice.derived_reference.model_copy(update={"effective_classification": classification})
    changed = choice.model_copy(update={"derived_reference": ref})
    observed = ObservedStore(fixture[1])
    with pytest.raises(ValueError):
        load(
            fixture,
            observed,
            selection=changed,
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        )
    assert observed.gets == []


def test_weaker_raw_derivative_hidden_by_hr_elevation_holds(fixture):
    session, store, _, _ = fixture
    choice = hr_sources(fixture)
    assert (
        load(
            fixture,
            selection=choice,
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        ).selection
        == choice
    )
    session.execute(
        update(Source)
        .where(Source.id == choice.derived_reference.source_id)
        .values(data_classification=C.CONFIDENTIAL)
    )
    session.add(
        SourceClassificationElevation(
            id=uuid4(),
            source_id=choice.derived_reference.source_id,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented",
            elevated_by="invented",
            elevated_at=datetime(2026, 10, 7, tzinfo=UTC),
        )
    )
    session.flush()
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(
            fixture,
            observed,
            selection=choice,
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        )
    assert observed.gets == []


@pytest.mark.parametrize("boundary_fault", [True, False])
def test_corrupt_elevation_boundary_or_downward_label_holds(fixture, boundary_fault):
    session, store, choice, _ = fixture
    assert load(fixture).selection == choice
    if not boundary_fault:
        session.execute(
            update(Source)
            .where(Source.id == choice.detail_reference.source_id)
            .values(data_classification=C.HIGHLY_RESTRICTED)
        )
    session.add(
        SourceClassificationElevation(
            id=uuid4(),
            source_id=choice.detail_reference.source_id,
            trust_boundary=B.PERSONAL if boundary_fault else B.BRAINSTORM,
            previous_classification=C.INTERNAL,
            new_classification=C.CONFIDENTIAL,
            reason="invented corruption",
            elevated_by="invented",
            elevated_at=datetime(2026, 10, 7, tzinfo=UTC),
        )
    )
    session.flush()
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(
            fixture,
            observed,
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        )
    assert observed.gets == []


def test_canonical_getter_parity_and_strongest_tie(fixture):
    from zacai.intelligence.evidence import resolve_evidence_reference
    from zacai.state_repository import get_source

    session, store, choice, _ = fixture
    for ref in (choice.detail_reference, choice.metadata_reference, choice.derived_reference):
        assert (
            resolve_evidence_reference(
                session, source_id=ref.source_id, requestor_boundaries=frozenset({B.BRAINSTORM})
            )
            == ref
        )
        source = get_source(
            session, source_id=ref.source_id, requestor_boundaries=frozenset({B.BRAINSTORM})
        )
        assert source.content_hash == ref.content_hash
        assert (
            get_source(
                session, source_id=ref.source_id, requestor_boundaries=frozenset({B.PERSONAL})
            )
            is None
        )
        with pytest.raises(ValueError):
            resolve_evidence_reference(
                session, source_id=ref.source_id, requestor_boundaries=frozenset({B.PERSONAL})
            )
    assert load(fixture).selection == choice
    for previous, new in ((C.INTERNAL, C.CONFIDENTIAL), (C.CONFIDENTIAL, C.HIGHLY_RESTRICTED)):
        session.add(
            SourceClassificationElevation(
                id=uuid4(),
                source_id=choice.metadata_reference.source_id,
                trust_boundary=B.BRAINSTORM,
                previous_classification=previous,
                new_classification=new,
                reason="invented",
                elevated_by="invented",
                elevated_at=datetime(2026, 10, 7, tzinfo=UTC),
            )
        )
    session.flush()
    current = resolve_evidence_reference(
        session,
        source_id=choice.metadata_reference.source_id,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
    )
    assert current.effective_classification is C.HIGHLY_RESTRICTED
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert observed.gets == []
    with pytest.raises(ValueError):
        resolve_evidence_reference(
            session, source_id=uuid4(), requestor_boundaries=frozenset({B.BRAINSTORM})
        )


def test_late_raw_derivative_downgrade_under_hr_elevation_holds(fixture):
    session, store, _, _ = fixture
    choice = hr_sources(fixture)
    fired = []

    def callback(count):
        if count == 3:
            session.execute(
                update(Source)
                .where(Source.id == choice.derived_reference.source_id)
                .values(data_classification=C.CONFIDENTIAL)
            )
            session.add(
                SourceClassificationElevation(
                    id=uuid4(),
                    source_id=choice.derived_reference.source_id,
                    trust_boundary=B.BRAINSTORM,
                    previous_classification=C.CONFIDENTIAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented",
                    elevated_by="invented",
                    elevated_at=datetime(2026, 10, 7, tzinfo=UTC),
                )
            )
            session.flush()
            fired.append(True)

    observed = ObservedStore(store, callback)
    with pytest.raises(ValueError):
        load(
            fixture,
            observed,
            selection=choice,
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        )
    assert fired == [True] and len(observed.gets) == 3


def test_canonical_resolver_missing_hash_parity(fixture):
    from zacai.intelligence.evidence import resolve_evidence_reference
    from zacai.state_repository import get_source

    session, store, choice, _ = fixture
    session.execute(
        update(Source)
        .where(Source.id == choice.metadata_reference.source_id)
        .values(content_hash=None)
    )
    assert (
        get_source(
            session,
            source_id=choice.metadata_reference.source_id,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
        )
        is not None
    )
    with pytest.raises(ValueError):
        resolve_evidence_reference(
            session,
            source_id=choice.metadata_reference.source_id,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
        )
    observed = ObservedStore(store)
    with pytest.raises(ValueError):
        load(fixture, observed)
    assert observed.gets == []
