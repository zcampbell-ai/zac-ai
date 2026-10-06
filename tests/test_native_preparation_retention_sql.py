"""Root-only genuine PG preparation retention, all provider/owner bytes invented.

Real committed native12/project13 -> two own MANUAL Sources14/15. No model or actual
human consent/recovery is claimed. Uses actual assembler/projection/body/rows.
"""

from datetime import timedelta

import pytest
from sqlalchemy import select, text

from tests.test_native_contextual_assembly_sql import (
    committed_project_selection,
    committed_selection,
    options,
)
from tests.test_native_contextual_assembly_sql import (
    private_store as private_store,  # noqa: PLC0414 - actual root-only fixture export
)
from zacai.ingestion import native_contextual_preparation_retention as m
from zacai.intelligence import native_contextual_assembly as assembly
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import EvidenceStance, MeetingProjectAssociation, Source
from zacai.state_repository import (
    EvidenceInput,
    create_project,
    elevate_source_classification,
    get_project,
    retract_meeting,
)


def prepare(factory, store, project=False):
    if project:
        selection, association_id = committed_project_selection(factory, store)
    else:
        selection, _, _ = committed_selection(factory, store)
        association_id = None
    preparation = assembly.assemble_native_contextual_selection(
        factory, **options(selection, store)
    )
    assert len(preparation.hashes) == (13 if project else 12)
    original_observed = preparation.request.context.task.event.observed_at
    retained_at = original_observed + timedelta(seconds=1)
    with factory() as sql:
        assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
        reference = m.retain_native_contextual_preparation(
            sql, factory=factory, artifacts=store, preparation=preparation, retained_at=retained_at
        )
        sql.commit()
    return preparation, reference, retained_at, association_id


@pytest.mark.parametrize("project", [False, True])
def test_actual_retention_reopen_idempotence_complete_union(
    test_session_factory, private_store, project
):
    preparation, reference, retained_at, _ = prepare(test_session_factory, private_store, project)
    with test_session_factory() as sql:
        rows = list(
            sql.execute(
                select(*Source.__table__.columns).where(
                    Source.id.in_(
                        (
                            *dict(preparation.hashes),
                            reference.body_reference.source_id,
                            reference.dependency_reference.source_id,
                        )
                    )
                )
            ).mappings()
        )
        assert len(rows) == (15 if project else 14)
        own = next(row for row in rows if row["id"] == reference.body_reference.source_id)
        assert own["captured_at"] == retained_at
        assert own["content_hash"] == reference.body_reference.content_hash
        assert own["supersedes_source_id"] is None
        assert own["external_ref"] == "native-contextual-preparation/" + str(
            preparation.request.context.task.task_id
        )
        result = m.load_retained_native_contextual_preparation(
            sql,
            factory=test_session_factory,
            artifacts=private_store,
            reference=reference,
            as_of=retained_at + timedelta(seconds=3),
        )
        assert (
            result.request == preparation.request
            and result.binding_bytes == preparation.binding_bytes
        )
        assert result.captured_at == retained_at
        assert result.request.context.task.event.observed_at == retained_at - timedelta(seconds=1)
        assert not result.processing_authorized and not result.recovery_verified
        # Same prepared bytes replay. No new request assembly or time remint.
        replay = m.retain_native_contextual_preparation(
            sql,
            factory=test_session_factory,
            artifacts=private_store,
            preparation=preparation,
            retained_at=retained_at + timedelta(seconds=4),
        )
        sql.commit()
        assert replay == reference
    with test_session_factory() as sql:
        assert rows == list(
            sql.execute(
                select(*Source.__table__.columns).where(
                    Source.id.in_(
                        (
                            *dict(preparation.hashes),
                            reference.body_reference.source_id,
                            reference.dependency_reference.source_id,
                        )
                    )
                )
            ).mappings()
        )
        assert (
            m.load_retained_native_contextual_preparation(
                sql,
                factory=test_session_factory,
                artifacts=private_store,
                reference=reference,
                as_of=retained_at + timedelta(seconds=5),
            ).request
            == preparation.request
        )


def test_actual_own_source_elevation_denies_before_any_body(test_session_factory, private_store):
    preparation, reference, retained_at, _ = prepare(test_session_factory, private_store)
    with test_session_factory() as writer:
        elevate_source_classification(
            writer,
            source_id=reference.body_reference.source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented own restriction",
            elevated_by="invented-owner",
        )
        writer.commit()
    original = private_store.get
    reads = []

    def get(*args):
        reads.append(True)
        return original(*args)

    private_store.get = get
    try:
        with test_session_factory() as sql:
            with pytest.raises(m.NativePreparationRetentionError):
                m.load_retained_native_contextual_preparation(
                    sql,
                    factory=test_session_factory,
                    artifacts=private_store,
                    reference=reference,
                    as_of=retained_at,
                )
            sql.rollback()
    finally:
        private_store.get = original
    assert reads == [] and preparation.processing_authorized is False


@pytest.mark.parametrize("fault", ["acl", "meeting", "project"])
def test_actual_separately_committed_last_get_data_drift(
    test_session_factory, private_store, fault
):
    preparation, reference, retained_at, association = prepare(
        test_session_factory, private_store, fault == "project"
    )
    original = private_store.get
    reads = []

    def count(*args):
        reads.append(args[1])
        return original(*args)

    private_store.get = count
    try:
        with test_session_factory() as sql:
            assert (
                m.load_retained_native_contextual_preparation(
                    sql,
                    factory=test_session_factory,
                    artifacts=private_store,
                    reference=reference,
                    as_of=retained_at,
                ).request
                == preparation.request
            )
    finally:
        private_store.get = original
    total = len(reads)
    assert total > 2
    reads.clear()
    fired = []
    with test_session_factory() as sql:
        if association is not None:
            project_id = sql.get(MeetingProjectAssociation, association).project_id
        before_sources = set(sql.scalars(select(Source.id)))

    def mutate():
        with test_session_factory() as writer:
            assert writer.scalar(text("SELECT current_database()")) == "zacai_test"
            writer.execute(text("SET LOCAL lock_timeout='2s'"))
            if fault == "acl":
                elevate_source_classification(
                    writer,
                    source_id=preparation.selection.native[0].source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Invented last-read restriction",
                    elevated_by="invented-owner",
                )
            elif fault == "meeting":
                retract_meeting(
                    writer,
                    meeting_id=preparation.selection.selected.meeting_id,
                    requestor_boundaries=frozenset({B.BRAINSTORM}),
                    source_id=preparation.selection.intake_instruction_reference.source_id,
                    reason="Invented final meeting withdrawal",
                )
            else:
                current = get_project(
                    writer, entity_id=project_id, requestor_boundaries=frozenset({B.BRAINSTORM})
                )
                assert current is not None
                advanced = create_project(
                    writer,
                    entity_id=project_id,
                    trust_boundary=current.trust_boundary,
                    data_classification=current.data_classification,
                    name="Invented changed project version",
                    company_id=current.company_id,
                    status=current.status,
                    evidence=[
                        EvidenceInput(
                            source_id=preparation.selection.projects[0].source_id,
                            stance=EvidenceStance.SUPPORTS,
                            confidence=1.0,
                        )
                    ],
                )
                assert advanced.version == current.version + 1
            writer.commit()
            fired.append(fault)

    def last(boundary, where):
        raw = original(boundary, where)
        reads.append(where)
        if len(reads) == total:
            mutate()
        return raw

    private_store.get = last
    try:
        with test_session_factory() as sql:
            with pytest.raises(m.NativePreparationRetentionError):
                m.load_retained_native_contextual_preparation(
                    sql,
                    factory=test_session_factory,
                    artifacts=private_store,
                    reference=reference,
                    as_of=retained_at,
                )
            sql.rollback()
    finally:
        private_store.get = original
    assert len(reads) == total and fired == [fault]
    with test_session_factory() as sql:
        assert before_sources == set(sql.scalars(select(Source.id)))


def test_actual_first_insert_release_fault_caller_rollback(
    test_session_factory, private_store, monkeypatch
):
    from contextlib import contextmanager

    selection, _, _ = committed_selection(test_session_factory, private_store)
    preparation = assembly.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    )
    external = "native-contextual-preparation/" + str(preparation.request.context.task.task_id)
    own_names = {
        external,
        external.replace(
            "native-contextual-preparation/", "native-contextual-preparation-dependencies/"
        ),
    }
    with test_session_factory() as sql:
        baseline = set(sql.execute(select(Source.id, Source.external_ref)).tuples())
        assert not any(name in own_names for _, name in baseline)
        actual = sql.begin_nested
        fired = []

        @contextmanager
        def failed_release():
            is_outer = sql.get_nested_transaction() is None
            with actual() as nested:
                yield nested
            if is_outer:
                fired.append(True)
                raise ValueError("Invented post-flush release failure")

        monkeypatch.setattr(sql, "begin_nested", failed_release)
        with pytest.raises(m.NativePreparationRetentionError) as exc:
            m.retain_native_contextual_preparation(
                sql,
                factory=test_session_factory,
                artifacts=private_store,
                preparation=preparation,
                retained_at=preparation.request.context.task.event.observed_at
                + timedelta(seconds=1),
            )
        assert fired == [True] and exc.value.__context__ is None
        pending = set(
            sql.execute(
                select(Source.id, Source.external_ref).where(
                    Source.external_ref.in_(tuple(own_names))
                )
            ).tuples()
        )
        assert len(pending) == 2 and {name for _, name in pending} == own_names
        assert (
            set(sql.execute(select(Source.id, Source.external_ref)).tuples()) == baseline | pending
        )
        with test_session_factory() as separate:
            assert (
                set(separate.execute(select(Source.id, Source.external_ref)).tuples()) == baseline
            )
            assert not list(
                separate.scalars(select(Source.id).where(Source.external_ref.in_(tuple(own_names))))
            )
        sql.rollback()
        assert set(sql.execute(select(Source.id, Source.external_ref)).tuples()) == baseline
    with test_session_factory() as separate:
        assert set(separate.execute(select(Source.id, Source.external_ref)).tuples()) == baseline
        assert not list(
            separate.scalars(select(Source.id).where(Source.external_ref.in_(tuple(own_names))))
        )


@pytest.mark.parametrize("when", ["initial", "after_header"])
def test_actual_selected_elevation_prevents_own_text_body(
    test_session_factory, private_store, when
):
    preparation, references, retained_at, _ = prepare(test_session_factory, private_store)
    selected = preparation.request.context.task.event.provenance[0].source_id
    with test_session_factory() as sql:
        body_location = sql.scalar(
            select(Source.content_location).where(Source.id == references.body_reference.source_id)
        )
        header_location = sql.scalar(
            select(Source.content_location).where(
                Source.id == references.dependency_reference.source_id
            )
        )
    fired = []

    def restrict():
        with test_session_factory() as writer:
            elevate_source_classification(
                writer,
                source_id=selected,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="Invented selected restriction",
                elevated_by="invented-owner",
            )
            writer.commit()
        fired.append(True)

    if when == "initial":
        restrict()
    reads = []
    actual = private_store.get

    def get(boundary, location):
        raw = actual(boundary, location)
        reads.append(location)
        if when == "after_header" and location == header_location and not fired:
            restrict()
        return raw

    private_store.get = get
    try:
        with test_session_factory() as sql, pytest.raises(m.NativePreparationRetentionError):
            m.load_retained_native_contextual_preparation(
                sql,
                factory=test_session_factory,
                artifacts=private_store,
                reference=references,
                as_of=retained_at + timedelta(seconds=2),
            )
    finally:
        private_store.get = actual
    assert fired == [True] and reads == [header_location]
    assert body_location not in reads
