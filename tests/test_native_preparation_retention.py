"""Invented SQLite/files native integrity, mocked base/isolation, no authority."""

from datetime import timedelta

import pytest
from sqlalchemy import select, update

from tests.test_native_contextual_assembly import call
from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.ingestion import native_contextual_preparation_retention as m
from zacai.intelligence import native_contextual_assembly as a
from zacai.state import Source


@pytest.fixture
def retained(prepared, monkeypatch):
    monkeypatch.setattr(m, "assemble_contextual_context", a.assemble_contextual_context)
    value = call(prepared)
    sql, factory, _, args, *_ = prepared
    now = args["observed_at"] + timedelta(seconds=1)
    ref = m.retain_native_contextual_preparation(
        sql, factory=factory, artifacts=args["artifacts"], preparation=value, retained_at=now
    )
    sql.commit()
    return prepared, value, ref, now


def test_original_bytes_ids_and_actual_capture_time_survive_reopen(retained):
    prepared, value, ref, now = retained
    sql, factory, _, args, *_ = prepared
    row = sql.execute(select(Source).where(Source.id == ref.body_reference.source_id)).scalar_one()
    assert row.external_ref == "native-contextual-preparation/" + str(
        value.request.context.task.task_id
    )
    assert row.captured_at.replace(tzinfo=now.tzinfo) == now
    result = m.load_retained_native_contextual_preparation(
        sql,
        factory=factory,
        artifacts=args["artifacts"],
        reference=ref,
        as_of=now + timedelta(seconds=2),
    )
    assert result.request == value.request
    assert result.binding_bytes == value.binding_bytes
    assert result.request.context.task.event.observed_at < result.captured_at
    assert not result.processing_authorized and not result.recovery_verified
    sql.rollback()
    same = m.retain_native_contextual_preparation(
        sql,
        factory=factory,
        artifacts=args["artifacts"],
        preparation=value,
        retained_at=now + timedelta(seconds=3),
    )
    sql.commit()
    assert same == ref
    assert (
        sql.execute(select(Source.captured_at).where(Source.id == ref.body_reference.source_id))
        .scalar_one()
        .replace(tzinfo=now.tzinfo)
        == now
    )
    with factory() as reopened:
        result = m.load_retained_native_contextual_preparation(
            reopened,
            factory=factory,
            artifacts=args["artifacts"],
            reference=ref,
            as_of=now + timedelta(seconds=4),
        )
        assert result.request == value.request


def test_first_header_callback_source_change_holds(retained, monkeypatch):
    prepared, _, ref, now = retained
    sql, factory, _, args, sources, *_ = prepared
    original = args["artifacts"].get
    fired = []

    def changed(boundary, location):
        raw = original(boundary, location)
        if not fired:
            sql.execute(
                update(Source).where(Source.id == sources[-1].id).values(excerpt="Invented drift")
            )
            fired.append(True)
        return raw

    monkeypatch.setattr(args["artifacts"], "get", changed)
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )
    assert fired == [True]


def test_current_meeting_withdrawal_holds_before_native_reads(prepared, monkeypatch):
    from uuid import uuid4

    from sqlalchemy import insert

    from tests.test_native_contextual_assembly import REAL_RELATIONSHIPS
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B
    from zacai.state import Meeting, MeetingRetraction, MeetingSource

    sql, factory, options, args, *_ = prepared
    selected = options["selection"]
    for model in (Meeting, MeetingSource, MeetingRetraction):
        model.__table__.create(sql.get_bind(), checkfirst=True)
    sql.execute(
        insert(Meeting).values(
            id=selected.selected.meeting_id,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            title="Invented",
            occurred_at=args["observed_at"],
            noted_at=args["observed_at"],
        )
    )
    sql.commit()
    monkeypatch.setattr(a, "_base_relationships", REAL_RELATIONSHIPS)
    monkeypatch.setattr(m, "assemble_contextual_context", a.assemble_contextual_context)
    value = call(prepared)
    now = args["observed_at"] + timedelta(seconds=1)
    ref = m.retain_native_contextual_preparation(
        sql, factory=factory, artifacts=args["artifacts"], preparation=value, retained_at=now
    )
    sql.commit()
    # Actual relationship table mutation; data rows and saved request unchanged.
    sql.execute(
        insert(MeetingRetraction).values(
            id=uuid4(),
            meeting_id=selected.selected.meeting_id,
            trust_boundary=B.BRAINSTORM,
            source_id=selected.intake_instruction_reference.source_id,
            retracted_at=now,
            reason="Invented withdrawal",
        )
    )
    sql.commit()
    reads = []
    actual = args["artifacts"].get

    def get(*args):
        reads.append(args)
        return actual(*args)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )
    # Only dependency header is read, with no body/provider/proposal bytes after denied relationship.
    assert len(reads) == 1  # dependency-only header; body remains unread


def test_project_head_change_is_persisted_relationship_drift(prepared, monkeypatch):
    from uuid import uuid4

    from sqlalchemy import insert

    from tests.test_native_contextual_assembly import REAL_RELATIONSHIPS
    from zacai.intelligence.project_review_context import ReviewedProjectEvidence
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B
    from zacai.state import (
        Meeting,
        MeetingProjectAssociation,
        MeetingProjectAssociationRetraction,
        MeetingRetraction,
        MeetingSource,
        ProjectHead,
    )

    sql, factory, options, args, *_ = prepared
    selected = options["selection"]
    aid, pid = uuid4(), uuid4()
    from tests import test_native_batch_inventory as native
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.meeting_review import ReviewContext
    from zacai.state import SourceSystem

    confirmation = native.put_source(
        sql,
        args["artifacts"],
        SourceSystem.MANUAL,
        "invented/project-confirmation",
        b"Invented project association",
    )
    sql.commit()
    confirmation_ref = native.ref(confirmation)
    original = args["context"].task.model_dump()
    original["event"]["provenance"] = (*args["context"].task.event.provenance, confirmation_ref)
    args["context"] = ReviewContext(
        IntelligenceTask.model_validate(original),
        args["context"].meeting_source_id,
        args["context"].related_source_ids,
    )
    monkeypatch.setattr(a, "get_meeting_project_context", lambda *pos, **kw: ())
    options["selection"] = selected.model_copy(
        update={"projects": (ReviewedProjectEvidence(aid, confirmation_ref.source_id),)}
    )
    selected = options["selection"]
    for model in (
        Meeting,
        MeetingSource,
        MeetingRetraction,
        MeetingProjectAssociation,
        MeetingProjectAssociationRetraction,
        ProjectHead,
    ):
        model.__table__.create(sql.get_bind(), checkfirst=True)
    sql.execute(
        insert(Meeting).values(
            id=selected.selected.meeting_id,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            title="Invented",
            occurred_at=args["observed_at"],
            noted_at=args["observed_at"],
        )
    )
    sql.execute(
        insert(ProjectHead).values(entity_id=pid, trust_boundary=B.BRAINSTORM, current_version=1)
    )
    sql.execute(
        insert(MeetingProjectAssociation).values(
            id=aid,
            meeting_id=selected.selected.meeting_id,
            project_id=pid,
            reviewed_project_version=1,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            confirmation_source_id=confirmation_ref.source_id,
            noted_at=args["observed_at"],
        )
    )
    sql.commit()
    # Base assembler's original context is deliberately mocked in this fixture.
    monkeypatch.setattr(a, "_base_relationships", REAL_RELATIONSHIPS)
    monkeypatch.setattr(m, "assemble_contextual_context", a.assemble_contextual_context)
    value = call(prepared)
    now = args["observed_at"] + timedelta(seconds=1)
    ref = m.retain_native_contextual_preparation(
        sql, factory=factory, artifacts=args["artifacts"], preparation=value, retained_at=now
    )
    sql.commit()
    assert (
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        ).request
        == value.request
    )
    sql.execute(update(ProjectHead).where(ProjectHead.entity_id == pid).values(current_version=2))
    sql.commit()
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )


def test_callback_transaction_switch_holds(retained, monkeypatch):
    prepared, _, ref, now = retained
    sql, factory, _, args, *_ = prepared
    actual = m.assemble_contextual_context
    fired = []

    def base(*pos, **kw):
        result = actual(*pos, **kw)
        sql.commit()
        fired.append(True)
        return result

    monkeypatch.setattr(m, "assemble_contextual_context", base)
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )
    assert fired == [True]


@pytest.mark.parametrize("fault", ["missing_file", "classification"])
def test_own_source_classification_or_missing_file_holds(retained, monkeypatch, fault):
    from zacai.policy import DataClassification as C

    prepared, _, ref, now = retained
    sql, factory, _, args, *_ = prepared
    body_location = sql.scalar(
        select(Source.content_location).where(Source.id == ref.body_reference.source_id)
    )
    header_location = sql.scalar(
        select(Source.content_location).where(Source.id == ref.dependency_reference.source_id)
    )
    if fault == "missing_file":
        path = args["artifacts"]._path_for(
            ref.body_reference.trust_boundary, ref.body_reference.content_hash
        )
        assert path.is_file()
        path.unlink()
    else:
        sql.execute(
            update(Source)
            .where(Source.id == ref.body_reference.source_id)
            .values(data_classification=C.HIGHLY_RESTRICTED)
        )
        sql.commit()
    reads = []
    actual = args["artifacts"].get

    def get(boundary, location):
        reads.append(location)
        return actual(boundary, location)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )
    assert reads == ([] if fault == "classification" else [header_location, body_location])


@pytest.mark.parametrize("fault", ["duplicate", "extra", "noncanonical", "fingerprint"])
def test_closed_retained_binding_does_not_admit_changed_envelope(retained, fault):
    import json

    from zacai.ingestion.artifact_store import canonical_bytes

    _prepared, value, _, _ = retained
    raw = value.binding_bytes
    if fault == "duplicate":
        raw = raw[:-1] + b',"format":"zac-native-contextual-assembly-binding-v2"}'
    elif fault == "noncanonical":
        raw = b" " + raw
    else:
        data = json.loads(raw)
        if fault == "extra":
            data["processing_authorized"] = True
        else:
            data["source_fingerprints"][0][1] = "invalid"
        raw = canonical_bytes(data)
    with pytest.raises(ValueError):
        m._decode(raw)


def test_failed_matching_retention_does_not_overwrite_or_create_revision(retained):
    from dataclasses import replace

    prepared, value, ref, now = retained
    sql, factory, _, args, *_ = prepared
    before = list(sql.execute(select(*Source.__table__.columns)).mappings())
    with pytest.raises(m.NativePreparationRetentionError):
        m.retain_native_contextual_preparation(
            sql,
            factory=factory,
            artifacts=args["artifacts"],
            preparation=replace(value, relationship_fingerprint="0" * 64),
            retained_at=now,
        )
    assert list(sql.execute(select(*Source.__table__.columns)).mappings()) == before
    assert (
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        ).request
        == value.request
    )


def test_failed_savepoint_release_never_acknowledges_existing_preparation(retained, monkeypatch):
    from contextlib import contextmanager

    prepared, value, _, now = retained
    sql, factory, _, args, *_ = prepared
    actual = sql.begin_nested
    fired = []

    @contextmanager
    def failed_release():
        with actual() as nested:
            yield nested
        fired.append(True)
        raise ValueError("Invented release failure")

    monkeypatch.setattr(sql, "begin_nested", failed_release)
    with pytest.raises(m.NativePreparationRetentionError) as exc:
        m.retain_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], preparation=value, retained_at=now
        )
    assert fired == [True]
    assert exc.value.__context__ is None and exc.value.__cause__ is None


def test_base_read_current_acl_denies_before_its_body(retained, monkeypatch):
    from uuid import uuid4

    from sqlalchemy import insert

    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B
    from zacai.state import SourceClassificationElevation

    prepared, _, ref, now = retained
    sql, factory, _, args, *_ = prepared
    sid = args["context"].task.context[0].reference.source_id
    location = sql.scalar(select(Source.content_location).where(Source.id == sid))
    sql.rollback()
    actual_get = args["artifacts"].get
    reads = []
    callbacks = []

    def get(boundary, where):
        reads.append(where)
        return actual_get(boundary, where)

    def base(actual_factory, **kwargs):
        assert actual_factory is factory
        sql.execute(
            insert(SourceClassificationElevation).values(
                id=uuid4(),
                source_id=sid,
                trust_boundary=B.BRAINSTORM,
                previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="Invented before-body elevation",
                elevated_by="invented-owner",
                elevated_at=now,
            )
        )
        callbacks.append(True)
        kwargs["artifacts"].get(B.BRAINSTORM, location)
        return args["context"]

    monkeypatch.setattr(args["artifacts"], "get", get)
    monkeypatch.setattr(m, "assemble_contextual_context", base)
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )
    assert callbacks == [True]
    assert location not in reads


@pytest.mark.parametrize("fault", ["source", "relationship"])
def test_genuine_last_get_then_final_callback_free_comparison_holds(retained, monkeypatch, fault):
    prepared, _, ref, now = retained
    sql, factory, _, args, sources, *_ = prepared
    location = sql.scalar(
        select(Source.content_location).where(
            Source.id == args["context"].task.context[0].reference.source_id
        )
    )
    sql.rollback()
    actual_get = args["artifacts"].get
    reads = []
    fired = []
    relationships = a._base_relationships
    observations = []

    def get(boundary, where):
        reads.append(where)
        return actual_get(boundary, where)

    def relationship(*pos):
        result = relationships(*pos)
        observations.append(bool(fired))
        return "0" * 64 if fault == "relationship" and fired else result

    def base(actual_factory, **kwargs):
        # Genuine final get inside the last external base callback.
        kwargs["artifacts"].get(args["context"].task.event.trust_boundary, location)
        assert reads[-1] == location
        if fault == "source":
            sql.execute(
                update(Source)
                .where(Source.id == sources[-1].id)
                .values(excerpt="Invented final drift")
            )
        fired.append(True)
        return args["context"]

    monkeypatch.setattr(args["artifacts"], "get", get)
    monkeypatch.setattr(a, "_base_relationships", relationship)
    monkeypatch.setattr(m, "assemble_contextual_context", base)
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=ref, as_of=now
        )
    assert fired == [True] and reads[-1] == location
    assert (
        not observations[0] and observations[-1]
    )  # final relationship branch reached after external work


def test_first_insert_release_fault_leaves_pending_row_until_caller_rollback(prepared, monkeypatch):
    from contextlib import contextmanager

    monkeypatch.setattr(m, "assemble_contextual_context", a.assemble_contextual_context)
    value = call(prepared)
    sql, factory, _, args, *_ = prepared
    from sqlalchemy import text

    # Explicit SQLite BEGIN models the genuine PostgreSQL outer transaction;
    # SQLite's deferred read transaction otherwise commits a released savepoint.
    sql.execute(text("BEGIN"))
    actual = sql.begin_nested
    fired = []

    @contextmanager
    def failed_release():
        is_outer = sql.get_nested_transaction() is None
        with actual() as nested:
            yield nested
        if is_outer:
            fired.append(True)
            raise ValueError("Invented first-insert release failure")

    monkeypatch.setattr(sql, "begin_nested", failed_release)
    prefix = "native-contextual-preparation/" + str(value.request.context.task.task_id)
    with pytest.raises(m.NativePreparationRetentionError):
        m.retain_native_contextual_preparation(
            sql,
            factory=factory,
            artifacts=args["artifacts"],
            preparation=value,
            retained_at=args["observed_at"] + timedelta(seconds=1),
        )
    assert fired == [True]
    pending = sql.scalar(select(Source.id).where(Source.external_ref == prefix))
    assert pending is not None
    sql.rollback()
    with factory() as check:
        assert check.scalar(select(Source.id).where(Source.external_ref == prefix)) is None
