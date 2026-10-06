"""Invented real SQLite/provider/files; base assembler and RC explicitly mocked."""

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_preparation_retention import retained as retained  # noqa: PLC0414
from zacai.ingestion import native_preparation_recovery_inventory as m
from zacai.policy import DataClassification as C
from zacai.state import Source


def inventory(retained):
    setup, _, ref, now = retained
    sql, factory, _, args, *_ = setup
    return m.prepare_retained_native_contextual_recovery_inventory(
        sql,
        factory=factory,
        artifacts=args["artifacts"],
        reference=ref,
        as_of=now + timedelta(seconds=2),
    )


def test_complete_kinds_dates_rows_flags_and_reopen(retained, monkeypatch):
    setup, preparation, ref, now = retained
    sql, factory, _, args, *_ = setup

    def no_put(*_args, **_kwargs):
        raise AssertionError("Inventory cannot write artifacts")

    monkeypatch.setattr(args["artifacts"], "put", no_put)
    result = inventory(retained)
    expected = dict(preparation.hashes) | {
        ref.body_reference.source_id: ref.body_reference.content_hash,
        ref.dependency_reference.source_id: ref.dependency_reference.content_hash,
    }
    assert dict(result.hashes) == expected and len(expected) == 12
    assert {x.source_id: x.content_hash for x in result.references} == expected
    rows = [dict(row) for row in result.source_rows]
    assert {row["id"]: row["content_hash"] for row in rows} == expected
    assert {row["system"].value for row in rows} >= {"EMAIL", "SLACK", "USER_INSTRUCTION", "MANUAL"}
    assert set(dict(result.native.hashes)) < set(dict(preparation.hashes))
    assert len(result.native.hashes) == 9
    assert result.artifact_hashes == frozenset(expected.values())
    assert dict(result.source_fingerprints) == m._fingerprints(result.source_rows)
    assert result.retained.request == preparation.request
    assert result.original_observed_at == preparation.request.context.task.event.observed_at
    assert result.retained_at == now < result.checked_at
    assert all(
        getattr(result, key) is False
        for key in (
            "processing_authorized",
            "recovery_verified",
            "access_authorized",
            "capture_authorized",
        )
    )
    assert str(ref.body_reference.source_id) not in repr(result)
    with pytest.raises(ValueError):
        replace(result, recovery_verified=True)
    sql.rollback()
    with factory() as reopened:
        again = m.prepare_retained_native_contextual_recovery_inventory(
            reopened,
            factory=factory,
            artifacts=args["artifacts"],
            reference=ref,
            as_of=now + timedelta(seconds=3),
        )
        assert again.hashes == result.hashes and again.source_rows == result.source_rows


@pytest.mark.parametrize("which", ["own", "ancestor"])
def test_current_classification_before_body(retained, monkeypatch, which):
    setup, preparation, ref, _ = retained
    sql, _, _, args, *_ = setup
    sid = ref.body_reference.source_id if which == "own" else next(iter(dict(preparation.hashes)))
    sql.execute(
        update(Source).where(Source.id == sid).values(data_classification=C.HIGHLY_RESTRICTED)
    )
    sql.commit()
    reads = []
    original = args["artifacts"].get

    def get(*args):
        reads.append(args)
        return original(*args)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativePreparationRecoveryInventoryError) as held:
        inventory(retained)
    assert held.value.__context__ is None
    assert len(reads) == (0 if which == "own" else 1)


@pytest.mark.parametrize("which", ["own", "ancestor"])
def test_final_scalar_drift_after_last_loader(retained, monkeypatch, which):
    setup, preparation, ref, _ = retained
    sql = setup[0]
    sid = ref.body_reference.source_id if which == "own" else next(iter(dict(preparation.hashes)))
    actual = m.prepare_native_batch_recovery_selection
    fired = []

    def last(*args, **kwargs):
        result = actual(*args, **kwargs)
        sql.execute(update(Source).where(Source.id == sid).values(excerpt="Invented final drift"))
        fired.append(True)
        return result

    monkeypatch.setattr(m, "prepare_native_batch_recovery_selection", last)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert fired == [True]
    sql.rollback()
    monkeypatch.setattr(m, "prepare_native_batch_recovery_selection", actual)
    assert inventory(retained).retained.reference == ref.body_reference


def test_final_relationship_drift(retained, monkeypatch):
    actual = m.prepare_native_batch_recovery_selection
    fired = []

    def last(*args, **kwargs):
        result = actual(*args, **kwargs)
        monkeypatch.setattr(m.assembly, "_base_relationships", lambda *_: "0" * 64)
        fired.append(True)
        return result

    monkeypatch.setattr(m, "prepare_native_batch_recovery_selection", last)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert fired == [True]


def test_callback_transaction_replacement(retained, monkeypatch):
    sql = retained[0][0]
    actual = m.prepare_native_batch_recovery_selection

    def changed(*args, **kwargs):
        result = actual(*args, **kwargs)
        sql.rollback()
        sql.execute(select(Source.id).limit(1))
        return result

    monkeypatch.setattr(m, "prepare_native_batch_recovery_selection", changed)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)


def test_mismatched_native_subset(retained, monkeypatch):
    actual = m.prepare_native_batch_recovery_selection

    def changed(*args, **kwargs):
        result = actual(*args, **kwargs)
        return replace(
            result,
            hashes=(
                *result.hashes,
                (retained[2].body_reference.source_id, retained[2].body_reference.content_hash),
            ),
        )

    monkeypatch.setattr(m, "prepare_native_batch_recovery_selection", changed)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)


def test_union_bound_counts_own(retained, monkeypatch):
    result = inventory(retained)
    monkeypatch.setattr(m.assembly, "MAX_REFERENCES", len(result.references) - 1)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)


def test_missing_own_artifact_no_repair(retained, monkeypatch):
    store = retained[0][3]["artifacts"]
    actual = store.get
    location = retained[0][0].scalar(
        select(Source.content_location).where(Source.id == retained[2].body_reference.source_id)
    )

    def missing(boundary, content_location):
        if content_location == location:
            raise FileNotFoundError("Invented missing own artifact")
        return actual(boundary, content_location)

    monkeypatch.setattr(store, "get", missing)
    with pytest.raises(m.NativePreparationRecoveryInventoryError) as held:
        inventory(retained)
    assert held.value.__context__ is None


@pytest.mark.parametrize("which", ["own", "ancestor"])
def test_effective_elevation_holds(retained, which):
    from uuid import uuid4

    from sqlalchemy import insert

    from zacai.state import SourceClassificationElevation

    setup, preparation, ref, now = retained
    sql = setup[0]
    sid = ref.body_reference.source_id if which == "own" else next(iter(dict(preparation.hashes)))
    sql.execute(
        insert(SourceClassificationElevation).values(
            id=uuid4(),
            source_id=sid,
            new_classification=C.HIGHLY_RESTRICTED,
            trust_boundary=ref.body_reference.trust_boundary,
            previous_classification=C.CONFIDENTIAL,
            elevated_by="invented-owner",
            elevated_at=now,
            reason="Invented current elevation",
        )
    )
    sql.commit()
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)


@pytest.mark.parametrize("which", ["own", "ancestor"])
def test_missing_selected_row_holds(retained, which):
    from sqlalchemy import delete

    setup, preparation, ref, _ = retained
    sql = setup[0]
    sid = ref.body_reference.source_id if which == "own" else next(iter(dict(preparation.hashes)))
    sql.execute(delete(Source).where(Source.id == sid))
    sql.commit()
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)


def test_current_header_elevation_holds_before_any_private_read(retained, monkeypatch):
    setup, _, pair, _ = retained
    sql, _, _, args, *_ = setup
    sql.execute(
        update(Source)
        .where(Source.id == pair.dependency_reference.source_id)
        .values(data_classification=C.HIGHLY_RESTRICTED)
    )
    sql.commit()
    reads = []
    actual = args["artifacts"].get

    def get(*args):
        reads.append(args)
        return actual(*args)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert not reads


def test_missing_actual_provider_file_holds_without_write(retained, monkeypatch):
    setup, preparation, _, _ = retained
    sql, _, _, args, *_ = setup
    provider = preparation.request.artifact_references[0][0]
    location = sql.scalar(select(Source.content_location).where(Source.id == provider.source_id))
    assert args["artifacts"].location_for(provider.content_hash) == location
    path = args["artifacts"]._path_for(provider.trust_boundary, provider.content_hash)
    assert path.is_file()
    path.unlink()

    def no_put(*_args, **_kwargs):
        raise AssertionError("Missing inventory never repairs")

    monkeypatch.setattr(args["artifacts"], "put", no_put)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
