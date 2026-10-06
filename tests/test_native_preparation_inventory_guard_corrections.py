"""Discriminating actual SQLite row/transaction mutations; mocked base and RC."""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, update

from tests.test_native_contextual_assembly import call
from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_preparation_recovery_inventory import inventory
from tests.test_native_preparation_retention import retained as retained  # noqa: PLC0414
from zacai.ingestion import native_contextual_preparation_retention as retention
from zacai.ingestion import native_preparation_recovery_inventory as m
from zacai.state import Source, SourceSystem


@pytest.mark.parametrize(
    "field",
    [
        "excerpt",
        "content_location",
        "system",
        "external_ref",
        "captured_at",
        "supersedes_source_id",
    ],
)
def test_loaded_own_metadata_cannot_become_new_baseline(retained, monkeypatch, field):
    setup, preparation, refs, now = retained
    sql = setup[0]
    original = m.load_retained_native_contextual_preparation
    fired = []

    def loaded(*args, **kwargs):
        saved = original(*args, **kwargs)
        changes = {
            "excerpt": "Invented altered own metadata",
            "content_location": "invented/changed-location",
            "system": SourceSystem.EMAIL,
            "external_ref": "native-contextual-preparation/" + str(uuid4()),
            "captured_at": now - timedelta(seconds=1),
            "supersedes_source_id": preparation.request.context.task.event.provenance[0].source_id,
        }
        sql.execute(
            update(Source)
            .where(Source.id == refs.body_reference.source_id)
            .values(**{field: changes[field]})
        )
        fired.append(True)
        return saved

    monkeypatch.setattr(m, "load_retained_native_contextual_preparation", loaded)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert fired == [True]


@pytest.mark.parametrize("nested", [False, True])
def test_loader_return_transaction_replacement_held(retained, monkeypatch, nested):
    sql = retained[0][0]
    original = m.load_retained_native_contextual_preparation
    if nested:
        sql.begin_nested()
    fired = []

    def loaded(*args, **kwargs):
        saved = original(*args, **kwargs)
        if nested:
            sql.get_nested_transaction().commit()
            sql.begin_nested()
        else:
            sql.commit()
            sql.execute(select(Source.id).limit(1))
        fired.append(True)
        return saved

    monkeypatch.setattr(m, "load_retained_native_contextual_preparation", loaded)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert fired == [True]
    sql.rollback()


def test_valid_original_nested_context_succeeds(retained):
    sql = retained[0][0]
    with sql.begin_nested() as nested:
        result = inventory(retained)
        assert sql.get_nested_transaction() is nested and nested.is_active
        assert len(result.hashes) == 12 and result.recovery_verified is False


def test_initial_retention_relationship_change_stops_next_body_get(prepared, monkeypatch):
    monkeypatch.setattr(
        retention, "assemble_contextual_context", retention.assembly.assemble_contextual_context
    )
    preparation = call(prepared)
    sql, factory, _, args, *_ = prepared
    before = set(sql.scalars(select(Source.id)))
    original = args["artifacts"].get
    reads = []

    def changed(boundary, location):
        raw = original(boundary, location)
        reads.append(location)
        if len(reads) == 1:
            monkeypatch.setattr(retention.assembly, "_base_relationships", lambda *_: "0" * 64)
        return raw

    monkeypatch.setattr(args["artifacts"], "get", changed)
    with pytest.raises(retention.NativePreparationRetentionError):
        retention.retain_native_contextual_preparation(
            sql,
            factory=factory,
            artifacts=args["artifacts"],
            preparation=preparation,
            retained_at=args["observed_at"] + timedelta(seconds=1),
        )
    assert len(reads) == 1
    assert set(sql.scalars(select(Source.id))) == before


def test_header_has_no_nested_relevance_or_task_plaintext(prepared, monkeypatch):
    import json

    monkeypatch.setattr(
        retention, "assemble_contextual_context", retention.assembly.assemble_contextual_context
    )
    sql, factory, options, args, *_ = prepared
    phrase = "Invented private reason MUST NOT be copied into header"
    selection = options["selection"]
    options["selection"] = selection.model_copy(
        update={
            "native": tuple(
                item.model_copy(update={"relevance_reason": phrase}) for item in selection.native
            )
        }
    )
    preparation = call(prepared)
    now = args["observed_at"] + timedelta(seconds=1)
    refs = retention.retain_native_contextual_preparation(
        sql, factory=factory, artifacts=args["artifacts"], preparation=preparation, retained_at=now
    )
    sql.commit()
    saved = retention.load_retained_native_contextual_preparation(
        sql, factory=factory, artifacts=args["artifacts"], reference=refs, as_of=now
    )
    assert phrase.encode() in saved.binding_bytes and phrase.encode() not in saved.dependency_bytes
    assert args["context"].task.instruction.encode() not in saved.dependency_bytes
    metadata = json.loads(saved.dependency_bytes)["selection"]
    assert set(metadata) == {
        "format",
        "selected",
        "earlier",
        "projects",
        "batch_id",
        "batch_reference",
        "intake_instruction_reference",
        "proposal_reference",
        "approved_proposal_hash",
        "native",
    }
    assert set(metadata["selected"]) == {"meeting_id", "source_id"}
    for item in metadata["earlier"]:
        assert set(item) == {"meeting_id", "source_id"}
    for item in metadata["projects"]:
        assert set(item) == {"association_id", "source_id"}
    for item in metadata["native"]:
        assert set(item) == {"source_id", "content_hash", "field", "field_text_hash", "spans"}
        assert set(item["spans"][0]) == {"start", "end"}


def test_missing_actual_own_body_only_after_header(retained, monkeypatch):
    setup, _, refs, _ = retained
    sql, _, _, args, *_ = setup
    header_location = sql.scalar(
        select(Source.content_location).where(Source.id == refs.dependency_reference.source_id)
    )
    body_location = sql.scalar(
        select(Source.content_location).where(Source.id == refs.body_reference.source_id)
    )
    path = args["artifacts"]._path_for(
        refs.body_reference.trust_boundary, refs.body_reference.content_hash
    )
    assert path.is_file()
    path.unlink()
    actual = args["artifacts"].get
    reads = []

    def get(boundary, location):
        reads.append(location)
        return actual(boundary, location)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(retention.NativePreparationRetentionError):
        retention.load_retained_native_contextual_preparation(
            sql, factory=setup[1], artifacts=args["artifacts"], reference=refs, as_of=retained[3]
        )
    assert reads == [header_location, body_location]


def test_actual_cross_pair_denies_before_either_body(retained, monkeypatch):
    from dataclasses import replace

    setup, _, first, now = retained
    sql, factory, _, args, *_ = setup
    args["context"] = replace(
        args["context"], task=args["context"].task.model_copy(update={"task_id": uuid4()})
    )
    second_preparation = call(setup)
    second = retention.retain_native_contextual_preparation(
        sql,
        factory=factory,
        artifacts=args["artifacts"],
        preparation=second_preparation,
        retained_at=now,
    )
    sql.commit()
    # Each original pair is independently valid, not merely shaped declarations.
    for pair in (first, second):
        assert (
            retention.load_retained_native_contextual_preparation(
                sql, factory=factory, artifacts=args["artifacts"], reference=pair, as_of=now
            ).recovery_verified
            is False
        )
    reads = []
    actual = args["artifacts"].get

    def get(boundary, location):
        reads.append(location)
        return actual(boundary, location)

    monkeypatch.setattr(args["artifacts"], "get", get)
    swapped = retention.PairedNativePreparationReferences(
        first.body_reference, second.dependency_reference
    )
    with pytest.raises(retention.NativePreparationRetentionError):
        retention.load_retained_native_contextual_preparation(
            sql, factory=factory, artifacts=args["artifacts"], reference=swapped, as_of=now
        )
    assert reads == [
        sql.scalar(
            select(Source.content_location).where(
                Source.id == second.dependency_reference.source_id
            )
        )
    ]


def test_effective_header_elevation_precedes_any_private_read(retained, monkeypatch):
    from sqlalchemy import insert

    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B
    from zacai.state import SourceClassificationElevation

    setup, _, refs, now = retained
    sql = setup[0]
    sql.execute(
        insert(SourceClassificationElevation).values(
            id=uuid4(),
            source_id=refs.dependency_reference.source_id,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented effective header restriction",
            elevated_by="invented-owner",
            elevated_at=now,
        )
    )
    sql.commit()
    reads = []
    actual = setup[3]["artifacts"].get

    def get(*args):
        reads.append(args)
        return actual(*args)

    monkeypatch.setattr(setup[3]["artifacts"], "get", get)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert not reads


def test_inventory_own_cap_reached_after_successful_loader(retained, monkeypatch):
    original = m.load_retained_native_contextual_preparation
    reached = []

    def loaded(*args, **kwargs):
        saved = original(*args, **kwargs)
        reached.append(True)
        monkeypatch.setattr(
            m.assembly, "MAX_REFERENCES", len(saved.request.context.task.event.provenance) + 1
        )
        return saved

    monkeypatch.setattr(m, "load_retained_native_contextual_preparation", loaded)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert reached == [True]


def test_native_subset_wrong_digest_holds(retained, monkeypatch):
    from dataclasses import replace

    actual = m.prepare_native_batch_recovery_selection
    reached = []

    def changed(*args, **kwargs):
        complete = actual(*args, **kwargs)
        sid, digest = complete.hashes[0]
        reached.append(True)
        return replace(
            complete,
            hashes=((sid, "0" * 64 if digest != "0" * 64 else "1" * 64), *complete.hashes[1:]),
        )

    monkeypatch.setattr(m, "prepare_native_batch_recovery_selection", changed)
    with pytest.raises(m.NativePreparationRecoveryInventoryError):
        inventory(retained)
    assert reached == [True]
