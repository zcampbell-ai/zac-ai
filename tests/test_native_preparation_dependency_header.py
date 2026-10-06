"""Real SQLite/files, mocked base assembler and READ COMMITTED fixture only.

Header is canonical content-free metadata. Its integrity is not human approval.
"""

from datetime import timedelta

import pytest
from sqlalchemy import insert, select, update

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_preparation_retention import retained as retained  # noqa: PLC0414
from zacai.ingestion import native_contextual_preparation_retention as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation


def load(retained):
    setup, _, refs, now = retained
    sql, factory, _, args, *_ = setup
    return m.load_retained_native_contextual_preparation(
        sql, factory=factory, artifacts=args["artifacts"], reference=refs, as_of=now
    )


def test_denied_selected_source_never_opens_text_body(retained, monkeypatch):
    setup, preparation, references, now = retained
    sql, _, _, args, *_ = setup
    body = getattr(references, "body_reference", references)
    body_location = sql.scalar(select(Source.content_location).where(Source.id == body.source_id))
    sid = preparation.request.context.task.event.provenance[0].source_id
    from uuid import uuid4

    sql.execute(
        insert(SourceClassificationElevation).values(
            id=uuid4(),
            source_id=sid,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented initial selected restriction",
            elevated_by="invented-owner",
            elevated_at=now,
        )
    )
    sql.commit()
    reads = []
    actual = args["artifacts"].get

    def get(boundary, location):
        reads.append(location)
        return actual(boundary, location)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativePreparationRetentionError):
        load(retained)
    assert body_location not in reads  # Old loader opens this complete text envelope first.
    assert len(reads) == 1  # New loader only reads content-free dependency header.


def test_header_only_contains_closed_ids_hashes_offsets_dates(retained):
    setup, preparation, refs, now = retained
    sql, _, _, args, *_ = setup
    result = load(retained)
    assert result.reference == refs.body_reference
    assert result.dependency_reference == refs.dependency_reference
    assert result.binding_bytes == preparation.binding_bytes
    assert result.captured_at == now
    import json

    header = json.loads(result.dependency_bytes)
    assert set(header) == {
        "format",
        "task_id",
        "body_reference",
        "selection",
        "dependencies",
        "source_fingerprints",
        "relationship_fingerprint",
        "original_observed_at",
    }
    assert "original_task" not in header and "request" not in header
    assert header["dependencies"] == [
        ref.model_dump(mode="json") for ref in preparation.request.context.task.event.provenance
    ]
    assert header["body_reference"] == refs.body_reference.model_dump(mode="json")
    rows = list(
        sql.execute(
            select(Source).where(
                Source.id.in_((refs.body_reference.source_id, refs.dependency_reference.source_id))
            )
        ).scalars()
    )
    assert len(rows) == 2 and len({row.captured_at for row in rows}) == 1
    assert {row.external_ref for row in rows} == {
        "native-contextual-preparation/" + header["task_id"],
        "native-contextual-preparation-dependencies/" + header["task_id"],
    }
    assert result.processing_authorized is False and result.recovery_verified is False
    # Exact paired replay preserves original rows/body/header and capture observation.
    same = m.retain_native_contextual_preparation(
        sql,
        factory=setup[1],
        artifacts=args["artifacts"],
        preparation=preparation,
        retained_at=now + timedelta(seconds=4),
    )
    assert same == refs and load(retained).dependency_bytes == result.dependency_bytes


def test_single_reference_is_not_an_upgrade_fallback(retained):
    setup, _, refs, now = retained
    with pytest.raises(m.NativePreparationRetentionError):
        m.load_retained_native_contextual_preparation(
            setup[0],
            factory=setup[1],
            artifacts=setup[3]["artifacts"],
            reference=refs.body_reference,
            as_of=now,
        )


@pytest.mark.parametrize("which", ["body", "header"])
def test_final_own_elevation_after_last_callback_holds(retained, monkeypatch, which):
    setup, _, refs, _ = retained
    sql = setup[0]
    sid = refs.body_reference.source_id if which == "body" else refs.dependency_reference.source_id
    actual = m.assemble_contextual_context
    fired = []

    def final(*args, **kwargs):
        result = actual(*args, **kwargs)
        sql.execute(
            update(Source).where(Source.id == sid).values(data_classification=C.HIGHLY_RESTRICTED)
        )
        fired.append(True)
        return result

    monkeypatch.setattr(m, "assemble_contextual_context", final)
    with pytest.raises(m.NativePreparationRetentionError):
        load(retained)
    assert fired == [True]


def test_incomplete_pair_never_repairs_missing_header(retained):
    from sqlalchemy import delete

    setup, preparation, refs, now = retained
    sql = setup[0]
    sql.execute(delete(Source).where(Source.id == refs.dependency_reference.source_id))
    sql.commit()
    before = list(sql.execute(select(Source.id)).scalars())
    with pytest.raises(m.NativePreparationRetentionError):
        m.retain_native_contextual_preparation(
            sql,
            factory=setup[1],
            artifacts=setup[3]["artifacts"],
            preparation=preparation,
            retained_at=now,
        )
    assert list(sql.execute(select(Source.id)).scalars()) == before


def test_header_artifact_failure_rolls_back_both_source_rows(prepared, monkeypatch):
    from tests.test_native_contextual_assembly import call

    monkeypatch.setattr(m, "assemble_contextual_context", m.assembly.assemble_contextual_context)
    preparation = call(prepared)
    sql, factory, _, args, *_ = prepared
    actual = args["artifacts"].put
    fired = []

    def put(boundary, digest, raw):
        if b"zac-native-contextual-preparation-dependencies-v2" in raw:
            fired.append(True)
            raise OSError("Invented header artifact failure")
        return actual(boundary, digest, raw)

    monkeypatch.setattr(args["artifacts"], "put", put)
    with pytest.raises(m.NativePreparationRetentionError):
        m.retain_native_contextual_preparation(
            sql,
            factory=factory,
            artifacts=args["artifacts"],
            preparation=preparation,
            retained_at=args["observed_at"] + timedelta(seconds=1),
        )
    assert fired == [True]
    assert not list(
        sql.execute(
            select(Source.id).where(Source.external_ref.like("native-contextual-preparation%"))
        ).scalars()
    )


@pytest.mark.parametrize("fault", ["unknown_text", "duplicate", "foreign_body", "bad_scope"])
def test_strict_content_free_header_codec_holds(retained, fault):
    import json
    from uuid import uuid4

    from zacai.ingestion.artifact_store import canonical_bytes

    saved = load(retained)
    value = json.loads(saved.dependency_bytes)
    if fault == "unknown_text":
        value["instruction"] = "Invented forbidden header text"
    elif fault == "duplicate":
        raw = saved.dependency_bytes[:-1] + b',"task_id":"' + value["task_id"].encode() + b'"}'
    elif fault == "foreign_body":
        value["body_reference"]["source_id"] = str(uuid4())
        value["dependencies"].append(value["body_reference"])
    else:
        value["dependencies"][0]["effective_classification"] = "INTERNAL"
    if fault != "duplicate":
        raw = canonical_bytes(value)
    with pytest.raises(ValueError):
        m._decode_header(raw)
