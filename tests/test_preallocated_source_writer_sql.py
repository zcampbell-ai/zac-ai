"""Root-only actual canonical Source UUID/lineage controls, all bytes invented.

No authority/source reserve row, fake SQL or native crypto needed. The actual
shared record_source and unchanged canonical Source model execute on zacai_test.
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, select

from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_current_source_revision, record_source

AT = datetime(2026, 10, 11, 12, tzinfo=UTC)


def stored(tmp_path, raw):
    artifacts = LocalFilesystemArtifactStore(tmp_path / "canonical")
    digest = content_hash_of(raw)
    path = artifacts.put(B.PERSONAL, digest, raw)
    assert artifacts.get_bounded(B.PERSONAL, path, max_bytes=4096) == raw
    return {
        "trust_boundary": B.PERSONAL,
        "data_classification": C.HIGHLY_RESTRICTED,
        "system": SourceSystem.MANUAL,
        "content_hash": digest,
        "content_location": path,
        "captured_at": AT,
    }


def rows(factory):
    with factory() as session:
        return tuple(session.scalars(select(Source).order_by(Source.id)))


def test_default_uuid_idempotent_and_revision_behavior_unchanged(clean_factory, tmp_path):
    factory = clean_factory
    key = f"invented/default/{uuid4()}"
    first = stored(tmp_path, b"invented first complete bytes")
    next_value = stored(tmp_path, b"invented subsequent complete bytes")
    with factory() as session, session.begin():
        source, new = record_source(session, external_ref=key, **first)
        assert new and type(source.id) is UUID and source.id.int
        sid = source.id
        repeated, new = record_source(session, external_ref=key, **first)
        assert not new and repeated is source
        revision, new = record_source(session, external_ref=key, **next_value)
        assert new and revision.id != sid and revision.supersedes_source_id == sid
        tip = get_current_source_revision(
            session, system=SourceSystem.MANUAL, external_ref=key, trust_boundary=B.PERSONAL
        )
        assert tip.id == revision.id
    assert len(rows(factory)) == 2


def test_fresh_explicit_uuid_and_self_namespace_alias_preserved(clean_factory, tmp_path):
    factory = clean_factory
    sid = uuid4()
    value = stored(tmp_path, b"invented packet bytes")
    with factory() as session, session.begin():
        source, new = record_source(
            session, external_ref=f"invented/explicit/{sid}", preallocated_source_id=sid, **value
        )
        assert new and source.id == sid and source.supersedes_source_id is None
    with factory() as session, session.begin():
        ref = EvidenceReference(
            source_id=sid,
            content_hash=value["content_hash"],
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        # lineage_id is the existing SQL namespace alias, not a new Source column.
        snapshot = _fragment_rows(
            session, (ref,), frozenset({B.PERSONAL}), frozenset({C.HIGHLY_RESTRICTED})
        )
        assert (
            len(snapshot) == 1 and dict(snapshot[0])["id"] == dict(snapshot[0])["lineage_id"] == sid
        )
    assert len(rows(factory)) == 1


def test_same_explicit_uuid_same_hash_is_canonical_noop(clean_factory, tmp_path):
    factory = clean_factory
    sid = uuid4()
    key = f"invented/same-id/{sid}"
    value = stored(tmp_path, b"invented idempotent bytes")
    with factory() as session, session.begin():
        source, new = record_source(session, external_ref=key, preallocated_source_id=sid, **value)
        assert new and source.id == sid
    with factory() as session, session.begin():
        repeated, new = record_source(
            session, external_ref=key, preallocated_source_id=sid, **value
        )
        assert not new and repeated.id == sid and repeated.supersedes_source_id is None
    assert len(rows(factory)) == 1


def test_same_hash_other_explicit_uuid_refuses_without_append(clean_factory, tmp_path):
    factory = clean_factory
    sid = uuid4()
    key = f"invented/conflicting-id/{sid}"
    value = stored(tmp_path, b"invented one logical source")
    with factory() as session, session.begin():
        record_source(session, external_ref=key, preallocated_source_id=sid, **value)
    with pytest.raises(ValueError), factory() as session, session.begin():
        record_source(session, external_ref=key, preallocated_source_id=uuid4(), **value)
    assert [v.id for v in rows(factory)] == [sid]


@pytest.mark.parametrize("collision", ["namespace", "content"])
def test_occupied_uuid_refuses_other_namespace_or_content(clean_factory, tmp_path, collision):
    factory = clean_factory
    sid = uuid4()
    key = f"invented/occupied/{sid}"
    first = stored(tmp_path, b"invented occupied row")
    other = stored(tmp_path, b"invented distinct content")
    with factory() as session, session.begin():
        record_source(session, external_ref=key, preallocated_source_id=sid, **first)
    with pytest.raises(ValueError), factory() as session, session.begin():
        record_source(
            session,
            external_ref=key + "-other" if collision == "namespace" else key,
            preallocated_source_id=sid,
            **(first if collision == "namespace" else other),
        )
    actual = rows(factory)
    assert (
        len(actual) == 1 and actual[0].id == sid and actual[0].content_hash == first["content_hash"]
    )
    assert actual[0].external_ref == key


@pytest.mark.parametrize(
    "invalid",
    [UUID(int=0), True, "not-a-uuid", 1, object()],
    ids=["zero", "bool", "string", "integer", "object"],
)
def test_invalid_explicit_uuid_refuses_before_any_actual_sql(clean_factory, tmp_path, invalid):
    factory = clean_factory
    value = stored(tmp_path, b"invented invalid ID test")
    statements = []
    engine = factory.kw["bind"]

    def before(*args):
        statements.append(True)

    event.listen(engine, "before_cursor_execute", before)
    try:
        with pytest.raises(ValueError), factory() as session, session.begin():
            record_source(
                session,
                external_ref="invented/invalid",
                preallocated_source_id=invalid,
                **value,
            )
        assert statements == []
    finally:
        event.remove(engine, "before_cursor_execute", before)
    assert not rows(factory)


def test_preallocated_revisions_keep_existing_supersedes_and_namespace_chain(
    clean_factory, tmp_path
):
    factory = clean_factory
    first_id, second_id = uuid4(), uuid4()
    key = f"invented/revision-chain/{first_id}"
    values = [
        stored(tmp_path, raw)
        for raw in [b"invented initial", b"invented second", b"invented third"]
    ]
    with factory() as session, session.begin():
        first, new = record_source(
            session, external_ref=key, preallocated_source_id=first_id, **values[0]
        )
        second, new2 = record_source(
            session, external_ref=key, preallocated_source_id=second_id, **values[1]
        )
        third, new3 = record_source(session, external_ref=key, **values[2])
        assert new and new2 and new3
        assert first.id == first_id and first.supersedes_source_id is None
        assert second.id == second_id and second.supersedes_source_id == first_id
        assert third.id not in {first_id, second_id} and third.supersedes_source_id == second_id
        final_id = third.id
        assert (
            get_current_source_revision(
                session, system=SourceSystem.MANUAL, external_ref=key, trust_boundary=B.PERSONAL
            ).id
            == final_id
        )
    with factory() as session, session.begin():
        refs = tuple(
            EvidenceReference(
                source_id=sid,
                content_hash=value["content_hash"],
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            for sid, value in zip((first_id, second_id, final_id), values, strict=True)
        )
        snapshot = _fragment_rows(
            session, refs, frozenset({B.PERSONAL}), frozenset({C.HIGHLY_RESTRICTED})
        )
        assert {dict(row)["id"] for row in snapshot} == {first_id, second_id, final_id}
        assert {dict(row)["lineage_id"] for row in snapshot} == {first_id, second_id, final_id}
    assert len(rows(factory)) == 3
