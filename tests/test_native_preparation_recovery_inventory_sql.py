"""Root-only exact native12/project13 + paired own14/15 selected-row inventory.

No mocked base/proof/writer. Provider data invented. This is not crypto recovery.
"""

from datetime import timedelta

import pytest
from sqlalchemy import select

from tests.test_native_preparation_retention_sql import prepare
from tests.test_native_preparation_retention_sql import (
    private_store as private_store,  # noqa: PLC0414
)
from zacai.ingestion import native_preparation_recovery_inventory as m
from zacai.policy import DataClassification as C
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


@pytest.mark.parametrize("project", [False, True])
def test_genuine_complete_selected_union(test_session_factory, private_store, project, monkeypatch):
    preparation, reference, retained_at, _ = prepare(test_session_factory, private_store, project)

    def no_put(*_args, **_kwargs):
        raise AssertionError("Read-only inventory cannot write")

    monkeypatch.setattr(private_store, "put", no_put)
    with test_session_factory() as sql:
        result = m.prepare_retained_native_contextual_recovery_inventory(
            sql,
            factory=test_session_factory,
            artifacts=private_store,
            reference=reference,
            as_of=retained_at + timedelta(seconds=2),
        )
        expected = dict(preparation.hashes) | {
            reference.body_reference.source_id: reference.body_reference.content_hash,
            reference.dependency_reference.source_id: reference.dependency_reference.content_hash,
        }
        assert dict(result.hashes) == expected and len(expected) == (15 if project else 14)
        actual = list(
            sql.execute(
                select(*Source.__table__.columns)
                .where(Source.id.in_(tuple(expected)))
                .order_by(Source.id)
            ).mappings()
        )
        assert [dict(row)["id"] for row in result.source_rows] == [row["id"] for row in actual]
        for frozen, row in zip(result.source_rows, actual, strict=True):
            assert {key: value for key, value in frozen if key != "effective"} == dict(row)
        assert set(dict(result.native.hashes)) < set(dict(preparation.hashes))
        assert len(result.native.hashes) == 9
        assert result.artifact_hashes == frozenset(expected.values())
        assert dict(result.source_fingerprints) == m.assembly._rows(
            sql, result.references, result.checked_at
        )
        assert all(dict(row)["effective"] is C.CONFIDENTIAL for row in result.source_rows)
        assert result.retained.binding_bytes == preparation.binding_bytes
        assert result.original_observed_at == preparation.request.context.task.event.observed_at
        assert result.retained_at == retained_at < result.checked_at
        assert not any(
            (
                result.processing_authorized,
                result.recovery_verified,
                result.access_authorized,
                result.capture_authorized,
            )
        )
    with test_session_factory() as sql:
        reopened = m.prepare_retained_native_contextual_recovery_inventory(
            sql,
            factory=test_session_factory,
            artifacts=private_store,
            reference=reference,
            as_of=retained_at + timedelta(seconds=3),
        )
        assert reopened.hashes == result.hashes and reopened.source_rows == result.source_rows
        assert reopened.source_fingerprints == result.source_fingerprints


def test_genuine_own_elevation_prevents_body(test_session_factory, private_store, monkeypatch):
    _, reference, retained_at, _ = prepare(test_session_factory, private_store)
    with test_session_factory() as writer:
        elevate_source_classification(
            writer,
            source_id=reference.body_reference.source_id,
            trust_boundary=reference.body_reference.trust_boundary,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented elevation",
            elevated_by="invented-owner",
        )
        writer.commit()
    reads = []
    actual = private_store.get

    def get(*args):
        reads.append(args)
        return actual(*args)

    monkeypatch.setattr(private_store, "get", get)
    with test_session_factory() as sql, pytest.raises(m.NativePreparationRecoveryInventoryError):
        m.prepare_retained_native_contextual_recovery_inventory(
            sql,
            factory=test_session_factory,
            artifacts=private_store,
            reference=reference,
            as_of=retained_at + timedelta(seconds=2),
        )
    assert not reads
