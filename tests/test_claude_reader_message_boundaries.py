"""Invented canonical rows/transactions, real artifacts and parser; no PG."""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414 - pytest export
from tests.test_claude_original_read import load
from tests.test_claude_original_read import saved as saved  # noqa: PLC0414 - pytest export
from tests.test_claude_reader_current_labels import confidential
from zacai import claude_original_read as m
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def test_message_preserves_date_revision_markers_and_explicit_binding_surface(saved):
    newer = dict(saved[0].rows[0])
    newer["id"] = uuid4()
    newer["supersedes_source_id"] = saved[0].rows[0]["id"]
    newer["captured_at"] += timedelta(seconds=1)
    newer["content_hash"] = "1" * 64
    saved[0].rows.append(newer)
    read = load(saved)
    message = m.project_claude_read_message(read, character_start=0, character_end=1)
    assert message.capture_binding_projection.reference == read.original_binding_reference
    assert not hasattr(message, "projection")
    assert message.projection_reference_semantics == "IMMUTABLE_CAPTURE_BINDING_ONLY"
    assert message.current_original_reference == read.original_reference
    assert message.current_companion_reference == read.companion_reference
    assert message.joint_output_classification == read.joint_output_classification
    assert message.captured_at == read.captured_at
    assert message.date_semantics == read.date_semantics
    assert message.reported_dates_after_acquired_at == read.reported_dates_after_acquired_at
    assert message.superseded_at_read is True and message.original_tip_id == newer["id"]
    assert message.recovery_verified is message.processing_authorized is False


def test_isolated_stale_reference_permitted_scope_holds_before_get(saved, monkeypatch):
    saved = confidential(saved)
    saved[0].rows[0]["effective"] = C.HIGHLY_RESTRICTED
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))
    assert calls == []


@pytest.mark.parametrize("when", ["entry", "after-inspection"])
def test_assigned_write_transaction_holds_even_when_orm_clean(saved, monkeypatch, when):
    calls = []
    actual_get = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        calls.append(1)
        return actual_get(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    if when == "entry":
        saved[0].assigned_write_txid = 73  # simulated already-flushed DB write
    else:
        actual_inspection = m.inspect_claude_custody_selection

        def inspect(*args, **kwargs):
            result = actual_inspection(*args, **kwargs)
            saved[0].assigned_write_txid = 73  # unrelated write; read rows unchanged
            return result

        monkeypatch.setattr(m, "inspect_claude_custody_selection", inspect)
    assert not saved[0].dirty and not saved[0].new and not saved[0].deleted
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert calls == ([] if when == "entry" else [1, 1])


def test_foreign_boundary_lineage_explicitly_holds_even_with_both_boundaries(saved, monkeypatch):
    newer = dict(saved[0].rows[0])
    newer["id"] = uuid4()
    newer["supersedes_source_id"] = saved[0].rows[0]["id"]
    newer["captured_at"] += timedelta(seconds=1)
    newer["content_hash"] = "1" * 64
    newer["trust_boundary"] = B.BRAINSTORM
    saved[0].rows.append(newer)
    # Isolate the explicit reader equality from capture's earlier indirect guard.
    monkeypatch.setattr(m, "_original_lineage", lambda rows: None)
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, requestor_boundaries=frozenset({B.PERSONAL, B.BRAINSTORM}))
    assert calls == []


@pytest.mark.parametrize("fault", ["capture-date", "supersession-shape"])
def test_adapter_rejects_inconsistent_declared_observations(saved, fault):
    from dataclasses import replace

    read = load(saved)
    changed = (
        replace(read, captured_at=read.captured_at + timedelta(seconds=1))
        if fault == "capture-date"
        else replace(read, superseded_at_read=True)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        m.project_claude_read_message(changed, character_start=0, character_end=1)
