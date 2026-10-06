"""Root-only real PG acceptance additions; invented exports, no authority/protection.

Strongest labels are current access observations. Host root identity is pinned
once before writes, never recomputed inside resolve. All callbacks use real
separately committed allowed mutations, not immutable Source corruption.
"""

from datetime import timedelta

import pytest

from tests.test_claude_original_capture_sql import AT, committed, prepared, record
from zacai import claude_original_capture as capture
from zacai import claude_original_read as read
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state_repository import elevate_source_classification


@pytest.fixture
def pinned_store(tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path / "custody")
    return store, capture.observe_claude_artifact_root(store)


def reference(ref, classification):
    return EvidenceReference(**{**ref.model_dump(), "effective_classification": classification})


def resolve(sql, pinned, saved, **changes):
    if not sql.in_transaction():
        sql.begin()
    values = {
        "artifacts": pinned[0],
        "expected_root": pinned[1],
        "original_reference": saved.original_reference,
        "companion_reference": saved.companion_reference,
        "expected_account_ref": "invented-reported-account",
        "expected_exported_at": AT,
        "requestor_boundaries": frozenset({B.PERSONAL}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
    }
    values.update(changes)
    return read.load_claude_original(sql, **values)


def elevate(sql, ref, classification=C.HIGHLY_RESTRICTED):
    return elevate_source_classification(
        sql,
        source_id=ref.source_id,
        trust_boundary=B.PERSONAL,
        new_classification=classification,
        reason="Invented reader acceptance elevation",
        elevated_by="invented-owner",
    )


@pytest.mark.parametrize("which", ["original", "companion"])
def test_actual_permitted_elevation_and_denied_updated_reference(
    test_session_factory, pinned_store, monkeypatch, which
):
    _, original, _, saved, _ = committed(test_session_factory, pinned_store[0])
    original_ref = getattr(saved, f"{which}_reference")
    with test_session_factory() as writer:
        elevate(writer, original_ref)
        writer.commit()
    changes = {f"{which}_reference": reference(original_ref, C.HIGHLY_RESTRICTED)}
    with test_session_factory() as sql:
        result = resolve(sql, pinned_store, saved, **changes)
        assert result.original_raw == original
        assert result.original_binding_reference.effective_classification == C.CONFIDENTIAL
        assert result.companion_binding_reference.effective_classification == C.CONFIDENTIAL
        assert result.joint_output_classification == C.HIGHLY_RESTRICTED
        projected = read.project_claude_read_message(result, character_start=0, character_end=8)
        assert projected.capture_binding_projection.selected_text == "Invented"
        assert projected.current_original_reference == result.original_reference
        assert projected.current_companion_reference == result.companion_reference
        sql.rollback()
    gets = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        gets.append(1)
        return actual(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with test_session_factory() as sql:
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(
                sql,
                pinned_store,
                saved,
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
                **changes,
            )
        sql.rollback()
    assert gets == []


def test_actual_same_transaction_timestamp_strongest_reader(test_session_factory, pinned_store):
    _, original, proposal_raw = prepared()
    proposal = capture.ClaudeCustodyProposal.model_validate_json(proposal_raw)
    public_raw = capture.prepare_claude_custody_proposal(
        custody_id=proposal.custody_id,
        original_raw=original,
        account_ref=proposal.account_ref,
        exported_at=proposal.exported_at,
        acquired_at=proposal.acquired_at,
        captured_at=proposal.captured_at,
        boundary=proposal.boundary,
        classification=C.PUBLIC,
        selections=proposal.selections,
    )
    with test_session_factory() as writer:
        writer.begin()
        saved = capture.record_claude_original(
            writer,
            artifacts=pinned_store[0],
            expected_root=pinned_store[1],
            original_raw=original,
            proposal_raw=public_raw,
            approved_proposal_hash=content_hash_of(public_raw),
            requestor_boundaries=frozenset({B.PERSONAL}),
            allowed_classifications=frozenset({C.PUBLIC}),
        )
        first = elevate(writer, saved.original_reference, C.CONFIDENTIAL)
        second = elevate(writer, saved.original_reference)
        assert first.elevated_at == second.elevated_at  # PG now() transaction timestamp
        writer.commit()
    with test_session_factory() as sql:
        result = resolve(
            sql,
            pinned_store,
            saved,
            original_reference=reference(saved.original_reference, C.HIGHLY_RESTRICTED),
            allowed_classifications=frozenset({C.PUBLIC, C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        )
        assert result.original_binding_reference.effective_classification == C.PUBLIC
        assert result.current_original_reference.effective_classification == C.HIGHLY_RESTRICTED
        sql.rollback()


def test_actual_after_first_get_acl_commit_stops_before_original(
    test_session_factory, pinned_store, monkeypatch
):
    _, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    actual = LocalFilesystemArtifactStore.get_bounded
    milestones = []

    def get(*args, **kwargs):
        raw = actual(*args, **kwargs)
        milestones.append("get")
        if milestones == ["get"]:
            with test_session_factory() as writer:
                elevate(writer, saved.original_reference)
                writer.commit()
            milestones.append("committed")
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with test_session_factory() as sql:
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(sql, pinned_store, saved)
        sql.rollback()
    assert milestones == ["get", "committed"]


@pytest.mark.parametrize("mutation", ["append", "elevation"])
def test_actual_after_inspection_commit_holds_final_union(
    test_session_factory, pinned_store, monkeypatch, mutation
):
    custody, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    actual = read.inspect_claude_custody_selection
    milestones = []

    def inspect(*args, **kwargs):
        result = actual(*args, **kwargs)
        with test_session_factory() as writer:
            if mutation == "append":
                _, revised, proposal = prepared(
                    custody, text="Invented correction", at=AT + timedelta(seconds=1)
                )
                record(writer, pinned_store[0], revised, proposal)
            else:
                elevate(writer, saved.original_reference)
            writer.commit()
        milestones.append("committed-after-inspection")
        return result

    monkeypatch.setattr(read, "inspect_claude_custody_selection", inspect)
    with test_session_factory() as sql:
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(sql, pinned_store, saved)
        sql.rollback()
    assert milestones == ["committed-after-inspection"]


def test_actual_old_revision_is_dated_at_read(test_session_factory, pinned_store):
    custody, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    _, revised, proposal = prepared(
        custody, text="Invented correction", at=AT + timedelta(seconds=1)
    )
    with test_session_factory() as writer:
        newer = record(writer, pinned_store[0], revised, proposal)
        writer.commit()
    with test_session_factory() as sql:
        result = resolve(sql, pinned_store, saved)
        assert result.superseded_at_read is True
        assert result.original_tip_id == newer.original_reference.source_id
        assert result.current_facts_verified is False
        sql.rollback()


def test_actual_flushed_uncommitted_elevation_is_not_canonical_read(
    test_session_factory, pinned_store, monkeypatch
):
    from sqlalchemy import func, select

    _, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    gets = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        gets.append(1)
        return actual(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with test_session_factory() as sql:
        elevate(sql, saved.original_reference)  # public writer flushes, but no commit
        assert not sql.dirty and not sql.new and not sql.deleted
        assert sql.scalar(select(func.txid_current_if_assigned())) is not None
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(
                sql,
                pinned_store,
                saved,
                original_reference=reference(saved.original_reference, C.HIGHLY_RESTRICTED),
            )
        sql.rollback()
    assert gets == []


def test_actual_unrelated_flushed_write_after_inspect_holds_final_read(
    test_session_factory, pinned_store, monkeypatch
):
    from sqlalchemy import func, select

    _, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    _, _, _, unrelated, _ = committed(test_session_factory, pinned_store[0])
    actual = read.inspect_claude_custody_selection
    milestones = []
    with test_session_factory() as sql:

        def inspect(*args, **kwargs):
            result = actual(*args, **kwargs)
            elevate(sql, unrelated.original_reference)
            assert not sql.dirty and not sql.new and not sql.deleted
            assert sql.scalar(select(func.txid_current_if_assigned())) is not None
            milestones.append("unrelated-flushed-write")
            return result

        monkeypatch.setattr(read, "inspect_claude_custody_selection", inspect)
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(sql, pinned_store, saved)
        sql.rollback()
    assert milestones == ["unrelated-flushed-write"]


def test_actual_unrelated_flushed_write_first_get_stops_before_original(
    test_session_factory, pinned_store, monkeypatch
):
    from sqlalchemy import func, select

    _, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    _, _, _, unrelated, _ = committed(test_session_factory, pinned_store[0])
    actual_get = LocalFilesystemArtifactStore.get_bounded
    milestones = []
    with test_session_factory() as sql:

        def get(*args, **kwargs):
            raw = actual_get(*args, **kwargs)
            milestones.append("get")
            elevate(sql, unrelated.original_reference)
            assert not sql.dirty and not sql.new and not sql.deleted
            assert sql.scalar(select(func.txid_current_if_assigned())) is not None
            milestones.append("unrelated-flushed-write")
            return raw

        monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(sql, pinned_store, saved)
        sql.rollback()
    assert milestones == ["get", "unrelated-flushed-write"]


def test_actual_nested_read_scope_is_refused_before_private_get(
    test_session_factory, pinned_store, monkeypatch
):
    _, _, _, saved, _ = committed(test_session_factory, pinned_store[0])
    calls = []
    actual_get = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        calls.append(1)
        return actual_get(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with test_session_factory() as sql:
        sql.begin()
        with sql.begin_nested():
            assert sql.get_nested_transaction() is not None
            with pytest.raises(read.ClaudeOriginalReadError):
                resolve(sql, pinned_store, saved)
        sql.rollback()
    assert calls == []
