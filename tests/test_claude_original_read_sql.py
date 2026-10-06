"""Root-only real committed/reopened reads, no protection/authentication claim."""

import pytest
from sqlalchemy import func, select

from tests.test_claude_original_capture_sql import AT, committed, rows
from zacai import claude_original_read as read
from zacai.claude_message_projection import extract_claude_selected_message
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


@pytest.fixture(scope="session")
def store(tmp_path_factory):
    return LocalFilesystemArtifactStore(tmp_path_factory.mktemp("claude-read-invented"))


def resolve(sql, store, saved):
    sql.begin()
    return read.load_claude_original(
        sql,
        artifacts=store,
        expected_root=observe_claude_artifact_root(store),
        original_reference=saved.original_reference,
        companion_reference=saved.companion_reference,
        expected_account_ref="invented-reported-account",
        expected_exported_at=AT,
        requestor_boundaries=frozenset({B.PERSONAL}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
    )


def test_actual_committed_reopen_read_without_artifact_writes(
    test_session_factory, store, monkeypatch
):
    custody, original, _, saved, expected = committed(test_session_factory, store)

    def no_write(*args, **kwargs):
        pytest.fail("read attempted artifact write/sync")

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", no_write)
    monkeypatch.setattr(LocalFilesystemArtifactStore, "put_durable", no_write)
    with test_session_factory() as sql:
        result = resolve(sql, store, saved)
        assert result.original_raw == original
        projection = extract_claude_selected_message(
            result.companion_raw,
            result.original_raw,
            expected_companion_hash=content_hash_of(result.companion_raw),
            expected_original_reference=result.original_reference,
            expected_account_ref=result.proposal.account_ref,
            expected_exported_at=result.proposal.exported_at,
            character_start=0,
            character_end=8,
        )
        assert projection.selected_text == "Invented"
        assert projection.reference == saved.original_reference
        assert rows(sql, custody) == expected
        assert (
            result.owner_authenticated
            is result.recovery_verified
            is result.processing_authorized
            is False
        )
        sql.rollback()


def test_actual_current_elevation_holds_before_get(test_session_factory, store, monkeypatch):
    _, _, _, saved, _ = committed(test_session_factory, store)
    with test_session_factory() as writer:
        elevate_source_classification(
            writer,
            source_id=saved.original_reference.source_id,
            trust_boundary=B.PERSONAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented restriction",
            elevated_by="invented-owner",
        )
        writer.commit()
    calls = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        calls.append(1)
        return actual(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with test_session_factory() as sql:
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(sql, store, saved)
        sql.rollback()
    assert calls == []


def test_actual_separately_committed_acl_after_get_holds(test_session_factory, store, monkeypatch):
    _, _, _, saved, _ = committed(test_session_factory, store)
    with test_session_factory() as sql:
        count = sql.scalar(select(func.count()).select_from(Source))
    actual = LocalFilesystemArtifactStore.get_bounded
    milestones = []

    def get(*args, **kwargs):
        raw = actual(*args, **kwargs)
        if not milestones:
            with test_session_factory() as writer:
                elevate_source_classification(
                    writer,
                    source_id=saved.original_reference.source_id,
                    trust_boundary=B.PERSONAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Invented concurrent restriction",
                    elevated_by="invented-owner",
                )
                writer.commit()
            milestones.append("actual-independent-commit")
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with test_session_factory() as sql:
        with pytest.raises(read.ClaudeOriginalReadError):
            resolve(sql, store, saved)
        sql.rollback()
    assert milestones == ["actual-independent-commit"]
    with test_session_factory() as sql:
        assert sql.scalar(select(func.count()).select_from(Source)) == count
