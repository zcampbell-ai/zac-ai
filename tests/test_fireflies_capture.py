"""D033B synthetic replies and rollback-isolated Zac State only."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zacai.connectors.fireflies_identity import (
    ACCOUNT_QUERY,
    build_account_request,
    prepare_account_reply,
)
from zacai.connectors.fireflies_wire import MAX_RESPONSE_BYTES, FirefliesWireError
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.ingestion.fireflies_capture import FirefliesCaptureError, capture_selected_transcript
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import Meeting, Source, UnresolvedIdentity
from zacai.state_repository import elevate_source_classification


def replies() -> tuple[bytes, bytes]:
    account = {"data": {"user": {"user_id": "synthetic-owner", "email": "owner@example.invalid"}}}
    transcript = {
        "data": {
            "transcript": {
                "id": "synthetic-capture",
                "title": "Synthetic private discussion",
                "dateString": "2026-10-02T13:00:00Z",
                "privacy": "owner",
                "is_live": False,
                "organizer_email": None,
                "participants": ["owner@example.invalid"],
                "user": account["data"]["user"],
                "meeting_attendees": [
                    {"name": None, "displayName": None, "email": "unnamed@example.invalid"}
                ],
                "sentences": [
                    {"index": 0, "speaker_name": "Speaker", "text": "Synthetic evidence"}
                ],
            }
        }
    }
    return json.dumps(account, indent=2).encode(), json.dumps(transcript, indent=2).encode()


def inputs(store: LocalFilesystemArtifactStore) -> dict[str, Any]:
    account, transcript = replies()
    return {
        "artifact_store": store,
        "requestor_boundaries": frozenset({TrustBoundary.BRAINSTORM}),
        "data_classification": DataClassification.CONFIDENTIAL,
        "expected_email": "owner@example.invalid",
        "expected_id": "synthetic-capture",
        "account_response": account,
        "transcript_response": transcript,
        "captured_at": datetime(2026, 10, 2, 14, tzinfo=UTC),
    }


def test_account_query_identifies_key_owner_without_any_caller_id() -> None:
    assert build_account_request() == {"query": ACCOUNT_QUERY, "variables": {}}
    assert "user(id" not in ACCOUNT_QUERY
    assert "users" not in ACCOUNT_QUERY
    raw, _ = replies()
    account = prepare_account_reply(raw, expected_email="OWNER@example.invalid")
    assert account.response_bytes == raw
    assert account.response_hash == content_hash_of(raw)
    assert "owner@example.invalid" not in repr(account)


@pytest.mark.parametrize(
    "expected",
    [
        "other@example.invalid",
        "",
        " owner@example.invalid",
        "a@@b",
        "a@",
        "é@b",
        "Owner <owner@example.invalid>",
    ],
)
def test_invalid_or_mismatched_account(expected: str) -> None:
    account, _ = replies()
    with pytest.raises(FirefliesWireError):
        prepare_account_reply(account, expected_email=expected)


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b'{"data":{"user":null}}',
        b'{"data":{"users":[]}}',
        b'{"data":{"user":{"user_id":"x","email":"owner@example.invalid"}},"errors":[{"message":"secret-marker"}]}',
        b'{"data":{"user":{"user_id":"x","user_id":"y","email":"owner@example.invalid"}}}',
        b'{"data":{"user":{"user_id":" ","email":"owner@example.invalid"}}}',
        b'{"data":{"user":{"user_id":"x","email":"owner@example.invalid","admin":true}}}',
        b"x" * (MAX_RESPONSE_BYTES + 1),
    ],
)
def test_bad_account_responses_fail_without_raw_diagnostics(raw: bytes) -> None:
    with pytest.raises(FirefliesWireError) as error:
        prepare_account_reply(raw, expected_email="owner@example.invalid")
    assert "secret-marker" not in str(error.value)


def test_capture_retains_three_artifacts_and_exact_provenance(
    db_session: Session, tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    receipt = capture_selected_transcript(db_session, **inputs(store))
    sources = [
        db_session.get(Source, sid)
        for sid in (receipt.account_source_id, receipt.raw_source_id, receipt.normalized_source_id)
    ]
    assert all(source is not None for source in sources)
    for source in sources:
        assert source is not None
        assert source.trust_boundary == TrustBoundary.BRAINSTORM
        assert source.data_classification == DataClassification.CONFIDENTIAL
        assert source.captured_at == datetime(2026, 10, 2, 14, tzinfo=UTC)
        assert source.content_location is not None
        assert (
            content_hash_of(store.get(source.trust_boundary, source.content_location))
            == source.content_hash
        )
    account, raw, normalized = sources
    assert account is not None and raw is not None and normalized is not None
    assert store.get(TrustBoundary.BRAINSTORM, raw.content_location) == replies()[1]
    view = json.loads(store.get(TrustBoundary.BRAINSTORM, normalized.content_location))
    assert view["raw_source"] == {"id": str(raw.id), "sha256": raw.content_hash}
    assert view["account_source"] == {"id": str(account.id), "sha256": account.content_hash}
    meeting = db_session.get(Meeting, receipt.meeting_id)
    assert meeting is not None
    assert meeting.occurred_at == datetime(2026, 10, 2, 13, tzinfo=UTC)
    unresolved = db_session.execute(
        select(UnresolvedIdentity).where(UnresolvedIdentity.meeting_id == meeting.id)
    ).scalar_one()
    assert unresolved.raw_email == "unnamed@example.invalid"
    assert unresolved.raw_name is None
    with pytest.raises(FileNotFoundError):
        store.get(TrustBoundary.PERSONAL, raw.content_location)


def test_repeat_capture_is_idempotent(db_session: Session, tmp_path: Path) -> None:
    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    first = capture_selected_transcript(db_session, **arguments)
    arguments["captured_at"] = datetime(2026, 10, 3, tzinfo=UTC)
    again = capture_selected_transcript(db_session, **arguments)
    assert first.was_new and not again.was_new
    assert first.meeting_id == again.meeting_id
    assert first.raw_source_id == again.raw_source_id
    assert first.normalized_source_id == again.normalized_source_id


@pytest.mark.parametrize(
    "boundaries",
    [frozenset(), frozenset({TrustBoundary.PERSONAL}), frozenset({TrustBoundary.SHARED})],
)
def test_boundary_denial_precedes_artifact_or_db_writes(
    db_session: Session, tmp_path: Path, boundaries: frozenset[TrustBoundary]
) -> None:
    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    arguments["requestor_boundaries"] = boundaries
    with pytest.raises(FirefliesCaptureError, match="boundary"):
        capture_selected_transcript(db_session, **arguments)
    assert not list(tmp_path.rglob("*.bin"))


@pytest.mark.parametrize("change", ["account", "transcript", "timestamp"])
def test_scope_or_timestamp_mismatch_precedes_writes(
    db_session: Session, tmp_path: Path, change: str
) -> None:
    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    if change == "timestamp":
        arguments["captured_at"] = datetime(2026, 10, 2, tzinfo=None)  # noqa: DTZ001 - intentional naive fixture
    else:
        key = "account_response" if change == "account" else "transcript_response"
        arguments[key] = arguments[key].replace(b"synthetic-owner", b"other-owner")
    with pytest.raises(FirefliesCaptureError):
        capture_selected_transcript(db_session, **arguments)
    assert not list(tmp_path.rglob("*.bin"))


def test_changed_privacy_creates_linked_raw_and_normalized_revisions(
    db_session: Session, tmp_path: Path
) -> None:
    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    first = capture_selected_transcript(db_session, **arguments)
    arguments["transcript_response"] = arguments["transcript_response"].replace(
        b'"owner"', b'"participants"'
    )
    second = capture_selected_transcript(db_session, **arguments)
    assert second.was_new and second.meeting_id != first.meeting_id
    for new_id, prior_id in [
        (second.raw_source_id, first.raw_source_id),
        (second.normalized_source_id, first.normalized_source_id),
    ]:
        source = db_session.get(Source, new_id)
        assert source is not None and source.supersedes_source_id == prior_id


def test_effective_classification_blocks_replay_without_partial_rows(
    db_session: Session, tmp_path: Path
) -> None:
    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    receipt = capture_selected_transcript(db_session, **arguments)
    elevate_source_classification(
        db_session,
        source_id=receipt.raw_source_id,
        trust_boundary=TrustBoundary.BRAINSTORM,
        new_classification=DataClassification.HIGHLY_RESTRICTED,
        reason="synthetic review",
        elevated_by="synthetic reviewer",
    )
    before = db_session.scalar(select(func.count()).select_from(Source))
    arguments["account_response"] += b" "
    with pytest.raises(FirefliesCaptureError, match="classification"):
        capture_selected_transcript(db_session, **arguments)
    assert db_session.scalar(select(func.count()).select_from(Source)) == before


class BrokenStore(LocalFilesystemArtifactStore):
    def get(self, trust_boundary: TrustBoundary, content_location: str) -> bytes:
        return b"corrupted synthetic bytes"


def test_bad_artifact_hash_prevents_source_rows(db_session: Session, tmp_path: Path) -> None:
    before = db_session.scalar(select(func.count()).select_from(Source))
    with pytest.raises(FirefliesCaptureError, match="verification"):
        capture_selected_transcript(db_session, **inputs(BrokenStore(tmp_path)))
    assert db_session.scalar(select(func.count()).select_from(Source)) == before


def test_changed_content_cannot_weaken_prior_revision(db_session: Session, tmp_path: Path) -> None:
    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    receipt = capture_selected_transcript(db_session, **arguments)
    elevate_source_classification(
        db_session,
        source_id=receipt.raw_source_id,
        trust_boundary=TrustBoundary.BRAINSTORM,
        new_classification=DataClassification.HIGHLY_RESTRICTED,
        reason="synthetic review",
        elevated_by="synthetic reviewer",
    )
    arguments["transcript_response"] += b" "
    with pytest.raises(FirefliesCaptureError, match="classification"):
        capture_selected_transcript(db_session, **arguments)


def test_capture_artifacts_are_in_boundary_backup_inventory(
    db_session: Session, tmp_path: Path
) -> None:
    from zacai.backup_artifacts import source_hashes_for_boundary

    store = LocalFilesystemArtifactStore(tmp_path)
    receipt = capture_selected_transcript(db_session, **inputs(store))
    captured = {
        db_session.get(Source, sid).content_hash
        for sid in (receipt.account_source_id, receipt.raw_source_id, receipt.normalized_source_id)
    }
    assert len(captured) == 3
    assert captured <= source_hashes_for_boundary(
        db_session, trust_boundary=TrustBoundary.BRAINSTORM
    )
    assert not (
        captured & source_hashes_for_boundary(db_session, trust_boundary=TrustBoundary.PERSONAL)
    )


def test_db_failure_rolls_back_partial_capture_and_retry_succeeds(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zacai.ingestion.fireflies_capture as module

    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    before_sources = db_session.scalar(select(func.count()).select_from(Source))
    before_meetings = db_session.scalar(select(func.count()).select_from(Meeting))
    original = module.record_unresolved_identity

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic secret marker do not surface")

    monkeypatch.setattr(module, "record_unresolved_identity", fail)
    with pytest.raises(FirefliesCaptureError) as failure:
        capture_selected_transcript(db_session, **arguments)
    assert "secret marker" not in str(failure.value)
    assert failure.value.__suppress_context__ is True
    assert db_session.scalar(select(func.count()).select_from(Source)) == before_sources
    assert db_session.scalar(select(func.count()).select_from(Meeting)) == before_meetings
    monkeypatch.setattr(module, "record_unresolved_identity", original)
    assert capture_selected_transcript(db_session, **arguments).was_new


def test_retracted_meeting_is_not_revived(db_session: Session, tmp_path: Path) -> None:
    from zacai.state_repository import retract_meeting

    arguments = inputs(LocalFilesystemArtifactStore(tmp_path))
    receipt = capture_selected_transcript(db_session, **arguments)
    retract_meeting(
        db_session,
        meeting_id=receipt.meeting_id,
        requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
        source_id=receipt.raw_source_id,
        reason="synthetic invalidation",
    )
    with pytest.raises(FirefliesCaptureError, match="retracted"):
        capture_selected_transcript(db_session, **arguments)


class NormalizedWriteFailure(LocalFilesystemArtifactStore):
    def put(self, trust_boundary: TrustBoundary, content_hash: str, raw_bytes: bytes) -> str:
        if b"zac-fireflies-normalized-v1" in raw_bytes:
            raise OSError("synthetic sensitive filesystem details")
        return super().put(trust_boundary, content_hash, raw_bytes)


def test_normalized_artifact_failure_rolls_back_raw_sources(
    db_session: Session, tmp_path: Path
) -> None:
    before = db_session.scalar(select(func.count()).select_from(Source))
    with pytest.raises(FirefliesCaptureError) as failure:
        capture_selected_transcript(db_session, **inputs(NormalizedWriteFailure(tmp_path)))
    assert "sensitive filesystem" not in str(failure.value)
    assert db_session.scalar(select(func.count()).select_from(Source)) == before
    assert len(list(tmp_path.rglob("*.bin"))) == 2  # accepted, unreferenced orphans
