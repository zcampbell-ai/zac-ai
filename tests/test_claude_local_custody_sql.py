"""Root-only real PostgreSQL capture/commit/reopen, invented files and owner.
Human affirmation alone is simulated; no real archive, key or model accessed.
"""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from tests.test_claude_original_capture import inputs
from tests.test_private_host import CONFIG, OWNER, enroll
from zacai import claude_local_custody as m
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.state import Source


def test_actual_canonical_capture_commit_reopen(tmp_path, monkeypatch, test_session_factory):
    directory = tmp_path / "owner"
    enroll(directory, lambda: datetime.now(UTC), scopes=m._SCOPE)
    original, raw = inputs(custody_id=uuid4())
    original_path, proposal_path = tmp_path / "original.json", tmp_path / "proposal.json"
    for path, data in ((original_path, original), (proposal_path, raw)):
        path.write_bytes(data)
        path.chmod(0o600)
    artifacts = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    human_actions = []
    monkeypatch.setattr(m, "_approve_on_tty", lambda *args, **kwargs: human_actions.append("simulated human"))
    result = m.run_local_claude_custody(
        configuration=CONFIG,
        owner_directory=directory,
        expected_identity=OWNER,
        escrow_confirmed_by_operator=True,
        original_path=original_path,
        expected_original_hash=content_hash_of(original),
        proposal_path=proposal_path,
        expected_proposal_hash=content_hash_of(raw),
        session_factory=test_session_factory,
        artifacts=artifacts,
        expected_root=observe_claude_artifact_root(artifacts),
    )
    assert human_actions == ["simulated human"]
    assert result.status == "COMMITTED_REOPENED_RECOVERY_PENDING"
    assert not result.recovery_verified and not result.processing_authorized
    ids = {result.original_reference.source_id, result.companion_reference.source_id}
    with test_session_factory() as session:
        rows = session.scalars(select(Source).where(Source.id.in_(ids))).all()
        assert len(rows) == 2
        assert {row.content_hash for row in rows} == {
            result.original_reference.content_hash,
            result.companion_reference.content_hash,
        }


def test_actual_capture_owner_revocation_rolls_back(tmp_path, monkeypatch, test_session_factory):
    import pytest

    from zacai.claude_original_capture import record_claude_original

    directory = tmp_path / "owner"
    enrolled = enroll(directory, lambda: datetime.now(UTC), scopes=m._SCOPE)
    original, raw = inputs(custody_id=uuid4())
    original_path, proposal_path = tmp_path / "original.json", tmp_path / "proposal.json"
    for path, data in ((original_path, original), (proposal_path, raw)):
        path.write_bytes(data)
        path.chmod(0o600)
    artifacts = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    captured_ids = []
    monkeypatch.setattr(m, "_approve_on_tty", lambda *args, **kwargs: None)

    def revoke_after_actual_capture(session, **kwargs):
        result = record_claude_original(session, **kwargs)
        captured_ids.extend(
            [result.original_reference.source_id, result.companion_reference.source_id]
        )
        enrolled.owners.revoke()
        return result

    monkeypatch.setattr(m, "record_claude_original", revoke_after_actual_capture)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(
            configuration=CONFIG,
            owner_directory=directory,
            expected_identity=OWNER,
            escrow_confirmed_by_operator=True,
            original_path=original_path,
            expected_original_hash=content_hash_of(original),
            proposal_path=proposal_path,
            expected_proposal_hash=content_hash_of(raw),
            session_factory=test_session_factory,
            artifacts=artifacts,
            expected_root=observe_claude_artifact_root(artifacts),
        )
    assert len(captured_ids) == 2
    with test_session_factory() as session:
        assert session.scalars(select(Source).where(Source.id.in_(captured_ids))).all() == []
