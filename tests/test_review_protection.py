"""Throwaway age keys and local object clients; guarded test/restore DBs only."""

import io
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text

import tests.test_review_authorization as authorization_tests
from tests.test_fireflies_protection import keypair
from tests.test_review_host import Runtime, run
from zacai import backup, backup_artifacts
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.policy import TrustBoundary as B
from zacai.review_protection import (
    BrainstormReviewProtector,
    DisposableStateRestoreVerifier,
    ReviewProtectionError,
)
from zacai.state import Source


@pytest.fixture
def issued(test_session_factory, tmp_path):
    setup = next(authorization_tests.host_fixture.__wrapped__(test_session_factory, tmp_path))
    return authorization_tests.issued.__wrapped__(setup)


@pytest.fixture
def protected(issued, tmp_path, monkeypatch):
    factory, store, captured, baseline = issued[0]
    own = {captured.account_source_id, captured.raw_source_id, captured.normalized_source_id}

    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        # Existing committed synthetic fixtures refer to other ephemeral roots.
        # Production has no filter: it backs up every BRAINSTORM artifact.
        return [(h, loc) for sid, h, loc in found if sid not in baseline or sid in own]

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    identity = tmp_path / "throwaway.key"
    recipient = keypair(identity)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    restoration = DisposableStateRestoreVerifier()
    protector = BrainstormReviewProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=store,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest.cache",
        approval_id=issued[2],
        restoration=restoration,
    )
    return issued, protector, writer, reader, restoration


def target_absent():
    with backup._admin_connection() as admin:
        assert (
            admin.execute(
                text("SELECT count(*) FROM pg_database WHERE datname=:db"),
                {"db": backup.RESTORE_TEST_DATABASE},
            ).scalar_one()
            == 0
        )


def test_real_crypto_backup_full_restore_through_host(protected, tmp_path):
    issued, protector, _, _, _ = protected
    result = run(issued[0], authorization=issued[5](), protection=protector)
    assert result.review.summary
    encrypted = list((tmp_path / "objects" / "BRAINSTORM" / "state").rglob("*.age"))
    assert len(encrypted) == 1
    assert str(result.run_id).encode() not in encrypted[0].read_bytes()
    assert not list(tmp_path.rglob("*.csv"))
    target_absent()


@pytest.mark.parametrize("failure", ["remote_artifact", "remote_state", "restore"])
def test_protection_failure_never_releases_host_draft(protected, monkeypatch, failure):
    issued, protector, _, reader, restoration = protected
    original = reader.get_object
    if failure == "restore":

        def broken(*args):
            raise RuntimeError("invented private restore error")

        monkeypatch.setattr(restoration, "verify", broken)
    else:

        def broken(key):
            is_state = "/state/" in key
            if is_state == (failure == "remote_state"):
                return b"invented corrupted ciphertext"
            return original(key)

        monkeypatch.setattr(reader, "get_object", broken)
    runtime = Runtime(*issued[0][:2])
    from zacai.intelligence.review_host import ReviewHostError

    with pytest.raises(ReviewHostError) as error:
        run(issued[0], runtime=runtime, authorization=issued[5](), protection=protector)
    assert runtime.calls == 1
    assert "private" not in str(error.value)


def test_unrelated_run_or_incomplete_audits_reject(protected):
    issued, protector, _, _, _ = protected
    result = run(issued[0], authorization=issued[5]())
    for rid, audits in (
        (uuid4(), result.audit_source_ids),
        (result.run_id, result.audit_source_ids[:2]),
    ):
        with pytest.raises(ReviewProtectionError):
            protector.protect(rid, audits)


def test_restore_checks_fields_not_only_ids_counts(test_session_factory):
    from tests.test_backup import _make_source

    with test_session_factory() as session:
        sid = _make_source(session, trust_boundary=B.BRAINSTORM)
        session.commit()
    buffer = io.BytesIO()
    backup.export_boundary_stream(test_session_factory.kw["bind"], B.BRAINSTORM, buffer)
    original = buffer.getvalue()
    # Equal-length field alteration leaves UUIDs and all row counts intact.
    changed = original.replace(b"D028 backup test fixture", b"D028 tamper test fixture")
    assert changed != original and len(changed) == len(original)
    backup.recreate_restore_test_database()
    backup.upgrade_restore_test_schema()
    engine = create_engine(backup.RESTORE_TEST_URL)
    try:
        backup.restore_boundary_stream(engine, io.BytesIO(changed))
        with engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM source WHERE id=:id"), {"id": sid}
                ).scalar_one()
                == 1
            )
        with pytest.raises(RuntimeError, match="differs"):
            backup.verify_restored_boundary_stream(
                engine, io.BytesIO(original), boundary=B.BRAINSTORM
            )
    finally:
        engine.dispose()
        backup.drop_restore_test_database()


def test_read_verifier_refuses_canonical_or_test_target(test_session_factory):
    with pytest.raises(RuntimeError, match="restore"):
        backup.verify_restored_boundary_stream(
            test_session_factory.kw["bind"], io.BytesIO(b"invalid"), boundary=B.BRAINSTORM
        )


def test_bad_snapshot_cleanup_and_diagnostics():
    with pytest.raises(ReviewProtectionError) as error:
        DisposableStateRestoreVerifier().verify(b"invented private marker", {uuid4(): "a" * 64})
    assert "private marker" not in str(error.value)
    target_absent()
