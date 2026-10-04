"""Real crypto, disposable recovery and transactional DDL; invented test state only."""

import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from tests.test_fireflies_protection import keypair
from zacai import schema_rollout as rollout
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, Source, SourceSystem

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)


@pytest.fixture
def prepared(_test_engine, test_session_factory, tmp_path):
    # D027 fixture holds the test-only session lease; never use app/global engine.
    with _test_engine.connect() as conn:
        assert conn.scalar(text("SELECT current_database()")) == "zacai_test"
    config = Config(str(rollout._ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(rollout._ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", _test_engine.url.render_as_string())
    command.downgrade(config, "base")
    command.upgrade(config, "0004")
    try:
        with test_session_factory() as session:
            source = Source(
                trust_boundary=B.BRAINSTORM,
                data_classification=C.INTERNAL,
                system=SourceSystem.MANUAL,
                excerpt="D028 backup test fixture",
                content_hash=content_hash_of(b"invented original artifact"),
            )
            session.add(source)
            session.flush()
            sid = source.id
            journal = ArtifactBackupRun(
                trust_boundary=B.BRAINSTORM,
                status=ArtifactBackupRunStatus.SUCCEEDED,
                started_at=NOW - timedelta(minutes=2),
                finished_at=NOW,
                artifacts_checked=7,
                artifacts_backed_up=5,
                artifacts_already_protected=2,
                artifacts_repaired=0,
                artifacts_failed=0,
                error="invented journal marker",
            )
            session.add(journal)
            session.commit()
            jid = journal.id
        identity = tmp_path / "throwaway.key"
        recipient = keypair(identity)
        approval = rollout.SchemaRolloutApproval(
            target_database="zacai_test",
            code_revision=subprocess.check_output(
                ["git", "-C", str(rollout._ROOT), "rev-parse", "HEAD"]
            )
            .decode()
            .strip(),
            migration_hash=content_hash_of((rollout._ROOT / rollout._MIGRATION).read_bytes()),
            human_reference="synthetic operator approval",
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=15),
        )
        args = {
            "approval": approval,
            "objects": LocalDirectoryBackupStore(tmp_path / "objects"),
            "verification_objects": LocalDirectoryBackupStore(tmp_path / "objects"),
            "recipient": recipient,
            "identity_path": identity,
            "restoration": DisposableStateRestoreVerifier(),
            "receipt_path": tmp_path / "receipt.json",
            "clock": lambda: NOW,
        }
        yield _test_engine, args, sid, jid
    finally:
        command.upgrade(config, "0005")


def revision(engine):
    with engine.connect() as conn:
        return conn.scalar(text("SELECT version_num FROM alembic_version"))


def run(prepared):
    engine, args, _, _ = prepared
    rollout.execute_protected_schema_rollout(engine, **args)


def test_exact_upgrade_preserves_every_field_and_journal(prepared, tmp_path):
    engine, args, sid, jid = prepared
    run(prepared)
    assert revision(engine) == "0005"
    proof = json.loads(args["receipt_path"].read_text())
    assert proof["status"] == "APPLIED"
    assert proof["independent_full_state_and_journal_restore"] == "passed"
    assert args["receipt_path"].stat().st_mode & 0o777 == 0o600
    with engine.connect() as conn:
        assert (
            conn.scalar(text("SELECT excerpt FROM source WHERE id=:id"), {"id": sid})
            == "D028 backup test fixture"
        )
        assert (
            conn.scalar(text("SELECT error FROM artifact_backup_run WHERE id=:id"), {"id": jid})
            == "invented journal marker"
        )
        rollout._new_schema(conn)
    files = list((tmp_path / "objects").rglob("*.age"))
    assert len(files) == 2
    for file in files:
        assert b"invented journal marker" not in file.read_bytes()
        assert b"D028 backup test fixture" not in file.read_bytes()
    assert not list(tmp_path.rglob("*.csv"))


def test_post_ddl_failure_rolls_back_external_alembic_transaction(prepared, monkeypatch):
    engine, args, _, _ = prepared

    def fail(conn):
        assert conn.scalar(text("SELECT version_num FROM alembic_version")) == "0005"
        assert inspect(conn).has_table("meeting_project_association")
        raise RuntimeError("invented sensitive error")

    monkeypatch.setattr(rollout, "_new_schema", fail)
    with pytest.raises(rollout.SchemaRolloutError) as error:
        run(prepared)
    assert "sensitive" not in str(error.value)
    assert revision(engine) == "0004"
    assert not inspect(engine).has_table("meeting_project_association")
    assert json.loads(args["receipt_path"].read_text())["status"] == "FAILED_OR_UNCONFIRMED"


@pytest.mark.parametrize(
    "failure", ["ciphertext", "restore", "expired", "wrong_code", "same_reader"]
)
def test_failed_preparation_never_attempts_live_ddl(prepared, monkeypatch, failure):
    engine, args, _, _ = prepared
    if failure == "ciphertext":
        monkeypatch.setattr(
            args["verification_objects"], "get_object", lambda key: b"bad encrypted object"
        )
    elif failure == "restore":

        def fail(*a, **kw):
            raise RuntimeError("invented restore failure")

        monkeypatch.setattr(args["restoration"], "verify", fail)
    elif failure == "expired":
        args["clock"] = lambda: NOW + timedelta(minutes=15)
    elif failure == "wrong_code":
        args["approval"] = args["approval"].model_copy(update={"code_revision": "0" * 40})
    else:
        args["verification_objects"] = args["objects"]
    with pytest.raises(rollout.SchemaRolloutError):
        run(prepared)
    assert revision(engine) == "0004"
    if failure in ("ciphertext", "restore"):
        assert json.loads(args["receipt_path"].read_text())["status"] == "FAILED_OR_UNCONFIRMED"
    else:
        assert not args["receipt_path"].exists()


@pytest.mark.parametrize("change", ["canonical", "journal", "other_boundary"])
def test_network_stage_has_no_write_locks_and_stale_checkpoint_aborts(
    prepared, monkeypatch, change
):
    engine, args, _, jid = prepared
    original = args["verification_objects"].get_object
    changed = False

    def retrieve(key):
        nonlocal changed
        if not changed:
            changed = True
            # This independent write must complete while remote retrieval runs.
            with engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout='100ms'"))
                if change == "journal":
                    conn.execute(
                        text("UPDATE artifact_backup_run SET artifacts_checked=8 WHERE id=:id"),
                        {"id": jid},
                    )
                else:
                    boundary = "PERSONAL" if change == "other_boundary" else "BRAINSTORM"
                    conn.execute(
                        text(
                            "INSERT INTO source (id, trust_boundary, data_classification, system, excerpt) VALUES (gen_random_uuid(), :boundary, 'INTERNAL', 'MANUAL', 'new invented source')"
                        ),
                        {"boundary": boundary},
                    )
        return original(key)

    monkeypatch.setattr(args["verification_objects"], "get_object", retrieve)
    with pytest.raises(rollout.SchemaRolloutError):
        run(prepared)
    assert changed
    assert revision(engine) == "0004"
    assert json.loads(args["receipt_path"].read_text())["status"] == "FAILED_OR_UNCONFIRMED"


def test_active_writer_stops_upgrade_without_waiting(prepared, monkeypatch):
    engine, args, _, jid = prepared
    original = args["verification_objects"].get_object
    held = engine.connect()
    try:

        def retrieve(key):
            if not held.in_transaction():
                held.execute(
                    text("UPDATE artifact_backup_run SET artifacts_checked=9 WHERE id=:id"),
                    {"id": jid},
                )
            return original(key)

        monkeypatch.setattr(args["verification_objects"], "get_object", retrieve)
        with pytest.raises(rollout.SchemaRolloutError):
            run(prepared)
        assert revision(engine) == "0004"
    finally:
        held.rollback()
        held.close()


def test_failed_final_receipt_does_not_downgrade_committed_schema(prepared, monkeypatch):
    engine, args, _, _ = prepared
    original = rollout._receipt

    def write(path, proof):
        if proof["status"] == "APPLIED":
            raise OSError("invented disk failure")
        original(path, proof)

    monkeypatch.setattr(rollout, "_receipt", write)
    with pytest.raises(rollout.SchemaRolloutError):
        run(prepared)
    assert revision(engine) == "0005"
    assert json.loads(args["receipt_path"].read_text())["status"] == "FAILED_OR_UNCONFIRMED"


def test_existing_attempt_receipt_prevents_more_remote_writes(prepared, monkeypatch):
    engine, args, _, _ = prepared
    args["receipt_path"].write_text("previous attempt")

    def fail(*a, **kw):
        pytest.fail("another remote write must not occur")

    monkeypatch.setattr(args["objects"], "put_object", fail)
    with pytest.raises(rollout.SchemaRolloutError):
        run(prepared)
    assert revision(engine) == "0004"
    assert args["receipt_path"].read_text() == "previous attempt"


def test_authority_expiring_during_remote_stage_stops_before_more_uploads(prepared, monkeypatch):
    engine, args, _, _ = prepared
    original = args["verification_objects"].get_object
    now = NOW

    def retrieve(key):
        nonlocal now
        now = NOW + timedelta(minutes=15)
        return original(key)

    args["clock"] = lambda: now
    monkeypatch.setattr(args["verification_objects"], "get_object", retrieve)
    with pytest.raises(rollout.SchemaRolloutError):
        run(prepared)
    assert revision(engine) == "0004"
    assert len(list((args["receipt_path"].parent / "objects").rglob("*.age"))) == 1


def test_initial_receipt_failure_is_recorded_before_any_remote_write(prepared, monkeypatch):
    engine, args, _, _ = prepared
    original = rollout._receipt
    failed = False

    def write(path, proof):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("invented initial receipt failure")
        original(path, proof)

    def remote(*a, **kw):
        pytest.fail("no remote action after initial receipt failure")

    monkeypatch.setattr(rollout, "_receipt", write)
    monkeypatch.setattr(args["objects"], "put_object", remote)
    with pytest.raises(rollout.SchemaRolloutError):
        run(prepared)
    assert revision(engine) == "0004"
    assert json.loads(args["receipt_path"].read_text())["status"] == "FAILED_OR_UNCONFIRMED"


def test_omitted_database_port_cannot_be_inherited_from_environment(prepared):
    from sqlalchemy import create_engine

    engine = create_engine("postgresql+psycopg://127.0.0.1/zacai_test")
    try:
        with pytest.raises(ValueError, match="target"):
            rollout._target(engine, "zacai_test")
    finally:
        engine.dispose()


def test_unexpected_public_table_stops_before_upload(prepared, monkeypatch):
    engine, args, _, _ = prepared
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE unexpected_state (id integer)"))
    try:

        def remote(*a, **kw):
            pytest.fail("unexpected state must prevent remote work")

        monkeypatch.setattr(args["objects"], "put_object", remote)
        with pytest.raises(rollout.SchemaRolloutError):
            run(prepared)
        assert revision(engine) == "0004"
    finally:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE unexpected_state"))


def test_search_path_shadow_is_ignored(prepared):
    engine, _, _, _ = prepared
    with engine.connect() as conn:
        conn.execute(text("CREATE TEMP TABLE alembic_version (version_num text)"))
        conn.execute(text("INSERT INTO pg_temp.alembic_version VALUES ('shadow')"))
        conn.execute(text("SET LOCAL search_path=pg_temp,public"))
        rollout._connected(conn, "zacai_test")
        assert conn.scalar(text("SELECT version_num FROM alembic_version")) == "0004"
