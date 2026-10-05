"""Mocked preparation/restore sequencing only; no PostgreSQL, crypto or cloud."""

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from zacai import personal_sql_recovery_drill as module
from zacai.policy import TrustBoundary as B
from zacai.state import CommitmentStatus


class Artifacts:
    def __init__(self):
        self.values = {}

    def put(self, boundary, digest, raw):
        assert boundary == B.PERSONAL
        self.values[digest] = raw
        return digest

    def get(self, boundary, location):
        assert boundary == B.PERSONAL
        return self.values[location]


@pytest.fixture
def harness(monkeypatch):
    events = []
    state = {"oid": None, "counter": 40, "locked": True, "readback": b"invented fixed frame stream"}
    admin = MagicMock()

    def scalar(query, parameters=None):
        if "pg_try_advisory_lock" in str(query):
            return state["locked"]
        assert parameters == {"name": module.backup.RESTORE_TEST_DATABASE}
        return state["oid"]

    def execute(query):
        assert str(query) == "CREATE DATABASE zacai_restore_test"
        assert state["oid"] is None
        state["counter"] += 1
        state["oid"] = state["counter"]
        events.append("create")

    admin.scalar.side_effect = scalar
    admin.execute.side_effect = execute

    @contextmanager
    def admin_connection():
        events.append("admin-open")
        try:
            yield admin
        finally:
            events.append("admin-close")

    engine = MagicMock()
    engine.connect.return_value.__enter__.return_value.scalar.return_value = "zacai_restore_test"
    engine.dispose.side_effect = lambda: events.append("dispose")
    monkeypatch.setattr(module, "create_engine", lambda url, **kwargs: engine)
    monkeypatch.setattr(module.backup, "_admin_connection", admin_connection)
    monkeypatch.setattr(
        module.backup, "upgrade_restore_test_schema", lambda: events.append("upgrade")
    )

    def drop():
        assert state["oid"] is not None
        state["oid"] = None
        events.append("drop")

    monkeypatch.setattr(module.backup, "drop_restore_test_database", drop)

    def export(_engine, boundary, stream):
        assert _engine is engine and boundary == B.PERSONAL
        stream.write(state["readback"])
        events.append("export")

    monkeypatch.setattr(module.backup, "export_boundary_stream", export)
    restored = []
    monkeypatch.setattr(
        module.backup,
        "restore_boundary_stream",
        lambda _engine, stream: restored.append(stream.read()),
    )
    verified = []
    monkeypatch.setattr(
        module.backup,
        "verify_restored_boundary_stream",
        lambda _engine, stream, **kwargs: verified.append((stream.read(), kwargs)),
    )
    monkeypatch.setattr(module, "Session", lambda _engine: MagicMock())
    sources = []

    def source(session, **kwargs):
        sources.append(kwargs)
        return SimpleNamespace(id=uuid4()), True

    monkeypatch.setattr(module, "record_source", source)
    people, commitments = [], []
    monkeypatch.setattr(module, "create_person", lambda session, **kwargs: people.append(kwargs))
    monkeypatch.setattr(
        module, "create_commitment", lambda session, **kwargs: commitments.append(kwargs)
    )
    drill = module.PersonalSqlDrill(run_id=uuid4(), artifacts=Artifacts())
    return SimpleNamespace(
        drill=drill,
        state=state,
        events=events,
        engine=engine,
        sources=sources,
        people=people,
        commitments=commitments,
        restored=restored,
        verified=verified,
    )


def test_mocked_full_lifecycle_uses_fixed_inventory_and_full_backup_comparison(harness):
    with harness.drill as drill:
        prepared = drill.prepare()
        assert prepared.artifact_hashes and not prepared.ingestion_authorized
        assert not prepared.off_device_verified
        assert drill.restore_exact(prepared.snapshot_bytes) == prepared.snapshot_hash
        assert harness.restored == [prepared.snapshot_bytes]
        assert harness.verified == [(prepared.snapshot_bytes, {"boundary": B.PERSONAL})]
    assert harness.state["oid"] is None
    assert harness.events.count("create") == 2
    assert harness.events.count("drop") == 2
    assert len(harness.sources) == 2
    assert all(item["trust_boundary"] == B.PERSONAL for item in harness.sources)
    assert harness.sources[0]["external_ref"] == harness.sources[1]["external_ref"]
    assert [item["status"] for item in harness.commitments] == [
        CommitmentStatus.OPEN,
        CommitmentStatus.DONE,
    ]
    assert harness.people[0]["entity_id"] == harness.people[1]["entity_id"]
    assert harness.commitments[0]["entity_id"] == harness.commitments[1]["entity_id"]


@pytest.mark.parametrize("blocked", ["occupied", "locked"])
def test_occupied_target_or_missing_window_never_destroyed(harness, blocked):
    if blocked == "occupied":
        harness.state["oid"] = 123
    else:
        harness.state["locked"] = False
    with pytest.raises(module.PersonalSqlDrillError) as error, harness.drill:
        pytest.fail("must not enter")
    assert error.value.__context__ is None
    assert "create" not in harness.events and "drop" not in harness.events


def test_changed_database_oid_prevents_destructive_cleanup(harness):
    with pytest.raises(module.PersonalSqlDrillError), harness.drill:
        harness.state["oid"] = 999
    assert "drop" not in harness.events
    assert harness.state["oid"] == 999
    assert "admin-close" in harness.events


def test_tampered_private_or_unknown_snapshot_rejected_before_rebuild(harness):
    with harness.drill as drill:
        prepared = drill.prepare()
        before = list(harness.events)
        with pytest.raises(module.PersonalSqlDrillError):
            drill.restore_exact(prepared.snapshot_bytes + b"unknown private source")
        assert harness.events == before
        assert not harness.restored


def test_full_readback_mismatch_rejected(harness):
    with harness.drill as drill:
        prepared = drill.prepare()
        harness.state["readback"] = prepared.snapshot_bytes + b"changed"
        with pytest.raises(module.PersonalSqlDrillError) as error:
            drill.restore_exact(prepared.snapshot_bytes)
        assert error.value.__context__ is None
    assert harness.state["oid"] is None


def test_preparation_and_restore_cannot_replay(harness):
    with harness.drill as drill:
        prepared = drill.prepare()
        with pytest.raises(module.PersonalSqlDrillError):
            drill.prepare()
        drill.restore_exact(prepared.snapshot_bytes)
        with pytest.raises(module.PersonalSqlDrillError):
            drill.restore_exact(prepared.snapshot_bytes)
    with pytest.raises(module.PersonalSqlDrillError), harness.drill:
        pytest.fail("one lifecycle only")


def test_no_caller_url_or_private_snapshot_constructor():
    with pytest.raises(TypeError):
        module.PersonalSqlDrill(run_id=uuid4(), artifacts=Artifacts(), source_url="zacai_dev")
    with pytest.raises(TypeError):
        module.PersonalSqlDrill(run_id=uuid4(), artifacts=Artifacts(), snapshot_bytes=b"private")


@pytest.mark.parametrize("phase", ["schema", "connected_database"])
def test_initialization_failure_cleans_only_owned_database(harness, monkeypatch, phase):
    if phase == "schema":
        monkeypatch.setattr(
            module.backup,
            "upgrade_restore_test_schema",
            lambda: (_ for _ in ()).throw(RuntimeError("private SQL details")),
        )
    else:
        harness.engine.connect.return_value.__enter__.return_value.scalar.return_value = "zacai_dev"
    with pytest.raises(module.PersonalSqlDrillError) as error, harness.drill:
        pytest.fail("must not enter")
    assert harness.state["oid"] is None
    assert harness.events.count("drop") == 1
    assert "admin-close" in harness.events
    assert error.value.__context__ is None
    assert "private" not in str(error.value)


def test_prepare_failure_consumes_attempt_and_cleans_owned_database(harness, monkeypatch):
    def failed_export(*args, **kwargs):
        raise RuntimeError("private export values")

    monkeypatch.setattr(module.backup, "export_boundary_stream", failed_export)
    with harness.drill as drill:
        with pytest.raises(module.PersonalSqlDrillError) as error:
            drill.prepare()
        assert error.value.__context__ is None
        source_count = len(harness.sources)
        with pytest.raises(module.PersonalSqlDrillError):
            drill.prepare()
        assert len(harness.sources) == source_count == 2
    assert harness.state["oid"] is None


def test_failed_restore_consumes_attempt_without_rebuilding_again(harness, monkeypatch):
    with harness.drill as drill:
        prepared = drill.prepare()
        monkeypatch.setattr(
            module.backup,
            "verify_restored_boundary_stream",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private row")),
        )
        with pytest.raises(module.PersonalSqlDrillError):
            drill.restore_exact(prepared.snapshot_bytes)
        created = harness.events.count("create")
        with pytest.raises(module.PersonalSqlDrillError):
            drill.restore_exact(prepared.snapshot_bytes)
        assert harness.events.count("create") == created == 2
    assert harness.state["oid"] is None


def test_cleanup_failure_is_closed_retains_target_and_closes_admin(harness, monkeypatch):
    def failed_drop():
        harness.events.append("failed-drop")
        raise RuntimeError("private database cleanup error")

    monkeypatch.setattr(module.backup, "drop_restore_test_database", failed_drop)
    with pytest.raises(module.PersonalSqlDrillError) as error, harness.drill:
        harness.drill.prepare()
    assert harness.state["oid"] is not None
    assert harness.events.count("failed-drop") == 1
    assert "admin-close" in harness.events
    assert error.value.__context__ is None


def test_created_database_lost_before_restore_is_never_dropped(harness):
    with pytest.raises(module.PersonalSqlDrillError), harness.drill as drill:
        prepared = drill.prepare()
        harness.state["oid"] = 999
        drill.restore_exact(prepared.snapshot_bytes)
    assert harness.state["oid"] == 999
    assert "drop" not in harness.events
