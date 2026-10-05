"""Mocked administrative leases only; no actual SQL connections or DB changes."""

from contextvars import Context, copy_context
from unittest.mock import MagicMock

import pytest

from zacai import backup


@pytest.fixture
def database(monkeypatch):
    state = {"held": False, "oid": 41, "drops": 0, "creates": 0, "connections": [], "events": []}

    def factory(url, **kwargs):
        assert url == backup._ADMIN_URL
        engine, connection = MagicMock(), MagicMock()
        owns = {"value": False}
        state["connections"].append(connection)
        engine.connect.return_value.__enter__.return_value = connection

        def execute(query, parameters=None):
            sql = str(query)
            if sql == "SELECT current_database()":
                value = "postgres"
            elif "pg_try_advisory_lock" in sql:
                assert parameters == {"key": backup._RESTORE_TARGET_LOCK}
                value = not state["held"]
                if value:
                    state["held"], owns["value"] = True, True
                    state["events"].append("lock")
            elif "pg_advisory_unlock" in sql:
                assert owns["value"]
                state["held"], owns["value"] = False, False
                state["events"].append("unlock")
                value = True
            elif sql == "DROP DATABASE IF EXISTS zacai_restore_test":
                assert owns["value"]
                state["oid"] = None
                state["drops"] += 1
                value = None
            elif sql == "CREATE DATABASE zacai_restore_test":
                assert owns["value"]
                state["oid"] = 99
                state["creates"] += 1
                value = None
            else:
                raise AssertionError("unexpected mocked SQL")
            result = MagicMock()
            result.scalar_one.return_value = value
            return result

        def dispose():
            if owns["value"]:
                state["held"], owns["value"] = False, False
            state["events"].append("dispose")

        connection.execute.side_effect = execute
        engine.dispose.side_effect = dispose
        return engine

    monkeypatch.setattr(backup, "create_engine", factory)
    assert backup._RESTORE_TARGET_LEASE.get() is None
    return state


def test_nested_fixed_helpers_reuse_owner_connection_without_reacquiring(database):
    with backup._admin_connection() as owner:
        with backup._admin_connection() as nested:
            assert nested is owner
        backup.drop_restore_test_database()
        backup.recreate_restore_test_database()
        assert len(database["connections"]) == 1
        assert database["held"]
    assert database["drops"] == 2
    assert database["creates"] == 1
    assert database["events"] == ["lock", "unlock", "dispose"]
    assert backup._RESTORE_TARGET_LEASE.get() is None


def test_competing_replacement_between_oid_check_and_drop_is_refused(database):
    with backup._admin_connection():
        owned_oid = database["oid"]  # Invented equivalent of the caller OID check.
        with pytest.raises(RuntimeError, match="lease unavailable"):
            Context().run(backup.recreate_restore_test_database)
        assert database["oid"] == owned_oid
        assert database["drops"] == database["creates"] == 0
        backup.drop_restore_test_database()
    assert database["oid"] is None
    assert database["drops"] == 1


def test_owner_exception_releases_lease_and_allows_next_operator(database):
    with pytest.raises(ValueError), backup._admin_connection():
        raise ValueError("invented failure")
    assert not database["held"]
    backup.drop_restore_test_database()
    assert database["drops"] == 1
    assert backup._RESTORE_TARGET_LEASE.get() is None


def test_stale_copied_context_cannot_reuse_closed_admin_connection(database):
    with backup._admin_connection():
        stale = copy_context()
    with pytest.raises(RuntimeError, match="owner mismatch"):
        stale.run(backup.drop_restore_test_database)
    assert database["drops"] == 0
    assert len(database["connections"]) == 1


def test_context_migrated_to_another_thread_is_refused(database, monkeypatch):
    with backup._admin_connection():
        monkeypatch.setattr(backup, "get_ident", lambda: -1)
        with pytest.raises(RuntimeError, match="owner mismatch"):
            backup.drop_restore_test_database()
    assert database["drops"] == 0


def test_unsafe_admin_url_rejects_before_any_connection(database, monkeypatch):
    monkeypatch.setattr(backup, "_ADMIN_URL", "postgresql+psycopg://127.0.0.1/zacai_dev")
    with pytest.raises(RuntimeError):
        backup.drop_restore_test_database()
    assert database["connections"] == []


def test_copied_context_from_another_async_task_is_refused(database, monkeypatch):
    task = object()
    monkeypatch.setattr(backup, "_current_task_owner", lambda: task)
    with backup._admin_connection():
        monkeypatch.setattr(backup, "_current_task_owner", object)
        with pytest.raises(RuntimeError, match="owner mismatch"):
            backup.drop_restore_test_database()
    assert database["drops"] == 0


def test_cli_drill_keeps_one_lease_across_all_steps(monkeypatch):
    import sys
    from contextlib import contextmanager

    events = []

    @contextmanager
    def leased_admin():
        events.append("acquired")
        try:
            yield object()
        finally:
            events.append("released")

    def step(name):
        def run(*args):
            assert events[0] == "acquired" and "released" not in events
            events.append(name)
        return run

    monkeypatch.setattr(backup, "_admin_connection", leased_admin)
    monkeypatch.setattr(backup, "recreate_restore_test_database", step("create"))
    monkeypatch.setattr(backup, "upgrade_restore_test_schema", step("upgrade"))
    monkeypatch.setattr(backup, "restore_boundary", step("restore"))
    monkeypatch.setattr(sys, "argv", ["zacai-backup", "drill", "--artifact", "invented.age", "--identity", "invented.agekey"])
    backup.main()
    assert events == ["acquired", "create", "upgrade", "restore", "released"]
