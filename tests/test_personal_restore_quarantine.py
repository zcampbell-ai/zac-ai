"""Deny-only cluster marker controls with invented admin connections, no PG."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from zacai import backup
from zacai import review_protection as m


@pytest.fixture
def admin(monkeypatch):
    state = {"marker": None, "target": None, "next": 100, "events": []}

    class Connection:
        def execute(self, query, params=None):
            sql = str(query)
            state["events"].append(sql)
            if "current_database()" in sql:
                return SimpleNamespace(scalar_one=lambda: "postgres")
            if "pg_try_advisory_lock" in sql:
                return SimpleNamespace(scalar_one=lambda: True)
            if "pg_advisory_unlock" in sql:
                return SimpleNamespace(scalar_one=lambda: True)
            if sql.startswith("CREATE ROLE"):
                assert state["marker"] is None
                assert all(
                    part in sql
                    for part in [
                        "NOLOGIN",
                        "NOSUPERUSER",
                        "NOCREATEDB",
                        "NOCREATEROLE",
                        "NOINHERIT",
                        "NOREPLICATION",
                        "NOBYPASSRLS",
                    ]
                )
                state["marker"] = 100
            elif sql.startswith("DROP ROLE"):
                assert state["marker"] == 100
                state["marker"] = None
            elif sql.startswith("DROP DATABASE"):
                state["target"] = None
            else:
                pytest.fail(sql)

        def scalar(self, query, params=None):
            if "NOT EXISTS" in str(query):
                return True
            if "pg_roles" in str(query):
                return state["marker"]
            assert "pg_database" in str(query)
            return state["target"]

    connection = Connection()

    @contextmanager
    def connect():
        yield connection

    monkeypatch.setattr(
        backup,
        "create_engine",
        lambda *a, **kw: SimpleNamespace(
            connect=connect, dispose=lambda: state["events"].append("dispose")
        ),
    )
    return SimpleNamespace(state=state, connection=connection)


def test_ordinary_legacy_admin_and_nested_helper_remain_unchanged(admin):
    with backup._admin_connection() as first, backup._admin_connection() as nested:
        assert nested is first
    assert admin.state["events"][-1] == "dispose"


def test_preexisting_quarantine_blocks_actual_legacy_drop_before_any_ddl(admin):
    admin.state["marker"] = 999
    admin.state["target"] = 88
    with pytest.raises(RuntimeError, match="quarantined"):
        backup.drop_restore_test_database()
    assert admin.state["target"] == 88 and admin.state["marker"] == 999
    assert not any(event.startswith("DROP") for event in admin.state["events"])


def test_owned_scoped_nested_helpers_only_while_matching_oid(admin):
    with backup._admin_connection() as conn:
        oid = backup._reserve_personal_restore_marker(conn)
        with backup._admin_connection() as nested:
            assert nested is conn
        admin.state["marker"] = 999
        with pytest.raises(RuntimeError, match="quarantined"), backup._admin_connection():
            pytest.fail("replacement must hold")
        with pytest.raises(RuntimeError):
            backup._release_personal_restore_marker(conn, oid)
    assert admin.state["marker"] == 999


def test_process_failure_leaves_marker_and_next_ordinary_process_path_holds(admin):
    with pytest.raises(KeyboardInterrupt), backup._admin_connection() as conn:
        backup._reserve_personal_restore_marker(conn)
        raise KeyboardInterrupt()
    assert backup._RESTORE_TARGET_LEASE.get() is None
    with pytest.raises(RuntimeError, match="quarantined"):
        backup.recreate_restore_test_database()
    assert admin.state["marker"] == 100
    assert not any(event.startswith("DROP") for event in admin.state["events"])


def test_exact_marker_only_released_when_owned_target_absent(admin):
    with backup._admin_connection() as conn:
        oid = backup._reserve_personal_restore_marker(conn)
        admin.state["target"] = 88
        with pytest.raises(RuntimeError, match="occupied"):
            backup._release_personal_restore_marker(conn, oid)
        assert admin.state["marker"] == 100
        admin.state["target"] = None
        backup._release_personal_restore_marker(conn, oid)
        assert admin.state["marker"] is None


def test_matching_object_input_copy_cannot_drift_during_callback(setup, monkeypatch):
    # setup is imported from the actual adapter mechanics fixture below.
    original = {setup.sid: "a" * 64}
    previous = m.backup.upgrade_restore_test_schema

    def alter():
        original.clear()
        previous()

    monkeypatch.setattr(m.backup, "upgrade_restore_test_schema", alter)
    setup.run(hashes=original)
    assert original == {}
    assert ("selected", {setup.sid: "a" * 64}) in setup.events


from tests.test_personal_state_restoration import setup as setup  # noqa: PLC0414
