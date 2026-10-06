"""Invented admin/restore adapter controls; no PostgreSQL, crypto or private State."""

from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url

from zacai import review_protection as m
from zacai.policy import TrustBoundary as B


@pytest.fixture
def setup(monkeypatch):
    sid = uuid4()
    events = []
    state = {
        "oid": None,
        "lock": True,
        "unlock": True,
        "journal": {"PERSONAL"},
        "source": SimpleNamespace(trust_boundary=B.PERSONAL, content_hash="a" * 64),
        "database": "zacai_restore_test",
        "marker": None,
    }

    class Admin:
        def execute(self, query, params=None):
            sql = str(query)
            events.append(sql)
            if "pg_try_advisory_lock" in sql:
                return SimpleNamespace(scalar_one=lambda: state["lock"])
            if "pg_advisory_unlock" in sql:
                return SimpleNamespace(scalar_one=lambda: state["unlock"])
            if sql.startswith("CREATE ROLE"):
                assert state["marker"] is None
                assert "NOLOGIN NOSUPERUSER" in sql
                state["marker"] = 123
            elif sql.startswith("DROP ROLE"):
                assert state["marker"] == 123
                state["marker"] = None
            elif sql.startswith("CREATE DATABASE"):
                assert state["oid"] is None
                state["oid"] = 100
            elif sql.startswith("DROP DATABASE"):
                assert state["oid"] == 100  # A replacement is never collateral cleanup.
                state["oid"] = None
            else:
                pytest.fail(sql)

        def scalar(self, query, params):
            if "NOT EXISTS" in str(query):
                return state.get("marker_valid", True)
            if "pg_roles" in str(query):
                return state["marker"]
            assert "SELECT oid FROM pg_database" in str(query)
            return state["oid"]

    @contextmanager
    def admin():
        existing = m.backup._RESTORE_TARGET_LEASE.get()
        if existing is not None:
            m.backup._assert_restore_marker_scope(existing)
            yield existing.connection
            return
        connection = Admin()
        lease = m.backup._RestoreTargetLease(
            connection, m.backup.get_ident(), m.backup._current_task_owner()
        )
        token = m.backup._RESTORE_TARGET_LEASE.set(lease)
        try:
            m.backup._assert_restore_marker_scope(lease)
            yield connection
        finally:
            lease.active = False
            m.backup._RESTORE_TARGET_LEASE.reset(token)

    class Connection:
        def scalar(self, sql):
            if "SELECT oid FROM pg_database" in str(sql):
                return state.get("connected_oid", state["oid"])
            assert str(sql) == "SELECT current_database()"
            events.append("connected-target")
            return state["database"]

        def execute(self, sql):
            assert "SELECT DISTINCT trust_boundary" in str(sql)
            return SimpleNamespace(scalars=lambda: state["journal"])

    @contextmanager
    def connect():
        yield Connection()

    engine = SimpleNamespace(
        connect=connect, begin=connect, dispose=lambda: events.append("dispose")
    )
    current = create_engine("postgresql+psycopg://127.0.0.1/zacai_test")
    monkeypatch.setattr(m.backup, "_admin_connection", admin)
    monkeypatch.setattr(m.backup, "upgrade_restore_test_schema", lambda: events.append("upgrade"))
    monkeypatch.setattr(m, "create_engine", lambda url, **kw: engine)
    monkeypatch.setattr(event, "listen", lambda *a, **kw: events.append("physical-hook"))
    monkeypatch.setattr(
        m.backup,
        "restore_boundary_stream",
        lambda engine, stream: events.append(("restore", stream.read())),
    )
    monkeypatch.setattr(
        m.backup,
        "verify_restored_boundary_stream",
        lambda engine, stream, **kw: events.append(("verify", stream.read(), kw)),
    )
    monkeypatch.setattr(m.backup, "_raw_connection", lambda connection: connection)
    monkeypatch.setattr(
        m.backup,
        "_restore_table_csv",
        lambda raw, table, data: events.append(("journal_restore", table, data)),
    )
    monkeypatch.setattr(
        m.backup,
        "_verify_table_csv",
        lambda raw, table, data: events.append(("journal_verify", table, data)),
    )
    monkeypatch.setattr(
        m,
        "_verify_personal_selected_source_rows",
        lambda restored, live, hashes: events.append(("selected", hashes)),
    )

    @contextmanager
    def session(engine):
        yield SimpleNamespace(get=lambda cls, found: state["source"] if found == sid else None)

    monkeypatch.setattr(m, "Session", session)
    return SimpleNamespace(
        sid=sid,
        state=state,
        events=events,
        current=current,
        run=lambda **kw: m.DisposableStateRestoreVerifier().verify_personal(
            kw.pop("snapshot", b"invented full State"),
            kw.pop("hashes", {sid: "a" * 64}),
            current_selected_sources=kw.pop("current", current),
            operational_journal=kw.pop("journal", b"invented journal"),
        ),
    )


def test_full_personal_call_and_owned_cleanup(setup):
    s = setup
    assert s.run() is None
    assert ("verify", b"invented full State", {"boundary": B.PERSONAL}) in s.events
    assert ("journal_verify", "artifact_backup_run", b"invented journal") in s.events
    assert ("selected", {s.sid: "a" * 64}) in s.events
    assert s.state["oid"] is None
    assert s.state["marker"] is None
    assert s.events[-2:] == [
        f"DROP ROLE {m.backup._PERSONAL_RESTORE_MARKER}",
        "SELECT pg_advisory_unlock(:key)",
    ]
    assert s.events.index("physical-hook") < s.events.index("connected-target")
    assert s.events.index("connected-target") < s.events.index("upgrade")
    assert s.state["marker"] is None
    assert s.events.index("dispose") < s.events.index("DROP DATABASE zacai_restore_test")


@pytest.mark.parametrize("fault", ["missing", "crossboundary", "hash", "journal", "emptyjournal"])
def test_required_personal_rows_and_journal_hold_with_cleanup(setup, fault):
    s = setup
    if fault == "missing":
        s.state["source"] = None
    elif fault == "crossboundary":
        s.state["source"].trust_boundary = B.BRAINSTORM
    elif fault == "hash":
        s.state["source"].content_hash = "b" * 64
    elif fault == "journal":
        s.state["journal"] = {"BRAINSTORM"}
    else:
        s.state["journal"] = set()
    with raises_exact(m.ReviewProtectionError) as error:
        s.run()
    assert error.value.__context__ is None
    assert s.state["oid"] is None
    assert s.state["marker"] is None
    assert "dispose" in s.events
    assert s.events[-1] == "SELECT pg_advisory_unlock(:key)"


@pytest.mark.parametrize("fault", ["lock", "occupied", "unsafe", "capacity", "digest"])
def test_refuse_before_create_or_private_restore(setup, fault):
    s = setup
    args = {}
    if fault == "lock":
        s.state["lock"] = False
    elif fault == "occupied":
        s.state["oid"] = 999
    elif fault == "unsafe":
        args["current"] = create_engine("postgresql+psycopg://remote/zacai_dev")
    elif fault == "capacity":
        args["journal"] = b""
    else:
        args["hashes"] = {s.sid: "not-a-hash"}
    with raises_exact(m.ReviewProtectionError):
        s.run(**args)
    assert not any(str(event).startswith("CREATE DATABASE") for event in s.events)
    assert not any(isinstance(event, tuple) for event in s.events)
    assert s.state["oid"] == (999 if fault == "occupied" else None)


def test_replaced_target_never_dropped(setup, monkeypatch):
    s = setup
    monkeypatch.setattr(m.backup, "restore_boundary_stream", lambda *_: s.state.update(oid=999))
    with raises_exact(m.ReviewProtectionCleanupUncertain):
        s.run()
    assert s.state["oid"] == 999
    assert s.state["marker"] == 123
    assert "DROP DATABASE zacai_restore_test" not in s.events
    assert s.events[-1] == "SELECT pg_advisory_unlock(:key)"


def test_interrupt_preserved_after_dispose_drop_unlock(setup, monkeypatch):
    def interrupt(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(m.backup, "restore_boundary_stream", interrupt)
    with pytest.raises(KeyboardInterrupt):
        setup.run()
    assert setup.state["oid"] is None
    assert setup.state["marker"] is None
    assert "dispose" in setup.events
    assert setup.events[-1] == "SELECT pg_advisory_unlock(:key)"


def test_unconfirmed_unlock_holds(setup):
    setup.state["unlock"] = False
    with raises_exact(m.ReviewProtectionError):
        setup.run()
    assert setup.state["oid"] is None
    assert setup.state["marker"] is None


def test_actual_database_name_checked_before_restore(setup):
    setup.state["database"] = "zacai_dev"
    with raises_exact(m.ReviewProtectionError):
        setup.run()
    assert not any(isinstance(event, tuple) for event in setup.events)
    assert setup.state["oid"] is None
    assert setup.state["marker"] is None


@pytest.mark.parametrize("field", list(m._SELECTED_SOURCE_COLUMNS))
def test_selected_personal_copy_compares_every_canonical_field(monkeypatch, field):
    import csv
    import io

    sid = uuid4()
    expected = {sid: "a" * 64}

    def encoded(changed):
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(m._SELECTED_SOURCE_COLUMNS)
        writer.writerow(
            [
                "changed" if changed and column == field else f"value-{column}"
                for column in m._SELECTED_SOURCE_COLUMNS
            ]
        )
        return buffer.getvalue().encode()

    calls = []

    class Connection:
        def __init__(self, name):
            self.name = name

        def execute(self, sql):
            if str(sql).startswith("SET "):
                return None
            if "information_schema.columns" in str(sql):
                return SimpleNamespace(
                    scalars=lambda: SimpleNamespace(all=lambda: list(m._SELECTED_SOURCE_COLUMNS))
                )
            assert sql.compile().params["trust_boundary_1"] == B.PERSONAL
            return list(expected.items())

        def scalar(self, sql):
            return "zacai_test" if self.name == "live" else "zacai_restore_test"

        @contextmanager
        def cursor(self):
            yield self

        @contextmanager
        def copy(self, sql, params):
            assert params == (B.PERSONAL.value, [sid])
            assert all(column in sql for column in m._SELECTED_SOURCE_COLUMNS)
            calls.append(self.name)
            yield [encoded(self.name == "recovered")]

    def engine(name, database):
        @contextmanager
        def connect():
            yield Connection(name)

        return SimpleNamespace(
            url=make_url(f"postgresql+psycopg://127.0.0.1/{database}"), connect=connect
        )

    monkeypatch.setattr(m.backup, "_raw_connection", lambda connection: connection)
    with pytest.raises(ValueError, match="changed since historical checkpoint"):
        m._verify_personal_selected_source_rows(
            engine("recovered", "zacai_restore_test"), engine("live", "zacai_test"), expected
        )
    assert calls == ["live", "recovered"]


def test_schema_failure_cleans_owned_database_before_engine_exists(setup, monkeypatch):
    def fail():
        raise RuntimeError("invented private schema failure")

    monkeypatch.setattr(m.backup, "upgrade_restore_test_schema", fail)
    with raises_exact(m.ReviewProtectionError) as error:
        setup.run()
    assert error.value.__context__ is None
    assert setup.state["oid"] is None
    assert setup.state["marker"] is None
    assert "dispose" in setup.events
    assert setup.events[-1] == "SELECT pg_advisory_unlock(:key)"


def test_creation_unconfirmed_does_not_drop_unknown_target(setup, monkeypatch):
    original = m._personal_restore_oid

    def read(admin):
        if setup.state["oid"] == 100:
            return None
        return original(admin)

    monkeypatch.setattr(m, "_personal_restore_oid", read)
    with raises_exact(m.ReviewProtectionCleanupUncertain):
        setup.run()
    assert setup.state["oid"] == 100
    assert setup.state["marker"] == 123
    assert "DROP DATABASE zacai_restore_test" not in setup.events
    assert setup.events[-1] == "SELECT pg_advisory_unlock(:key)"


def test_cleanup_uncertain_is_distinct_and_persists_guard(setup, monkeypatch):
    def interrupted(*args):
        setup.state["marker"] = 999
        raise KeyboardInterrupt()

    monkeypatch.setattr(m.backup, "restore_boundary_stream", interrupted)
    with raises_exact(m.ReviewProtectionCleanupUncertain) as error:
        setup.run()
    assert error.value.__context__ is None
    assert setup.state["marker"] == 999 and setup.state["oid"] == 100
    assert not any(event.startswith("DROP ") for event in setup.events)


def test_current_engine_cannot_be_shaped_url(setup):
    with raises_exact(m.ReviewProtectionError):
        setup.run(
            current=SimpleNamespace(url=make_url("postgresql+psycopg://127.0.0.1/zacai_test"))
        )
    assert setup.events == []


def test_restore_url_and_name_must_match_before_admin(setup, monkeypatch):
    monkeypatch.setattr(m.backup, "RESTORE_TEST_DATABASE", "unmatched_name")
    with raises_exact(m.ReviewProtectionError):
        setup.run()
    assert setup.events == []


def test_preexisting_marker_denies_before_target_changes(setup):
    setup.state["marker"] = 999
    with raises_exact(m.ReviewProtectionError):
        setup.run()
    assert setup.state["marker"] == 999 and setup.state["oid"] is None
    assert not any(event.startswith("CREATE") for event in setup.events)


def test_connected_oid_mismatch_denies_before_migration_writes(setup):
    setup.state["connected_oid"] = 999
    with raises_exact(m.ReviewProtectionError):
        setup.run()
    assert "upgrade" not in setup.events
    assert setup.state["oid"] is None and setup.state["marker"] is None


@contextmanager
def raises_exact(exception, **kwargs):
    with pytest.raises(exception, **kwargs) as error:
        yield error
    assert type(error.value) is exception
    assert error.value.__context__ is None


def test_caller_held_lease_poison_denies_actual_nested_legacy_drop(setup, monkeypatch):
    s = setup
    monkeypatch.setattr(m.backup, "restore_boundary_stream", lambda *_: s.state.update(oid=999))
    with m.backup._admin_connection():
        with raises_exact(m.ReviewProtectionCleanupUncertain):
            s.run()
        with pytest.raises(RuntimeError, match="quarantined"):
            m.backup.drop_restore_test_database()
        assert m.backup._RESTORE_TARGET_LEASE.get().personal_marker_oid == 0
    assert s.state["oid"] == 999 and s.state["marker"] == 123
    assert "DROP DATABASE IF EXISTS zacai_restore_test" not in s.events


def test_early_interrupt_poison_retains_quarantine(setup, monkeypatch):
    s = setup

    def interrupt(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(m, "_personal_restore_oid", interrupt)
    # This interrupt precedes marker reservation and creates no pending marker.
    with pytest.raises(KeyboardInterrupt):
        s.run()
    assert s.state["marker"] is None


def test_every_physical_connection_oid_guard():
    class Cursor:
        def __init__(self, row):
            self.row = row
            self.closed = False

        def execute(self, sql):
            assert "current_database" in sql

        def fetchone(self):
            return self.row

        def close(self):
            self.closed = True

    for row in [("zacai_restore_test", 100), ("zacai_restore_test", 999), ("other", 100)]:
        cursor = Cursor(row)
        rollbacks = []
        connection = SimpleNamespace(
            cursor=lambda cursor=cursor: cursor,
            rollback=lambda rollbacks=rollbacks: rollbacks.append(True),
        )
        if row == ("zacai_restore_test", 100):
            assert m._personal_connection_guard(100)(connection, None) is None
        else:
            with pytest.raises(ValueError):
                m._personal_connection_guard(100)(connection, None)
        assert cursor.closed
        assert rollbacks == ([True] if row == ("zacai_restore_test", 100) else [])


def test_interrupt_before_owned_oid_preserves_marker_and_poison(setup, monkeypatch):
    s = setup
    original = m._personal_restore_oid

    def read(admin):
        if s.state["oid"] == 100:
            raise KeyboardInterrupt()
        return original(admin)

    monkeypatch.setattr(m, "_personal_restore_oid", read)
    with m.backup._admin_connection():
        with pytest.raises(KeyboardInterrupt):
            s.run()
        with pytest.raises(RuntimeError, match="quarantined"):
            m.backup.drop_restore_test_database()
    assert s.state["oid"] == 100 and s.state["marker"] == 123
    assert not any(str(item).startswith("DROP DATABASE") for item in s.events)


def test_module_entry_guard_after_all_quarantine_helpers():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(m.backup.__file__).read_text())
    guard = next(
        i
        for i, n in enumerate(tree.body)
        if isinstance(n, ast.If) and "__name__" in ast.unparse(n.test)
    )
    assert all(
        i < guard
        for i, n in enumerate(tree.body)
        if isinstance(n, ast.FunctionDef) and ("marker" in n.name or "poison" in n.name)
    )


def test_created_marker_privileges_or_membership_hold_before_database(setup):
    s = setup
    s.state["marker_valid"] = False
    with m.backup._admin_connection():
        with raises_exact(m.ReviewProtectionCleanupUncertain):
            s.run()
        with pytest.raises(RuntimeError, match="quarantined"):
            m.backup.recreate_restore_test_database()
    assert s.state["oid"] is None and s.state["marker"] == 123
    assert not any(str(event).startswith("CREATE DATABASE") for event in s.events)
