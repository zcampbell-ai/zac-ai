"""Shared fixtures for D026/D027 Zac State tests.

D027: all database tests run against a dedicated, disposable `zacai_test`
database - never `zacai_dev`. See DECISIONS.md D027 for the full
rationale. Two independent safety layers guard this:
- `assert_safe_test_database_url()` validates the configured URL before
  any connection is opened (host/database/port/password all checked).
- `assert_connected_to_safe_test_database()` re-verifies via a live
  `SELECT current_database()` immediately after connecting, as defense
  in depth against anything the URL string alone couldn't catch.

A session-level PostgreSQL advisory lock (`_TEST_SESSION_LOCK_KEY`)
serializes schema resets between two concurrent `pytest` processes - test
infrastructure only, unrelated to and never interacting with D026's own
row-level concurrency mechanism (`INSERT ON CONFLICT` + `SELECT FOR
UPDATE` in `zacai.state_repository`).

Not autouse: only a test that requests `db_session`/`test_session_factory`
(directly or via a fixture that depends on them) ever touches PostgreSQL.
Every other test in this suite (policy, gateway, config, health, logging,
main) runs exactly as before, with no database dependency introduced by
this file's mere existence.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import Session, sessionmaker

_SAFE_TEST_HOST = "127.0.0.1"
_SAFE_TEST_DATABASE = "zacai_test"
_SAFE_TEST_PORT = 5432
_DEFAULT_TEST_DATABASE_URL = f"postgresql+psycopg://{_SAFE_TEST_HOST}:{_SAFE_TEST_PORT}/{_SAFE_TEST_DATABASE}"

# Arbitrary but fixed - tied to "D027". Must never collide with any other
# advisory lock key added to this repo later (none exist yet).
_TEST_SESSION_LOCK_KEY = 727027

_ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"


def _test_database_url() -> str:
    """Reads ZACAI_TEST_DATABASE_URL if set; otherwise a safe, hardcoded
    default. There is no path by which an unset variable resolves to
    something unsafe - the default itself is the one permitted target."""
    return os.environ.get("ZACAI_TEST_DATABASE_URL", _DEFAULT_TEST_DATABASE_URL)


def assert_safe_test_database_url(url: str) -> None:
    """Fail closed unless `url` is exactly the one permitted test target.

    Checked individually, not as one combined condition, so a
    misconfiguration is immediately diagnosable: the raised error names
    exactly which field is wrong and what was expected (D027).
    """
    parsed = make_url(url)
    if parsed.host != _SAFE_TEST_HOST:
        raise RuntimeError(
            f"refusing to run database tests: host {parsed.host!r} is not "
            f"{_SAFE_TEST_HOST!r} (D027)"
        )
    if parsed.database != _SAFE_TEST_DATABASE:
        raise RuntimeError(
            f"refusing to run database tests: database {parsed.database!r} is not "
            f"{_SAFE_TEST_DATABASE!r} (D027) - zacai_dev must never be used by tests"
        )
    if parsed.port is not None and parsed.port != _SAFE_TEST_PORT:
        raise RuntimeError(
            f"refusing to run database tests: port {parsed.port!r} is not "
            f"None (default) or {_SAFE_TEST_PORT!r} (D027)"
        )
    if parsed.password:
        raise RuntimeError(
            "refusing to run database tests: the test database URL must not "
            "contain a password (D027)"
        )


def assert_connected_to_safe_test_database(reported_database: str) -> None:
    """Pure check, no I/O - separated from the query itself so it's
    unit-testable with plain strings, not just via a live connection.

    Defense in depth: `assert_safe_test_database_url()` already validated
    the URL string before a connection was ever opened; this independently
    verifies what was *actually* connected to, catching anything the
    string alone couldn't (a connection alias, a DSN quirk, a driver
    default resolving somewhere unexpected).
    """
    if reported_database != _SAFE_TEST_DATABASE:
        raise RuntimeError(
            f"connected database reports {reported_database!r}, not "
            f"{_SAFE_TEST_DATABASE!r} - refusing to proceed (D027)"
        )


def _acquire_test_session_lock(connection: Connection) -> None:
    """Try non-blocking first for immediate operator feedback; only block
    (and only after printing why) if another pytest process already holds
    it. Never fails fast - the friendlier default for what is normally an
    accidental double-launch."""
    acquired = connection.execute(
        text("SELECT pg_try_advisory_lock(:key)"), {"key": _TEST_SESSION_LOCK_KEY}
    ).scalar_one()
    if not acquired:
        print(
            "D027: another pytest session is using zacai_test - waiting for it to finish...",
            file=sys.stderr,
        )
        connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _TEST_SESSION_LOCK_KEY})


def _release_test_session_lock(connection: Connection) -> None:
    connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _TEST_SESSION_LOCK_KEY})


def _reset_test_schema(url: str, *, already_stamped: bool) -> None:
    """Runs the same Alembic migration used for zacai_dev/production
    against the test database - no hand-built test tables, ever."""
    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", url)
    if already_stamped:
        command.downgrade(config, "base")
    command.upgrade(config, "head")


@pytest.fixture(scope="session")
def _test_engine() -> Iterator[Engine]:
    """Session-scoped: validates the test database URL, verifies the live
    connection really is zacai_test, holds the D027 advisory lock for the
    whole session, resets the schema via Alembic, and yields a test-only
    engine. Never touches `zacai.db.get_engine()` (the app's own,
    dev/prod-pointed engine) - there is no shared global state through
    which a test could accidentally inherit the dev database."""
    url = _test_database_url()
    assert_safe_test_database_url(url)

    engine = create_engine(url, future=True)
    lock_connection = engine.connect()
    try:
        reported = lock_connection.execute(text("SELECT current_database()")).scalar_one()
        assert_connected_to_safe_test_database(reported)

        already_stamped = inspect(lock_connection).has_table("alembic_version")
        _acquire_test_session_lock(lock_connection)
        try:
            _reset_test_schema(url, already_stamped=already_stamped)
            yield engine
        finally:
            _release_test_session_lock(lock_connection)
    finally:
        lock_connection.close()
        engine.dispose()


@pytest.fixture(scope="session")
def _require_state_schema(_test_engine: Engine) -> None:
    inspector = inspect(_test_engine)
    if "person" not in inspector.get_table_names():
        pytest.fail(
            "zacai_test is missing the D026 state schema after the D027 reset - "
            "check the Alembic migration",
            pytrace=False,
        )


@pytest.fixture(scope="session")
def test_session_factory(_test_engine: Engine) -> sessionmaker[Session]:
    """For tests that need genuinely separate, independently-committed
    transactions (the D026 concurrency tests) - always bound to the
    disposable zacai_test engine, never `zacai.db`'s app-level factory."""
    return sessionmaker(bind=_test_engine, future=True, expire_on_commit=False)


@pytest.fixture
def db_session(_test_engine: Engine, _require_state_schema: None) -> Iterator[Session]:
    """A Session bound to its own connection, joined to an outer
    transaction via a SAVEPOINT, rolled back at teardown so tests never
    leave data behind in zacai_test.

    Uses SQLAlchemy's standard "join a Session into an external
    transaction" recipe: an expected failure inside a test (e.g.
    `pytest.raises` around a constraint violation) ends the Session's own
    transaction, which would otherwise also end the outer DBAPI
    transaction this fixture relies on for rollback-based isolation. The
    `after_transaction_end` listener below re-opens a fresh SAVEPOINT
    whenever that happens, so the test can keep using `db_session`
    afterward, and the fixture's own teardown still rolls everything back.
    """
    connection = _test_engine.connect()
    outer_transaction = connection.begin()
    connection.begin_nested()
    session = Session(bind=connection)

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess: Session, transaction: object) -> None:
        if not connection.in_nested_transaction():
            connection.begin_nested()

    try:
        yield session
    finally:
        session.close()
        outer_transaction.rollback()
        connection.close()
