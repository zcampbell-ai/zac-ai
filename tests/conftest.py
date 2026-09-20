"""Shared fixtures for D026 Zac State tests.

Not autouse: only a test that requests `db_session` (directly or via a
fixture that depends on it) ever touches PostgreSQL. Every other test in
this suite (policy, gateway, config, health, logging, main) runs exactly
as before, with no database dependency introduced by this file's mere
existence.

Uses `zacai_dev` only, per D026's approved scope - no separate test
database is created. Most tests run inside an outer transaction rolled
back at teardown, so they never leave data behind; the concurrency tests
in tests/test_state_repository.py are a deliberate, documented exception,
since they must exercise real, independently-committed transactions.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from zacai.db import get_engine


@pytest.fixture(scope="session")
def _require_state_schema() -> None:
    inspector = inspect(get_engine())
    if "person" not in inspector.get_table_names():
        pytest.fail(
            "zacai_dev is missing the D026 state schema - run 'alembic upgrade head' first",
            pytrace=False,
        )


@pytest.fixture
def db_session(_require_state_schema: None) -> Iterator[Session]:
    """A Session bound to its own connection, joined to an outer
    transaction via a SAVEPOINT, rolled back at teardown so tests never
    leave data behind in zacai_dev.

    Uses SQLAlchemy's standard "join a Session into an external
    transaction" recipe: an expected failure inside a test (e.g.
    `pytest.raises` around a constraint violation) ends the Session's own
    transaction, which would otherwise also end the outer DBAPI
    transaction this fixture relies on for rollback-based isolation. The
    `after_transaction_end` listener below re-opens a fresh SAVEPOINT
    whenever that happens, so the test can keep using `db_session`
    afterward, and the fixture's own teardown still rolls everything back.
    """
    connection = get_engine().connect()
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
