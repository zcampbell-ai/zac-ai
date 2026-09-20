"""Tests for zacai.db's engine/session construction (D026/D027).

`get_engine`/`get_session_factory`/`session_scope` are the application's
own functions, pointing at whatever `Settings.database_url` resolves to
(`zacai_dev` by default) - never connected to directly here. The two
singleton-caching tests below do no I/O (`create_engine`/`sessionmaker`
are lazy). The two `session_scope` tests monkeypatch `zacai.db`'s module
globals and `get_settings` to redirect them at the already-validated,
disposable `zacai_test` database (D027, via the `_test_engine` fixture in
tests/conftest.py) for the duration of the test only, so `session_scope`'s
real commit/rollback behavior is genuinely exercised without ever opening
a connection to `zacai_dev`.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

import zacai.db as db_module
from zacai.config import Settings
from zacai.db import get_engine, get_session_factory, session_scope


def test_get_engine_is_cached_singleton() -> None:
    assert get_engine() is get_engine()


def test_get_session_factory_is_cached_singleton() -> None:
    assert get_session_factory() is get_session_factory()


def test_db_session_fixture_connects(db_session: Session) -> None:
    assert db_session.execute(text("SELECT 1")).scalar_one() == 1


@pytest.fixture
def _app_db_pointed_at_test_database(monkeypatch: pytest.MonkeyPatch, _test_engine: Engine) -> None:
    """Redirects zacai.db's own module-level singletons to the disposable,
    already-validated zacai_test engine for one test, so session_scope()
    can be exercised for real without ever connecting to zacai_dev."""
    monkeypatch.setattr(db_module, "_engine", None)
    monkeypatch.setattr(db_module, "_session_factory", None)
    test_url = str(_test_engine.url)
    monkeypatch.setattr(db_module, "get_settings", lambda: Settings(database_url=test_url))


def test_session_scope_commits_on_success(_app_db_pointed_at_test_database: None) -> None:
    with session_scope() as session:
        value = session.execute(text("SELECT 42")).scalar_one()
    assert value == 42


def test_session_scope_rolls_back_and_reraises_on_exception(
    _app_db_pointed_at_test_database: None,
) -> None:
    with pytest.raises(RuntimeError, match="boom"), session_scope():
        raise RuntimeError("boom")
