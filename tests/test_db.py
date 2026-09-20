"""Tests for zacai.db's engine/session construction (D026).

Uses `zacai_dev` only, no real data.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from zacai.db import get_engine, get_session_factory, session_scope


def test_get_engine_is_cached_singleton() -> None:
    assert get_engine() is get_engine()


def test_get_session_factory_is_cached_singleton() -> None:
    assert get_session_factory() is get_session_factory()


def test_get_engine_connects(db_session: Session) -> None:
    assert db_session.execute(text("SELECT 1")).scalar_one() == 1


def test_session_scope_commits_on_success() -> None:
    with session_scope() as session:
        value = session.execute(text("SELECT 42")).scalar_one()
    assert value == 42


def test_session_scope_rolls_back_and_reraises_on_exception() -> None:
    with pytest.raises(RuntimeError, match="boom"), session_scope():
        raise RuntimeError("boom")
