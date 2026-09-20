"""Tests for the D027 test-database safety guards in tests/conftest.py.

These test the guards themselves - pure functions, no I/O for most cases
- plus one integration test proving the real, live zacai_test connection
actually reports what the guard expects. No PostgreSQL advisory-lock
behavior is unit-tested here (the implementation is PostgreSQL's own);
that is instead verified once, manually (see DECISIONS.md D027).
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine

from tests.conftest import (
    _SAFE_TEST_DATABASE,
    assert_connected_to_safe_test_database,
    assert_safe_test_database_url,
)

_SAFE_URL = "postgresql+psycopg://127.0.0.1:5432/zacai_test"


# --- assert_safe_test_database_url: accepted shape --------------------------


def test_safe_url_accepts_the_one_permitted_target() -> None:
    assert_safe_test_database_url(_SAFE_URL)


def test_safe_url_accepts_omitted_port() -> None:
    assert_safe_test_database_url("postgresql+psycopg://127.0.0.1/zacai_test")


# --- assert_safe_test_database_url: host ------------------------------------


@pytest.mark.parametrize(
    "host",
    ["localhost", "[::1]", "192.168.1.10", "100.64.0.1", "example.com"],
)
def test_safe_url_rejects_unsafe_host(host: str) -> None:
    with pytest.raises(RuntimeError, match="host"):
        assert_safe_test_database_url(f"postgresql+psycopg://{host}:5432/zacai_test")


# --- assert_safe_test_database_url: database name ---------------------------


@pytest.mark.parametrize("database", ["zacai_dev", "postgres", "zacai", ""])
def test_safe_url_rejects_unsafe_database_name(database: str) -> None:
    with pytest.raises(RuntimeError, match="database"):
        assert_safe_test_database_url(f"postgresql+psycopg://127.0.0.1:5432/{database}")


# --- assert_safe_test_database_url: port ------------------------------------


@pytest.mark.parametrize("port", [5433, 5432 + 1, 15432, 80])
def test_safe_url_rejects_unsafe_port(port: int) -> None:
    with pytest.raises(RuntimeError, match="port"):
        assert_safe_test_database_url(f"postgresql+psycopg://127.0.0.1:{port}/zacai_test")


def test_safe_url_accepts_explicit_default_port() -> None:
    assert_safe_test_database_url("postgresql+psycopg://127.0.0.1:5432/zacai_test")


# --- assert_safe_test_database_url: password --------------------------------


def test_safe_url_rejects_embedded_password() -> None:
    with pytest.raises(RuntimeError, match="password"):
        assert_safe_test_database_url("postgresql+psycopg://user:hunter2@127.0.0.1:5432/zacai_test")


def test_safe_url_rejects_embedded_password_even_with_no_username() -> None:
    with pytest.raises(RuntimeError, match="password"):
        assert_safe_test_database_url("postgresql+psycopg://:hunter2@127.0.0.1:5432/zacai_test")


# --- assert_connected_to_safe_test_database: pure checker --------------------


def test_post_connect_check_accepts_zacai_test() -> None:
    assert_connected_to_safe_test_database("zacai_test")


@pytest.mark.parametrize("reported", ["zacai_dev", "postgres", ""])
def test_post_connect_check_rejects_anything_else(reported: str) -> None:
    with pytest.raises(RuntimeError, match="zacai_test"):
        assert_connected_to_safe_test_database(reported)


# --- integration: the real, live test engine really is zacai_test ----------


def test_real_test_engine_reports_zacai_test(_test_engine: Engine) -> None:
    with _test_engine.connect() as connection:
        reported = connection.execute(text("SELECT current_database()")).scalar_one()
    assert reported == _SAFE_TEST_DATABASE
    assert_connected_to_safe_test_database(reported)
