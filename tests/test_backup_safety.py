"""Tests for the D028 restore-target safety guards in zacai.backup_safety.

Pure functions, no I/O, no PostgreSQL connection required.
"""

from __future__ import annotations

import pytest

from zacai.backup_safety import (
    assert_connected_to_safe_admin_database,
    assert_connected_to_safe_restore_database,
    assert_safe_admin_url,
    assert_safe_restore_target_url,
)

_SAFE_URL = "postgresql+psycopg://127.0.0.1:5432/zacai_restore_test"
_SAFE_ADMIN_URL = "postgresql+psycopg://127.0.0.1:5432/postgres"


# --- assert_safe_restore_target_url: accepted shape -------------------------


def test_safe_restore_url_accepts_the_one_permitted_target() -> None:
    assert_safe_restore_target_url(_SAFE_URL)


def test_safe_restore_url_accepts_omitted_port() -> None:
    assert_safe_restore_target_url("postgresql+psycopg://127.0.0.1/zacai_restore_test")


# --- assert_safe_restore_target_url: host -----------------------------------


@pytest.mark.parametrize(
    "host",
    ["localhost", "[::1]", "192.168.1.10", "100.64.0.1", "example.com"],
)
def test_safe_restore_url_rejects_unsafe_host(host: str) -> None:
    with pytest.raises(RuntimeError, match="host"):
        assert_safe_restore_target_url(f"postgresql+psycopg://{host}:5432/zacai_restore_test")


# --- assert_safe_restore_target_url: database name --------------------------


@pytest.mark.parametrize("database", ["zacai_dev", "zacai_test", "postgres", ""])
def test_safe_restore_url_rejects_unsafe_database_name(database: str) -> None:
    with pytest.raises(RuntimeError, match="database"):
        assert_safe_restore_target_url(f"postgresql+psycopg://127.0.0.1:5432/{database}")


# --- assert_safe_restore_target_url: port -----------------------------------


@pytest.mark.parametrize("port", [5433, 15432, 80])
def test_safe_restore_url_rejects_unsafe_port(port: int) -> None:
    with pytest.raises(RuntimeError, match="port"):
        assert_safe_restore_target_url(f"postgresql+psycopg://127.0.0.1:{port}/zacai_restore_test")


def test_safe_restore_url_accepts_explicit_default_port() -> None:
    assert_safe_restore_target_url("postgresql+psycopg://127.0.0.1:5432/zacai_restore_test")


# --- assert_safe_restore_target_url: password -------------------------------


def test_safe_restore_url_rejects_embedded_password() -> None:
    with pytest.raises(RuntimeError, match="password"):
        assert_safe_restore_target_url(
            "postgresql+psycopg://user:hunter2@127.0.0.1:5432/zacai_restore_test"
        )


# --- assert_connected_to_safe_restore_database: pure checker ----------------


def test_post_connect_restore_check_accepts_zacai_restore_test() -> None:
    assert_connected_to_safe_restore_database("zacai_restore_test")


@pytest.mark.parametrize("reported", ["zacai_dev", "zacai_test", "postgres", ""])
def test_post_connect_restore_check_rejects_anything_else(reported: str) -> None:
    with pytest.raises(RuntimeError, match="zacai_restore_test"):
        assert_connected_to_safe_restore_database(reported)


# --- assert_safe_admin_url -----------------------------------------------


def test_safe_admin_url_accepts_the_one_permitted_target() -> None:
    assert_safe_admin_url(_SAFE_ADMIN_URL)


@pytest.mark.parametrize(
    "database", ["zacai_dev", "zacai_test", "zacai_restore_test", "template1"]
)
def test_safe_admin_url_rejects_unsafe_database_name(database: str) -> None:
    with pytest.raises(RuntimeError, match="database"):
        assert_safe_admin_url(f"postgresql+psycopg://127.0.0.1:5432/{database}")


@pytest.mark.parametrize("host", ["localhost", "[::1]", "192.168.1.10"])
def test_safe_admin_url_rejects_unsafe_host(host: str) -> None:
    with pytest.raises(RuntimeError, match="host"):
        assert_safe_admin_url(f"postgresql+psycopg://{host}:5432/postgres")


def test_safe_admin_url_rejects_embedded_password() -> None:
    with pytest.raises(RuntimeError, match="password"):
        assert_safe_admin_url("postgresql+psycopg://user:hunter2@127.0.0.1:5432/postgres")


def test_post_connect_admin_check_accepts_postgres() -> None:
    assert_connected_to_safe_admin_database("postgres")


@pytest.mark.parametrize("reported", ["zacai_dev", "zacai_restore_test", ""])
def test_post_connect_admin_check_rejects_anything_else(reported: str) -> None:
    with pytest.raises(RuntimeError, match="postgres"):
        assert_connected_to_safe_admin_database(reported)
