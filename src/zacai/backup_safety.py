"""Fail-closed target validation for D028 Zac State backup/restore
tooling.

Mirrors D027's `assert_safe_test_database_url` in shape (tests/conftest.py)
but is hardcoded to the one disposable restore-drill database this module
is ever permitted to touch destructively: `zacai_restore_test`. Never
`zacai_dev`, never `zacai_test` (D027's own, differently-purposed disposable
database). See DECISIONS.md D028.

Two independent layers, exactly like D027:
- `assert_safe_restore_target_url` validates the connection string before
  any connection is opened.
- `assert_connected_to_safe_restore_database` re-verifies via a live
  `SELECT current_database()` immediately after connecting.

A third fixed-database administrative connection (to PostgreSQL's own
always-present `postgres` maintenance database, required because
PostgreSQL cannot drop a database while connected to it) is validated by
`assert_safe_admin_url` - a narrower check that only confirms host/port/
password safety, since that connection's database name is intentionally
`postgres`, not `zacai_restore_test`.
"""

from __future__ import annotations

from sqlalchemy.engine.url import make_url

_SAFE_RESTORE_HOST = "127.0.0.1"
_SAFE_RESTORE_DATABASE = "zacai_restore_test"
_SAFE_RESTORE_PORT = 5432
_SAFE_ADMIN_DATABASE = "postgres"


def assert_safe_restore_target_url(url: str) -> None:
    """Fail closed unless `url` is exactly the one permitted restore
    target. Checked field-by-field, each with a specific error, so a
    misconfiguration is immediately diagnosable (D027/D028 pattern)."""
    parsed = make_url(url)
    if parsed.host != _SAFE_RESTORE_HOST:
        raise RuntimeError(
            f"refusing to run restore operations: host {parsed.host!r} is not "
            f"{_SAFE_RESTORE_HOST!r} (D028)"
        )
    if parsed.database != _SAFE_RESTORE_DATABASE:
        raise RuntimeError(
            f"refusing to run restore operations: database {parsed.database!r} is not "
            f"{_SAFE_RESTORE_DATABASE!r} (D028) - zacai_dev and zacai_test must never "
            "be used as a restore target"
        )
    if parsed.port is not None and parsed.port != _SAFE_RESTORE_PORT:
        raise RuntimeError(
            f"refusing to run restore operations: port {parsed.port!r} is not "
            f"None (default) or {_SAFE_RESTORE_PORT!r} (D028)"
        )
    if parsed.password:
        raise RuntimeError(
            "refusing to run restore operations: the restore target URL must not "
            "contain a password (D028)"
        )


def assert_connected_to_safe_restore_database(reported_database: str) -> None:
    """Pure check, no I/O - defense in depth after a live
    `SELECT current_database()`, independent of the pre-connect URL check."""
    if reported_database != _SAFE_RESTORE_DATABASE:
        raise RuntimeError(
            f"connected database reports {reported_database!r}, not "
            f"{_SAFE_RESTORE_DATABASE!r} - refusing to proceed (D028)"
        )


def assert_safe_admin_url(url: str) -> None:
    """Validates the fixed administrative connection used only to drop/
    create `zacai_restore_test` (PostgreSQL forbids dropping a database
    while connected to it). This connection's database is intentionally
    `postgres`, not `zacai_restore_test` - `assert_safe_restore_target_url`
    does not apply to it."""
    parsed = make_url(url)
    if parsed.host != _SAFE_RESTORE_HOST:
        raise RuntimeError(
            f"refusing to run an administrative database operation: host "
            f"{parsed.host!r} is not {_SAFE_RESTORE_HOST!r} (D028)"
        )
    if parsed.database != _SAFE_ADMIN_DATABASE:
        raise RuntimeError(
            f"refusing to run an administrative database operation: database "
            f"{parsed.database!r} is not {_SAFE_ADMIN_DATABASE!r} (D028)"
        )
    if parsed.port is not None and parsed.port != _SAFE_RESTORE_PORT:
        raise RuntimeError(
            f"refusing to run an administrative database operation: port "
            f"{parsed.port!r} is not None (default) or {_SAFE_RESTORE_PORT!r} (D028)"
        )
    if parsed.password:
        raise RuntimeError(
            "refusing to run an administrative database operation: the admin "
            "URL must not contain a password (D028)"
        )


def assert_connected_to_safe_admin_database(reported_database: str) -> None:
    if reported_database != _SAFE_ADMIN_DATABASE:
        raise RuntimeError(
            f"connected database reports {reported_database!r}, not "
            f"{_SAFE_ADMIN_DATABASE!r} - refusing to proceed (D028)"
        )
