"""D028 Zac State Lane B backup/restore pipeline.

Streams a trust boundary's data across all `zacai.state` tables in `TABLE_ORDER`,
in one fixed FK-safe order, directly through an encryption subprocess
into the durable artifact - no persistent plaintext export ever touches
disk in the normal path. Restore reverses this exactly: a decrypt
subprocess's output is streamed straight into `COPY ... FROM STDIN`, in
the same order, for a disposable restore-drill database only.

See DECISIONS.md D028 for the full architecture review. `age` is the
encryption tool this module shells out to, but nothing here is coupled to
`age` specifically beyond invoking whatever command a caller supplies -
tests exercise the framing/streaming logic with a no-op passthrough
command, independent of whether `age` is installed.

This module never touches `zacai_dev`: `export_boundary_stream` accepts
any source URL a caller supplies (typically `zacai_test` for a drill, or
a future, separately-approved run against `zacai_dev`), but all
*destructive* operations (`recreate_restore_test_database`,
`drop_restore_test_database`) are hardcoded to the single fixed constant
`zacai_restore_test` - there is no parameter through which a caller could
redirect them to a different database.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import IO, Any, BinaryIO

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

from zacai.backup_safety import (
    assert_connected_to_safe_admin_database,
    assert_connected_to_safe_restore_database,
    assert_safe_admin_url,
    assert_safe_restore_target_url,
)
from zacai.policy import TrustBoundary

# Fixed FK-safe order: every reference in this schema (D026/D029) points
# only earlier in this list, so a single top-to-bottom pass satisfies
# every foreign key without deferring constraints - with exactly one
# exception: decision.supersedes_decision_id, a self-reference within the
# `decision` table itself, which cannot be solved by ordering alone (two
# decision rows can reference each other regardless of which is written
# first). That FK is declared DEFERRABLE INITIALLY DEFERRED in the schema
# (D029), so PostgreSQL checks it only at the final COMMIT of a boundary's
# restore - restore_boundary_stream already runs one boundary's entire
# table set inside a single transaction, so this composes with no pipeline
# code change. `decision`'s own row order below therefore only needs to
# be deterministic for human-readability, not for FK correctness.
TABLE_ORDER: tuple[str, ...] = (
    "source",
    "company_head",
    "project_head",
    "person_head",
    "commitment_head",
    "company",
    "project",
    "person",
    "person_company_relationship",
    "meeting",
    "commitment",
    "decision",
    "meeting_attendee",
    "meeting_source",
    "person_evidence",
    "commitment_evidence",
    "company_evidence",
    "project_evidence",
    "decision_evidence",
    "decision_retraction",
    "meeting_retraction",
)

_ORDER_BY: dict[str, str] = {
    "source": "id",
    "company_head": "entity_id",
    "project_head": "entity_id",
    "person_head": "entity_id",
    "commitment_head": "entity_id",
    "company": "entity_id, version",
    "project": "entity_id, version",
    "person": "entity_id, version",
    "person_company_relationship": "id",
    "meeting": "id",
    "commitment": "entity_id, version",
    "decision": "id",
    "meeting_attendee": "id",
    "meeting_source": "id",
    "person_evidence": "id",
    "commitment_evidence": "id",
    "company_evidence": "id",
    "project_evidence": "id",
    "decision_evidence": "id",
    "decision_retraction": "id",
    "meeting_retraction": "id",
}

# Fixed constants for the one destructive restore target this module is
# ever permitted to touch. Never accepted as a function parameter.
RESTORE_TEST_DATABASE = "zacai_restore_test"
_ADMIN_URL = "postgresql+psycopg://127.0.0.1:5432/postgres"
RESTORE_TEST_URL = f"postgresql+psycopg://127.0.0.1:5432/{RESTORE_TEST_DATABASE}"


def _raw_connection(conn: Connection) -> Any:
    """The underlying psycopg3 connection, for its streaming COPY API -
    SQLAlchemy's own Core/ORM layer has no equivalent streaming COPY."""
    return conn.connection.dbapi_connection


def _export_table_csv(raw_conn: Any, table: str, boundary_value: str) -> bytes:
    """`table` only ever comes from the fixed `TABLE_ORDER` tuple above,
    never external input, so f-string interpolation of it is safe; the
    boundary value is passed as a real bound parameter."""
    query = (
        f"COPY (SELECT * FROM {table} WHERE trust_boundary = %s "
        f"ORDER BY {_ORDER_BY[table]}) TO STDOUT WITH (FORMAT csv, HEADER true)"
    )
    buf = bytearray()
    with raw_conn.cursor() as cur, cur.copy(query, (boundary_value,)) as copy:
        for data in copy:
            buf.extend(data)
    return bytes(buf)


def _restore_table_csv(raw_conn: Any, table: str, data: bytes) -> None:
    query = f"COPY {table} FROM STDIN WITH (FORMAT csv, HEADER true)"
    with raw_conn.cursor() as cur, cur.copy(query) as copy:
        copy.write(data)


def _write_frame(stream: IO[bytes], table: str, data: bytes) -> None:
    """One table's export: `<table>\\n<byte length>\\n<raw bytes>`."""
    stream.write(f"{table}\n{len(data)}\n".encode("ascii"))
    stream.write(data)


def _read_line(stream: IO[bytes]) -> str:
    chars = bytearray()
    while True:
        byte = stream.read(1)
        if not byte:
            raise RuntimeError("unexpected end of stream while reading a backup frame header")
        if byte == b"\n":
            return chars.decode("ascii")
        chars.extend(byte)


def _read_exact(stream: IO[bytes], count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            raise RuntimeError("unexpected end of stream while reading a backup frame body")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def export_boundary_stream(engine: Engine, boundary: TrustBoundary, out_stream: IO[bytes]) -> None:
    """Writes every row belonging to `boundary`, across all tables
    in `TABLE_ORDER`, as a sequence of length-prefixed frames into
    `out_stream`. Read-only against `engine` - never writes anything."""
    with engine.connect() as conn:
        raw = _raw_connection(conn)
        for table in TABLE_ORDER:
            data = _export_table_csv(raw, table, boundary.value)
            _write_frame(out_stream, table, data)


def restore_boundary_stream(engine: Engine, in_stream: IO[bytes]) -> None:
    """Reads frames from `in_stream` in the exact `TABLE_ORDER` sequence
    and restores each via `COPY ... FROM STDIN`. Raises if the frame
    order doesn't match `TABLE_ORDER` exactly, rather than silently
    restoring tables in the wrong (FK-unsafe) order."""
    with engine.connect() as conn:
        raw = _raw_connection(conn)
        for expected_table in TABLE_ORDER:
            table = _read_line(in_stream)
            if table != expected_table:
                raise RuntimeError(
                    f"backup frame order mismatch: expected {expected_table!r}, got {table!r}"
                )
            length = int(_read_line(in_stream))
            data = _read_exact(in_stream, length)
            _restore_table_csv(raw, table, data)
        # The COPY writes above ran on the raw psycopg3 connection/cursor
        # directly, bypassing SQLAlchemy's own transaction bookkeeping -
        # SQLAlchemy's Connection.commit() only commits a transaction it
        # believes it started, so it would be a silent no-op here (and
        # the rows would be rolled back when the connection is returned
        # to the pool). Committing the raw DBAPI connection directly is
        # what actually makes the COPYs durable.
        raw.commit()


def export_boundary(
    source_url: str,
    boundary: TrustBoundary,
    output_path: Path,
    encrypt_command: Sequence[str],
) -> None:
    """Streams `boundary`'s data through `encrypt_command` (its stdin is
    the plaintext frame stream, its stdout is the durable artifact)
    directly into `output_path`. No plaintext file is ever written -
    `output_path` is created with mode 0600 atomically (`O_CREAT |
    O_EXCL`, not a permissions fix applied after the fact), and is
    removed if anything fails partway through.
    """
    engine = create_engine(source_url, future=True)
    try:
        fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as out_file:
                _run_export_through_subprocess(engine, boundary, encrypt_command, out_file)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                output_path.unlink()
            raise
    finally:
        engine.dispose()


def _run_export_through_subprocess(
    engine: Engine, boundary: TrustBoundary, command: Sequence[str], out_file: BinaryIO
) -> None:
    proc = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=out_file)
    assert proc.stdin is not None
    try:
        export_boundary_stream(engine, boundary, proc.stdin)
    except BrokenPipeError:
        # The encryption command has already exited (e.g. it failed
        # immediately) and closed its end of the pipe - proc.wait() below
        # recovers its real exit code for a clear error, rather than
        # letting a raw BrokenPipeError surface as the failure reason.
        pass
    finally:
        with contextlib.suppress(OSError):
            proc.stdin.close()
    returncode = proc.wait()
    if returncode != 0:
        raise RuntimeError(f"export encryption command exited with status {returncode}")


def restore_boundary(
    artifact_path: Path,
    target_url: str,
    decrypt_command_prefix: Sequence[str],
) -> None:
    """Decrypts `artifact_path` via `[*decrypt_command_prefix,
    str(artifact_path)]` and restores it into `target_url`, which must be
    exactly `zacai_restore_test` - validated pre-connect and post-connect
    before any restore statement runs."""
    assert_safe_restore_target_url(target_url)
    engine = create_engine(target_url, future=True)
    try:
        with engine.connect() as verify_conn:
            reported = verify_conn.execute(text("SELECT current_database()")).scalar_one()
        assert_connected_to_safe_restore_database(reported)

        command = [*decrypt_command_prefix, str(artifact_path)]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE)
        assert proc.stdout is not None
        try:
            restore_boundary_stream(engine, proc.stdout)
        finally:
            proc.stdout.close()
            returncode = proc.wait()
        if returncode != 0:
            raise RuntimeError(f"restore decryption command exited with status {returncode}")
    finally:
        engine.dispose()


@contextlib.contextmanager
def _admin_connection() -> Iterator[Connection]:
    assert_safe_admin_url(_ADMIN_URL)
    engine = create_engine(_ADMIN_URL, future=True, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            reported = conn.execute(text("SELECT current_database()")).scalar_one()
            assert_connected_to_safe_admin_database(reported)
            yield conn
    finally:
        engine.dispose()


def drop_restore_test_database() -> None:
    """Drops exactly `zacai_restore_test`, via the fixed administrative
    connection. `RESTORE_TEST_DATABASE` is a module constant - this
    function takes no database-name parameter, so there is no way to
    call it against a different database."""
    with _admin_connection() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {RESTORE_TEST_DATABASE}"))


def recreate_restore_test_database() -> None:
    """Drops (if present) and recreates exactly `zacai_restore_test`."""
    with _admin_connection() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {RESTORE_TEST_DATABASE}"))
        conn.execute(text(f"CREATE DATABASE {RESTORE_TEST_DATABASE}"))


def upgrade_restore_test_schema() -> None:
    """Runs the exact same Alembic migration used for `zacai_dev`/
    `zacai_test` against `zacai_restore_test` - no hand-built schema."""
    from alembic import command
    from alembic.config import Config

    assert_safe_restore_target_url(RESTORE_TEST_URL)
    engine = create_engine(RESTORE_TEST_URL, future=True)
    try:
        with engine.connect() as conn:
            reported = conn.execute(text("SELECT current_database()")).scalar_one()
        assert_connected_to_safe_restore_database(reported)
    finally:
        engine.dispose()

    alembic_ini = Path(__file__).resolve().parent.parent.parent / "alembic.ini"
    config = Config(str(alembic_ini))
    config.set_main_option("sqlalchemy.url", RESTORE_TEST_URL)
    command.upgrade(config, "head")


def main() -> None:
    """`uv run zacai-backup export|drill ...` - a thin CLI wrapper. All
    the safety/streaming logic lives in the functions above; this only
    parses arguments and calls them."""
    import argparse

    parser = argparse.ArgumentParser(prog="zacai-backup", description="Zac State Lane B backup/restore (D028)")
    sub = parser.add_subparsers(dest="command", required=True)

    export_parser = sub.add_parser("export", help="Export one trust boundary to an age-encrypted artifact")
    export_parser.add_argument("--source-url", required=True, help="e.g. Settings.database_url for zacai_dev")
    export_parser.add_argument("--boundary", required=True, choices=[b.value for b in TrustBoundary])
    export_parser.add_argument("--output", required=True, type=Path)
    export_parser.add_argument("--recipient", required=True, help="age public recipient key for this boundary")

    drill_parser = sub.add_parser(
        "drill", help="Recreate zacai_restore_test and restore one decrypted artifact into it"
    )
    drill_parser.add_argument("--artifact", required=True, type=Path)
    drill_parser.add_argument("--identity", required=True, type=Path, help="age private identity file")

    args = parser.parse_args()

    if args.command == "export":
        export_boundary(
            args.source_url,
            TrustBoundary(args.boundary),
            args.output,
            ["age", "-r", args.recipient],
        )
    elif args.command == "drill":
        recreate_restore_test_database()
        upgrade_restore_test_schema()
        restore_boundary(args.artifact, RESTORE_TEST_URL, ["age", "-d", "-i", str(args.identity)])


if __name__ == "__main__":
    main()
