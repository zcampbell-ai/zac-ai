"""D028 Zac State Lane B backup/restore pipeline.

Streams a trust boundary's business state in its schema's fixed FK-safe inventory,
from one read-only snapshot, directly through an encryption subprocess
into the durable artifact - no persistent plaintext export ever touches
disk in the normal path. Restore reverses this exactly: a decrypt
subprocess's output is streamed straight into `COPY ... FROM STDIN`, in
the same order, for a disposable restore-drill database only.

See DECISIONS.md D028 for the full architecture review. `age` is the
encryption tool this module shells out to, but nothing here is coupled to
`age` specifically beyond invoking whatever command a caller supplies -
tests exercise the framing/streaming logic with a no-op passthrough
command, independent of whether `age` is installed.

This module never restores or modifies `zacai_dev`: `export_boundary_stream` accepts
any source URL a caller supplies (typically `zacai_test` for a drill, or
a future, separately-approved run against `zacai_dev`), but all
*destructive* operations (`recreate_restore_test_database`,
`drop_restore_test_database`) are hardcoded to the single fixed constant
`zacai_restore_test` - there is no parameter through which a caller could
redirect them to a different database.
"""

from __future__ import annotations

import contextlib
import csv
import io
import os
import re
import subprocess
from collections.abc import Callable, Iterator, Sequence
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

# Fixed FK-safe order: every reference in this schema (D026/D029/D030)
# points only earlier in this list, so a single top-to-bottom pass
# satisfies every foreign key without deferring constraints - with
# exactly two exceptions, both self-references within their own table,
# which cannot be solved by ordering alone (two rows can reference each
# other regardless of which is written first):
#   - decision.supersedes_decision_id (D029)
#   - source.supersedes_source_id (D030 Source lineage)
# Both FKs are declared DEFERRABLE INITIALLY DEFERRED in the schema, so
# PostgreSQL checks them only at the final COMMIT of a boundary's
# restore - restore_boundary_stream already runs one boundary's entire
# table set inside a single transaction, so this composes with no
# pipeline code change. `decision`'s and `source`'s own row order below
# therefore only needs to be deterministic for human-readability, not
# for FK correctness.
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
    "ingestion_cursor",
    "ingestion_run",
    "extraction_record",
    "extraction_candidate",
    "extraction_candidate_review",
    "source_classification_elevation",
    "unresolved_identity",
    "meeting_project_association",
    "meeting_project_association_retraction",
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
    "ingestion_cursor": "id",
    "ingestion_run": "id",
    "extraction_record": "id",
    "extraction_candidate": "id",
    "extraction_candidate_review": "id",
    "source_classification_elevation": "id",
    "unresolved_identity": "id",
    "meeting_project_association": "id",
    "meeting_project_association_retraction": "id",
}

# Historical inventories are fixed allowlists, never stream-supplied SQL names.
_SCHEMA_TABLES: dict[str, tuple[str, ...]] = {
    "0001": (
        "source",
        "person_head",
        "commitment_head",
        "person",
        "commitment",
        "person_evidence",
        "commitment_evidence",
    ),
    "0002": TABLE_ORDER[:21],
    "0003": TABLE_ORDER[:-2],
    "0004": TABLE_ORDER[:-2],
    "0005": TABLE_ORDER,
}
_BACKUP_MAGIC = "zacai-state-backup-v2"
_MAX_FRAME_BYTES = 256 * 1024 * 1024


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
            if len(buf) + len(data) > _MAX_FRAME_BYTES:
                raise RuntimeError("backup table outside supported size")
            buf.extend(data)
    return bytes(buf)


def _csv_columns(table: str, data: bytes) -> list[str]:
    # Historical schemas added nullable Source/Commitment columns. Use validated
    # CSV column names rather than COPY's positional current-schema assumption.
    from zacai.state import Base

    columns = next(csv.reader(io.StringIO(data.decode("utf-8"))), [])
    current = set(Base.metadata.tables[table].columns.keys())
    allowed = [current]
    if table == "source":
        allowed.append(current - {"content_hash", "content_location", "supersedes_source_id"})
    elif table == "commitment":
        allowed.append(current - {"project_id"})
    if not columns or len(set(columns)) != len(columns) or set(columns) not in allowed:
        raise RuntimeError("backup CSV columns do not match supported schema")
    return columns


def _restore_table_csv(raw_conn: Any, table: str, data: bytes) -> None:
    names = ", ".join(f'"{name}"' for name in _csv_columns(table, data))
    query = f"COPY {table} ({names}) FROM STDIN WITH (FORMAT csv, HEADER true)"
    with raw_conn.cursor() as cur, cur.copy(query) as copy:
        copy.write(data)


def _verify_table_csv(raw_conn: Any, table: str, data: bytes) -> None:
    # Select original validated columns: legacy nullable additions do not change
    # the exported snapshot. Compare every row/field, not counts or selected IDs.
    names = ", ".join(f'"{name}"' for name in _csv_columns(table, data))
    query = f"COPY (SELECT {names} FROM {table} ORDER BY {_ORDER_BY[table]}) TO STDOUT WITH (FORMAT csv, HEADER true)"
    offset = 0
    with raw_conn.cursor() as cur, cur.copy(query) as copy:
        for chunk in copy:
            value = bytes(chunk)
            if data[offset : offset + len(value)] != value:
                raise RuntimeError("restored state differs from backup")
            offset += len(value)
    if offset != len(data):
        raise RuntimeError("restored state differs from backup")


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
        if len(chars) >= 256:
            raise RuntimeError("backup frame header outside supported size")
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
    """Versioned per-boundary stream from one fresh read-only snapshot.

    Select the fixed inventory for the actual schema; never query 0005-only
    tables on 0004. Unknown revisions fail rather than omit future state.
    Operational artifact_backup_run history is deliberately excluded as before.
    """
    if not isinstance(boundary, TrustBoundary):
        raise TypeError("backup requires a trust boundary")
    with engine.connect() as conn:
        if conn.dialect.name != "postgresql":
            raise RuntimeError("PostgreSQL backup connection required")
        conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        revisions = conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        if len(revisions) != 1 or revisions[0] not in _SCHEMA_TABLES:
            raise RuntimeError("unsupported state backup schema")
        revision = revisions[0]
        out_stream.write(f"{_BACKUP_MAGIC}\n{revision}\n{boundary.value}\n".encode("ascii"))
        raw = _raw_connection(conn)
        for table in _SCHEMA_TABLES[revision]:
            data = _export_table_csv(raw, table, boundary.value)
            _write_frame(out_stream, table, data)


def _optional_line(stream: IO[bytes]) -> str | None:
    first = stream.read(1)
    return None if not first else first.decode("ascii") + _read_line(stream)


def _restore_frames(
    raw: Any, stream: IO[bytes], *, verify_only: bool = False, expected_boundary: str | None = None
) -> None:
    first: str | None = _read_line(stream)
    inventories: tuple[tuple[str, ...], ...]
    if first == _BACKUP_MAGIC:
        revision = _read_line(stream)
        if revision not in _SCHEMA_TABLES:
            raise RuntimeError("unsupported state backup schema")
        boundary: str | None = TrustBoundary(_read_line(stream)).value
        inventories = (_SCHEMA_TABLES[revision],)
        first = _optional_line(stream)
    else:
        boundary = None
        # D028/D029/D030 legacy streams have no manifest. Accept only complete
        # exact historical inventories. No arbitrary extra/missing table names.
        inventories = tuple(dict.fromkeys(_SCHEMA_TABLES[r] for r in ("0001", "0002", "0003")))
    seen: tuple[str, ...] = ()
    table = first
    while table is not None:
        seen += (table,)
        if not any(order[: len(seen)] == seen for order in inventories):
            raise RuntimeError("backup frame order mismatch")
        value = _read_line(stream)
        if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > _MAX_FRAME_BYTES:
            raise RuntimeError("backup frame length outside supported size")
        data = _read_exact(stream, int(value))
        if verify_only:
            _verify_table_csv(raw, table, data)
        else:
            _restore_table_csv(raw, table, data)
        # Ask PostgreSQL to validate parsed boundary values, avoiding Python CSV
        # field-size limits on old large excerpts. The disposable restore target
        # must hold one boundary; mixed existing state also fails closed.
        with raw.cursor() as cur:
            cur.execute(f"SELECT DISTINCT trust_boundary FROM {table}")
            labels = {row[0] for row in cur.fetchall()}
        if (
            len(labels) > 1
            or boundary is not None
            and labels - {boundary}
            or expected_boundary is not None
            and labels - {expected_boundary}
        ):
            raise RuntimeError("backup restore boundary mismatch")
        if boundary is None and labels:
            boundary = TrustBoundary(next(iter(labels))).value
        table = _optional_line(stream)
    if seen not in inventories:
        raise RuntimeError("incomplete backup table inventory")
    if expected_boundary is not None and boundary not in (None, expected_boundary):
        raise RuntimeError("backup restore boundary mismatch")
    if verify_only:
        for extra in set(TABLE_ORDER) - set(seen):
            with raw.cursor() as cur:
                cur.execute(f"SELECT EXISTS (SELECT 1 FROM {extra})")
                if cur.fetchone()[0]:
                    raise RuntimeError("restored state contains additional rows")
    # Versioned streams remove legacy EOF ambiguity between historical inventories.
    # Encryption authenticates legacy stream completeness; CSV isn't an authority.


def restore_boundary_stream(
    engine: Engine,
    in_stream: IO[bytes],
    *,
    before_commit: Callable[[], None] | None = None,
) -> None:
    """Restore complete known inventory atomically, including legacy CSV columns.

    The wrapper uses before_commit to verify decryption success after stream EOF
    and before DB commit. No plaintext file or partial table commit is created.
    """
    with engine.connect() as conn:
        raw = _raw_connection(conn)
        try:
            _restore_frames(raw, in_stream)
            if before_commit is not None:
                before_commit()
            raw.commit()
        except BaseException:
            raw.rollback()
            raise


def verify_restored_boundary_stream(
    engine: Engine, in_stream: IO[bytes], *, boundary: TrustBoundary
) -> None:
    """Read-only full row/field verification on the guarded disposable target.

    Reuses the restore parser and original columns/order, including legacy
    inventories. No count-only shortcut; additional rows/tables also reject.
    This verifies DB contents, not encryption, escrow or off-device provenance.
    """
    assert_safe_restore_target_url(engine.url.render_as_string(hide_password=False))
    with engine.connect() as conn:
        conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        reported = conn.execute(text("SELECT current_database()")).scalar_one()
        assert_connected_to_safe_restore_database(reported)
        _restore_frames(
            _raw_connection(conn), in_stream, verify_only=True, expected_boundary=boundary.value
        )


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

        def verify_decryption() -> None:
            if proc.wait() != 0:
                raise RuntimeError("restore decryption command failed before commit")

        try:
            restore_boundary_stream(engine, proc.stdout, before_commit=verify_decryption)
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

    parser = argparse.ArgumentParser(
        prog="zacai-backup", description="Zac State Lane B backup/restore (D028)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    export_parser = sub.add_parser(
        "export", help="Export one trust boundary to an age-encrypted artifact"
    )
    export_parser.add_argument(
        "--source-url", required=True, help="e.g. Settings.database_url for zacai_dev"
    )
    export_parser.add_argument(
        "--boundary", required=True, choices=[b.value for b in TrustBoundary]
    )
    export_parser.add_argument("--output", required=True, type=Path)
    export_parser.add_argument(
        "--recipient", required=True, help="age public recipient key for this boundary"
    )

    drill_parser = sub.add_parser(
        "drill", help="Recreate zacai_restore_test and restore one decrypted artifact into it"
    )
    drill_parser.add_argument("--artifact", required=True, type=Path)
    drill_parser.add_argument(
        "--identity", required=True, type=Path, help="age private identity file"
    )

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
