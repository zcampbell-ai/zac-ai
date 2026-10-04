"""Explicit protected 0004 -> 0005 operator rollout, no enabled command/issuer.

All live use requires fresh human scope supplied outside agents. Remote recovery
is completed without live write locks. A short final locked transaction rechecks
the exact protected state and journal before additive DDL and commits only after
validation. Exceptions never trigger an automatic downgrade or second attempt.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

from zacai import backup
from zacai.backup_artifacts import BackupObjectStore, age_decrypt, age_encrypt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import TrustBoundary as B
from zacai.review_protection import BoundedStateBuffer, DisposableStateRestoreVerifier

_ROOT = Path(__file__).resolve().parents[2]
_MIGRATION = "alembic/versions/0005_meeting_project_association.py"
_ROLLOUT_LOCK = 73403415
_JOURNAL_LIMIT = 4_000_000


class SchemaRolloutError(RuntimeError):
    """Fixed diagnostics; an ambiguous commit requires operator investigation."""


class SchemaRolloutApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    target_database: Literal["zacai_dev", "zacai_test"]
    code_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    migration_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    human_reference: str = Field(min_length=1, max_length=500)
    approved_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def bounded(self) -> SchemaRolloutApproval:
        if not self.human_reference.strip() or not (
            timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=15)
        ):
            raise ValueError("invalid bounded operator approval")
        return self


def _target(engine: Engine, database: str) -> None:
    url = engine.url
    if (
        url.drivername != "postgresql+psycopg"
        or url.host != "127.0.0.1"
        or url.port != 5432
        or url.database != database
        or url.password
        or url.query
    ):
        raise ValueError("rollout target differs from approved local database")


def _connected(conn: Connection, database: str) -> None:
    actual = conn.execute(
        text(
            "SELECT pg_catalog.current_database(), pg_catalog.inet_server_port(), pg_catalog.host(pg_catalog.inet_server_addr())"
        )
    ).one()
    if tuple(actual) != (database, 5432, "127.0.0.1"):
        raise ValueError("connected rollout target differs")
    conn.execute(text("SET LOCAL search_path=public,pg_catalog,pg_temp"))


def _authority(scope: SchemaRolloutApproval, now: datetime) -> None:
    if now.utcoffset() is None or not scope.approved_at <= now < scope.expires_at:
        raise ValueError("rollout approval inactive")
    revision = (
        subprocess.run(
            ["git", "-C", str(_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            timeout=5,
        )
        .stdout.decode()
        .strip()
    )
    if (
        revision != scope.code_revision
        or content_hash_of((_ROOT / _MIGRATION).read_bytes()) != scope.migration_hash
    ):
        raise ValueError("rollout code differs from approval")
    if scope.target_database == "zacai_dev":
        dirty = subprocess.run(
            ["git", "-C", str(_ROOT), "status", "--porcelain"],
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout
        if dirty:
            raise ValueError("live rollout requires clean reviewed checkout")


def _config(conn: Connection) -> Config:
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", conn.engine.url.render_as_string(hide_password=False))
    config.attributes["connection"] = conn
    scripts = ScriptDirectory.from_config(config)
    if scripts.get_heads() != ["0005"] or scripts.get_revision("0005").down_revision != "0004":
        raise ValueError("rollout migration chain changed")
    return config


def _inventory(conn: Connection, revision: str) -> None:
    expected = set(backup._SCHEMA_TABLES[revision]) | {"artifact_backup_run", "alembic_version"}
    if set(inspect(conn).get_table_names(schema="public")) != expected:
        raise ValueError("public table inventory differs from reviewed scope")


def _scope(conn: Connection) -> None:
    _inventory(conn, "0004")
    if conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all() != ["0004"]:
        raise ValueError("rollout requires exactly schema 0004")
    for table in (*backup._SCHEMA_TABLES["0004"], "artifact_backup_run"):
        if conn.scalar(
            text(f"SELECT EXISTS (SELECT 1 FROM {table} WHERE trust_boundary <> 'BRAINSTORM')")
        ):
            raise ValueError("another boundary requires its own recovery scope")


def _journal(conn: Connection) -> bytes:
    raw = backup._raw_connection(conn)
    query = "COPY (SELECT * FROM artifact_backup_run ORDER BY id) TO STDOUT WITH (FORMAT csv, HEADER true)"
    result = bytearray()
    with raw.cursor() as cur, cur.copy(query) as copy:
        for chunk in copy:
            if len(result) + len(chunk) > _JOURNAL_LIMIT:
                raise ValueError("rollout journal outside capacity")
            result.extend(chunk)
    return bytes(result)


def _original_rows(conn: Connection, snapshot: bytes) -> None:
    """Comparison only, never restoration into the live database."""
    stream = io.BytesIO(snapshot)
    if [backup._read_line(stream) for _ in range(3)] != [
        "zacai-state-backup-v2",
        "0004",
        B.BRAINSTORM.value,
    ]:
        raise ValueError("rollout snapshot manifest mismatch")
    raw = backup._raw_connection(conn)
    for table in backup._SCHEMA_TABLES["0004"]:
        if backup._read_line(stream) != table:
            raise ValueError("rollout snapshot inventory mismatch")
        size = int(backup._read_line(stream))
        if not 0 < size <= 64_000_000:
            raise ValueError("rollout frame outside capacity")
        backup._verify_table_csv(raw, table, backup._read_exact(stream, size))
    if stream.read(1):
        raise ValueError("extra rollout snapshot frames")


def _new_schema(conn: Connection) -> None:
    _inventory(conn, "0005")
    if conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all() != ["0005"]:
        raise ValueError("unexpected resulting rollout revision")
    inspector = inspect(conn)
    specs = {
        "meeting_project_association": {
            (("meeting_id", "trust_boundary"), "meeting", ("id", "trust_boundary")),
            (
                ("project_id", "reviewed_project_version", "trust_boundary"),
                "project",
                ("entity_id", "version", "trust_boundary"),
            ),
            (("confirmation_source_id", "trust_boundary"), "source", ("id", "trust_boundary")),
        },
        "meeting_project_association_retraction": {
            (
                ("association_id", "trust_boundary"),
                "meeting_project_association",
                ("id", "trust_boundary"),
            ),
            (("confirmation_source_id", "trust_boundary"), "source", ("id", "trust_boundary")),
        },
    }
    from zacai.state import Base

    for table, foreign_keys in specs.items():
        if conn.scalar(text(f"SELECT EXISTS (SELECT 1 FROM {table})")):
            raise ValueError("new rollout evidence is not empty")
        columns = inspector.get_columns(table)
        if {column["name"] for column in columns} != set(
            Base.metadata.tables[table].columns.keys()
        ) or any(column["nullable"] for column in columns):
            raise ValueError("new rollout columns differ")
        if inspector.get_pk_constraint(table)["constrained_columns"] != ["id"]:
            raise ValueError("new rollout primary key differs")
        actual = {
            (tuple(fk["constrained_columns"]), fk["referred_table"], tuple(fk["referred_columns"]))
            for fk in inspector.get_foreign_keys(table)
        }
        if actual != foreign_keys:
            raise ValueError("new rollout boundary foreign keys differ")
        checks = {c["name"] for c in inspector.get_check_constraints(table)}
        required = {f"{table}_trust_boundary"}
        if table == "meeting_project_association":
            required.add("meeting_project_association_data_classification")
        if not required <= checks:
            raise ValueError("new rollout label checks unavailable")
        trigger = conn.execute(
            text(
                "SELECT t.tgtype, t.tgenabled, p.proname FROM pg_trigger t "
                "JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_proc p ON p.oid=t.tgfoid "
                "WHERE n.nspname='public' AND c.relname=:table AND t.tgname=:trigger AND NOT t.tgisinternal"
            ),
            {"table": table, "trigger": f"{table}_forbid_mutation"},
        ).one()
        if tuple(trigger) != (27, "O", "zacai_forbid_mutation"):
            raise ValueError("new rollout append-only trigger differs")


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _receipt(path: Path, proof: dict[str, object]) -> None:
    data = json.dumps(proof, sort_keys=True, indent=2).encode()
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".rollout-")
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
        _fsync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def execute_protected_schema_rollout(
    engine: Engine,
    *,
    approval: SchemaRolloutApproval,
    objects: BackupObjectStore,
    verification_objects: BackupObjectStore,
    recipient: str,
    identity_path: Path,
    restoration: DisposableStateRestoreVerifier,
    receipt_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Trusted operator only after actual human approval; never called by agents.

    B2/current identity configuration and permission are supplied by the host.
    Tests use explicit zacai_test scope and local invented stores. Live checkout
    must be clean and pinned. Receipt paths must already have a private parent
    outside Git, selected by the trusted host. No Source, association or model
    draft is created here. Remote orphan objects may remain after a failed attempt.
    """
    proof: dict[str, object] = {}
    created_receipt = False
    try:
        approval = SchemaRolloutApproval.model_validate(approval)
        _target(engine, approval.target_database)
        _authority(approval, clock())
        if objects is verification_objects or not isinstance(
            restoration, DisposableStateRestoreVerifier
        ):
            raise ValueError("independent reader and actual restoration required")
        if (
            not receipt_path.is_absolute()
            or not receipt_path.parent.is_dir()
            or receipt_path.parent.stat().st_uid != os.getuid()
            or receipt_path.parent.stat().st_mode & 0o077
        ):
            raise ValueError("private receipt destination required")
        proof = {
            "format": "zac-protected-schema-rollout-v1",
            "status": "STARTED",
            "target_database": approval.target_database,
            "code_revision": approval.code_revision,
            "migration_hash": approval.migration_hash,
            "human_reference": approval.human_reference,
            "started_at": clock().isoformat(),
        }
        fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created_receipt = True
        os.close(fd)
        _receipt(receipt_path, proof)
        challenge = b"zacai protected Brainstorm schema rollout identity readiness"
        if age_decrypt(age_encrypt(challenge, recipient), identity_path) != challenge:
            raise ValueError("rollout identity mismatch")

        # No live write locks during any network or disposable restoration work.
        with engine.connect() as conn:
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            _connected(conn, approval.target_database)
            _scope(conn)
            with BoundedStateBuffer() as out:
                backup._export_boundary_connection(conn, B.BRAINSTORM, out)
                snapshot = out.getvalue()
            journal = _journal(conn)
            expected = dict(
                conn.execute(
                    text(
                        "SELECT id, content_hash FROM source WHERE trust_boundary='BRAINSTORM' AND content_hash IS NOT NULL"
                    )
                )
                .tuples()
                .all()
            )
        run_id = uuid4()
        encrypted_state, encrypted_journal = (
            age_encrypt(snapshot, recipient),
            age_encrypt(journal, recipient),
        )
        state_hash, journal_hash = (
            content_hash_of(encrypted_state),
            content_hash_of(encrypted_journal),
        )
        state_key = f"BRAINSTORM/state/{run_id}/{state_hash}.age"
        journal_key = f"BRAINSTORM/state/{run_id}/journal-{journal_hash}.age"
        recovered = []
        for key, encrypted, plain in (
            (state_key, encrypted_state, snapshot),
            (journal_key, encrypted_journal, journal),
        ):
            _authority(approval, clock())
            objects.put_object(key, encrypted)
            _authority(approval, clock())
            if verification_objects.stat(key).size != len(encrypted):
                raise ValueError("rollout object size differs")
            returned = verification_objects.get_object(key)
            if content_hash_of(returned) != content_hash_of(encrypted):
                raise ValueError("rollout remote ciphertext differs")
            decrypted = age_decrypt(returned, identity_path)
            if content_hash_of(decrypted) != content_hash_of(plain):
                raise ValueError("rollout remote plaintext differs")
            recovered.append(decrypted)
        _authority(approval, clock())
        restoration.verify(recovered[0], expected, operational_journal=recovered[1])
        _authority(approval, clock())
        proof.update(
            {
                "format": "zac-protected-schema-rollout-v1",
                "status": "PREPARED",
                "run_id": str(run_id),
                "target_database": approval.target_database,
                "code_revision": approval.code_revision,
                "migration_hash": approval.migration_hash,
                "human_reference": approval.human_reference,
                "prepared_at": clock().isoformat(),
                "state_object": state_key,
                "state_ciphertext_hash": state_hash,
                "state_plaintext_hash": content_hash_of(snapshot),
                "journal_object": journal_key,
                "journal_ciphertext_hash": journal_hash,
                "journal_plaintext_hash": content_hash_of(journal),
                "independent_full_state_and_journal_restore": "passed",
            }
        )
        _receipt(receipt_path, proof)
        # SHARE locks affect whole tables, even though permitted data is BRAINSTORM.
        with (
            engine.connect().execution_options(isolation_level="READ COMMITTED") as conn,
            conn.begin(),
        ):
            conn.execute(text("SET LOCAL statement_timeout='5s'"))
            conn.execute(text("SET LOCAL lock_timeout='1s'"))
            _connected(conn, approval.target_database)
            if not conn.scalar(
                text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": _ROLLOUT_LOCK}
            ):
                raise ValueError("another rollout is active")
            tables = ", ".join(
                (*backup._SCHEMA_TABLES["0004"], "artifact_backup_run", "alembic_version")
            )
            conn.execute(text(f"LOCK TABLE {tables} IN SHARE MODE NOWAIT"))
            _scope(conn)
            _original_rows(conn, snapshot)
            if _journal(conn) != journal:
                raise ValueError("operational journal changed during recovery")
            _authority(approval, clock())
            command.upgrade(_config(conn), "0005")
            _new_schema(conn)
            _original_rows(conn, snapshot)
            if _journal(conn) != journal or conn.scalar(text("SELECT 1")) != 1:
                raise ValueError("post-upgrade journal or database check failed")
            _authority(approval, clock())
        # External transaction has committed; only now can success be recorded.
        proof.update(
            status="APPLIED",
            completed_at=clock().isoformat(),
            original_rows_and_journal="preserved",
        )
        _receipt(receipt_path, proof)
    except Exception:  # noqa: BLE001 - never expose private rows/credentials/backend errors
        if created_receipt:
            try:
                # Even a failed final receipt may follow a committed upgrade.
                proof.update(status="FAILED_OR_UNCONFIRMED", failed_at=clock().isoformat())
                _receipt(receipt_path, proof)
            except Exception:  # noqa: BLE001, S110 - sanitized terminal error below
                pass
        raise SchemaRolloutError(
            "protected rollout failed or unconfirmed; inspect state before any retry"
        ) from None
