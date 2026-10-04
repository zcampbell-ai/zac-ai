"""Explicit local-only 0004 -> 0005 -> 0004 rehearsal, never live migration.

Current BRAINSTORM canonical rows are held in bounded RAM and temporarily in
zacai_restore_test. No plaintext export file, remote I/O or model call. Run only
in an exclusive operator window relative to legacy recovery tools.
"""

import io
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from zacai import backup
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import TrustBoundary as B
from zacai.review_protection import BoundedStateBuffer

ROOT = Path(__file__).resolve().parent.parent
LIVE_URL = "postgresql+psycopg://127.0.0.1:5432/zacai_dev"
LOCK = 73403412  # Same lease as DisposableStateRestoreVerifier.


def exported(engine):
    with BoundedStateBuffer() as out:
        backup.export_boundary_stream(engine, B.BRAINSTORM, out)
        return out.getvalue()


def main():
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", backup.RESTORE_TEST_URL)
    if ScriptDirectory.from_config(config).get_current_head() != "0005":
        raise RuntimeError("rehearsal needs re-review for another revision")
    backup.assert_safe_restore_target_url(backup.RESTORE_TEST_URL)
    live = create_engine(LIVE_URL, future=True)
    try:
        with live.connect() as conn:
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            if conn.scalar(text("SELECT current_database()")) != "zacai_dev":
                raise RuntimeError("canonical target mismatch")
            if conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all() != [
                "0004"
            ]:
                raise RuntimeError("canonical schema changed")
        snapshot = exported(live)
        # Export opens its own read-only snapshot; revalidate its actual manifest.
        if not snapshot.startswith(b"zacai-state-backup-v2\n0004\nBRAINSTORM\n"):
            raise RuntimeError("snapshot revision mismatch")
    finally:
        live.dispose()

    with backup._admin_connection() as admin:
        if not admin.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK}):
            raise RuntimeError("recovery verifier active")
        created = False
        try:
            if admin.scalar(
                text("SELECT count(*) FROM pg_stat_activity WHERE datname=:db"),
                {"db": backup.RESTORE_TEST_DATABASE},
            ):
                raise RuntimeError("disposable target in use")
            admin.execute(text(f"DROP DATABASE IF EXISTS {backup.RESTORE_TEST_DATABASE}"))
            admin.execute(text(f"CREATE DATABASE {backup.RESTORE_TEST_DATABASE}"))
            created = True
            command.upgrade(config, "0004")
            target = create_engine(backup.RESTORE_TEST_URL, future=True)
            try:
                with target.connect() as conn:
                    backup.assert_connected_to_safe_restore_database(
                        conn.scalar(text("SELECT current_database()"))
                    )
                backup.restore_boundary_stream(target, io.BytesIO(snapshot))
                if exported(target) != snapshot:
                    raise RuntimeError("baseline restore differs")
                command.upgrade(config, "0005")
                with target.connect() as conn:
                    if conn.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalars().all() != ["0005"]:
                        raise RuntimeError("upgrade revision mismatch")
                backup.verify_restored_boundary_stream(
                    target, io.BytesIO(snapshot), boundary=B.BRAINSTORM
                )
                with target.connect() as conn:
                    for table in backup.TABLE_ORDER[-2:]:
                        if conn.scalar(text(f"SELECT EXISTS (SELECT 1 FROM {table})")):
                            raise RuntimeError("new association inventory is not empty")
                command.downgrade(config, "0004")
                if exported(target) != snapshot:
                    raise RuntimeError("rollback differs")
            finally:
                target.dispose()
        finally:
            try:
                if created:
                    admin.execute(text(f"DROP DATABASE {backup.RESTORE_TEST_DATABASE}"))
            finally:
                admin.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK})

    verified_at = datetime.now(UTC)
    proof = {
        "format": "zac-schema-rehearsal-v1",
        "verified_at": verified_at.isoformat(),
        "boundary": "BRAINSTORM",
        "snapshot_hash": content_hash_of(snapshot),
        "from_revision": "0004",
        "to_revision": "0005",
        "baseline_full_comparison": "passed",
        "upgrade_full_row_field_comparison": "passed",
        "rollback_full_comparison": "passed",
        "new_association_tables_empty": True,
        "disposable_target_cleaned": True,
        "canonical_writes": False,
        "uploads": False,
        "model_calls": False,
        "off_device_snapshot_verified": False,
        "scope": "canonical boundary inventory only; operational backup-run history excluded",
    }
    local_date = verified_at.astimezone(ZoneInfo("America/New_York")).date()
    path = ROOT / f"private-data/schema-rollout-rehearsal-{local_date}-{uuid4()}.json"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        json.dump(proof, out, indent=2)
    print(
        json.dumps(
            {
                k: proof[k]
                for k in (
                    "baseline_full_comparison",
                    "upgrade_full_row_field_comparison",
                    "rollback_full_comparison",
                    "disposable_target_cleaned",
                    "canonical_writes",
                    "uploads",
                    "model_calls",
                )
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 - never display private state or database diagnostics
        print(json.dumps({"schema_rehearsal": "failed", "private_diagnostics_displayed": False}))
        raise SystemExit(1) from None
