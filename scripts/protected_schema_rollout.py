"""Explicit Mac Studio operator command; default only describes the scope.

The approval JSON is created by the trusted operator after actual human consent.
No approval issuer, background service or automatic retry is supplied here.
"""

import argparse
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine

from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
from zacai.config import get_secret
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.schema_rollout import (
    SchemaRolloutApproval,
    _authority,
    _fsync_directory,
    execute_protected_schema_rollout,
)

ROOT = Path(__file__).resolve().parent.parent
PRIVATE = ROOT / "private-data"
IDENTITY = Path.home() / ".config/zacai/backup-keys/brainstorm.agekey"
RECIPIENT = "age1c84dtx3xxed5lacj3pn48v6p7xjvmvalr8umgnvs97fd02pg6yss34hvfr"


def credential(service, name):
    found = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-w", "-s", service, "-a", "brainstormzac"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )
    value = found.stdout.decode().removesuffix("\n")
    secret = get_secret(name, B.BRAINSTORM, env={name: value})
    if not secret:
        raise RuntimeError("backup credential unavailable")
    return secret


def approval_from_private_file(path):
    if path.resolve().parent != PRIVATE.resolve():
        raise ValueError("approval must be in operator private directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        stat = os.fstat(file.fileno())
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077 or stat.st_size > 8192:
            raise ValueError("approval file must be private and bounded")
        return SchemaRolloutApproval.model_validate_json(file.read(8193))


def claim_approval(approval):
    # Stable human approval reference prevents re-encoding/replaying that consent.
    # Consume before credentials or remote I/O; even a failed attempt needs review.
    digest = content_hash_of(approval.human_reference.strip().encode())
    claim = PRIVATE / f"schema-rollout-approval-{digest}.used"
    with os.fdopen(
        os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w"
    ) as file:
        file.write(datetime.now(UTC).isoformat())
        file.flush()
        os.fsync(file.fileno())
    _fsync_directory(PRIVATE)
    return PRIVATE / f"schema-rollout-{digest}.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(
            json.dumps(
                {
                    "mode": "proposal_only",
                    "target": "zacai_dev",
                    "from": "0004",
                    "to": "0005",
                    "backup": "encrypted BRAINSTORM state and operational journal to existing B2",
                    "recovery": "independent readback and full disposable restoration",
                    "migration": "two empty association tables; original state and journal preserved",
                    "write_pause": "final local validation and DDL only; table-wide",
                    "live_actions": False,
                    "human_approval_required": True,
                }
            )
        )
        return
    if not args.approval:
        raise ValueError("explicit operator approval file required")
    if PRIVATE.stat().st_uid != os.getuid() or PRIVATE.stat().st_mode & 0o077:
        raise ValueError("operator directory must be private")
    if (
        subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-q", "private-data/rollout-probe"],
            check=False,
            capture_output=True,
            timeout=5,
        ).returncode
        != 0
    ):
        raise ValueError("private operator directory must be excluded from Git")
    approval = approval_from_private_file(args.approval)
    if approval.target_database != "zacai_dev":
        raise ValueError("operator command only supports the approved local canonical database")
    _authority(approval, datetime.now(UTC))
    receipt = claim_approval(approval)
    access = credential("zacai-brainstorm-b2-backup-key-id", "BRAINSTORM_B2_BACKUP_KEY_ID")
    secret = credential(
        "zacai-brainstorm-b2-backup-application-key", "BRAINSTORM_B2_BACKUP_APPLICATION_KEY"
    )
    config = {
        "bucket": "zac-ai-brainstorm-backup",
        "endpoint_url": "https://s3.us-east-005.backblazeb2.com",
        "region": "us-east-005",
        "access_key_id": access,
        "secret_access_key": secret,
        "max_attempts": 0,
    }
    writer, reader = (
        S3CompatibleBackupObjectStore(**config),
        S3CompatibleBackupObjectStore(**config),
    )
    engine = create_engine("postgresql+psycopg://127.0.0.1:5432/zacai_dev", hide_parameters=True)
    try:
        execute_protected_schema_rollout(
            engine,
            approval=approval,
            objects=writer,
            verification_objects=reader,
            recipient=RECIPIENT,
            identity_path=IDENTITY,
            restoration=DisposableStateRestoreVerifier(),
            receipt_path=receipt,
        )
    finally:
        engine.dispose()
    print(
        json.dumps(
            {
                "protected_schema_rollout": "APPLIED",
                "schema": "0005",
                "original_rows_and_journal": "preserved",
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 - no credential/provider/private state diagnostics
        print(
            json.dumps(
                {"protected_schema_rollout": "FAILED_OR_UNCONFIRMED", "automatic_retry": False}
            )
        )
        raise SystemExit(1) from None
