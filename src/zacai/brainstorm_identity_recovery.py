"""Reusable independently recovered BRAINSTORM age identity verification.

Trusted host supplies a pinned private operator proof and bound read-only object
client/current crypto configuration. Flags attest an independently performed
password-manager/off-device/full-restore drill; they are operator evidence, not
cryptographic proof of a password-manager UI. This call decrypts that original
object with the current identity and verifies the recipient by fresh challenge.
No credential lookup, default callback, SQL, approval, Source authority or model
processing is supplied. Tests use invented proof files/objects/crypto only.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any
from uuid import UUID

from zacai.backup_artifacts import BackupObjectStore, age_decrypt, age_encrypt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import TrustBoundary as B

_DIGEST = r"^[0-9a-f]{64}$"


class BrainstormIdentityRecoveryError(ValueError):
    """Fixed diagnostic; hosts must disable private traceback-local capture."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate proof field")
        value[key] = item
    return value


def assert_brainstorm_recovery_state_key(key: str, digest: str) -> None:
    match = re.fullmatch(
        r"BRAINSTORM/state/(review-|contextual-research-)?([0-9a-f-]{36})/([0-9a-f]{64})\.age", key
    )
    if not match or str(UUID(match[2])) != match[2] or match[3] != digest:
        raise ValueError("invalid state recovery object binding")


def _recover(
    objects: BackupObjectStore, identity: Path, key: str, *, limit: int, digest: str
) -> bytes:
    size = objects.stat(key).size
    if not 0 < size <= limit:
        raise ValueError("recovery object outside capacity")
    raw = objects.get_object(key)
    if len(raw) != size or content_hash_of(raw) != digest:
        raise ValueError("recovery ciphertext changed")
    return age_decrypt(raw, identity)


def _verify(
    *,
    verification_objects: BackupObjectStore,
    recipient: str,
    identity_path: Path,
    recovered_key_receipt: Path,
    expected_receipt_hash: str,
) -> None:
    if stat.S_IMODE(recovered_key_receipt.stat().st_mode) != 0o600:
        raise ValueError("private recovery receipt permissions required")
    with recovered_key_receipt.open("rb") as file:
        raw = file.read(64_001)
    if len(raw) > 64_000 or content_hash_of(raw) != expected_receipt_hash:
        raise ValueError("recovered-key evidence changed")
    proof = json.loads(raw, object_pairs_hook=_unique_pairs)
    if (
        proof["format"] != "zac-existing-state-recovery-v1"
        or proof["boundary"] != B.BRAINSTORM.value
        or proof["full_row_field_comparison"] != "passed"
        or proof["target_cleaned"] is not True
        or proof["off_device_retrieval"] is not True
        or proof["recovered_identity_from_password_manager"] is not True
        or proof["temporary_recovered_key_removed"] is not True
        or not re.fullmatch(_DIGEST, proof["plaintext_hash"])
    ):
        raise ValueError("independent recovered-key evidence unavailable")
    assert_brainstorm_recovery_state_key(proof["state_object"], proof["ciphertext_hash"])
    prior = _recover(
        verification_objects,
        identity_path,
        proof["state_object"],
        limit=65_000_000,
        digest=proof["ciphertext_hash"],
    )
    if content_hash_of(prior) != proof["plaintext_hash"]:
        raise ValueError("current identity differs from recovered-key evidence")
    challenge = b"zacai BRAINSTORM pre-context recovery identity readiness"
    if age_decrypt(age_encrypt(challenge, recipient), identity_path) != challenge:
        raise ValueError("recipient identity mismatch")


def verify_brainstorm_recovered_identity(
    *,
    verification_objects: BackupObjectStore,
    recipient: str,
    identity_path: Path,
    recovered_key_receipt: Path,
    expected_receipt_hash: str,
) -> None:
    """Read-only verification against separately pinned actual recovery evidence.

    Preserve the existing proof bytes/flags/namespace/read bounds; no new receipt
    or gate permission is created. Raw key material never enters the proof model.
    """
    failed = False
    try:
        _verify(
            verification_objects=verification_objects,
            recipient=recipient,
            identity_path=identity_path,
            recovered_key_receipt=recovered_key_receipt,
            expected_receipt_hash=expected_receipt_hash,
        )
    except Exception:  # noqa: BLE001 - fixed private-safe diagnostics outside handler
        failed = True
    if failed:
        raise BrainstormIdentityRecoveryError("Brainstorm recovered identity unavailable")
