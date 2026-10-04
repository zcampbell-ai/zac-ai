"""Canonical locator and encrypted recovery receipt, not action authority.

The locator is committed BEFORE the protected snapshot and points to a separate
immutable encrypted receipt. This avoids a receipt containing the hash of a
snapshot that contains that same receipt. After a cold restore, canonical state
retains the locator needed to find the exact state/journal recovery evidence.
No source/model access or backup service is enabled by these records.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from zacai.backup_artifacts import BackupObjectStore, age_decrypt, backup_object_key_for
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest
from zacai.intelligence.review_context import _unique_pairs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class RecoveryLocator(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-contextual-recovery-locator-v1"] = "zac-contextual-recovery-locator-v1"
    locator_id: UUID
    packet_source_id: UUID
    packet_digest: Digest
    task_id: UUID
    builder_id: UUID
    created_at: AwareDatetime

    @property
    def receipt_object(self) -> str:
        return f"BRAINSTORM/state/contextual-packet-{self.packet_source_id}/receipt-{self.locator_id}.age"


class ContextualRecoveryReceipt(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-contextual-recovery-receipt-v1"] = "zac-contextual-recovery-receipt-v1"
    locator: RecoveryLocator
    locator_source_id: UUID
    locator_digest: Digest
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    audit_source_ids: tuple[UUID, ...]
    state_object: str
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_object: str
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def exact_objects(self) -> Self:
        prefix = f"BRAINSTORM/state/contextual-packet-{self.locator.packet_source_id}"
        if (
            self.locator_digest
            != content_hash_of(canonical_bytes(self.locator.model_dump(mode="json")))
            or self.state_object != f"{prefix}/{self.state_ciphertext_hash}.age"
            or self.journal_object != f"{prefix}/journal-{self.journal_ciphertext_hash}.age"
            or self.verified_at < self.locator.created_at
            or len(set(self.audit_source_ids)) != len(self.audit_source_ids)
            or len(self.audit_source_ids) > 16
        ):
            raise ValueError("recovery receipt binding mismatch")
        return self


def encode_recovery_receipt(receipt: ContextualRecoveryReceipt) -> bytes:
    receipt = ContextualRecoveryReceipt.model_validate(receipt)
    return canonical_bytes(receipt.model_dump(mode="json"))


def _recover(objects: BackupObjectStore, key: str, identity: Path, limit: int) -> bytes:
    size = objects.stat(key).size
    if not 0 < size <= limit:
        raise ValueError("recovery object outside capacity")
    ciphertext = objects.get_object(key)
    if len(ciphertext) != size:
        raise ValueError("recovery object outside capacity")
    raw = age_decrypt(ciphertext, identity)
    if len(raw) > limit:
        raise ValueError("recovery plaintext outside capacity")
    return raw


def _load_locator(
    session: Session,
    locator_source_id: UUID,
    expected_locator_digest: str,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
    verification_objects: BackupObjectStore,
    identity_path: Path,
) -> tuple[Source, RecoveryLocator]:
    source = session.get(Source, locator_source_id)
    if (
        B.BRAINSTORM not in authorized_boundaries
        or C.CONFIDENTIAL not in allowed_classifications
        or source is None
        or source.trust_boundary != B.BRAINSTORM
        or source.system != SourceSystem.MANUAL
        or source.content_hash != expected_locator_digest
        or source.data_classification != C.CONFIDENTIAL
        or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
    ):
        raise ValueError("locator access denied")
    raw = _recover(
        verification_objects,
        backup_object_key_for(B.BRAINSTORM, expected_locator_digest),
        identity_path,
        64_000,
    )
    locator = RecoveryLocator.model_validate(json.loads(raw, object_pairs_hook=_unique_pairs))
    if (
        raw != canonical_bytes(locator.model_dump(mode="json"))
        or content_hash_of(raw) != expected_locator_digest
        or source.external_ref
        != f"contextual-recovery-locator/{locator.packet_source_id}/{locator.locator_id}"
        or source.captured_at != locator.created_at
    ):
        raise ValueError("locator binding mismatch")
    return source, locator


def load_contextual_recovery_receipt(
    session: Session,
    *,
    locator_source_id: UUID,
    expected_locator_digest: str,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
    verification_objects: BackupObjectStore,
    identity_path: Path,
) -> ContextualRecoveryReceipt:
    """Use canonical restored metadata to recover the locator and exact receipt.

    Verify receipt bindings and exact state/journal ciphertext availability, not
    current business freshness, full restore today, topology or dispatch access.
    A future operator must decrypt and verify the disposable restore again.
    The expected digest is a consistency check, not an independent trust anchor;
    the canonical row must come from an independently verified state restore.
    """
    result: ContextualRecoveryReceipt | None = None
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        source, locator = _load_locator(
            session,
            locator_source_id,
            expected_locator_digest,
            authorized_boundaries,
            allowed_classifications,
            verification_objects,
            identity_path,
        )
        payload = _recover(verification_objects, locator.receipt_object, identity_path, 64_000)
        receipt = ContextualRecoveryReceipt.model_validate(
            json.loads(payload, object_pairs_hook=_unique_pairs)
        )
        if (
            payload != encode_recovery_receipt(receipt)
            or receipt.locator != locator
            or receipt.locator_source_id != source.id
            or receipt.locator_digest != expected_locator_digest
        ):
            raise ValueError("receipt binding mismatch")
        for key, digest, limit in (
            (receipt.state_object, receipt.state_ciphertext_hash, 65_000_000),
            (receipt.journal_object, receipt.journal_ciphertext_hash, 4_100_000),
        ):
            size = verification_objects.stat(key).size
            if not 0 < size <= limit:
                raise ValueError("snapshot outside capacity")
            ciphertext = verification_objects.get_object(key)
            if len(ciphertext) != size or content_hash_of(ciphertext) != digest:
                raise ValueError("snapshot receipt unavailable")
        result = receipt
    except Exception:  # noqa: BLE001, S110 - suppress private object diagnostics
        pass
    if result is None:
        raise ValueError("contextual recovery receipt unavailable or mismatched")
    return result


def find_contextual_recovery_receipt(
    session: Session,
    *,
    packet_source_id: UUID,
    expected_packet_digest: str,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
    verification_objects: BackupObjectStore,
    identity_path: Path,
) -> ContextualRecoveryReceipt:
    """Find one valid packet-indexed receipt; missing receipts are orphan plans.

    Skip only a verified locator with a missing receipt object. Corruption,
    inaccessible metadata and multiple completed receipts reject; never silently
    choose a latest record. Caller supplies an independently verified snapshot.
    """
    result: ContextualRecoveryReceipt | None = None
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("pending writes")
        source = session.get(Source, packet_source_id)
        if (
            B.BRAINSTORM not in authorized_boundaries
            or C.CONFIDENTIAL not in allowed_classifications
            or source is None
            or source.trust_boundary != B.BRAINSTORM
            or source.system != SourceSystem.MANUAL
            or source.content_hash != expected_packet_digest
            or source.external_ref != f"contextual-review-packet/{expected_packet_digest}"
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("packet access denied")
        rows = session.scalars(
            select(Source)
            .where(
                Source.trust_boundary == B.BRAINSTORM,
                Source.system == SourceSystem.MANUAL,
                Source.external_ref.startswith(f"contextual-recovery-locator/{packet_source_id}/"),
            )
            .limit(17)
        ).all()
        if not rows or len(rows) > 16:
            raise ValueError("locator inventory unavailable")
        receipts = []
        for row in rows:
            if row.content_hash is None:
                raise ValueError("locator hash unavailable")
            _, locator = _load_locator(
                session,
                row.id,
                row.content_hash,
                authorized_boundaries,
                allowed_classifications,
                verification_objects,
                identity_path,
            )
            if (
                locator.packet_source_id != packet_source_id
                or locator.packet_digest != expected_packet_digest
            ):
                raise ValueError("locator packet mismatch")
            if not verification_objects.exists(locator.receipt_object):
                continue
            receipts.append(
                load_contextual_recovery_receipt(
                    session,
                    locator_source_id=row.id,
                    expected_locator_digest=row.content_hash,
                    authorized_boundaries=authorized_boundaries,
                    allowed_classifications=allowed_classifications,
                    verification_objects=verification_objects,
                    identity_path=identity_path,
                )
            )
        if len(receipts) != 1:
            raise ValueError("missing or ambiguous recovery receipts")
        result = receipts[0]
    except Exception:  # noqa: BLE001, S110 - no private receipt diagnostics
        pass
    if result is None:
        raise ValueError("contextual recovery receipt lookup unavailable or ambiguous")
    return result
