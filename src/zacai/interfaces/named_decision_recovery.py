"""Named-owner-decision durability via existing audited Brainstorm checkpoints.

Historical receipt-only repair never renews admission, grants processing or
executes work. Constructor does no I/O. Real host/key/cloud composition and an
exclusive cooperating restore window remain operator requirements. Callbacks
run outside SQL/restore leases; rows-only inventory runs inside its own session.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from threading import RLock
from uuid import UUID

from sqlalchemy import text

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.brainstorm_identity_recovery import verify_brainstorm_recovered_identity
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_decision_capture import (
    NamedDecisionCheckpointScope,
    NamedDecisionRecoveryReceipt,
    named_decision_receipt_key,
)
from zacai.interfaces.named_decision_inventory import (
    NamedDecisionInventory,
    load_named_decision_inventory,
)
from zacai.interfaces.named_followup_decision import NamedFollowupDecision
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation


class NamedDecisionRecoveryError(ValueError):
    """Fixed private-safe diagnostics; no traceback-local capture is safe."""


def _inventory_digest(hashes: dict[UUID, str]) -> str:
    return content_hash_of(
        canonical_bytes({str(k): v for k, v in sorted(hashes.items(), key=lambda p: str(p[0]))})
    )


def _receipt_bytes(receipt: NamedDecisionRecoveryReceipt) -> bytes:
    return canonical_bytes(
        NamedDecisionRecoveryReceipt.model_validate(receipt).model_dump(mode="json")
    )


class BrainstormNamedDecisionRecovery:
    """Receipt recovery, not session authority or a backup engine.

    Mandatory fresh callback verifies actual owner/session/canonical binding and
    returns exact None. It must preserve historical integrity after processing
    expiry without authorizing a model. Corrupt receipts are never overwritten.
    Non-cooperating administrators still require an exclusive host window.
    """

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        clock: HostObservedClock,
        fresh: Callable[[NamedFollowupDecision, datetime], object],
        recovered_key_receipt: Path,
        expected_key_proof_digest: str,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
            or type(clock) is not HostObservedClock
            or not callable(fresh)
            or type(expected_key_proof_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_key_proof_digest) is None
        ):
            raise NamedDecisionRecoveryError("named decision recovery configuration rejected")
        self._protector, self._clock, self._fresh_binding = protector, clock, fresh
        self._key_receipt, self._key_proof_digest = recovered_key_receipt, expected_key_proof_digest
        self._lock = RLock()

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def _now(self) -> datetime:
        return self._clock()

    def _scope(self, scope: NamedDecisionCheckpointScope) -> NamedDecisionCheckpointScope:
        if (
            type(scope) is not NamedDecisionCheckpointScope
            or type(scope.source_id) is not UUID
            or type(scope.decision_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", scope.decision_digest) is None
            or type(scope.captured_at) is not datetime
            or scope.captured_at.utcoffset() is None
            or scope.boundary is not B.BRAINSTORM
            or scope.classification is not C.CONFIDENTIAL
        ):
            raise ValueError("named decision checkpoint scope invalid")
        return scope

    def _key_check(self) -> None:
        p = self._protector
        verify_brainstorm_recovered_identity(
            verification_objects=p._reader,
            recipient=p._recipient,
            identity_path=p._identity,
            recovered_key_receipt=self._key_receipt,
            expected_receipt_hash=self._key_proof_digest,
        )

    def _inventory(self, scope: NamedDecisionCheckpointScope) -> NamedDecisionInventory:
        self._scope(scope)
        p, now = self._protector, self._now()
        reference = EvidenceReference(
            source_id=scope.source_id,
            content_hash=scope.decision_digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("decision inventory session mismatch")
            inventory = load_named_decision_inventory(
                session, artifacts=p._artifacts, reference=reference, as_of=now
            )
            if (
                inventory.decision.admitted_at != scope.captured_at
                or inventory.decision.bound_at > now
            ):
                raise ValueError("decision scope chronology differs")
            return inventory

    def _hashes(self, scope: NamedDecisionCheckpointScope) -> dict[UUID, str]:
        return dict(self._inventory(scope).hashes)

    def _fresh_scope(self, scope: NamedDecisionCheckpointScope) -> None:
        inventory = self._inventory(scope)  # Session closes before callback.
        if self._protector._lease_guard is not None:
            raise ValueError("host callback cannot run inside recovery lease")
        if self._fresh_binding(inventory.decision, self._now()) is not None:
            raise ValueError("current host binding denied")

    @contextmanager
    def _lease(self) -> Iterator[Callable[[], None]]:
        with checkpoint_lease(self._protector, self._lock) as require:
            yield require

    def _load_receipt(self, key: str) -> NamedDecisionRecoveryReceipt:
        p = self._protector
        raw = age_decrypt(p._read(key, 64_000), p._identity)
        receipt = NamedDecisionRecoveryReceipt.model_validate_json(raw)
        if raw != _receipt_bytes(receipt) or receipt.receipt_object != key:
            raise ValueError("noncanonical recovery receipt")
        return receipt

    def _verify(
        self, scope: NamedDecisionCheckpointScope, receipt: NamedDecisionRecoveryReceipt
    ) -> datetime:
        p = self._protector
        started = self._now()
        hashes = self._hashes(scope)
        bound_at = self._inventory(scope).decision.bound_at
        if (
            started.utcoffset() is None
            or (receipt.source_id, receipt.decision_digest, receipt.captured_at)
            != (scope.source_id, scope.decision_digest, scope.captured_at)
            or receipt.inventory_digest != _inventory_digest(hashes)
            or receipt.key_proof_digest != self._key_proof_digest
            or receipt.verified_at > started
            or receipt.verified_at < bound_at
        ):
            raise ValueError("named decision receipt mismatch")
        # Artifact keys bind plaintext, and backup repair may re-encrypt them.
        # Historical observed ciphertext remains in the immutable receipt, but
        # current recoverability requires decryption and exact plaintext hash.
        for digest in hashes.values():
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("decision/dependency artifact mismatch")
        state = p._read(receipt.state_object, 65_000_000)
        journal = p._read(receipt.journal_object, 4_100_000)
        if (
            content_hash_of(state) != receipt.state_ciphertext_hash
            or content_hash_of(journal) != receipt.journal_ciphertext_hash
        ):
            raise ValueError("checkpoint ciphertext mismatch")
        plain = age_decrypt(state, p._identity)
        plain_journal = age_decrypt(journal, p._identity)
        if (
            content_hash_of(plain) != receipt.state_plaintext_hash
            or content_hash_of(plain_journal) != receipt.journal_plaintext_hash
        ):
            raise ValueError("checkpoint plaintext mismatch")
        backup._csv_columns("artifact_backup_run", plain_journal)
        runs = list(csv.DictReader(io.StringIO(plain_journal.decode("utf-8"))))
        matched = [row for row in runs if row.get("id") == str(receipt.artifact_backup_run_id)]
        if (
            len(matched) != 1
            or matched[0].get("trust_boundary") != B.BRAINSTORM.value
            or matched[0].get("status") != "SUCCEEDED"
        ):
            raise ValueError("artifact backup journal binding mismatch")
        run_started = datetime.fromisoformat(matched[0]["started_at"])
        run_finished = datetime.fromisoformat(matched[0]["finished_at"])
        if (
            run_started.utcoffset() is None
            or run_finished.utcoffset() is None
            or not scope.captured_at
            <= bound_at
            <= run_started
            <= run_finished
            <= receipt.verified_at
        ):
            raise ValueError("artifact backup run chronology mismatch")
        p._restoration.verify(
            plain, hashes, current_selected_sources=p._engine, operational_journal=plain_journal
        )
        if self._hashes(scope) != hashes:
            raise ValueError("decision inventory changed during restore")
        final = self._now()
        if final.utcoffset() is None or final < started or final < receipt.verified_at:
            raise ValueError("host clock moved backward")
        return final

    def protect(self, scope: NamedDecisionCheckpointScope) -> NamedDecisionRecoveryReceipt:
        result: NamedDecisionRecoveryReceipt | None = None
        try:
            scope = self._scope(scope)
            operation_started = self._now()
            self._key_check()
            self._fresh_scope(scope)
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            with self._lease() as require:
                hashes = self._hashes(scope)
                key = named_decision_receipt_key(scope.source_id, scope.decision_digest)
                p = self._protector
                if p._reader.exists(key):
                    receipt = self._load_receipt(key)
                    completed = self._verify(scope, receipt)
                else:
                    protected = p._protect_state(
                        hashes, f"BRAINSTORM/state/named-decision-{scope.source_id}"
                    )
                    artifact = p._read(
                        backup_object_key_for(B.BRAINSTORM, scope.decision_digest), 8_500_000
                    )
                    receipt = NamedDecisionRecoveryReceipt(
                        source_id=scope.source_id,
                        decision_digest=scope.decision_digest,
                        captured_at=scope.captured_at,
                        inventory_digest=_inventory_digest(hashes),
                        key_proof_digest=self._key_proof_digest,
                        verified_at=self._now(),
                        artifact_backup_run_id=protected.artifact_backup_run_id,
                        artifact_ciphertext_hash=content_hash_of(artifact),
                        state_ciphertext_hash=protected.state_ciphertext_hash,
                        state_plaintext_hash=protected.state_plaintext_hash,
                        journal_ciphertext_hash=protected.journal_ciphertext_hash,
                        journal_plaintext_hash=protected.journal_plaintext_hash,
                    )
                    if (
                        protected.state_object != receipt.state_object
                        or protected.journal_object != receipt.journal_object
                    ):
                        raise ValueError("checkpoint namespace mismatch")
                    completed = self._verify(scope, receipt)
                    if completed < operation_started:
                        raise ValueError("host clock moved backward during recovery")
                    receipt = NamedDecisionRecoveryReceipt.model_validate(
                        receipt.model_copy(update={"verified_at": completed})
                    )
                    raw = _receipt_bytes(receipt)
                    encrypted = age_encrypt(raw, p._recipient)
                    require()
                    if p._reader.exists(key):
                        raise ValueError("receipt already present; explicit retry required")
                    p._put(key, encrypted)
                    if p._read(key, 64_000) != encrypted or self._load_receipt(key) != receipt:
                        raise ValueError("receipt readback mismatch")
                    if self._hashes(scope) != hashes:
                        raise ValueError("decision changed before receipt release")
                final = self._now()
                if (
                    type(final) is not datetime
                    or final.utcoffset() is None
                    or final < operation_started
                    or final < completed
                    or final < receipt.verified_at
                ):
                    raise ValueError("host clock moved backward before receipt release")
                require()
            self._key_check()
            self._fresh_scope(scope)
            if self._hashes(scope) != hashes:
                raise ValueError("decision inventory changed after lease release")
            released = self._now()
            if type(released) is not datetime or released.utcoffset() is None or released < final:
                raise ValueError("host clock moved backward after lease release")
            result = receipt
        except Exception:  # noqa: BLE001,S110 - no source/configuration diagnostics
            pass
        if result is None:
            raise NamedDecisionRecoveryError(
                "named decision recovery unavailable; no acknowledgement"
            )
        return result

    def recheck(
        self, scope: NamedDecisionCheckpointScope, receipt: NamedDecisionRecoveryReceipt
    ) -> None:
        succeeded = False
        try:
            scope = self._scope(scope)
            operation_started = self._now()
            self._key_check()
            self._fresh_scope(scope)
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            receipt = NamedDecisionRecoveryReceipt.model_validate(receipt)
            with self._lease() as require:
                hashes = self._hashes(scope)  # Current source ACL/identity before object reads.
                if (
                    (receipt.source_id, receipt.decision_digest, receipt.captured_at)
                    != (scope.source_id, scope.decision_digest, scope.captured_at)
                    or receipt.inventory_digest != _inventory_digest(hashes)
                    or receipt.key_proof_digest != self._key_proof_digest
                ):
                    raise ValueError("retained receipt subject/inventory/proof differs")
                loaded = self._load_receipt(receipt.receipt_object)
                if loaded != receipt:
                    raise ValueError("retained receipt differs")
                completed = self._verify(scope, loaded)
                require()
            self._key_check()
            self._fresh_scope(scope)
            if self._hashes(scope) != hashes:
                raise ValueError("decision inventory changed after lease release")
            final = self._now()
            if (
                type(final) is not datetime
                or final.utcoffset() is None
                or final < operation_started
                or final < completed
                or final < receipt.verified_at
            ):
                raise ValueError("host clock moved backward before recovery acknowledgement")
            succeeded = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not succeeded:
            raise NamedDecisionRecoveryError(
                "named decision recovery recheck unavailable; no acknowledgement"
            )
