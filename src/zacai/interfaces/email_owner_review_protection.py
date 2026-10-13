"""Concrete email-owner-review recovery using existing BRAINSTORM backup/restore mechanics.

Construction performs no I/O. Host must explicitly approve/configure live use,
actual independent object clients and an exclusive cooperating recovery window.
No credentials, service mounting, approval, model or source-system action exists.
Local/mock clients demonstrate mechanics, never actual off-device availability.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from threading import RLock
from uuid import UUID

from sqlalchemy import text

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.email_input import _current_rows
from zacai.interfaces.email_owner_review import (
    EmailOwnerReviewCheckpointScope,
    email_owner_review_receipt_key,
    load_email_owner_review_inventory,
)
from zacai.interfaces.email_owner_review_contracts import EmailOwnerReviewRecoveryReceiptV1
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation


class EmailOwnerReviewProtectionError(ValueError):
    """Fixed diagnostics; host must disable traceback-local capture."""


def _receipt_bytes(receipt: EmailOwnerReviewRecoveryReceiptV1) -> bytes:
    return canonical_bytes(
        EmailOwnerReviewRecoveryReceiptV1.model_validate(receipt).model_dump(mode="json")
    )


class BrainstormEmailOwnerReviewProtection:
    """Concrete email owner review record/dependency backup, no inference permission.

    Serializes with existing contextual operators plus backup's shared throwaway
    target lease. Non-cooperating administrators still require an exclusive host
    recovery window. Existing receipts are never overwritten, including corrupt
    ones. Historical full snapshots remain recoverable as unrelated work grows;
    The selected inventory covers current owner assessment/release, the completed
    consent/claim/output chain and original input/native dependencies. Review may
    outlive generator consent; the actual original owner session must stay current.
    Selected provenance or current ACL/context changes can hold release. The
    host must reconcile that hold rather than silently replacing its receipt.
    """

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        operation: NamedSessionOperation,
        original_binding: str,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
            or type(protector._artifacts) is not LocalFilesystemArtifactStore
            or type(operation) is not NamedSessionOperation
            or type(operation.host_clock) is not HostObservedClock
            or type(original_binding) is not str
            or re.fullmatch(r"[0-9a-f]{64}", original_binding) is None
        ):
            raise EmailOwnerReviewProtectionError(
                "email owner review protection configuration rejected"
            )
        self._protector, self._clock = protector, operation.host_clock
        self._operation, self._binding = operation, original_binding
        self._artifacts: LocalFilesystemArtifactStore = protector._artifacts
        self._active = operation.recheck(original_binding)
        self._lock = RLock()
        self._last_observed: datetime | None = None

    def _now(self) -> datetime:
        """Validate every observed host clock value, including inventory reads.

        Equal observations are valid. This process-local watermark is not a
        persistent/global clock service or standalone inventory transaction gate.
        """
        with self._lock:
            now = self._clock()
            if (
                type(now) is not datetime
                or now.utcoffset() is None
                or (self._last_observed is not None and now < self._last_observed)
            ):
                raise ValueError("host clock observation moved backward or is invalid")
            self._last_observed = now
            return now

    @contextmanager
    def _lease(self) -> Iterator[Callable[[], None]]:
        with checkpoint_lease(self._protector, self._lock) as require:
            yield require

    def _hashes(self, scope: EmailOwnerReviewCheckpointScope) -> dict[UUID, str]:
        from zacai.policy import DataClassification as C

        if not any(
            s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
            for s in self._active.principal.scopes
        ):
            raise ValueError("current business owner read scope required")
        p = self._protector
        now = self._now()
        if (
            type(scope) is not EmailOwnerReviewCheckpointScope
            or scope.source_id.int == 0
            or re.fullmatch(r"[0-9a-f]{64}", scope.record_digest) is None
            or scope.captured_at.utcoffset() is None
            or scope.captured_at > now
        ):
            raise ValueError("exact email owner review record checkpoint required")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("canonical email session target mismatch")
            inventory = load_email_owner_review_inventory(session, self._artifacts, scope)
            consent = inventory.output.consent
            if (
                consent.session_binding != self._binding
                or consent.issuer != self._active.principal.identity.issuer
                or consent.subject != self._active.principal.identity.subject
                or consent.original_session_issued_at != self._active.issued_at
                or inventory.assessment.original_session_binding != self._binding
            ):
                raise ValueError("original email owner review owner differs")
            _current_rows(session, inventory.references)
            return {r.source_id: r.content_hash for r in inventory.references}

    def _load_receipt(self, key: str) -> EmailOwnerReviewRecoveryReceiptV1:
        p = self._protector
        raw = age_decrypt(p._read(key, 64_000), p._identity)
        receipt = EmailOwnerReviewRecoveryReceiptV1.model_validate_json(raw)
        if raw != _receipt_bytes(receipt) or receipt.receipt_object != key:
            raise ValueError("noncanonical recovery receipt")
        return receipt

    def _verify(
        self, scope: EmailOwnerReviewCheckpointScope, receipt: EmailOwnerReviewRecoveryReceiptV1
    ) -> datetime:
        p = self._protector
        started = self._now()
        if (
            started.utcoffset() is None
            or receipt.source_id != scope.source_id
            or receipt.record_digest != scope.record_digest
            or receipt.captured_at != scope.captured_at
            or receipt.verified_at > started
        ):
            raise ValueError("email owner review receipt mismatch")
        hashes = self._hashes(scope)
        # Artifact keys bind plaintext, and backup repair may re-encrypt them.
        # Historical observed ciphertext remains in the immutable receipt, but
        # current recoverability requires decryption and exact plaintext hash.
        for digest in hashes.values():
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("email owner review/dependency artifact mismatch")
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
            or not scope.captured_at <= run_started <= run_finished <= receipt.verified_at
        ):
            raise ValueError("artifact backup run chronology mismatch")
        p._restoration.verify(
            plain, hashes, current_selected_sources=p._engine, operational_journal=plain_journal
        )
        if self._hashes(scope) != hashes:
            raise ValueError("email owner review inventory changed during restore")
        final = self._now()
        if final.utcoffset() is None or final < started or final < receipt.verified_at:
            raise ValueError("host clock moved backward")
        return final

    def protect(self, scope: EmailOwnerReviewCheckpointScope) -> EmailOwnerReviewRecoveryReceiptV1:
        result: EmailOwnerReviewRecoveryReceiptV1 | None = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            self._active = self._operation.recheck(self._binding)
            operation_started = self._now()
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            with self._lease() as require:
                hashes = self._hashes(scope)
                key = email_owner_review_receipt_key(scope.source_id, scope.record_digest)
                p = self._protector
                if p._reader.exists(key):
                    receipt = self._load_receipt(key)
                    completed = self._verify(scope, receipt)
                else:
                    protected = p._protect_state(
                        hashes, f"BRAINSTORM/state/email-owner-review-{scope.source_id}"
                    )
                    artifact = p._read(
                        backup_object_key_for(B.BRAINSTORM, scope.record_digest), 8_500_000
                    )
                    receipt = EmailOwnerReviewRecoveryReceiptV1(
                        source_id=scope.source_id,
                        record_digest=scope.record_digest,
                        captured_at=scope.captured_at,
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
                    receipt = EmailOwnerReviewRecoveryReceiptV1.model_validate(
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
                        raise ValueError("email owner review changed before receipt release")
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
            released = self._now()
            if type(released) is not datetime or released.utcoffset() is None or released < final:
                raise ValueError("host clock moved backward after lease release")
            self._active = self._operation.recheck(self._binding)
            result = receipt
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewProtectionError(
                "email owner review recovery unavailable; no acknowledgement"
            )
        return result

    def recheck(
        self, scope: EmailOwnerReviewCheckpointScope, receipt: EmailOwnerReviewRecoveryReceiptV1
    ) -> None:
        succeeded = False
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            self._active = self._operation.recheck(self._binding)
            operation_started = self._now()
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            receipt = EmailOwnerReviewRecoveryReceiptV1.model_validate(receipt)
            with self._lease() as require:
                self._hashes(scope)  # Current source ACL/identity before object reads.
                loaded = self._load_receipt(receipt.receipt_object)
                if loaded != receipt:
                    raise ValueError("retained receipt differs")
                completed = self._verify(scope, loaded)
                require()
            final = self._now()
            if (
                type(final) is not datetime
                or final.utcoffset() is None
                or final < operation_started
                or final < completed
                or final < receipt.verified_at
            ):
                raise ValueError("host clock moved backward before recovery acknowledgement")
            self._active = self._operation.recheck(self._binding)
            succeeded = True
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if not succeeded:
            raise EmailOwnerReviewProtectionError(
                "email owner review recovery recheck unavailable; no acknowledgement"
            )
