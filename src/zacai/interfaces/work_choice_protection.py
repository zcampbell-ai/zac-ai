"""Concrete choice recovery using existing BRAINSTORM backup/restore mechanics.

Construction performs no I/O. Host must explicitly approve/configure live use,
actual independent object clients and an exclusive cooperating recovery window.
No credentials, service mounting, approval, model or source-system action exists.
Local/mock clients demonstrate mechanics, never actual off-device availability.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from threading import Lock
from uuid import UUID

from sqlalchemy import text

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces.work_choice_capture import (
    ChoiceCheckpointScope,
    WorkChoiceRecoveryReceipt,
    _decode,
    choice_receipt_key,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification

_OPERATOR_LOCK = 73403416  # Share contextual operator's artifact/manifest lease.


class WorkChoiceProtectionError(ValueError):
    """Fixed diagnostics; host must disable traceback-local capture."""


def _receipt_bytes(receipt: WorkChoiceRecoveryReceipt) -> bytes:
    return canonical_bytes(
        WorkChoiceRecoveryReceipt.model_validate(receipt).model_dump(mode="json")
    )


class BrainstormWorkChoiceProtection:
    """Dedicated concrete protector, not an agent-provided backup dependency.

    Serializes with existing contextual operators plus backup's shared throwaway
    target lease. Non-cooperating administrators still require an exclusive host
    recovery window. Existing receipts are never overwritten, including corrupt
    ones. Historical full snapshots remain recoverable as unrelated work grows;
    selected provenance or current ACL/context changes can hold release. The
    host must reconcile that hold rather than silently replacing its receipt.
    """

    def __init__(
        self, *, protector: BrainstormContextualProtector, clock: Callable[[], datetime]
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
        ):
            raise WorkChoiceProtectionError("choice protection configuration rejected")
        self._protector, self._clock = protector, clock
        self._lock = Lock()

    @contextmanager
    def _lease(self) -> Iterator[Callable[[], None]]:
        p = self._protector
        with self._lock, p._engine.connect() as lease:
            p._assert_target()
            lease.execute(text("SET TRANSACTION READ ONLY"))
            lease.execute(text("SET LOCAL idle_in_transaction_session_timeout = 0"))
            if (
                lease.scalar(text("SELECT current_setting('server_version_num')::integer"))
                >= 170000
            ):
                lease.execute(text("SET LOCAL transaction_timeout = 0"))
            if not lease.scalar(text(f"SELECT pg_try_advisory_xact_lock({_OPERATOR_LOCK})")):
                raise ValueError("operator recovery lease unavailable")

            def require() -> None:
                if not lease.scalar(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                        "AND pid=pg_backend_pid() AND classid=0 AND objid=73403416 "
                        "AND objsubid=1 AND granted)"
                    )
                ):
                    raise ValueError("operator recovery lease lost")

            if p._lease_guard is not None:
                raise ValueError("protector already in use")
            p._lease_guard = require
            try:
                with backup._admin_connection():
                    require()
                    yield require
                    require()
            finally:
                p._lease_guard = None

    def _hashes(self, scope: ChoiceCheckpointScope) -> dict[UUID, str]:
        p = self._protector
        now = self._clock()
        if (
            type(scope) is not ChoiceCheckpointScope
            or now.utcoffset() is None
            or scope.boundary != B.BRAINSTORM
            or scope.classification != C.CONFIDENTIAL
            or scope.captured_at.utcoffset() is None
            or scope.captured_at > now
        ):
            raise ValueError("choice scope/time mismatch")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("choice session target mismatch")
            source = session.get(Source, scope.source_id)
            if (
                source is None
                or source.system != SourceSystem.USER_INSTRUCTION
                or source.trust_boundary != B.BRAINSTORM
                or source.data_classification != C.CONFIDENTIAL
                or source.content_hash != scope.choice_digest
                or source.captured_at != scope.captured_at
                or get_effective_source_classification(session, source_id=source.id)
                != C.CONFIDENTIAL
            ):
                raise ValueError("choice source mismatch")
            choice = _decode(_bytes(session, p._artifacts, source))
            if (
                source.external_ref != f"work-choice/{choice.request_id}"
                or choice.recorded_at != scope.captured_at
            ):
                raise ValueError("choice identity mismatch")
            packet = load_contextual_packet(
                session,
                artifacts=p._artifacts,
                source_id=choice.packet_reference.source_id,
                expected_digest=choice.packet_reference.content_hash,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
            if (
                choice.proposal.packet_digest != packet_fingerprint(packet)
                or packet.created_at > choice.recorded_at
                or packet.task.event.trust_boundary != B.BRAINSTORM
                or packet.review.data_classification != C.CONFIDENTIAL
            ):
                raise ValueError("choice packet mismatch")
            hashes = {
                scope.source_id: scope.choice_digest,
                choice.packet_reference.source_id: choice.packet_reference.content_hash,
            }
            for item in packet.task.context:
                sid, digest = item.reference.source_id, item.reference.content_hash
                if sid in hashes and hashes[sid] != digest:
                    raise ValueError("conflicting artifact inventory")
                hashes[sid] = digest
            return hashes

    def _load_receipt(self, key: str) -> WorkChoiceRecoveryReceipt:
        p = self._protector
        raw = age_decrypt(p._read(key, 64_000), p._identity)
        receipt = WorkChoiceRecoveryReceipt.model_validate_json(raw)
        if raw != _receipt_bytes(receipt) or receipt.receipt_object != key:
            raise ValueError("noncanonical recovery receipt")
        return receipt

    def _verify(self, scope: ChoiceCheckpointScope, receipt: WorkChoiceRecoveryReceipt) -> datetime:
        p = self._protector
        started = self._clock()
        if (
            started.utcoffset() is None
            or receipt.source_id != scope.source_id
            or receipt.choice_digest != scope.choice_digest
            or receipt.captured_at != scope.captured_at
            or receipt.verified_at > started
        ):
            raise ValueError("choice receipt mismatch")
        hashes = self._hashes(scope)
        # Artifact keys bind plaintext, and backup repair may re-encrypt them.
        # Historical observed ciphertext remains in the immutable receipt, but
        # current recoverability requires decryption and exact plaintext hash.
        for digest in hashes.values():
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("choice/dependency artifact mismatch")
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
            raise ValueError("choice inventory changed during restore")
        final = self._clock()
        if final.utcoffset() is None or final < started or final < receipt.verified_at:
            raise ValueError("host clock moved backward")
        return final

    def protect(self, scope: ChoiceCheckpointScope) -> WorkChoiceRecoveryReceipt:
        result: WorkChoiceRecoveryReceipt | None = None
        try:
            with self._lease() as require:
                hashes = self._hashes(scope)
                key = choice_receipt_key(scope.source_id, scope.choice_digest)
                p = self._protector
                if p._reader.exists(key):
                    receipt = self._load_receipt(key)
                    self._verify(scope, receipt)
                else:
                    protected = p._protect_state(
                        hashes, f"BRAINSTORM/state/work-choice-{scope.source_id}"
                    )
                    artifact = p._read(
                        backup_object_key_for(B.BRAINSTORM, scope.choice_digest), 8_500_000
                    )
                    receipt = WorkChoiceRecoveryReceipt(
                        source_id=scope.source_id,
                        choice_digest=scope.choice_digest,
                        captured_at=scope.captured_at,
                        verified_at=self._clock(),
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
                    receipt = WorkChoiceRecoveryReceipt.model_validate(
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
                        raise ValueError("choice changed before receipt release")
                final = self._clock()
                if final.utcoffset() is None or final < receipt.verified_at:
                    raise ValueError("host clock moved backward before receipt release")
                require()
            result = receipt
        except Exception:  # noqa: BLE001,S110 - no source/configuration diagnostics
            pass
        if result is None:
            raise WorkChoiceProtectionError("choice recovery unavailable; no acknowledgement")
        return result

    def recheck(self, scope: ChoiceCheckpointScope, receipt: WorkChoiceRecoveryReceipt) -> None:
        succeeded = False
        try:
            receipt = WorkChoiceRecoveryReceipt.model_validate(receipt)
            with self._lease() as require:
                self._hashes(scope)  # Current source ACL/identity before object reads.
                loaded = self._load_receipt(receipt.receipt_object)
                if loaded != receipt:
                    raise ValueError("retained receipt differs")
                self._verify(scope, loaded)
                require()
            succeeded = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not succeeded:
            raise WorkChoiceProtectionError(
                "choice recovery recheck unavailable; no acknowledgement"
            )
