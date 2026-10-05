"""Concrete user-turn recovery using existing BRAINSTORM backup/restore mechanics.

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
from sqlalchemy.orm import Session

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.text_turn_capture import (
    TextTurn,
    TextTurnCheckpointScope,
    TextTurnRecoveryReceipt,
    decode_text_turn,
    text_turn_receipt_key,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class TextTurnProtectionError(ValueError):
    """Fixed diagnostics; host must disable traceback-local capture."""


def _receipt_bytes(receipt: TextTurnRecoveryReceipt) -> bytes:
    return canonical_bytes(TextTurnRecoveryReceipt.model_validate(receipt).model_dump(mode="json"))


class BrainstormTextTurnProtection:
    """Dedicated concrete protector, not an agent-provided backup dependency.

    Serializes with existing contextual operators plus backup's shared throwaway
    target lease. Non-cooperating administrators still require an exclusive host
    recovery window. Existing receipts are never overwritten, including corrupt
    ones. Historical full snapshots remain recoverable as unrelated work grows;
    The selected inventory covers the child and explicit direct parent envelopes,
    packet and packet original context; ancestor bodies are not traversed.
    Selected provenance or current ACL/context changes can hold release. The
    host must reconcile that hold rather than silently replacing its receipt.
    """

    def __init__(
        self, *, protector: BrainstormContextualProtector, clock: Callable[[], datetime]
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
        ):
            raise TextTurnProtectionError("turn protection configuration rejected")
        self._protector, self._clock = protector, clock
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

    def _read_turn(self, session: Session, source: Source) -> TextTurn:
        if (
            source.system != SourceSystem.USER_INSTRUCTION
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("turn Source denied")
        turn = decode_text_turn(_bytes(session, self._protector._artifacts, source))
        if (
            source.external_ref != f"text-turn/{turn.request_id}"
            or source.captured_at != turn.recorded_at
        ):
            raise ValueError("turn Source provenance mismatch")
        return turn

    def _hashes(self, scope: TextTurnCheckpointScope) -> dict[UUID, str]:
        # Production callers hold _lease across inventory/recovery/recheck.
        # _now serializes only clock observations, not this SQL transaction.
        p = self._protector
        now = self._now()
        if (
            type(scope) is not TextTurnCheckpointScope
            or type(scope.source_id) is not UUID
            or type(scope.turn_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", scope.turn_digest) is None
            or type(now) is not datetime
            or now.utcoffset() is None
            or scope.boundary != B.BRAINSTORM
            or scope.classification != C.CONFIDENTIAL
            or type(scope.captured_at) is not datetime
            or scope.captured_at.utcoffset() is None
            or scope.captured_at > now
        ):
            raise ValueError("turn scope/time mismatch")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("turn session target mismatch")
            source = session.get(Source, scope.source_id)
            if (
                source is None
                or source.content_hash != scope.turn_digest
                or source.captured_at != scope.captured_at
            ):
                raise ValueError("turn Source missing/mismatched")
            turn = self._read_turn(session, source)
            hashes = {scope.source_id: scope.turn_digest}

            def add(sid: UUID, digest: str) -> None:
                if sid in hashes:
                    raise ValueError("duplicate selected recovery Source")
                hashes[sid] = digest

            add(turn.packet_reference.source_id, turn.packet_reference.content_hash)
            for ref in turn.parent_references:
                if ref.source_id == scope.source_id:
                    raise ValueError("self-parent denied")
                parent_source = session.get(Source, ref.source_id)
                if parent_source is None or parent_source.content_hash != ref.content_hash:
                    raise ValueError("parent Source revision missing")
                parent = self._read_turn(session, parent_source)
                if (
                    parent.issuer != turn.issuer
                    or parent.subject != turn.subject
                    or parent.conversation_id != turn.conversation_id
                    or parent.packet_reference != turn.packet_reference
                    or parent.packet_receipt_digest != turn.packet_receipt_digest
                    or parent.recorded_at > turn.recorded_at
                    or parent.request_id == turn.request_id
                ):
                    raise ValueError("parent turn account/context mismatch")
                add(ref.source_id, ref.content_hash)
            packet = load_contextual_packet(
                session,
                artifacts=p._artifacts,
                source_id=turn.packet_reference.source_id,
                expected_digest=turn.packet_reference.content_hash,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
            if (
                packet_fingerprint(packet) != turn.packet_reference.content_hash
                or packet.created_at > turn.recorded_at
                or packet.task.event.trust_boundary != B.BRAINSTORM
                or packet.review.data_classification != C.CONFIDENTIAL
            ):
                raise ValueError("turn packet mismatch")
            for item in packet.task.context:
                add(item.reference.source_id, item.reference.content_hash)
            return hashes

    def _load_receipt(self, key: str) -> TextTurnRecoveryReceipt:
        p = self._protector
        raw = age_decrypt(p._read(key, 64_000), p._identity)
        receipt = TextTurnRecoveryReceipt.model_validate_json(raw)
        if raw != _receipt_bytes(receipt) or receipt.receipt_object != key:
            raise ValueError("noncanonical recovery receipt")
        return receipt

    def _verify(self, scope: TextTurnCheckpointScope, receipt: TextTurnRecoveryReceipt) -> datetime:
        p = self._protector
        started = self._now()
        if (
            started.utcoffset() is None
            or receipt.source_id != scope.source_id
            or receipt.turn_digest != scope.turn_digest
            or receipt.captured_at != scope.captured_at
            or receipt.verified_at > started
        ):
            raise ValueError("turn receipt mismatch")
        hashes = self._hashes(scope)
        # Artifact keys bind plaintext, and backup repair may re-encrypt them.
        # Historical observed ciphertext remains in the immutable receipt, but
        # current recoverability requires decryption and exact plaintext hash.
        for digest in hashes.values():
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("turn/dependency artifact mismatch")
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
            raise ValueError("turn inventory changed during restore")
        final = self._now()
        if final.utcoffset() is None or final < started or final < receipt.verified_at:
            raise ValueError("host clock moved backward")
        return final

    def protect(self, scope: TextTurnCheckpointScope) -> TextTurnRecoveryReceipt:
        result: TextTurnRecoveryReceipt | None = None
        try:
            operation_started = self._now()
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            with self._lease() as require:
                hashes = self._hashes(scope)
                key = text_turn_receipt_key(scope.source_id, scope.turn_digest)
                p = self._protector
                if p._reader.exists(key):
                    receipt = self._load_receipt(key)
                    completed = self._verify(scope, receipt)
                else:
                    protected = p._protect_state(
                        hashes, f"BRAINSTORM/state/text-turn-{scope.source_id}"
                    )
                    artifact = p._read(
                        backup_object_key_for(B.BRAINSTORM, scope.turn_digest), 8_500_000
                    )
                    receipt = TextTurnRecoveryReceipt(
                        source_id=scope.source_id,
                        turn_digest=scope.turn_digest,
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
                    receipt = TextTurnRecoveryReceipt.model_validate(
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
                        raise ValueError("turn changed before receipt release")
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
            result = receipt
        except Exception:  # noqa: BLE001,S110 - no source/configuration diagnostics
            pass
        if result is None:
            raise TextTurnProtectionError("turn recovery unavailable; no acknowledgement")
        return result

    def recheck(self, scope: TextTurnCheckpointScope, receipt: TextTurnRecoveryReceipt) -> None:
        succeeded = False
        try:
            operation_started = self._now()
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            receipt = TextTurnRecoveryReceipt.model_validate(receipt)
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
            succeeded = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not succeeded:
            raise TextTurnProtectionError("turn recovery recheck unavailable; no acknowledgement")
