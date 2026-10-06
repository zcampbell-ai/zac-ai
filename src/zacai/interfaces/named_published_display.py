"""Concrete published scope display gate, never question/model permission.

Uses the existing canonical packet/turn bytes, independent encrypted receipts,
shared checkpoint lease and disposable restore verifier. Construction reads no
credentials or data. Real operator/client/key setup is still mandatory. Cache
below is a bounded transient verification observation, never canonical memory.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import cast
from uuid import UUID

from sqlalchemy import select

from zacai import backup
from zacai.backup_artifacts import age_decrypt, backup_object_key_for
from zacai.brainstorm_identity_recovery import verify_brainstorm_recovered_identity
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import (
    ContextualRecoveryReceipt,
    RecoveryLocator,
    encode_recovery_receipt,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.review_context import _unique_pairs
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.followup_authorization import _owner_digest
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import NamedAdmissionRecord
from zacai.interfaces.named_runtime_binding import FixedLocalNamedRuntimeBinding, NamedRuntimePins
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.text_turn_capture import (
    TextTurn,
    TextTurnCheckpointScope,
    decode_text_turn,
    text_turn_receipt_key,
)
from zacai.interfaces.text_turn_protection import BrainstormTextTurnProtection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class NamedPublishedDisplayError(ValueError):
    """Fixed private-safe display diagnostics."""


@dataclass(frozen=True)
class _Rows:
    hashes: tuple[tuple[UUID, str], ...] = field(repr=False)
    locators: tuple[tuple[UUID, str, RecoveryLocator], ...] = field(repr=False)
    parents: tuple[tuple[UUID, str, TextTurn], ...] = field(repr=False)
    packet_created_at: datetime


_MAX_VERIFIED = 128


class CanonicalNamedPublishedDisplayGate:
    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        question_protection: BrainstormTextTurnProtection,
        clock: HostObservedClock,
        runtime: FixedLocalNamedRuntimeBinding,
        recovered_key_receipt: Path,
        expected_key_proof_digest: str,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
            or type(question_protection) is not BrainstormTextTurnProtection
            or question_protection._protector is not protector
            or question_protection._clock is not clock
            or type(clock) is not HostObservedClock
            or type(runtime) is not FixedLocalNamedRuntimeBinding
            or type(expected_key_proof_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_key_proof_digest) is None
        ):
            raise NamedPublishedDisplayError("published display configuration unavailable")
        self._p, self._q, self._clock, self._runtime = (
            protector,
            question_protection,
            clock,
            runtime,
        )
        self._key_receipt, self._key_digest = recovered_key_receipt, expected_key_proof_digest
        self._lock = RLock()
        self._restore_lock = RLock()
        self._refreshing: set[str] = set()
        self._verified: dict[str, tuple[str, datetime]] = {}

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def _key_check(self) -> None:
        p = self._p
        verify_brainstorm_recovered_identity(
            verification_objects=p._reader,
            recipient=p._recipient,
            identity_path=p._identity,
            recovered_key_receipt=self._key_receipt,
            expected_receipt_hash=self._key_digest,
        )

    def _rows(self, record: NamedAdmissionRecord, now: datetime) -> _Rows:
        if type(record) is not NamedAdmissionRecord:
            raise ValueError("actual published record required")
        record = NamedAdmissionRecord.model_validate(record)
        m = record.manifest
        p = self._p
        if not m.issued_at <= now:
            raise ValueError("future published manifest")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            hashes = {}

            def add(source_id: UUID, expected: str, system: SourceSystem | None = None) -> Source:
                row = session.get(Source, source_id)
                if (
                    row is None
                    or row.content_hash != expected
                    or row.trust_boundary != B.BRAINSTORM
                    or row.data_classification != C.CONFIDENTIAL
                    or row.captured_at > now
                    or get_effective_source_classification(session, source_id=source_id)
                    != C.CONFIDENTIAL
                    or (system is not None and row.system != system)
                ):
                    raise ValueError("published Source denied")
                hashes[source_id] = expected
                return row

            add(m.packet_reference.source_id, m.packet_reference.content_hash, SourceSystem.MANUAL)
            packet = load_contextual_packet(
                session,
                artifacts=p._artifacts,
                source_id=m.packet_reference.source_id,
                expected_digest=m.packet_reference.content_hash,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
            if (
                packet.created_at > m.issued_at
                or tuple(item.reference for item in packet.task.context) != m.evidence_references
            ):
                raise ValueError("original published packet differs")
            for item in packet.task.context:
                row = add(item.reference.source_id, item.reference.content_hash)
                if row.content_location is None:
                    raise ValueError("published evidence location absent")
                raw = p._artifacts.get(B.BRAINSTORM, row.content_location)
                if len(raw) > 8_500_000 or content_hash_of(raw) != row.content_hash:
                    raise ValueError("published evidence bytes differ")
            parents = []
            for selected in m.parents:
                ref = selected.reference
                row = add(ref.source_id, ref.content_hash, SourceSystem.USER_INSTRUCTION)
                turn = decode_text_turn(_bytes(session, p._artifacts, row))
                if (
                    row.external_ref != f"text-turn/{turn.request_id}"
                    or row.captured_at != turn.recorded_at
                    or (turn.issuer, turn.subject) != (m.actor_issuer, m.actor_subject)
                    or turn.conversation_id != m.conversation_id
                    or turn.request_id == m.request_id
                    or turn.packet_reference != m.packet_reference
                    or turn.packet_receipt_digest != m.packet_receipt_digest
                    or turn.recorded_at > m.issued_at
                ):
                    raise ValueError("published explicit parent differs")
                parents.append((row.id, ref.content_hash, turn))
            rows = session.scalars(
                select(Source)
                .where(
                    Source.trust_boundary == B.BRAINSTORM,
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.startswith(
                        f"contextual-recovery-locator/{m.packet_reference.source_id}/"
                    ),
                )
                .limit(17)
            ).all()
            if not rows or len(rows) > 16:
                raise ValueError("bounded canonical locators required")
            locators = []
            for row in rows:
                if row.content_hash is None:
                    raise ValueError("canonical locator digest absent")
                add(row.id, row.content_hash, SourceSystem.MANUAL)
                raw = _bytes(session, p._artifacts, row)
                locator = RecoveryLocator.model_validate(
                    json.loads(raw, object_pairs_hook=_unique_pairs)
                )
                if (
                    raw != canonical_bytes(locator.model_dump(mode="json"))
                    or row.captured_at != locator.created_at
                    or row.external_ref
                    != f"contextual-recovery-locator/{locator.packet_source_id}/{locator.locator_id}"
                    or locator.packet_source_id != m.packet_reference.source_id
                    or locator.packet_digest != m.packet_reference.content_hash
                ):
                    raise ValueError("canonical locator differs")
                locators.append((row.id, row.content_hash, locator))
            return _Rows(
                tuple(sorted(hashes.items(), key=lambda item: str(item[0]))),
                tuple(sorted(locators, key=lambda item: str(item[0]))),
                tuple(parents),
                packet.created_at,
            )

    def _packet(self, record: NamedAdmissionRecord, rows: _Rows) -> ContextualRecoveryReceipt:
        p = self._p
        matches = []
        for source_id, digest, locator in rows.locators:
            if not p._reader.exists(locator.receipt_object):
                continue
            raw = age_decrypt(p._read(locator.receipt_object, 64_000), p._identity)
            if content_hash_of(raw) != record.manifest.packet_receipt_digest:
                continue
            receipt = ContextualRecoveryReceipt.model_validate(
                json.loads(raw, object_pairs_hook=_unique_pairs)
            )
            if (
                raw != encode_recovery_receipt(receipt)
                or receipt.locator != locator
                or receipt.locator_source_id != source_id
                or receipt.locator_digest != digest
                or not rows.packet_created_at
                <= locator.created_at
                <= receipt.verified_at
                <= record.manifest.issued_at
            ):
                raise ValueError("actual selected packet proof differs")
            matches.append(receipt)
        if len(matches) != 1:
            raise ValueError("exact original packet receipt unavailable")
        return matches[0]

    def _restore(
        self, record: NamedAdmissionRecord, rows: _Rows, receipt: ContextualRecoveryReceipt
    ) -> None:
        p = self._p
        # Only packet/evidence+selected locator belong to this older snapshot;
        # explicit later parents have their own independent turn checkpoints.
        hashes = {
            record.manifest.packet_reference.source_id: record.manifest.packet_reference.content_hash,
            **{ref.source_id: ref.content_hash for ref in record.manifest.evidence_references},
            receipt.locator_source_id: receipt.locator_digest,
        }
        with checkpoint_lease(p, self._restore_lock) as require:
            for digest in hashes.values():
                if (
                    content_hash_of(
                        age_decrypt(
                            p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000),
                            p._identity,
                        )
                    )
                    != digest
                ):
                    raise ValueError("packet checkpoint artifact differs")
            state = p._read(receipt.state_object, 65_000_000)
            journal = p._read(receipt.journal_object, 4_100_000)
            if (
                content_hash_of(state) != receipt.state_ciphertext_hash
                or content_hash_of(journal) != receipt.journal_ciphertext_hash
            ):
                raise ValueError("packet checkpoint ciphertext differs")
            plain = age_decrypt(state, p._identity)
            operational = age_decrypt(journal, p._identity)
            if (
                content_hash_of(plain) != receipt.state_plaintext_hash
                or content_hash_of(operational) != receipt.journal_plaintext_hash
            ):
                raise ValueError("packet checkpoint plaintext differs")
            backup._csv_columns("artifact_backup_run", operational)
            runs = [
                row
                for row in csv.DictReader(io.StringIO(operational.decode("utf-8")))
                if row.get("id") == str(receipt.artifact_backup_run_id)
            ]
            if (
                len(runs) != 1
                or runs[0].get("trust_boundary") != B.BRAINSTORM.value
                or runs[0].get("status") != "SUCCEEDED"
            ):
                raise ValueError("packet checkpoint journal differs")
            started = datetime.fromisoformat(runs[0]["started_at"])
            finished = datetime.fromisoformat(runs[0]["finished_at"])
            if (
                started.utcoffset() is None
                or finished.utcoffset() is None
                or not receipt.locator.created_at <= started <= finished <= receipt.verified_at
            ):
                raise ValueError("packet checkpoint chronology differs")
            p._restoration.verify(
                plain, hashes, current_selected_sources=p._engine, operational_journal=operational
            )
            require()
            if self._rows(record, self._clock()) != rows:
                raise ValueError("canonical display rows changed during restore")

    def _session(self, operation: NamedSessionOperation, record: NamedAdmissionRecord) -> None:
        if type(operation) is not NamedSessionOperation or operation.host_clock is not self._clock:
            raise ValueError("actual published session required")
        current = operation.recheck(record.session_binding)
        owner = OwnerGrant(current.principal.identity, current.principal.scopes)
        m = record.manifest
        if (
            (owner.identity.issuer, owner.identity.subject) != (m.actor_issuer, m.actor_subject)
            or _owner_digest(owner) != m.owner_grant_digest
            or not any(
                scope.boundary == B.BRAINSTORM and C.CONFIDENTIAL in scope.classifications
                for scope in owner.scopes
            )
        ):
            raise ValueError("published actor scope differs")

    def _verify_fresh_work(
        self, operation: NamedSessionOperation, record: NamedAdmissionRecord, key: str
    ) -> object:
        okay = False
        try:
            start = self._clock()
            self._session(operation, record)
            rows = self._rows(record, self._clock())
            self._key_check()
            receipt = self._packet(record, rows)
            self._restore(record, rows, receipt)
            for source_id, digest, turn in rows.parents:
                retained = self._q._load_receipt(text_turn_receipt_key(source_id, digest))
                if (
                    cast(Callable[..., object], self._q.recheck)(
                        TextTurnCheckpointScope(source_id, digest, turn.recorded_at), retained
                    )
                    is not None
                ):
                    raise ValueError("explicit parent protection held")
            self._runtime.verify_published(record.manifest)
            self._key_check()
            self._session(operation, record)
            if (
                self._runtime.pins()
                != NamedRuntimePins(
                    record.manifest.tokenizer_digest, record.manifest.request_template_digest
                )
                or self._rows(record, self._clock()) != rows
                or self._clock() < start
            ):
                raise ValueError("published display changed during callbacks")
            expires = record.processing_expires_at or record.manifest.admission_expires_at
            if self._clock() >= expires:
                raise ValueError("published observation expired")
            digest = self._rows_digest(rows)
            final = self._clock()
            with self._lock:
                self._prune(final)
                if key not in self._refreshing or final >= expires:
                    raise ValueError("published observation no longer current")
                self._verified[key] = (digest, expires)
                okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedPublishedDisplayError("actual published scope held")
        return None

    @staticmethod
    def _rows_digest(rows: _Rows) -> str:
        # Preserve the complete comparison semantics while retaining only a
        # digest: decoded parent originals exist transiently during the check.
        projection = {
            "hashes": [[str(source_id), digest] for source_id, digest in rows.hashes],
            "locators": [
                [str(source_id), digest, locator.model_dump(mode="json")]
                for source_id, digest, locator in rows.locators
            ],
            "parents": [
                [str(source_id), digest, turn.model_dump(mode="json")]
                for source_id, digest, turn in rows.parents
            ],
            "packet_created_at": rows.packet_created_at.isoformat(),
        }
        return content_hash_of(b"zac-published-display-rows-v1\x00" + canonical_bytes(projection))

    @staticmethod
    def _record_key(record: NamedAdmissionRecord) -> str:
        if type(record) is not NamedAdmissionRecord:
            raise ValueError("actual published record required")
        checked = NamedAdmissionRecord.model_validate(record)
        return content_hash_of(
            b"zac-published-display-observation-v1\x00"
            + canonical_bytes(checked.model_dump(mode="json"))
        )

    def _prune(self, now: datetime) -> None:
        for key, (_, expires) in tuple(self._verified.items()):
            if expires <= now:
                del self._verified[key]

    def verify_fresh(
        self, operation: NamedSessionOperation, record: NamedAdmissionRecord
    ) -> object:
        key: str | None = None
        reserved = False
        result: object = False
        try:
            key = self._record_key(record)
            now = self._clock()
            with self._lock:
                self._prune(now)
                if key in self._refreshing:
                    raise ValueError("same published record already refreshing")
                # Invalidate only this exact observation; no active eviction.
                self._verified.pop(key, None)
                if len(self._verified) + len(self._refreshing) >= _MAX_VERIFIED:
                    raise ValueError("published observation capacity held")
                self._refreshing.add(key)
                reserved = True
            result = self._verify_fresh_work(operation, record, key)
        except Exception:  # noqa: BLE001,S110
            pass
        finally:
            if reserved and key is not None:
                with self._lock:
                    self._refreshing.discard(key)
                    if result is not None:
                        self._verified.pop(key, None)
        if result is not None:
            raise NamedPublishedDisplayError("actual published scope held")
        return None

    def verify_rows(self, record: NamedAdmissionRecord, now: datetime) -> object:
        okay = False
        key: str | None = None
        observed: tuple[str, datetime] | None = None
        try:
            current = self._clock()
            key = self._record_key(record)
            with self._lock:
                self._prune(current)
                observed = self._verified.get(key)
            if (
                observed is None
                or type(now) is not datetime
                or now.utcoffset() is None
                or now > current
                or now >= observed[1]
                or self._rows_digest(self._rows(record, now)) != observed[0]
            ):
                raise ValueError("published rows changed after verification")
            # No cache lock is held while opening SQL/reading canonical bytes.
            # Identity detects a refresh even when the resulting digest equals
            # the old one; an old in-flight check cannot certify a new entry.
            final = self._clock()
            with self._lock:
                self._prune(final)
                if self._verified.get(key) is not observed or key in self._refreshing:
                    raise ValueError("published observation changed during rows")
                okay = True
        except Exception:  # noqa: BLE001
            if key is not None:
                with self._lock:
                    if observed is not None and self._verified.get(key) is observed:
                        self._verified.pop(key, None)
        if not okay:
            raise NamedPublishedDisplayError("actual published canonical rows held")
        return None
