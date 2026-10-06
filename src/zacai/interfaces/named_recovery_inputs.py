"""Retained-proof lookup; no capture, repair, grants or provider calls.

Canonical rows/local artifact bytes are inventoried in short READ COMMITTED
sessions. Remote encrypted reads and concrete recovery rechecks occur only after
those sessions close. Actual user-turn recovery restores the packet and original
context as selected dependencies; this is not a new independent restoration of
the original packet checkpoint. A principal/session must still be validated by
CanonicalNamedDecisionAdmission and its assembler after this lookup.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from sqlalchemy import select

from zacai.backup_artifacts import age_decrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import (
    ContextualRecoveryReceipt,
    RecoveryLocator,
    encode_recovery_receipt,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.review_context import _unique_pairs
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import NamedAdmissionRecord
from zacai.interfaces.named_decision_admission import QuestionRecoveryInputs
from zacai.interfaces.named_decision_capture import (
    NamedDecisionCheckpointScope,
    NamedDecisionRecoveryReceipt,
    named_decision_receipt_key,
)
from zacai.interfaces.named_decision_inventory import (
    NamedDecisionInventory,
    load_named_decision_inventory,
)
from zacai.interfaces.named_decision_recovery import BrainstormNamedDecisionRecovery
from zacai.interfaces.named_followup_decision import (
    NamedFollowupDecision,
    decode_named_decision,
    encode_named_decision,
)
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


class NamedRecoveryInputsError(ValueError):
    """Fixed diagnostics; disable traceback-local capture in actual host."""


@dataclass(frozen=True)
class _QuestionInventory:
    turn: TextTurn = field(repr=False)
    locators: tuple[tuple[str, RecoveryLocator], ...] = field(repr=False)


class RetainedQuestionRecoveryInputs:
    """Concrete retained lookups, not authority or permissive proof callbacks."""

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        question_protection: BrainstormTextTurnProtection,
        clock: HostObservedClock,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or type(question_protection) is not BrainstormTextTurnProtection
            or type(clock) is not HostObservedClock
            or protector._approval_id is not None
            or question_protection._protector is not protector
            or question_protection._clock is not clock
        ):
            raise NamedRecoveryInputsError(
                "retained question proof configuration unavailable"
            )
        self._p, self._question, self._clock = protector, question_protection, clock

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def _inventory(self, record: NamedAdmissionRecord) -> _QuestionInventory:
        now = self._clock()
        p = self._p
        if (
            type(record) is not NamedAdmissionRecord
            or record.question_reference is None
        ):
            raise ValueError("canonical question attachment required")
        record = NamedAdmissionRecord.model_validate(record)
        assert record.question_reference is not None
        with p._factory() as session:
            _assert_ledger_isolation(session)

            def allowed(row: Source | None, reference: EvidenceReference | None = None) -> Source:
                if (
                    row is None
                    or row.trust_boundary != B.BRAINSTORM
                    or row.data_classification != C.CONFIDENTIAL
                    or get_effective_source_classification(session, source_id=row.id)
                    != C.CONFIDENTIAL
                    or row.captured_at > now
                    or (
                        reference is not None
                        and row.content_hash != reference.content_hash
                    )
                ):
                    raise ValueError("current source denied")
                return row

            source = allowed(
                session.get(Source, record.question_reference.source_id),
                record.question_reference,
            )
            raw = _bytes(session, p._artifacts, source)
            turn = decode_text_turn(raw)
            if (
                source.system != SourceSystem.USER_INSTRUCTION
                or source.external_ref != f"text-turn/{turn.request_id}"
                or source.captured_at != turn.recorded_at
                or content_hash_of(raw) != source.content_hash
                or record.admitted_at is None
                or not record.admitted_at <= turn.recorded_at <= now
                or turn.request_id != record.manifest.request_id
                or turn.conversation_id != record.manifest.conversation_id
                or turn.issuer != record.manifest.actor_issuer
                or turn.subject != record.manifest.actor_subject
                or turn.packet_reference != record.manifest.packet_reference
                or turn.packet_receipt_digest != record.manifest.packet_receipt_digest
                or content_hash_of(turn.original_text.encode())
                != record.question_digest
                or len(turn.original_text.encode()) != record.question_bytes
            ):
                raise ValueError("canonical question differs")
            packet = allowed(
                session.get(Source, turn.packet_reference.source_id),
                turn.packet_reference,
            )
            if (
                packet.system != SourceSystem.MANUAL
                or packet.external_ref
                != f"contextual-review-packet/{turn.packet_reference.content_hash}"
            ):
                raise ValueError("canonical packet differs")
            rows = session.scalars(
                select(Source)
                .where(
                    Source.trust_boundary == B.BRAINSTORM,
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.startswith(
                        f"contextual-recovery-locator/{packet.id}/"
                    ),
                )
                .limit(17)
            ).all()
            if not rows or len(rows) > 16:
                raise ValueError("locator inventory unavailable")
            locators = []
            for row in rows:
                allowed(row)
                raw = _bytes(session, p._artifacts, row)
                locator = RecoveryLocator.model_validate(
                    json.loads(raw, object_pairs_hook=_unique_pairs)
                )
                if (
                    raw != canonical_bytes(locator.model_dump(mode="json"))
                    or content_hash_of(raw) != row.content_hash
                    or row.external_ref
                    != f"contextual-recovery-locator/{packet.id}/{locator.locator_id}"
                    or row.captured_at != locator.created_at
                    or locator.packet_source_id != packet.id
                    or locator.packet_digest != packet.content_hash
                ):
                    raise ValueError("canonical locator differs")
                locators.append((str(row.id), locator))
            return _QuestionInventory(
                turn, tuple(sorted(locators, key=lambda item: item[0]))
            )

    def _packet(
        self, inventory: _QuestionInventory, expected_digest: str
    ) -> ContextualRecoveryReceipt:
        p = self._p
        receipts = []
        for source_id, locator in inventory.locators:
            if not p._reader.exists(locator.receipt_object):
                continue  # Verified orphan locator; never invent/repair a receipt.
            raw = age_decrypt(p._read(locator.receipt_object, 64_000), p._identity)
            # The immutable manifest pins the original receipt, not a latest
            # checkpoint. Other completed checkpoints are not selected proof.
            if content_hash_of(raw) != expected_digest:
                continue
            receipt = ContextualRecoveryReceipt.model_validate(
                json.loads(raw, object_pairs_hook=_unique_pairs)
            )
            if (
                raw != encode_recovery_receipt(receipt)
                or receipt.locator != locator
                or str(receipt.locator_source_id) != source_id
                or receipt.verified_at > self._clock()
            ):
                raise ValueError("retained packet receipt differs")
            for key, expected, limit in (
                (receipt.state_object, receipt.state_ciphertext_hash, 65_000_000),
                (receipt.journal_object, receipt.journal_ciphertext_hash, 4_100_000),
            ):
                if content_hash_of(p._read(key, limit)) != expected:
                    raise ValueError("retained checkpoint ciphertext differs")
            receipts.append(receipt)
        if len(receipts) != 1:
            raise ValueError("missing or ambiguous packet receipts")
        return receipts[0]

    def __call__(self, record: NamedAdmissionRecord) -> QuestionRecoveryInputs:
        result = None
        try:
            inventory = self._inventory(record)
            packet = self._packet(
                inventory, record.manifest.packet_receipt_digest
            )  # Remote I/O outside SQL.
            ref = record.question_reference
            assert ref is not None
            question = self._question._load_receipt(
                text_turn_receipt_key(ref.source_id, ref.content_hash)
            )
            if (
                content_hash_of(encode_recovery_receipt(packet))
                != record.manifest.packet_receipt_digest
                or content_hash_of(canonical_bytes(question.model_dump(mode="json")))
                != record.question_recovery_digest
                or question.verified_at > self._clock()
            ):
                raise ValueError("original pinned recovery receipts differ")
            scope = TextTurnCheckpointScope(
                ref.source_id, ref.content_hash, inventory.turn.recorded_at
            )
            if (
                cast(Callable[..., object], self._question.recheck)(scope, question)
                is not None
            ):
                raise ValueError("concrete recovery acknowledgement invalid")
            if self._inventory(record) != inventory:
                raise ValueError("canonical lookup changed during recovery")
            result = QuestionRecoveryInputs(packet, question)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedRecoveryInputsError("retained question proofs unavailable")
        return result

    def for_decision(self, decision: NamedFollowupDecision) -> QuestionRecoveryInputs:
        """Canonical decision projection for actual binding, never admission.

        Supports a candidate decision before capture as well as retained history.
        Actual question/packet receipts, rows and concrete restore remain required;
        constructing this lookup projection grants no owner/session/processing.
        """
        result = None
        try:
            if type(decision) is not NamedFollowupDecision:
                raise ValueError("exact named decision required")
            decision = decode_named_decision(encode_named_decision(decision))
            now = self._clock()
            with self._p._factory() as session:
                _assert_ledger_isolation(session)
                row = session.get(Source, decision.question_reference.source_id)
                if (
                    row is None
                    or row.content_hash != decision.question_reference.content_hash
                ):
                    raise ValueError("canonical question unavailable")
                turn = decode_text_turn(_bytes(session, self._p._artifacts, row))
                question_bytes = len(turn.original_text.encode("utf-8"))
            record = NamedAdmissionRecord(
                phase="QUESTION_BOUND",
                manifest=decision.manifest,
                session_binding=decision.session_binding_digest,
                admitted_at=decision.admitted_at,
                processing_expires_at=decision.processing_expires_at,
                question_digest=decision.original_utf8_digest,
                question_bytes=question_bytes,
                question_reference=decision.question_reference,
                question_recovery_digest=decision.question_receipt_digest,
                decision_reference=None,
                decision_recovery_digest=None,
            )
            result = self(record)
            if self._clock() < now:
                raise ValueError("question lookup time moved backward")
        except Exception:  # noqa: BLE001
            result = None
        if result is None:
            raise NamedRecoveryInputsError(
                "retained decision question proofs unavailable"
            )
        return result


class RetainedNamedDecisionProofs:
    """Construct after actual named recovery; never needed by admission itself."""

    def __init__(
        self,
        *,
        question_inputs: RetainedQuestionRecoveryInputs,
        decision_recovery: BrainstormNamedDecisionRecovery,
    ) -> None:
        if (
            type(question_inputs) is not RetainedQuestionRecoveryInputs
            or type(decision_recovery) is not BrainstormNamedDecisionRecovery
            or decision_recovery._protector is not question_inputs._p
            or decision_recovery.host_clock is not question_inputs.host_clock
        ):
            raise NamedRecoveryInputsError(
                "retained decision proof configuration unavailable"
            )
        self._question_inputs, self._decision = question_inputs, decision_recovery
        self._p, self._clock = question_inputs._p, question_inputs.host_clock

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def resolve_decision(
        self, record: NamedAdmissionRecord
    ) -> NamedDecisionRecoveryReceipt:
        """Read/recheck an existing decision receipt; no historical renewal."""
        result = None
        try:
            if (
                type(record) is not NamedAdmissionRecord
                or record.decision_reference is None
            ):
                raise ValueError("canonical decision attachment required")
            record = NamedAdmissionRecord.model_validate(record)
            assert record.decision_reference is not None

            ref = record.decision_reference

            def inventory() -> NamedDecisionInventory:
                now = self._clock()
                with self._p._factory() as session:
                    return load_named_decision_inventory(
                        session,
                        artifacts=self._p._artifacts,
                        reference=ref,
                        as_of=now,
                    )

            original = inventory()
            decision = original.decision
            if (
                decision.manifest != record.manifest
                or decision.question_reference != record.question_reference
                or decision.admitted_at != record.admitted_at
                or decision.processing_expires_at != record.processing_expires_at
                or decision.session_binding_digest != record.session_binding
            ):
                raise ValueError("canonical admitted decision differs")
            ref = record.decision_reference
            assert ref is not None
            receipt = self._decision._load_receipt(
                named_decision_receipt_key(ref.source_id, ref.content_hash)
            )
            if (
                content_hash_of(canonical_bytes(receipt.model_dump(mode="json")))
                != record.decision_recovery_digest
            ):
                raise ValueError("original decision proof differs")
            scope = NamedDecisionCheckpointScope(
                ref.source_id, ref.content_hash, decision.admitted_at
            )
            if (
                cast(Callable[..., object], self._decision.recheck)(scope, receipt)
                is not None
                or inventory() != original
            ):
                raise ValueError("canonical decision recovery changed")
            result = receipt
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedRecoveryInputsError("retained decision proof unavailable")
        return result
