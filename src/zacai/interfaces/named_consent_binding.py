"""Concrete staged canonical named-consent integrity, never renewed processing.

Historical verification uses immutable canonical decision/protected receipt and a
current actual owner session; it never requires an unexpired operational store
row. The separate active method needs the original host-held admission handle
and session. The dispatch host must invoke that active check before and after
long work; a history binding or ledger TTL cannot substitute for it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import cast

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.interfaces.followup_authorization import (
    FollowupConsentV2,
    load_named_consent_inventory,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import NamedAdmissionRecord
from zacai.interfaces.named_decision_admission import CanonicalNamedDecisionAdmission
from zacai.interfaces.named_decision_capture import NamedDecisionRecoveryReceipt
from zacai.interfaces.named_decision_inventory import NamedDecisionInventory
from zacai.interfaces.named_recovery_inputs import (
    RetainedNamedDecisionProofs,
    RetainedQuestionRecoveryInputs,
)
from zacai.interfaces.text_turn_capture import decode_text_turn
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source


class NamedConsentBindingError(ValueError):
    """Fixed private-safe host error; disable traceback-local capture."""


class CanonicalNamedFollowupConsentBinding:
    def __init__(
        self,
        *,
        admission: CanonicalNamedDecisionAdmission,
        recovery_inputs: RetainedQuestionRecoveryInputs,
        decision_proofs: RetainedNamedDecisionProofs,
        clock: HostObservedClock,
    ) -> None:
        if (
            type(admission) is not CanonicalNamedDecisionAdmission
            or type(recovery_inputs) is not RetainedQuestionRecoveryInputs
            or type(decision_proofs) is not RetainedNamedDecisionProofs
            or decision_proofs._question_inputs is not recovery_inputs
            or decision_proofs.host_clock is not clock
            or type(clock) is not HostObservedClock
            or admission._clock is not clock
            or recovery_inputs._clock is not clock
            or admission._recovery_inputs is not recovery_inputs
            or recovery_inputs._question
            is not admission._assembler._capture._protection
            or recovery_inputs._p._factory is not admission._assembler._capture._factory
            or recovery_inputs._p._artifacts
            is not admission._assembler._capture._artifacts
        ):
            raise NamedConsentBindingError("actual named consent host unavailable")
        self._admission, self._resolver, self._decision_proofs, self._clock = (
            admission,
            recovery_inputs,
            decision_proofs,
            clock,
        )

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def _read(
        self, consent: FollowupConsentV2, now: datetime
    ) -> NamedDecisionInventory:
        capture = self._admission._assembler._capture
        with capture._factory() as session:
            _assert_ledger_isolation(session)
            return load_named_consent_inventory(
                session, artifacts=capture._artifacts, consent=consent, as_of=now
            )

    def _lookup_record(
        self, consent: FollowupConsentV2, inventory: NamedDecisionInventory
    ) -> NamedAdmissionRecord:
        """Canonical-derived lookup metadata; no operational admission proof.

        No handle/nonce/session is created. These fields only locate the pinned
        receipt and exact canonical dependencies through the concrete resolver.
        Never provide this projection to admit/resolve/recheck processing APIs.
        """
        d = inventory.decision
        capture = self._admission._assembler._capture
        observed = self._clock()
        with capture._factory() as session:
            _assert_ledger_isolation(session)
            if (
                load_named_consent_inventory(
                    session,
                    artifacts=capture._artifacts,
                    consent=consent,
                    as_of=observed,
                )
                != inventory
            ):
                raise ValueError("canonical lookup dependencies changed")
            row = session.get(Source, d.question_reference.source_id)
            if row is None:
                raise ValueError("canonical question absent")
            turn = decode_text_turn(_bytes(session, capture._artifacts, row))
            question_bytes = len(turn.original_text.encode("utf-8"))
        return NamedAdmissionRecord(
            phase="DECISION_BOUND",
            manifest=d.manifest,
            session_binding=d.session_binding_digest,
            admitted_at=d.admitted_at,
            processing_expires_at=d.processing_expires_at,
            question_digest=d.original_utf8_digest,
            question_bytes=question_bytes,
            question_reference=d.question_reference,
            question_recovery_digest=d.question_receipt_digest,
            decision_reference=consent.decision_reference,
            decision_recovery_digest=consent.decision_recovery_digest,
        )

    def _historical_session(self, inventory: NamedDecisionInventory) -> None:
        current = self._admission._operation.establish()
        if (
            self._admission.recheck_session(
                current.principal, inventory.decision, self._clock()
            )
            is not None
        ):
            raise ValueError("actual historical owner session denied")

    def verify_rows(
        self, session: Session, consent: FollowupConsentV2, now: datetime
    ) -> object:
        # No clock, session-store, owner, runtime or recovery callbacks here.
        capture = self._admission._assembler._capture
        load_named_consent_inventory(
            session, artifacts=capture._artifacts, consent=consent, as_of=now
        )
        return None

    def verify_fresh(self, consent: FollowupConsentV2, now: datetime) -> object:
        okay = False
        try:
            if (
                type(consent) is not FollowupConsentV2
                or type(now) is not datetime
                or now.utcoffset() is None
                or now > self._clock()
            ):
                raise ValueError("exact historical consent/time required")
            consent = FollowupConsentV2.model_validate(consent)
            original = self._read(consent, self._clock())
            self._historical_session(original)  # Actual owner session, outside SQL.
            # Recover named decision and its complete selected canonical
            # question/parent/packet/context inventory; no TTL renewal.
            record = self._lookup_record(consent, original)
            receipt = self._decision_proofs.resolve_decision(record)
            if (
                type(receipt) is not NamedDecisionRecoveryReceipt
                or content_hash_of(canonical_bytes(receipt.model_dump(mode="json")))
                != consent.decision_recovery_digest
                or receipt.source_id != consent.decision_reference.source_id
                or receipt.decision_digest != consent.decision_reference.content_hash
                or receipt.captured_at != original.decision.admitted_at
                or not original.decision.bound_at
                <= receipt.verified_at
                <= self._clock()
            ):
                raise ValueError("actual immutable decision proof differs")
            self._historical_session(original)  # Last external callback.
            if self._read(consent, self._clock()) != original:
                raise ValueError("canonical named consent changed during recovery")
            if self._clock() < now:
                raise ValueError("host time moved backward")
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedConsentBindingError("actual named consent integrity held")
        return None

    def verify_active(
        self, *, handle: str, consent: FollowupConsentV2, now: datetime
    ) -> object:
        """Original host-held admission/session, mandatory separate dispatch gate."""
        okay = False
        try:
            self.verify_fresh(consent, now)
            inventory = self._read(consent, self._clock())
            current = self._admission._operation.establish()
            if (
                cast(Callable[..., object], self._admission.recheck)(
                    handle, current.principal, inventory.decision, self._clock()
                )
                is not None
            ):
                raise ValueError("actual original admission denied")
            if (
                self._read(consent, self._clock()) != inventory
                or not consent.approved_at <= self._clock() < consent.expires_at
            ):
                raise ValueError("active original consent changed")
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedConsentBindingError("original named processing held")
        return None
