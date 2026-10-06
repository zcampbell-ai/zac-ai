"""Canonical named action inputs/runtime binding; no admission or inference grant.

Recovery, owner observations and runtime metadata checks occur outside SQL. Pure
row rechecks happen after the last external callback. Expired historical actions
may be checked for receipt-only preservation; this module cannot renew consent.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime

from sqlalchemy.orm import Session

from zacai.contextual_recovery_record import ContextualRecoveryReceipt, encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.interfaces.followup_authorization import FollowupHostSnapshot, scope_from_snapshot
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_candidate_rows import verify_named_candidate_rows
from zacai.interfaces.named_decision_admission import QuestionRecoveryInputs
from zacai.interfaces.named_followup_decision import (
    NamedFollowupDecision,
    decode_named_decision,
    encode_named_decision,
    validate_declared_bindings,
)
from zacai.interfaces.named_runtime_binding import FixedLocalNamedRuntimeBinding, NamedRuntimePins
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.text_followup_context import AssembledFollowup, CanonicalFollowupAssembler
from zacai.interfaces.text_turn_capture import TextTurnRecoveryReceipt


class CanonicalNamedDecisionBindingError(ValueError):
    """Closed diagnostic; never Source/prompt/session/runtime details."""


class CanonicalNamedDecisionBinding:
    def __init__(
        self,
        *,
        assembler: CanonicalFollowupAssembler,
        clock: HostObservedClock,
        recovery_inputs: Callable[[NamedFollowupDecision], QuestionRecoveryInputs],
        snapshot_builder: Callable[[AssembledFollowup, InterfacePrincipal], FollowupHostSnapshot],
        runtime: FixedLocalNamedRuntimeBinding,
    ) -> None:
        if (
            type(assembler) is not CanonicalFollowupAssembler
            or type(clock) is not HostObservedClock
            or assembler._capture._clock is not clock
            or type(runtime) is not FixedLocalNamedRuntimeBinding
            or not callable(recovery_inputs)
            or not callable(snapshot_builder)
        ):
            raise CanonicalNamedDecisionBindingError("canonical named binding unavailable")
        self._assembler, self._clock = assembler, clock
        self._recovery_inputs, self._snapshot_builder = recovery_inputs, snapshot_builder
        self._runtime = runtime

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def verify_rows(self, session: Session, decision: NamedFollowupDecision, now: datetime) -> None:
        verify_named_candidate_rows(
            session, artifacts=self._assembler._capture._artifacts, decision=decision, as_of=now
        )

    def verify_fresh(self, decision: NamedFollowupDecision, now: datetime) -> None:
        self._verify(decision, now, historical=False)

    def verify_historical(self, decision: NamedFollowupDecision, now: datetime) -> None:
        """Verify protected recorded inputs without probing today's runtime.

        Recorded pins describe history, never the currently executable profile.
        Active processing still requires verify_fresh and original admission.
        """
        self._verify(decision, now, historical=True)

    def _verify(self, decision: NamedFollowupDecision, now: datetime, *, historical: bool) -> None:
        okay = False
        try:
            decision = decode_named_decision(encode_named_decision(decision))
            start = self._clock()
            if (
                type(now) is not datetime
                or now.utcoffset() is None
                or now > start
                or decision.bound_at > start
            ):
                raise ValueError("current host observation required")
            owner = self._assembler._capture._owner()
            if type(owner) is not OwnerGrant:
                raise ValueError("current owner unavailable")
            principal = InterfacePrincipal(owner.identity, owner.scopes)
            inputs = self._recovery_inputs(decision)
            m = decision.manifest
            if (
                type(inputs) is not QuestionRecoveryInputs
                or type(inputs.packet_receipt) is not ContextualRecoveryReceipt
                or type(inputs.question_receipt) is not TextTurnRecoveryReceipt
                or content_hash_of(encode_recovery_receipt(inputs.packet_receipt))
                != m.packet_receipt_digest
                or content_hash_of(canonical_bytes(inputs.question_receipt.model_dump(mode="json")))
                != decision.question_receipt_digest
            ):
                raise ValueError("exact independently retained proof unavailable")
            assembled = self._assembler.assemble(
                principal=principal,
                source_id=decision.question_reference.source_id,
                expected_turn_digest=decision.question_reference.content_hash,
                retained_receipt=inputs.packet_receipt,
                expected_receipt_digest=m.packet_receipt_digest,
                recovery_receipt=inputs.question_receipt,
            )
            event = assembled.context.task.event.model_copy(
                update={"observed_at": decision.original_observed_at}
            )
            assembled = replace(
                assembled,
                context=replace(
                    assembled.context,
                    task=assembled.context.task.model_copy(update={"event": event}),
                ),
            )
            request = prepare_followup_request(assembled.context)
            if historical:
                pins = NamedRuntimePins(m.tokenizer_digest, m.request_template_digest)
            else:
                snapshot = self._snapshot_builder(assembled, principal)
                if (
                    type(snapshot) is not FollowupHostSnapshot
                    or snapshot.assembled is not assembled
                    or snapshot.principal != principal
                    or snapshot.owner != owner
                    or snapshot.route != self._runtime.route
                    or snapshot.model_digest != self._runtime.model_digest
                    or snapshot.route != m.route
                    or snapshot.model_digest != m.model_digest
                    or scope_from_snapshot(snapshot, run_id=m.run_id, builder_id=m.builder_id)
                    != decision.run_scope
                ):
                    raise ValueError("actual host snapshot differs")
                pins = self._runtime.pins()
            validate_declared_bindings(
                decision,
                owner=owner,
                turn=assembled.saved_turn.turn,
                turn_source_id=assembled.saved_turn.source_id,
                turn_receipt=inputs.question_receipt,
                packet_receipt=inputs.packet_receipt,
                request=request,
                runtime_endpoint="http://127.0.0.1:11434",
                tokenizer_digest=pins.tokenizer_digest,
                request_template_digest=pins.request_template_digest,
            )
            if not historical:
                self._runtime.verify(
                    request,
                    endpoint=m.runtime_endpoint,
                    tokenizer_digest=m.tokenizer_digest,
                    request_template_digest=m.request_template_digest,
                )
            # Complete all external owner observations BEFORE final row reads.
            self._assembler._capture._principal(principal, self._clock())
            if not historical and self._runtime.pins() != pins:
                raise ValueError("runtime pins changed during final owner callback")
            with self._assembler._capture._factory() as session:
                self.verify_rows(session, decision, self._clock())
            final = self._clock()
            if final < start or final < decision.bound_at:
                raise ValueError("host clock rolled back")
            okay = True
        except Exception:  # noqa: BLE001,S110 - no recovery/private runtime diagnostics
            pass
        if not okay:
            raise CanonicalNamedDecisionBindingError("canonical named binding unavailable")
