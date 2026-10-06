"""Real session/admission/canonical-question join; no HTTP or issuer.

Operational attachment hashes and receipt constructors prove no recovery. The
mandatory trusted resolver supplies exact retained proofs, then actual canonical
assembler/capture.load rechecks them outside SQL. Runtime pin checks remain the
separate mandatory NamedDecisionBinding; this adapter never invokes a model.
Source rows/bytes alone are not a protected decision acknowledgment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime

from zacai.contextual_recovery_record import ContextualRecoveryReceipt, encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.interfaces.followup_authorization import (
    FollowupHostSnapshot,
    _owner_digest,
    scope_from_snapshot,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import NamedAdmissionRecord, SqliteNamedAdmissionStore
from zacai.interfaces.named_candidate_rows import verify_named_candidate_rows
from zacai.interfaces.named_decision_capture import _find_named
from zacai.interfaces.named_followup_decision import (
    NamedFollowupDecision,
    decode_named_decision,
    encode_named_decision,
    named_manifest_digest,
    validate_declared_bindings,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.text_followup_context import AssembledFollowup, CanonicalFollowupAssembler
from zacai.interfaces.text_turn_capture import TextTurnRecoveryReceipt
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import SourceSystem
from zacai.state_repository import get_effective_source_classification


class NamedDecisionAdmissionError(ValueError):
    """Fixed diagnostic without canonical/private backend details."""


@dataclass(frozen=True)
class QuestionRecoveryInputs:
    packet_receipt: ContextualRecoveryReceipt = field(repr=False)
    question_receipt: TextTurnRecoveryReceipt = field(repr=False)


@dataclass(frozen=True)
class _CanonicalDecisionObservation:
    reference: EvidenceReference
    decision: NamedFollowupDecision = field(repr=False)


class CanonicalNamedDecisionAdmission:
    def __init__(self, *, store: SqliteNamedAdmissionStore, operation: NamedSessionOperation,
                 assembler: CanonicalFollowupAssembler,
                 recovery_inputs: Callable[[NamedAdmissionRecord], QuestionRecoveryInputs],
                 snapshot_builder: Callable[[AssembledFollowup, InterfacePrincipal], FollowupHostSnapshot],
                 clock: HostObservedClock) -> None:
        if (
            type(store) is not SqliteNamedAdmissionStore or type(operation) is not NamedSessionOperation
            or type(assembler) is not CanonicalFollowupAssembler or type(clock) is not HostObservedClock
            or operation.host_clock is not clock or store._clock is not clock
            or assembler._capture._clock is not clock or not callable(recovery_inputs) or not callable(snapshot_builder)
        ):
            raise NamedDecisionAdmissionError("named admission host dependencies unavailable")
        self._store, self._operation, self._assembler = store, operation, assembler
        self._recovery_inputs, self._snapshot_builder, self._clock = recovery_inputs, snapshot_builder, clock

    def _record(self, handle: str, principal: InterfacePrincipal, now: datetime) -> NamedAdmissionRecord:
        if type(principal) is not InterfacePrincipal or type(now) is not datetime or now.utcoffset() is None or now > self._clock():
            raise ValueError("actual principal/time required")
        current = self._operation.establish()
        if current.principal != principal:
            raise ValueError("current original principal changed")
        record = self._store.get(handle=handle, session_binding=current.binding_digest)
        if record.phase not in ("QUESTION_BOUND", "DECISION_BOUND") or record.question_reference is None:
            raise ValueError("protected canonical question attachment required")
        return record

    def _canonical(self, record: NamedAdmissionRecord, now: datetime) -> _CanonicalDecisionObservation | None:
        c = self._assembler._capture
        with c._factory() as session:
            _assert_ledger_isolation(session)
            source = _find_named(session, f"packet-followup-named-decision/{record.manifest.request_id}")
            if source is None:
                if record.phase == "DECISION_BOUND":
                    raise ValueError("attached decision Source missing")
                return None
            if source.system is not SourceSystem.USER_INSTRUCTION or source.trust_boundary is not B.BRAINSTORM or source.data_classification is not C.CONFIDENTIAL or get_effective_source_classification(session, source_id=source.id) is not C.CONFIDENTIAL:
                raise ValueError("canonical named decision family denied")
            raw = _bytes(session, c._artifacts, source)
            decision = decode_named_decision(raw)
            reference = EvidenceReference(source_id=source.id, content_hash=content_hash_of(raw),
                                          trust_boundary=B.BRAINSTORM, effective_classification=C.CONFIDENTIAL)
            if (raw != encode_named_decision(decision) or source.content_hash != reference.content_hash
                or source.external_ref != f"packet-followup-named-decision/{decision.manifest.request_id}"
                or source.captured_at != decision.admitted_at or decision.bound_at > now
                or (record.decision_reference is not None and record.decision_reference != reference)):
                raise ValueError("canonical named decision binding denied")
            return _CanonicalDecisionObservation(reference, decision)

    def _assemble(self, record: NamedAdmissionRecord, principal: InterfacePrincipal,
                  observed_at: datetime) -> tuple[AssembledFollowup, FollowupRequest, QuestionRecoveryInputs]:
        inputs = self._recovery_inputs(record)  # actual trusted receipt lookup OUTSIDE SQL
        if type(inputs) is not QuestionRecoveryInputs or type(inputs.packet_receipt) is not ContextualRecoveryReceipt or type(inputs.question_receipt) is not TextTurnRecoveryReceipt or record.question_reference is None:
            raise ValueError("exact retained question/packet proof required")
        if (content_hash_of(canonical_bytes(inputs.question_receipt.model_dump(mode="json"))) != record.question_recovery_digest
            or content_hash_of(encode_recovery_receipt(inputs.packet_receipt)) != record.manifest.packet_receipt_digest):
            raise ValueError("retained proof changed")
        assembled = self._assembler.assemble(principal=principal,
            source_id=record.question_reference.source_id, expected_turn_digest=record.question_reference.content_hash,
            retained_receipt=inputs.packet_receipt, expected_receipt_digest=record.manifest.packet_receipt_digest,
            recovery_receipt=inputs.question_receipt)
        turn = assembled.saved_turn.turn
        if (assembled.saved_turn.reference != record.question_reference
            or content_hash_of(turn.original_text.encode("utf-8")) != record.question_digest
            or len(turn.original_text.encode("utf-8")) != record.question_bytes
            or turn.request_id != record.manifest.request_id
            or turn.conversation_id != record.manifest.conversation_id
            or record.admitted_at is None or not record.admitted_at <= turn.recorded_at <= observed_at <= self._clock()):
            raise ValueError("original question/admission chronology changed")
        # Only immutable original observation is restored; no body/event/source/
        # budget/route field is substituted. Actual assembler proves current rows.
        event = assembled.context.task.event.model_copy(update={"observed_at": observed_at})
        context = replace(assembled.context, task=assembled.context.task.model_copy(update={"event": event}))
        return replace(assembled, context=context), prepare_followup_request(context), inputs

    def _snapshot(self, record: NamedAdmissionRecord, assembled: AssembledFollowup,
                  principal: InterfacePrincipal) -> FollowupHostSnapshot:
        snapshot = self._snapshot_builder(assembled, principal)  # actual trusted host config OUTSIDE SQL
        if (type(snapshot) is not FollowupHostSnapshot or snapshot.assembled is not assembled
            or snapshot.principal != principal or snapshot.route != record.manifest.route
            or snapshot.model_digest != record.manifest.model_digest
            or snapshot.owner != OwnerGrant(principal.identity, principal.scopes)):
            raise ValueError("actual route/model/owner differs from published manifest")
        return snapshot

    def _validate(self, record: NamedAdmissionRecord, principal: InterfacePrincipal,
                  decision: NamedFollowupDecision, assembled: AssembledFollowup,
                  request: FollowupRequest, inputs: QuestionRecoveryInputs) -> None:
        if (decision.manifest != record.manifest or decision.session_binding_digest != record.session_binding
            or decision.admitted_at != record.admitted_at or decision.processing_expires_at != record.processing_expires_at
            or decision.original_utf8_digest != record.question_digest
            or decision.question_reference != record.question_reference):
            raise ValueError("original admitted action changed")
        snapshot = self._snapshot(record, assembled, principal)
        if scope_from_snapshot(snapshot, run_id=record.manifest.run_id, builder_id=record.manifest.builder_id) != decision.run_scope:
            raise ValueError("actual host run scope changed")
        owner = snapshot.owner
        validate_declared_bindings(decision, owner=owner, turn=assembled.saved_turn.turn,
            turn_source_id=assembled.saved_turn.source_id, turn_receipt=inputs.question_receipt,
            packet_receipt=inputs.packet_receipt, request=request,
            runtime_endpoint=record.manifest.runtime_endpoint, tokenizer_digest=record.manifest.tokenizer_digest,
            request_template_digest=record.manifest.request_template_digest)
        current = self._operation.recheck(record.session_binding)
        if current.principal != principal or self._clock() >= decision.processing_expires_at:
            raise ValueError("original session or fixed processing deadline changed")

    def _final(self, handle: str, record: NamedAdmissionRecord,
               committed: _CanonicalDecisionObservation | None, decision: NamedFollowupDecision) -> None:
        """After ALL external callbacks: original store + canonical rows only.

        No session, owner, snapshot or recovery resolver callback follows these
        reads. The injected plain HostObservedClock alone checks final deadline.
        """
        current = self._store.get(handle=handle, session_binding=record.session_binding)
        if current != record:
            raise ValueError("operational original admission changed during callbacks")
        final = self._canonical(current, self._clock())
        if final != committed or (final is not None and final.decision != decision):
            raise ValueError("canonical original decision changed during callbacks")
        c = self._assembler._capture
        with c._factory() as session:
            _assert_ledger_isolation(session)
            verify_named_candidate_rows(
                session, artifacts=c._artifacts, decision=decision, as_of=self._clock()
            )
        if self._clock() >= decision.processing_expires_at:
            raise ValueError("fixed processing deadline elapsed after final reads")

    def prepare_original(self, handle: str, principal: InterfacePrincipal) -> FollowupRequest:
        """Restart reconstruction only when a real canonical decision exists.

        Returns a prepared request, not inference authority. No clock/observation
        inferred from manifest/bound time; exact stored original observation only.
        """
        result: FollowupRequest | None = None
        try:
            record = self._record(handle, principal, self._clock())
            committed = self._canonical(record, self._clock())
            if committed is None:
                raise ValueError("no committed original observation")
            decision = committed.decision
            assembled, request, inputs = self._assemble(record, principal, decision.original_observed_at)
            self._validate(record, principal, decision, assembled, request, inputs)
            self._final(handle, record, committed, decision)
            result = request
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedDecisionAdmissionError("original named request unavailable")
        return result

    def resolve(self, handle: str, principal: InterfacePrincipal, request: FollowupRequest,
                now: datetime) -> NamedFollowupDecision:
        result: NamedFollowupDecision | None = None
        try:
            if type(request) is not FollowupRequest or request != prepare_followup_request(request.context):
                raise ValueError("exact original prepared request required")
            record = self._record(handle, principal, now)
            committed = self._canonical(record, self._clock())
            observed = committed.decision.original_observed_at if committed is not None else request.context.task.event.observed_at
            assembled, original, inputs = self._assemble(record, principal, observed)
            if original != request:
                raise ValueError("submitted prepared request differs from original canonical inputs")
            if committed is not None:
                decision = committed.decision
            else:
                if (record.admitted_at is None or record.processing_expires_at is None
                    or record.question_reference is None or record.question_digest is None
                    or record.question_recovery_digest is None):
                    raise ValueError("complete original admission required")
                scope = scope_from_snapshot(self._snapshot(record, assembled, principal),
                    run_id=record.manifest.run_id, builder_id=record.manifest.builder_id)
                decision = NamedFollowupDecision(manifest=record.manifest,
                    manifest_digest=named_manifest_digest(record.manifest), admitted_at=record.admitted_at,
                    processing_expires_at=record.processing_expires_at, bound_at=self._clock(),
                    original_observed_at=observed, session_binding_digest=record.session_binding,
                    question_reference=record.question_reference, original_utf8_digest=record.question_digest,
                    question_receipt_digest=record.question_recovery_digest,
                    prepared_request_digest=original.digest, run_scope=scope)
            self._validate(record, principal, decision, assembled, original, inputs)
            self._final(handle, record, committed, decision)
            result = decision
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedDecisionAdmissionError("actual named admission unavailable")
        return result

    def recheck(self, handle: str, principal: InterfacePrincipal, decision: NamedFollowupDecision,
                now: datetime) -> object:
        okay = False
        try:
            if type(decision) is not NamedFollowupDecision:
                raise ValueError("exact canonical decision required")
            decode_named_decision(encode_named_decision(decision))
            record = self._record(handle, principal, now)
            committed = self._canonical(record, self._clock())
            if committed is not None and committed.decision != decision:
                raise ValueError("canonical original decision changed")
            assembled, request, inputs = self._assemble(record, principal, decision.original_observed_at)
            self._validate(record, principal, decision, assembled, request, inputs)
            self._final(handle, record, committed, decision)
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedDecisionAdmissionError("actual original admission held")
        return None

    def recheck_session(self, principal: InterfacePrincipal, decision: NamedFollowupDecision,
                        now: datetime) -> object:
        okay = False
        try:
            if type(decision) is not NamedFollowupDecision or type(now) is not datetime or now.utcoffset() is None or now > self._clock():
                raise ValueError("exact historical decision required")
            decode_named_decision(encode_named_decision(decision))
            current = self._operation.receipt_only(principal)
            owner = OwnerGrant(current.principal.identity, current.principal.scopes)
            if (current.principal != principal or _owner_digest(owner) != decision.manifest.owner_grant_digest
                or (owner.identity.issuer, owner.identity.subject) !=
                   (decision.manifest.actor_issuer, decision.manifest.actor_subject)):
                raise ValueError("historical actor changed")
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedDecisionAdmissionError("named history session held")
        return None
