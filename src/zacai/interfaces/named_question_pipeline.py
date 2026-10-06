"""Unmounted named question composition draft; not live processing readiness.

The host builds exact per-operation canonical dependencies. No default semantic
checker, runtime, owner, credentials or recovery acknowledgement is supplied.
An actual independently reviewed semantic checker is still a release prerequisite;
invented test callbacks cannot establish useful answer quality.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.followup_generation import (
    FollowupRequest,
    prepare_followup_request,
)
from zacai.intelligence.local_followup_runtime import NamedLocalFollowupRuntime
from zacai.intelligence.text_followup import FollowupReleaseGate, release_text_followup
from zacai.interfaces.followup_authority_recovery import (
    BrainstormFollowupAuthorityRecovery,
)
from zacai.interfaces.followup_authorization import (
    CanonicalFollowupAuthorization,
    ClaimedFollowup,
    FollowupClaim,
    FollowupConsentV2,
    _owner_digest,
    _reference,
    _source,
    decode_followup_consent,
    load_named_consent_inventory,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import (
    NamedAdmissionRecord,
    SqliteNamedAdmissionStore,
)
from zacai.interfaces.named_consent_binding import CanonicalNamedFollowupConsentBinding
from zacai.interfaces.named_decision_admission import CanonicalNamedDecisionAdmission
from zacai.interfaces.named_decision_binding import CanonicalNamedDecisionBinding
from zacai.interfaces.named_decision_capture import (
    CanonicalNamedDecisionCapture,
    _find_named,
)
from zacai.interfaces.named_decision_inventory import load_named_decision_inventory
from zacai.interfaces.named_decision_recovery import BrainstormNamedDecisionRecovery
from zacai.interfaces.named_followup_decision import named_decision_consent_id
from zacai.interfaces.named_published_display import CanonicalNamedPublishedDisplayGate
from zacai.interfaces.named_recovery_inputs import (
    RetainedNamedDecisionProofs,
    RetainedQuestionRecoveryInputs,
)
from zacai.interfaces.named_runtime_binding import FixedLocalNamedRuntimeBinding
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_reply_capture import (
    CanonicalTextReplyCapture,
    HistoricalReplyStatus,
    SavedHistoricalTextReply,
    SavedTextReply,
    text_reply_request_id,
)
from zacai.interfaces.text_reply_protection import BrainstormTextReplyProtection
from zacai.interfaces.text_turn_capture import (
    CanonicalTextTurnCapture,
    SavedTextTurn,
)
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceSystem


class NamedQuestionPipelineError(ValueError):
    """Private-safe hold; committed pending Sources are not automatic retries."""


@dataclass(frozen=True)
class NamedAttemptComponents:
    """Host-created per-run graph, not permission from constructor or callback."""

    admission: CanonicalNamedDecisionAdmission = field(repr=False)
    decisions: CanonicalNamedDecisionCapture = field(repr=False)
    binding: CanonicalNamedFollowupConsentBinding = field(repr=False)
    authorization: CanonicalFollowupAuthorization = field(repr=False)
    replies: CanonicalTextReplyCapture = field(repr=False)
    runtime: NamedLocalFollowupRuntime = field(repr=False)
    semantic: FollowupReleaseGate = field(repr=False)


class CanonicalNamedAskPipeline:
    def __init__(
        self,
        *,
        store: SqliteNamedAdmissionStore,
        clock: HostObservedClock,
        turns: CanonicalTextTurnCapture,
        assembler: CanonicalFollowupAssembler,
        display: CanonicalNamedPublishedDisplayGate,
        question_inputs: RetainedQuestionRecoveryInputs,
        build_history: Callable[
            [NamedSessionOperation, NamedAdmissionRecord], CanonicalTextReplyCapture
        ],
        build_attempt: Callable[
            [NamedSessionOperation, NamedAdmissionRecord, SavedTextTurn, ContextualRecoveryReceipt],
            NamedAttemptComponents,
        ],
    ):
        if (
            type(store) is not SqliteNamedAdmissionStore
            or type(clock) is not HostObservedClock
            or type(turns) is not CanonicalTextTurnCapture
            or type(assembler) is not CanonicalFollowupAssembler
            or type(display) is not CanonicalNamedPublishedDisplayGate
            or type(question_inputs) is not RetainedQuestionRecoveryInputs
            or question_inputs._p is not display._p
            or question_inputs._question is not display._q
            or store._clock is not clock
            or turns._clock is not clock
            or assembler._capture is not turns
            or display.host_clock is not clock
            or display._p._factory is not turns._factory
            or display._p._artifacts is not turns._artifacts
            or display._q is not turns._protection
            or not callable(build_attempt)
            or not callable(build_history)
        ):
            raise NamedQuestionPipelineError("named host composition unavailable")
        self._store, self._clock, self._turns, self._assembler = store, clock, turns, assembler
        self._display, self._build, self._question_inputs = display, build_attempt, question_inputs
        self._build_history = build_history

    def _active(
        self,
        operation: NamedSessionOperation,
        handle: str,
        admitted: NamedAdmissionRecord,
        original_utf8: bytes,
    ) -> tuple[InterfacePrincipal, NamedAdmissionRecord]:
        principal, current, _deadline = self._active_with_deadline(
            operation, handle, admitted, original_utf8
        )
        return principal, current

    def _active_with_deadline(
        self,
        operation: NamedSessionOperation,
        handle: str,
        admitted: NamedAdmissionRecord,
        original_utf8: bytes,
    ) -> tuple[InterfacePrincipal, NamedAdmissionRecord, datetime]:
        if (
            type(operation) is not NamedSessionOperation
            or operation.host_clock is not self._clock
            or type(admitted) is not NamedAdmissionRecord
            or type(original_utf8) is not bytes
            or not 0 < len(original_utf8) <= 8000
        ):
            raise ValueError("exact original operation required")
        admitted = NamedAdmissionRecord.model_validate(admitted)
        text = original_utf8.decode("utf-8", errors="strict")
        if (
            not text.strip()
            or len(text) > 2000
            or admitted.phase == "ISSUED"
            or content_hash_of(original_utf8) != admitted.question_digest
            or len(original_utf8) != admitted.question_bytes
        ):
            raise ValueError("original named input differs")
        actual = operation.recheck(admitted.session_binding)
        current = self._store.get(handle=handle, session_binding=admitted.session_binding)
        if (
            current.manifest != admitted.manifest
            or current.session_binding != admitted.session_binding
            or current.admitted_at != admitted.admitted_at
            or current.processing_expires_at != admitted.processing_expires_at
            or current.question_digest != admitted.question_digest
            or current.question_bytes != admitted.question_bytes
        ):
            raise ValueError("original action changed")
        actual = operation.recheck(admitted.session_binding)
        now = self._clock()
        if (
            current.admitted_at is None
            or current.processing_expires_at is None
            or not current.admitted_at <= now < current.processing_expires_at
            or now >= actual.effective_expires_at
        ):
            raise ValueError("original named window held")
        return actual.principal, current, actual.effective_expires_at

    def _components(
        self,
        operation: NamedSessionOperation,
        record: NamedAdmissionRecord,
        turn: SavedTextTurn,
        packet: ContextualRecoveryReceipt,
    ) -> NamedAttemptComponents:
        graph = self._build(operation, record, turn, packet)
        if (
            type(graph) is not NamedAttemptComponents
            or type(graph.admission) is not CanonicalNamedDecisionAdmission
            or type(graph.decisions) is not CanonicalNamedDecisionCapture
            or type(graph.binding) is not CanonicalNamedFollowupConsentBinding
            or type(graph.authorization) is not CanonicalFollowupAuthorization
            or type(graph.replies) is not CanonicalTextReplyCapture
            or type(graph.runtime) is not NamedLocalFollowupRuntime
            or graph.admission._operation is not operation
            or graph.admission._store is not self._store
            or graph.admission._assembler is not self._assembler
            or graph.admission._clock is not self._clock
            or graph.decisions._admission is not graph.admission
            or graph.decisions._clock is not self._clock
            or graph.decisions._factory is not self._turns._factory
            or graph.decisions._artifacts is not self._turns._artifacts
            or graph.binding._admission is not graph.admission
            or graph.binding.host_clock is not self._clock
            or graph.authorization._clock is not self._clock
            or graph.authorization._factory is not self._turns._factory
            or graph.authorization._store is not self._turns._artifacts
            or graph.authorization.named_binding is not graph.binding
            or not graph.authorization._named_only
            or graph.replies._authorization is not graph.authorization
            or graph.replies._assembler is not self._assembler
            or graph.runtime.route != record.manifest.route
            or graph.runtime.model_digest != record.manifest.model_digest
            or graph.replies._release_gate is not graph.semantic
            or not callable(graph.semantic.recheck)
        ):
            raise ValueError("actual per-original-operation graph required")
        decision_binding = graph.decisions._binding
        profile = graph.runtime._profile
        if (
            type(decision_binding) is not CanonicalNamedDecisionBinding
            or type(profile) is not FixedLocalNamedRuntimeBinding
            or decision_binding._runtime is not profile
            or graph.runtime._token_counter is not profile._counter
            or profile.route != record.manifest.route
            or profile.model_digest != record.manifest.model_digest
            or record.manifest.runtime_endpoint != "http://127.0.0.1:11434"
        ):
            raise ValueError("exact published runtime graph required")
        question_inputs = self._question_inputs
        proofs = graph.binding._decision_proofs
        if (
            decision_binding._clock is not self._clock
            or decision_binding._assembler is not self._assembler
            or graph.admission._recovery_inputs is not question_inputs
            or decision_binding._recovery_inputs != question_inputs.for_decision
            or graph.binding._resolver is not question_inputs
            or type(proofs) is not RetainedNamedDecisionProofs
            or proofs._question_inputs is not question_inputs
            or type(proofs._decision) is not BrainstormNamedDecisionRecovery
            or proofs._decision._fresh_binding != decision_binding.verify_historical
            or proofs._decision._protector is not question_inputs._p
            or proofs._decision.host_clock is not self._clock
            or graph.decisions._protection is not proofs._decision
            or graph.replies._capture is not self._turns
            or type(graph.replies._protection) is not BrainstormTextReplyProtection
            or graph.replies._protection._protector is not question_inputs._p
            or graph.replies._protection.host_clock is not self._clock
            or graph.replies._protection.named_binding is not graph.binding
            or type(graph.authorization._recovery) is not BrainstormFollowupAuthorityRecovery
            or graph.authorization._recovery._protector is not question_inputs._p
            or graph.authorization._recovery.host_clock is not self._clock
            or graph.authorization._recovery.named_binding is not graph.binding
        ):
            raise ValueError("canonical proof graph differs")
        pins = profile.pins()
        if (
            pins.tokenizer_digest != record.manifest.tokenizer_digest
            or pins.request_template_digest != record.manifest.request_template_digest
        ):
            raise ValueError("published tokenizer or serializer changed")
        return graph

    def submit(
        self,
        *,
        operation: NamedSessionOperation,
        admission_handle: str,
        admitted_record: NamedAdmissionRecord,
        original_utf8: bytes,
    ) -> SavedTextReply:
        result = None
        try:
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            # Bound/replayed actions cannot allocate a fresh runtime/chat attempt.
            if record.phase != "ADMITTED":
                raise ValueError("named question already bound; reconcile retained result")
            self._display.verify_fresh(operation, record)
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            # Reuse the concrete canonical receipt resolver, never construct a
            # shape-only receipt. This private seam needs a reviewed public API.
            rows = self._display._rows(record, self._clock())
            packet = self._display._packet(record, rows)
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            turn = self._turns.capture(
                principal=principal,
                request_id=record.manifest.request_id,
                conversation_id=record.manifest.conversation_id,
                original_utf8=original_utf8,
                retained_receipt=packet,
                expected_receipt_digest=record.manifest.packet_receipt_digest,
                parent_references=tuple(p.reference for p in record.manifest.parents),
            )
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            record = self._store.attach_question(
                handle=admission_handle,
                session_binding=record.session_binding,
                reference=turn.reference,
                recovery_digest=content_hash_of(
                    canonical_bytes(turn.recovery_receipt.model_dump(mode="json"))
                ),
            )
            assembled = self._assembler.assemble(
                principal=principal,
                source_id=turn.source_id,
                expected_turn_digest=turn.turn_digest,
                retained_receipt=packet,
                expected_receipt_digest=record.manifest.packet_receipt_digest,
                recovery_receipt=turn.recovery_receipt,
            )
            original_request = prepare_followup_request(assembled.context)
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            graph = self._components(operation, record, turn, packet)
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            decision = graph.decisions.capture(
                admission_handle=admission_handle,
                principal=principal,
                original_request=original_request,
            )
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            record = self._store.attach_decision(
                handle=admission_handle,
                session_binding=record.session_binding,
                reference=decision.reference,
                recovery_digest=content_hash_of(
                    canonical_bytes(decision.recovery_receipt.model_dump(mode="json"))
                ),
            )
            if record.decision_recovery_digest is None:
                raise ValueError("actual decision recovery digest required")
            consent = FollowupConsentV2(
                id=named_decision_consent_id(decision.reference.source_id),
                scope=decision.decision.run_scope,
                approved_at=decision.decision.admitted_at,
                expires_at=decision.decision.processing_expires_at,
                human_reference=f"named-owner-action/{decision.decision.manifest.request_id}",
                decision_reference=decision.reference,
                decision_recovery_digest=record.decision_recovery_digest,
            )
            last_session_deadline: datetime | None = None

            def active() -> InterfacePrincipal:
                nonlocal last_session_deadline
                principal, _ = self._active(
                    operation, admission_handle, admitted_record, original_utf8
                )
                if (
                    graph.binding.verify_active(
                        handle=admission_handle, consent=consent, now=self._clock()
                    )
                    is not None
                ):
                    raise ValueError("original named consent held")
                principal, _, last_session_deadline = self._active_with_deadline(
                    operation, admission_handle, admitted_record, original_utf8
                )
                return principal

            active()
            consent_source_id = graph.authorization.record(consent)
            active()
            graph.runtime.preflight(original_request)
            active()
            claimed = graph.authorization.claim(
                approval_id=consent_source_id, scope=consent.scope, request=original_request
            )
            active()
            graph.authorization.recheck(claimed, original_request)
            active()

            def before_dispatch(actual_request: FollowupRequest) -> None:
                if actual_request is not original_request:
                    raise ValueError("original dispatch request differs")
                active()
                graph.authorization.recheck(claimed, original_request)
                active()
                graph.authorization.recheck_dispatch_rows(claimed, original_request)
                if last_session_deadline is None or self._clock() >= last_session_deadline:
                    raise ValueError("original session expired during dispatch rows")

            draft = graph.runtime.generate(original_request, before_dispatch=before_dispatch)
            active()
            graph.authorization.recheck(claimed, original_request)
            usage = graph.runtime.usage
            if usage is None:
                raise ValueError("actual runtime usage required")
            release = release_text_followup(original_request.context, draft, gate=graph.semantic)
            principal = active()
            graph.authorization.recheck(claimed, original_request)
            saved = graph.replies.capture(
                principal=principal,
                request=original_request,
                claimed=claimed,
                release=release,
                usage=usage,
                retained_receipt=packet,
                text_receipt=turn.recovery_receipt,
            )
            active()
            # Final SQL row/ACL read follows every external session/recovery callback.
            graph.replies._final_named_rows(
                saved.reply, saved.source_id, saved.reply_digest, active=True
            )
            if last_session_deadline is None or self._clock() >= min(
                consent.expires_at, last_session_deadline
            ):
                raise ValueError("final original named deadline held")
            result = saved
        except Exception:  # noqa: BLE001,S110 - fixed private-safe hold.
            pass
        if result is None:
            raise NamedQuestionPipelineError("named question held; reconcile original action")
        return result

    def recheck(
        self,
        *,
        operation: NamedSessionOperation,
        admission_handle: str,
        admitted_record: NamedAdmissionRecord,
        original_utf8: bytes,
        saved: SavedTextReply,
    ) -> SavedTextReply:
        result = None
        try:
            if type(saved) is not SavedTextReply:
                raise ValueError("actual retained reply required")
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            if record.phase != "DECISION_BOUND" or record.question_reference is None:
                raise ValueError("original canonical named attachments required")
            inputs = self._question_inputs(record)
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            if record.question_reference is None:
                raise ValueError("original question attachment required")
            turn = self._turns.load(
                principal=principal,
                source_id=record.question_reference.source_id,
                expected_turn_digest=record.question_reference.content_hash,
                retained_receipt=inputs.packet_receipt,
                expected_receipt_digest=record.manifest.packet_receipt_digest,
                recovery_receipt=inputs.question_receipt,
            )
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            graph = self._components(operation, record, turn, inputs.packet_receipt)
            request = graph.admission.prepare_original(admission_handle, principal)
            if request.digest != saved.reply.claim.request_digest:
                raise ValueError("original reply request differs")
            graph.authorization.recheck(
                ClaimedFollowup(saved.reply.claim, saved.reply.claim_reference), request
            )
            principal, record = self._active(
                operation, admission_handle, admitted_record, original_utf8
            )
            current = graph.replies.load(
                principal=principal,
                source_id=saved.source_id,
                expected_reply_digest=saved.reply_digest,
                retained_receipt=inputs.packet_receipt,
                text_receipt=inputs.question_receipt,
                recovery_receipt=saved.recovery_receipt,
            )
            if current != saved:
                raise ValueError("retained reply changed")
            _, record, session_deadline = self._active_with_deadline(
                operation, admission_handle, admitted_record, original_utf8
            )
            graph.replies._final_named_rows(
                saved.reply, saved.source_id, saved.reply_digest, active=True
            )
            if record.processing_expires_at is None or self._clock() >= min(
                record.processing_expires_at, session_deadline
            ):
                raise ValueError("original final reply deadline held")
            result = current
        except Exception:  # noqa: BLE001,S110 - fixed private-safe hold.
            pass
        if result is None:
            raise NamedQuestionPipelineError("original retained answer held")
        return result

    def _history_components(
        self, operation: NamedSessionOperation, record: NamedAdmissionRecord
    ) -> CanonicalTextReplyCapture:
        replies = self._build_history(operation, record)
        if type(replies) is not CanonicalTextReplyCapture:
            raise ValueError("actual historical capture graph required")
        binding = replies._named_binding
        protection = replies._protection
        authority = replies._authorization
        if (
            type(binding) is not CanonicalNamedFollowupConsentBinding
            or binding._admission._operation is not operation
            or binding._admission._store is not self._store
            or binding._admission._clock is not self._clock
            or binding._admission._assembler is not self._assembler
            or binding._admission._recovery_inputs is not self._question_inputs
            or binding._resolver is not self._question_inputs
            or binding.host_clock is not self._clock
            or replies._assembler is not self._assembler
            or replies._capture is not self._turns
            or type(protection) is not BrainstormTextReplyProtection
            or protection._protector is not self._question_inputs._p
            or protection.host_clock is not self._clock
            or protection.named_binding is not binding
            or type(authority) is not CanonicalFollowupAuthorization
            or authority._clock is not self._clock
            or authority._factory is not self._turns._factory
            or authority._store is not self._turns._artifacts
            or authority.named_binding is not binding
            or type(authority._recovery) is not BrainstormFollowupAuthorityRecovery
            or authority._recovery._protector is not self._question_inputs._p
            or authority._recovery.host_clock is not self._clock
            or authority._recovery.named_binding is not binding
        ):
            raise ValueError("historical host graph differs")
        proofs = binding._decision_proofs
        if (
            type(proofs) is not RetainedNamedDecisionProofs
            or proofs._question_inputs is not self._question_inputs
            or proofs.host_clock is not self._clock
            or type(proofs._decision) is not BrainstormNamedDecisionRecovery
            or proofs._decision._protector is not self._question_inputs._p
            or proofs._decision.host_clock is not self._clock
        ):
            raise ValueError("historical actual decision proof graph differs")
        decision_binding = getattr(proofs._decision._fresh_binding, "__self__", None)
        if (
            type(decision_binding) is not CanonicalNamedDecisionBinding
            or proofs._decision._fresh_binding != decision_binding.verify_historical
            or decision_binding._clock is not self._clock
            or decision_binding._assembler is not self._assembler
            or decision_binding._recovery_inputs != self._question_inputs.for_decision
        ):
            raise ValueError("actual historical canonical binding required")
        return replies

    def reconcile(
        self, *, operation: NamedSessionOperation, decision_reference: EvidenceReference
    ) -> SavedHistoricalTextReply | HistoricalReplyStatus:
        """Resolve existing original output by canonical identity, never retry.

        Selector is a pinned canonical decision Source, not an expired browser
        nonce/session grant. The current owner/session, exact bytes, dependencies
        and retained real receipts remain required. No current runtime probe,
        semantic call, admission extension, capture/claim/generation or repair.
        """
        result = None
        try:
            if (
                type(operation) is not NamedSessionOperation
                or operation.host_clock is not self._clock
                or type(decision_reference) is not EvidenceReference
            ):
                raise ValueError("actual historical selector required")
            decision_reference = EvidenceReference.model_validate(decision_reference)
            verified = operation.establish()
            principal = verified.principal
            now = self._clock()
            self._turns._principal(principal, now)
            with self._turns._factory() as session:
                _assert_ledger_isolation(session)
                inventory = load_named_decision_inventory(
                    session,
                    artifacts=self._turns._artifacts,
                    reference=decision_reference,
                    as_of=now,
                )
                decision = inventory.decision
                scope = decision.run_scope
                if (
                    scope.actor_issuer != principal.identity.issuer
                    or scope.actor_subject != principal.identity.subject
                    or scope.owner_grant_digest
                    != _owner_digest(OwnerGrant(principal.identity, principal.scopes))
                ):
                    raise ValueError("historical owner differs")
                consent_id = named_decision_consent_id(decision_reference.source_id)
                source = _find_named(session, f"packet-followup-consent/{consent_id}")
                if source is None:
                    raise ValueError("no retained original consent")
                _, raw = _source(
                    session,
                    self._turns._artifacts,
                    source.id,
                    SourceSystem.USER_INSTRUCTION,
                    "packet-followup-consent/",
                )
                consent = decode_followup_consent(raw)
                if (
                    type(consent) is not FollowupConsentV2
                    or consent.id != consent_id
                    or consent.decision_reference != decision_reference
                ):
                    raise ValueError("historical consent differs")
                if (
                    load_named_consent_inventory(
                        session, artifacts=self._turns._artifacts, consent=consent, as_of=now
                    )
                    != inventory
                ):
                    raise ValueError("historical decision inventory differs")
                claim_source = _find_named(session, f"packet-followup-claim/{source.id}")
                if claim_source is None:
                    raise ValueError("no retained original claim")
                _, claim_raw = _source(
                    session,
                    self._turns._artifacts,
                    claim_source.id,
                    SourceSystem.MANUAL,
                    "packet-followup-claim/",
                )
                claim = FollowupClaim.model_validate_json(claim_raw)
                claim_ref = _reference(claim_source)
                if (
                    canonical_bytes(claim.model_dump(mode="json")) != claim_raw
                    or claim.consent_reference != _reference(source)
                    or claim.run_scope != scope
                    or claim.request_digest != decision.prepared_request_digest
                    or claim_source.captured_at != claim.claimed_at
                    or not decision.bound_at <= claim.claimed_at < consent.expires_at
                ):
                    raise ValueError("historical original claim differs")
                reply_id = text_reply_request_id(scope.run_id, claim_ref, claim.request_digest)
                reply_source = _find_named(session, f"text-reply/{reply_id}")
                if reply_source is None:
                    raise ValueError("no retained output; original attempt remains consumed")
                source_id, digest = reply_source.id, reply_source.content_hash
                question = session.get(Source, decision.question_reference.source_id)
                if question is None or _reference(question) != decision.question_reference:
                    raise ValueError("canonical question missing or changed")
                # Re-read through the canonical turn reader before any external
                # proof callback, including current raw/effective source ACLs.
                turn, _ = self._turns._read(session, question)
                record = NamedAdmissionRecord(
                    phase="DECISION_BOUND",
                    manifest=decision.manifest,
                    session_binding=decision.session_binding_digest,
                    admitted_at=decision.admitted_at,
                    processing_expires_at=decision.processing_expires_at,
                    question_digest=decision.original_utf8_digest,
                    question_bytes=len(turn.original_text.encode("utf-8")),
                    question_reference=decision.question_reference,
                    question_recovery_digest=decision.question_receipt_digest,
                    decision_reference=decision_reference,
                    decision_recovery_digest=consent.decision_recovery_digest,
                )
            # The record above is lookup data, never operational admission proof.
            inputs = self._question_inputs(record)
            replies = self._history_components(operation, record)
            named_binding = replies._named_binding
            protection = replies._protection
            if (
                type(named_binding) is not CanonicalNamedFollowupConsentBinding
                or type(protection) is not BrainstormTextReplyProtection
            ):
                raise ValueError("actual historical proof receiver required")
            named_binding._decision_proofs.resolve_decision(record)
            with self._turns._factory() as session:
                _assert_ledger_isolation(session)
                retained_source = session.get(Source, source_id)
                if retained_source is None:
                    raise ValueError("retained original reply missing")
                actual_reply, actual_digest = replies._read(session, retained_source)
                if (
                    actual_digest != digest
                    or actual_reply.claim != claim
                    or actual_reply.claim_reference != claim_ref
                ):
                    raise ValueError("retained original reply differs")
            from zacai.interfaces.text_reply_capture import text_reply_receipt_key

            key = text_reply_receipt_key(source_id, actual_digest)
            present = protection._protector._reader.exists(key)
            if type(present) is not bool:
                raise ValueError("retained receipt visibility unknown")
            receipt = protection._load_receipt(key) if present else None
            result = replies.load_history(
                operation=operation,
                principal=principal,
                source_id=source_id,
                expected_reply_digest=actual_digest,
                retained_receipt=inputs.packet_receipt,
                text_receipt=inputs.question_receipt,
                recovery_receipt=receipt,
            )
        except Exception:  # noqa: BLE001,S110 - private-safe status only.
            pass
        if result is None:
            raise NamedQuestionPipelineError(
                "original retained answer unavailable; no retry issued"
            )
        return result
