"""Explicit complete PERSONAL request preparation and observed owner task flow."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from html import escape
from threading import Lock, RLock
from urllib.parse import parse_qs, urlsplit

from starlette.requests import Request

from zacai.backup_artifacts import _assert_personal_custody_append_capacity
from zacai.claude_local_custody import _SCOPE
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import (
    ContextualOutcome,
    check_history_contextual_evaluation,
)
from zacai.intelligence.contextual_review import (
    render_contextual_preview,
    validate_contextual_review,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_contextual_codec import decode_history_contextual_packet
from zacai.intelligence.history_contextual_runtime import (
    LocalHistoryContextualRuntime,
    history_contextual_runtime_digest,
)
from zacai.intelligence.history_declaration_protection import (
    PersonalHistoryDeclarationReceiptV1,
    protect_history_declaration,
)
from zacai.intelligence.history_generation_review_declaration import (
    encode_history_generation_review_declaration,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_publication_admission import (
    AcknowledgedHistoryPublicationAdmission,
    _not_withdrawn,
    _record_posted_history_admission,
)
from zacai.intelligence.history_publication_generation import (
    CanonicalPersonalHistoryPublicationAuthorization,
    retain_personal_history_publication_output,
)
from zacai.intelligence.history_publication_protection import protect_history_assessment
from zacai.intelligence.history_publication_review import (
    CanonicalPersonalHistoryReviewAuthorization,
    HistoryPublicationAssessmentV1,
    PersonalHistoryRetainedAssessment,
    capture_history_publication_assessment,
    release_history_reviewed_text,
)
from zacai.intelligence.history_publication_withdrawal import (
    RetainedHistoryWithdrawal,
    _event_current,
    _target_current,
    load_history_withdrawal_target,
    withdraw_history_publication,
)
from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter
from zacai.intelligence.history_review_retention import (
    BOUNDARIES,
    LABELS,
    HistoryDeclarationContext,
    _ids,
    _parts,
    history_declaration_owner,
)
from zacai.intelligence.history_review_runtime import (
    LocalHistoryReviewRuntime,
    history_review_derivation_digest,
    history_review_runtime_digest,
    history_review_wire_digest,
)
from zacai.intelligence.local_contextual_runtime import _context_tokens, _fragment_verify_runtime
from zacai.intelligence.local_review_runtime import _http, verify_model
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.history_publication_action import _observe_history_http_post
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.personal_history_factory import (
    PersonalHistoryTaskConfiguration,
    PreparedPersonalHistoryDeclaration,
    prepare_personal_history_task,
)
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import _USER, _cookie
from zacai.review_authorization import _lock

_NATIVE_MONOTONIC = time.monotonic


class HistoryPublicationWebError(ValueError):
    """Fixed withheld response; recorded bodies may require reconciliation."""


class HistoryApprovalAlreadyEntered(HistoryPublicationWebError):
    """An observed APPROVE encountered the already-entered purpose gate."""


@dataclass(frozen=True, repr=False)
class HistoryPublicationResponse:
    html: str
    deadline: datetime
    kind: str
    receipt: PersonalHistoryDeclarationReceiptV1 | None = None
    reviewer: CanonicalPersonalHistoryReviewAuthorization | None = None
    assessment: PersonalHistoryRetainedAssessment | None = None
    withdrawal: RetainedHistoryWithdrawal | None = None
    rows: tuple[tuple[tuple[str, object], ...], ...] = ()


def _reviewed_result_html(
    gate: CanonicalPersonalHistoryReviewAuthorization,
    assessment: PersonalHistoryRetainedAssessment,
    text: str | None,
) -> str:
    if assessment.outcome is ContextualOutcome.NEEDS_CLARIFICATION:
        try:
            # The unchanged caller has already protected/rechecked the original
            # result. This branch displays one reviewed gap, never the held reply.
            if (
                type(gate) is not CanonicalPersonalHistoryReviewAuthorization
                or type(assessment) is not PersonalHistoryRetainedAssessment
                or type(assessment.assessment) is not HistoryPublicationAssessmentV1
                or gate._phase != "DELIVERY_RELEASED"
                or gate._result is not assessment
                or gate._assessment is not assessment.assessment
                or text is not None
            ):
                raise ValueError("original protected clarification result required")
            packet = decode_history_contextual_packet(gate._packet_raw)
            request = gate._generation._request
            if (
                packet.request() != request
                or check_history_contextual_evaluation(
                    assessment.assessment.evaluation, gate._packet_raw
                )
                is not ContextualOutcome.NEEDS_CLARIFICATION
            ):
                raise ValueError("exact all-PASS clarification evaluation required")
            review = validate_contextual_review(packet.review, request.context())
            gaps = (*review.conflicts, *review.clarifications)
            if not gaps:
                raise ValueError("a validated material question is required")
            gap = gaps[0]
            return (
                '<section class="decision-card"><h1>One quick question</h1>'
                "<p>I need one detail before I can finish. The full answer is still on hold. "
                "This uses earlier conversations, so current details may need an update.</p>"
                '<pre style="white-space:pre-wrap;overflow-wrap:anywhere">'
                + escape(gap.question)
                + "\nWhy it matters: "
                + escape(gap.reason)
                + "</pre></section>"
            )
        except Exception:  # noqa: BLE001,S110 - fixed withheld response, no private diagnostics
            pass
    if assessment.outcome is not ContextualOutcome.REVIEWED_PASS or text is None:
        return (
            "<h1>Reply withheld</h1><p>"
            + escape(assessment.outcome.value)
            + ": no reply is released.</p>"
        )
    packet = decode_history_contextual_packet(gate._packet_raw)
    main = render_contextual_preview(packet.review, gate._generation._request.context())
    return (
        '<section class="decision-card"><h1>Reviewed historical-context reply</h1>'
        "<p>This uses dated historical evidence; current facts may require fresh verification.</p>"
        '<pre style="white-space:pre-wrap;overflow-wrap:anywhere">'
        + escape(main)
        + "</pre><details><summary>Sources, dates and full retained evidence</summary>"
        '<pre style="white-space:pre-wrap;overflow-wrap:anywhere">'
        + escape(text)
        + "</pre></details></section>"
    )


class HistoryPublicationWeb:
    """Complete family only, entered solely by actual original APPROVE POST."""

    def __init__(
        self,
        *,
        continuity: NamedSessionContinuity,
        prepared: PreparedPersonalHistoryDeclaration,
        configuration: PersonalHistoryTaskConfiguration,
        review_counter: OllamaQwenHistoryReviewTokenCounter,
        rubric_utf8: bytes,
        template_utf8: bytes,
    ) -> None:
        if (
            type(continuity) is not NamedSessionContinuity
            or type(prepared) is not PreparedPersonalHistoryDeclaration
            or type(configuration) is not PersonalHistoryTaskConfiguration
            or type(review_counter) is not OllamaQwenHistoryReviewTokenCounter
            or prepared.protector._operation._source is not continuity
            or prepared.protector._clock is not continuity._clock
            or prepared.protector._factory is not configuration.factory
            or prepared.protector._artifacts is not configuration.artifacts
            or type(rubric_utf8) is not bytes
            or not 0 < len(rubric_utf8) <= 16000
            or type(template_utf8) is not bytes
            or not 0 < len(template_utf8) <= 16000
        ):
            raise HistoryPublicationWebError("exact complete owner configuration required")
        self._continuity, self._prepared, self._configuration = continuity, prepared, configuration
        self._publication, self._reference = (
            prepared.retained.declaration,
            prepared.retained.reference,
        )
        self._protector = prepared.protector
        self._review_counter = review_counter
        self._rubric, self._template = rubric_utf8, template_utf8
        self._raw = encode_history_generation_review_declaration(self._publication)
        self._graph = (
            continuity,
            prepared,
            configuration,
            review_counter,
            self._protector,
            self._protector._operation,
            continuity._clock,
            rubric_utf8,
            template_utf8,
        )
        self._approval_entered = False
        self._held = False
        self._cleanup_uncertain = False
        self._result: HistoryPublicationResponse | None = None
        self._cancellation_result: HistoryPublicationResponse | None = None
        self._task_lock = Lock()
        self._recovery_lock = RLock()
        self._pins()

    @property
    def host_clock(self) -> HostObservedClock:
        return self._continuity._clock

    def _pins(self) -> None:
        raw, g, q = _parts(self._publication)
        profile = self._publication.review
        c = self._configuration
        if (
            raw != self._raw
            or profile is None
            or self._graph
            != (
                self._continuity,
                self._prepared,
                c,
                self._review_counter,
                self._protector,
                self._protector._operation,
                self.host_clock,
                self._rubric,
                self._template,
            )
            or self._protector._operation._source is not self._continuity
            or self._protector._clock is not self.host_clock
            or self._protector._factory is not c.factory
            or self._protector._artifacts is not c.artifacts
            or type(c.generation_counter) is not OllamaQwenContextualTokenCounter
            or q is not self._prepared.request
            and q != self._prepared.request
            or g.runtime_digest != history_contextual_runtime_digest()
            or profile.model_digest != self._review_counter.model_digest
            or profile.tokenizer_digest != self._review_counter.tokenizer_digest
            or profile.renderer_digest != self._review_counter.renderer_digest
            or profile.runtime_digest != history_review_runtime_digest()
            or profile.reviewer_wire_digest != history_review_wire_digest()
            or profile.body_derivation_digest != history_review_derivation_digest()
            or profile.rubric_digest != content_hash_of(self._rubric)
            or profile.template_digest != content_hash_of(self._template)
        ):
            raise ValueError("original complete configuration changed")

    def _context(self) -> HistoryDeclarationContext:
        c = self._configuration
        return HistoryDeclarationContext(
            c.expected_root, c.expected_account_ref, c.expected_exported_at
        )

    def _owner(self, cookie: str) -> None:
        _, g, _ = _parts(self._publication)
        original = self._protector._operation
        current = self._continuity.for_cookie(cookie).establish()
        if original.recheck(current.binding_digest) != current:
            raise ValueError("original complete cookie operation changed")
        history_declaration_owner(original, self.host_clock, g)

    def _scalar_declaration(self, receipt: PersonalHistoryDeclarationReceiptV1) -> None:
        _, g, _ = _parts(self._publication)
        if (
            content_hash_of(self._protector._plan().rows) != receipt.full_plan_digest
            or content_hash_of(self._protector._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest
        ):
            raise ValueError("complete declaration proof stale")
        with self._configuration.factory() as session, session.begin():
            _lock(session, g.id)
            entry = _physical(session)
            _fragment_rows(session, (*g.provenance, self._reference), BOUNDARIES, LABELS)
            if _ids(session, g.id) != (self._reference.source_id,):
                raise ValueError("complete declaration namespace changed")
            _not_withdrawn(session, g.id)
            _same(session, entry)

    def page(self, *, cookie: str) -> HistoryPublicationResponse:
        result = None
        uncertain = False
        try:
            if self._cancellation_result is not None:
                return self.recheck_result(cookie=cookie, result=self._cancellation_result)
            if (
                self.host_clock() >= self._publication.expires_at
                or self._held
                or self._cleanup_uncertain
                or not self._recovery_lock.acquire(blocking=False)
            ):
                return self.cancellation_page(cookie=cookie)
            try:
                # Re-open the actual retained assessment under the same mutex;
                # never repeat the one-use model/release producers.
                existing = self._result
                if existing is not None and existing.kind == "RESULT":
                    return self.recheck_result(cookie=cookie, result=existing)
                if self._approval_entered:
                    return self.cancellation_page(cookie=cookie)
                self._pins()
                self._owner(cookie)
                _, g, q = _parts(self._publication)
                started = _NATIVE_MONOTONIC()
                with self.host_clock._lock:
                    observed = self.host_clock._last
                if (
                    observed is None
                    or (g.expires_at - observed).total_seconds() * 1000
                    < q.task.max_latency_ms + self._publication.review.max_latency_ms
                ):
                    raise ValueError("original whole task interval does not fit")
                deadline = started + (g.expires_at - observed).total_seconds()
                counter = self._configuration.generation_counter
                count = counter.count_prompt_tokens(self._prepared.generation_wire)
                if count != g.prompt_tokens or count + g.max_output_tokens > _context_tokens(
                    g.route
                ):
                    raise ValueError("original complete generation reservation does not fit")
                _fragment_verify_runtime(counter)
                verify_model(g.route.identity.model_id, g.model_digest, _http)
                engine = LocalHistoryReviewRuntime(counter=self._review_counter)
                self._review_counter.verify_runtime()
                engine._metadata(
                    min(deadline, started + self._publication.review.max_latency_ms / 1000),
                    self._publication.review.model_digest,
                )
                with self._configuration.factory() as session, session.begin():
                    _assert_personal_custody_append_capacity(session, 7)
                proof = protect_history_declaration(
                    self._protector,
                    reference=self._reference,
                    expected_declaration=self._publication,
                    context=self._context(),
                    read_existing=True,
                )
                user = self._continuity._sessions.peek_user(cookie, self.host_clock())
                if user is None:
                    raise ValueError("original signed session unavailable")
                self._pins()
                html = (
                    '<section class="decision-card"><h1>Approve this complete context task</h1>'
                    '<pre class="task-instruction">'
                    + escape(q.original_task.instruction)
                    + "</pre>"
                    "<p>This runs one local generation and an independent full-answer review. "
                    "The actual future answer must still fit its original review reservation. "
                    "Failure holds the reply without retry. This repeats full PERSONAL encrypted backup "
                    "and local plaintext recovery checkpoints.</p>"
                    "<details><summary>Full declaration, sources and original budgets</summary><pre>"
                    + escape(self._raw.decode())
                    + "</pre></details>"
                    + self._form(user.csrf, False)
                    + self._form(user.csrf, True)
                    + "</section>"
                )
                self._owner(cookie)
                self._scalar_declaration(proof)
                if _NATIVE_MONOTONIC() >= deadline:
                    raise ValueError("original complete publication expired")
                result = HistoryPublicationResponse(
                    html, g.expires_at, "PUBLICATION", receipt=proof
                )
            finally:
                self._recovery_lock.release()
        except PersonalFragmentCleanupUncertain:
            uncertain = True
            self._cleanup_uncertain = True
        except Exception:  # noqa: BLE001,S110
            pass
        if uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL complete publication cleanup uncertain"
            )
        if result is None:
            return self.cancellation_page(cookie=cookie)
        return result

    def _form(self, csrf: str, cancel: bool) -> str:
        action = (
            "withdraw_history_generation_and_review"
            if cancel
            else "approve_history_generation_and_review"
        )
        label = "Cancel this task" if cancel else "Approve the full declaration"
        return (
            '<form method="post" action="/ask-caz-locally">'
            '<input type="hidden" name="action" value="' + action + '">'
            '<input type="hidden" name="csrf" value="' + escape(csrf, quote=True) + '">'
            '<input type="hidden" name="publication_digest" value="'
            + history_generation_review_declaration_digest(self._publication)
            + '">'
            '<input type="hidden" name="source_id" value="' + str(self._reference.source_id) + '">'
            '<button type="submit">' + label + "</button></form>"
        )

    def cancellation_page(self, *, cookie: str) -> HistoryPublicationResponse:
        result = None
        try:
            operation = self._continuity.for_cookie(cookie)
            owner = operation.establish()
            _, g, _ = _parts(self._publication)
            if owner.principal.scopes != _SCOPE or (
                owner.principal.identity.issuer,
                owner.principal.identity.subject,
            ) != (g.owner_issuer, g.owner_subject):
                raise ValueError("current cancellation actor required")
            with self._configuration.factory() as session, session.begin():
                load_history_withdrawal_target(
                    session,
                    artifacts=self._configuration.artifacts,
                    reference=self._reference,
                    declaration=self._publication,
                )
                rows = _target_current(session, self._reference, self._publication)
            user = self._continuity._sessions.peek_user(cookie, self.host_clock())
            if user is None or operation.recheck(owner.binding_digest) != owner:
                raise ValueError("current cancellation session changed")
            html = (
                '<section class="decision-card"><h1>Published task</h1>'
                "<p>No new processing is started by this page. Cancel the original task; "
                "its processing window will not be renewed.</p>"
                + self._form(user.csrf, True)
                + "</section>"
            )
            result = HistoryPublicationResponse(
                html, owner.effective_expires_at, "CANCEL_PAGE", rows=rows
            )
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise HistoryPublicationWebError("complete cancellation target unavailable")
        return result

    def submit(self, *, request: Request, body: bytes) -> HistoryPublicationResponse:
        result = None
        uncertain = False
        entered = False
        already_entered = False
        interrupted: KeyboardInterrupt | SystemExit | None = None
        try:
            cookie = _cookie(request, _USER)
            fields = parse_qs(
                body.decode("ascii", errors="strict"), strict_parsing=True, max_num_fields=4
            )
            cancel = fields.get("action") == ["withdraw_history_generation_and_review"]
            operation = (
                self._continuity.for_cookie(cookie) if cancel else self._protector._operation
            )
            action = _observe_history_http_post(
                request=request,
                body=body,
                continuity=self._continuity,
                publication=self._publication,
                reference=self._reference,
                operation=operation,
            )
            if action._observation.purpose == "WITHDRAW":
                withdrawn = withdraw_history_publication(
                    factory=self._configuration.factory,
                    artifacts=self._configuration.artifacts,
                    action=action,
                )
                current = operation.establish()
                with self._configuration.factory() as session, session.begin():
                    rows = _event_current(session, self._reference, self._publication)
                result = HistoryPublicationResponse(
                    "<h1>Cancellation recorded</h1><p>The original window is not renewed.</p>",
                    current.effective_expires_at,
                    "CANCELLED",
                    withdrawal=withdrawn,
                    rows=rows,
                )
            else:
                with self._task_lock:
                    if self._approval_entered:
                        already_entered = True
                        raise ValueError("original complete approval already entered")
                    if self._held or self._cleanup_uncertain:
                        raise ValueError("original complete task held")
                    self._approval_entered = True
                    entered = True
                with self._recovery_lock:
                    self._pins()
                    acknowledged = _record_posted_history_admission(
                        factory=self._configuration.factory,
                        artifacts=self._configuration.artifacts,
                        action=action,
                        clock=self.host_clock,
                        context=self._context(),
                    )
                    result = self._run(cookie, acknowledged)
        except PersonalFragmentCleanupUncertain:
            self._cleanup_uncertain = True
            uncertain = True
        except (KeyboardInterrupt, SystemExit) as error:
            interrupted = error
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            if already_entered:
                raise HistoryApprovalAlreadyEntered(
                    "complete task already entered; reload for status"
                )
            if entered:
                self._held = True
                self._result = None
            if uncertain:
                raise PersonalFragmentCleanupUncertain("PERSONAL complete task cleanup uncertain")
            if interrupted is not None:
                raise type(interrupted)() from None
            raise HistoryPublicationWebError("complete action not acknowledged; stop and reconcile")
        if result.kind == "CANCELLED":
            self._cancellation_result = result
        else:
            self._result = result
        return result

    def _run(
        self, cookie: str, acknowledged: AcknowledgedHistoryPublicationAdmission
    ) -> HistoryPublicationResponse:
        self._owner(cookie)
        _, g, q = _parts(self._publication)
        parent = CanonicalPersonalHistoryPublicationAuthorization(
            factory=self._configuration.factory,
            artifacts=self._configuration.artifacts,
            declaration=self._publication,
            acknowledgment=acknowledged,
            request=self._prepared.request,
            protector=self._protector,
            operation=self._protector._operation,
            clock=self.host_clock,
            context=self._context(),
        )
        generation = LocalHistoryContextualRuntime(
            route=q.route,
            model_digest=g.model_digest,
            counter=self._configuration.generation_counter,
        )
        parent.bind_runtime(generation)
        generation.preflight(self._prepared.request)
        draft = generation.generate(self._prepared.request)
        output = retain_personal_history_publication_output(
            parent, runtime=generation, request=self._prepared.request, draft=draft
        )
        engine = LocalHistoryReviewRuntime(counter=self._review_counter)
        reviewer = CanonicalPersonalHistoryReviewAuthorization(
            generation_authorization=parent,
            output=output,
            runtime=engine,
            rubric_utf8=self._rubric,
            template_utf8=self._template,
        )
        observed = reviewer.invoke()
        assessed = capture_history_publication_assessment(reviewer, observed=observed)
        text = release_history_reviewed_text(reviewer, expected=assessed)
        html = _reviewed_result_html(reviewer, assessed, text)

        return HistoryPublicationResponse(
            html, g.expires_at, "RESULT", reviewer=reviewer, assessment=assessed
        )

    def recheck_result(
        self, *, cookie: str, result: HistoryPublicationResponse
    ) -> HistoryPublicationResponse:
        answer = None
        uncertain = False
        try:
            if result.kind == "RESULT":
                if result is not self._result or self._held or self._cleanup_uncertain:
                    raise ValueError("original complete result held")
                if result.reviewer is None or result.assessment is None:
                    raise ValueError("actual complete assessment required")
                proof = protect_history_assessment(result.reviewer, read_existing=True)
                if proof != result.assessment.recovery_receipt:
                    raise ValueError("original assessment checkpoint stale")
                self._pins()
                self._owner(cookie)
            elif result.kind == "CANCELLED":
                if result is not self._cancellation_result:
                    raise ValueError("actual original cancellation acknowledgment required")
                current = self._continuity.for_cookie(cookie).establish()
                if current.effective_expires_at != result.deadline:
                    raise ValueError("original cancellation session changed")
            else:
                raise ValueError("closed retained response required")
            self.scalar_response(result)
            answer = result
        except PersonalFragmentCleanupUncertain:
            uncertain = True
            self._cleanup_uncertain = True
        except Exception:  # noqa: BLE001,S110
            pass
        if answer is None:
            # Display failure never renews or retries processing, and must not
            # poison the independent current-owner cancellation acknowledgment.
            if uncertain:
                raise PersonalFragmentCleanupUncertain("PERSONAL complete result cleanup uncertain")
            raise HistoryPublicationWebError("complete result withheld")
        return answer

    def scalar_response(self, result: HistoryPublicationResponse) -> None:
        """Only canonical scalar/native checks after the actual final owner."""
        if result.kind == "PUBLICATION":
            if result.receipt is None:
                raise ValueError("actual publication checkpoint required")
            self._scalar_declaration(result.receipt)
        elif result.kind == "RESULT":
            if result is not self._result or result.reviewer is None or result.assessment is None:
                raise ValueError("actual original retained result required")
            gate = result.reviewer
            if gate._result is not result.assessment or gate._runtime._result is not gate._observed:
                raise ValueError("actual reviewer origin changed")
            gate._terminal(result.assessment.recovery_receipt, "DELIVERY_RELEASED")
            if gate._result is not result.assessment or gate._runtime._result is not gate._observed:
                raise ValueError("actual terminal reviewer origin changed")
        elif result.kind in ("CANCEL_PAGE", "CANCELLED"):
            with self._configuration.factory() as session, session.begin():
                entry = _physical(session)
                rows = (
                    _event_current(session, self._reference, self._publication)
                    if result.kind == "CANCELLED"
                    else _target_current(session, self._reference, self._publication)
                )
                if rows != result.rows:
                    raise ValueError("complete cancellation target changed")
                _same(session, entry)
        else:
            raise ValueError("closed complete response family required")


class HistoryPreparationError(ValueError):
    """Fixed preparation hold; a committed declaration may need reconciliation."""


def _instruction(value: object) -> str:
    """Exact bounded owner wording; never an approval or inferred selection."""
    if (
        type(value) is not str
        or value != value.strip()
        or not 0 < len(value.encode("utf-8", errors="strict")) <= 2048
    ):
        raise ValueError("exact nonblank bounded owner instruction required")
    return value


class HistoryPreparationWeb:
    """One trusted factory call after exact current owner POST, not consent.

    Root routes must bound the actual request stream before calling prepare and
    recheck the returned controller before displaying or consuming publication.
    Source custody, recovery configuration and factory body are separate host
    prerequisites. This wrapper neither performs nor acknowledges them.
    """

    def __init__(
        self,
        *,
        inputs: NamedOwnerHostInputs,
        factory: Callable[
            [NamedOwnerHostInputs, NamedSessionOperation, str], HistoryPublicationWeb
        ],
    ) -> None:
        if (
            type(inputs) is not NamedOwnerHostInputs
            or not callable(factory)
            or type(inputs.owners) is not OwnerGrantStore
            or getattr(inputs.owner, "__self__", None) is not inputs.owners
            or getattr(inputs.owner, "__func__", None) is not OwnerGrantStore.load
        ):
            raise HistoryPreparationError("local task preparation unavailable")
        self._inputs, self._factory = inputs, factory
        self.continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        self._pins = (inputs, factory, self.continuity)
        c = self.continuity
        self._continuity_pins = (c._sessions, c._owner, c._clock, c._context, c._key)
        self._phase = "NEW"
        self._controller: HistoryPublicationWeb | None = None
        self._lock = RLock()

    @staticmethod
    def page(*, csrf: str) -> str:
        """Pure form; root GET supplies actual current-session CSRF separately."""
        if type(csrf) is not str or not 1 <= len(csrf) <= 128:
            raise HistoryPreparationError("local task preparation unavailable")
        return (
            "<p>Describe the task for the configured context. This encrypts and backs up the full PERSONAL "
            "inventory and retains a plaintext recovery copy in a separate local folder. "
            "It does not approve "
            'AI processing.</p><form method="post" action="/prepare-caz-task" accept-charset="UTF-8">'
            '<input type="hidden" name="action" value="prepare">'
            '<input type="hidden" name="csrf" value="'
            + escape(csrf, quote=True)
            + '"><label for="task-instruction">What would you like Caz to do?</label>'
            '<textarea id="task-instruction" name="instruction" spellcheck="false" autocomplete="off" autocapitalize="off" required></textarea>'
            '<button type="submit">Prepare task</button></form>'
        )

    def prepared_controller(self) -> HistoryPublicationWeb:
        """Transient exact result only; never session or processing authority."""
        # PREPARED is terminal and its controller never changes. Do not block
        # or refuse withdrawal because an unrelated request holds this lock.
        if self._phase == "PREPARED" and self._controller is not None:
            return self._controller
        if not self._lock.acquire(blocking=False):
            raise HistoryPreparationError("local task preparation unavailable")
        try:
            if self._phase != "PREPARED" or self._controller is None:
                raise HistoryPreparationError("local task preparation unavailable")
            return self._controller
        finally:
            self._lock.release()

    def prepare(self, *, request: Request, body: bytes) -> HistoryPublicationWeb:
        if not self._lock.acquire(blocking=False):
            raise HistoryPreparationError("local task preparation unavailable")
        try:
            if self._phase != "NEW":
                raise HistoryPreparationError("local task preparation unavailable")
            result = None
            uncertain = False
            try:
                self._phase = "ENTERED"
                i, c = self._inputs, self.continuity
                if (
                    any(a is not b for a, b in zip(self._pins, (i, self._factory, c), strict=True))
                    or type(request) is not Request
                    or type(body) is not bytes
                    or not 0 < len(body) <= 2048
                    or request.method != "POST"
                    or request.url.path != "/prepare-caz-task"
                    or request.scope.get("query_string", b"")
                    or request.headers.getlist("host") != [urlsplit(i.origin).netloc]
                    or request.headers.getlist("origin") != [i.origin]
                    or request.headers.getlist("content-type")
                    != ["application/x-www-form-urlencoded"]
                ):
                    raise ValueError("exact preparation POST required")
                fields = parse_qs(
                    body.decode("ascii", errors="strict"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    encoding="utf-8",
                    errors="strict",
                )
                if (
                    set(fields) != {"action", "csrf", "instruction"}
                    or any(len(v) != 1 for v in fields.values())
                    or fields["action"] != ["prepare"]
                ):
                    raise ValueError("closed preparation fields required")
                instruction = _instruction(fields["instruction"][0])
                cookie = _cookie(request, _USER)
                operation = c.for_cookie(cookie)
                if operation._source is not c:
                    raise ValueError("original operation continuity required")
                operation_pins = (operation._read, operation._host_clock, operation._source)
                before = operation.establish()
                current = i.sessions.peek_user(cookie, i.clock())
                after = operation.recheck(before.binding_digest)
                if (
                    current is None
                    or before != after
                    or after.principal.scopes != _SCOPE
                    or current.identity != after.principal.identity
                    or not secrets.compare_digest(fields["csrf"][0], current.csrf)
                    or self._phase != "ENTERED"
                ):
                    raise ValueError("current exact owner preparation required")
                controller = self._factory(i, operation, instruction)
                if self._phase != "ENTERED" or type(controller) is not HistoryPublicationWeb:
                    raise ValueError("exact once-only controller required")
                if (
                    controller._continuity is not c
                    or controller.host_clock is not i.clock
                    or controller._protector._operation is not operation
                    or controller._protector._clock is not i.clock
                ):
                    raise ValueError("original operation graph required")
                _, _, prepared_request = _parts(controller._publication)
                if (
                    prepared_request.original_task.instruction != instruction
                    or prepared_request.task.instruction != instruction
                ):
                    raise ValueError("exact submitted instruction required")
                controller._pins()
                i.clock()
                final = operation.recheck(before.binding_digest)
                with i.clock._lock:
                    observed = i.clock._last
                _, generation, final_request = _parts(controller._publication)
                if (
                    self._phase != "ENTERED"
                    or final != before
                    or final_request.original_task.instruction != instruction
                    or final_request.task.instruction != instruction
                    or observed is None
                    or any(
                        a is not b
                        for a, b in zip(
                            self._pins, (self._inputs, self._factory, self.continuity), strict=True
                        )
                    )
                    or operation._source is not c
                    or controller._continuity is not c
                    or controller._protector._operation is not operation
                    or controller._protector._clock is not i.clock
                    or c._owner is not i.owner
                    or c._sessions is not i.sessions
                    or c._clock is not i.clock
                    or (c._sessions, c._owner, c._clock, c._context, c._key)
                    != self._continuity_pins
                    or any(
                        a is not b
                        for a, b in zip(
                            operation_pins,
                            (operation._read, operation._host_clock, operation._source),
                            strict=True,
                        )
                    )
                    or generation.owner_issuer != final.principal.identity.issuer
                    or generation.owner_subject != final.principal.identity.subject
                    or generation.original_session_binding != final.binding_digest
                    or generation.original_session_issued_at != final.issued_at
                    or generation.original_session_expires_at != final.effective_expires_at
                    or not generation.approved_at
                    <= observed
                    < generation.expires_at
                    <= final.effective_expires_at
                ):
                    raise ValueError("original declaration session/window required")
                self._controller = controller
                self._phase = "PREPARED"
                result = controller
            except PersonalFragmentCleanupUncertain:
                self._phase = "HELD"
                self._controller = None
                uncertain = True
            except BaseException:  # noqa: BLE001 - hold and sanitize interrupted callbacks too
                self._phase = "HELD"
                self._controller = None
            if result is None:
                if uncertain:
                    raise PersonalFragmentCleanupUncertain(
                        "PERSONAL recovery cleanup uncertain; operator review required"
                    )
                raise HistoryPreparationError("local task preparation unavailable")
            return result
        finally:
            self._lock.release()


def personal_history_publication_factory(
    *,
    configuration: PersonalHistoryTaskConfiguration,
    review_counter: OllamaQwenHistoryReviewTokenCounter,
    rubric_utf8: bytes,
    template_utf8: bytes,
) -> Callable[[NamedOwnerHostInputs, NamedSessionOperation, str], HistoryPublicationWeb]:
    """Trusted configured cohort only; no startup/GET capture or processing.

    The real request-bound operation is used once to prepare custody and its
    immutable protector. Processing still needs the later original APPROVE POST.
    """
    if (
        type(configuration) is not PersonalHistoryTaskConfiguration
        or type(review_counter) is not OllamaQwenHistoryReviewTokenCounter
        or type(rubric_utf8) is not bytes
        or not 0 < len(rubric_utf8) <= 16000
        or type(template_utf8) is not bytes
        or not 0 < len(template_utf8) <= 16000
    ):
        raise HistoryPublicationWebError("exact complete factory configuration required")

    def prepare(
        inputs: NamedOwnerHostInputs, operation: NamedSessionOperation, instruction: str
    ) -> HistoryPublicationWeb:
        prepared = prepare_personal_history_task(
            configuration, inputs=inputs, operation=operation, instruction=instruction
        )
        return HistoryPublicationWeb(
            continuity=operation._source,
            prepared=prepared,
            configuration=configuration,
            review_counter=review_counter,
            rubric_utf8=rubric_utf8,
            template_utf8=template_utf8,
        )

    return prepare
