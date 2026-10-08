"""Host-owned exact fragment publication POST and opt-in task consumption.

An observation is minted only after the concrete request, encrypted current
session, exact enrolled actor and CSRF are checked. Python/trusted host code is
not sandboxed; this is not a new signature or a bearer permission protocol.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock, RLock
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qs

from starlette.requests import Request

from zacai.claude_local_custody import _SCOPE
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.fragment_review_declaration import (
    FragmentGenerationReviewDeclarationV2,
    encode_fragment_generation_review_declaration,
    fragment_generation_review_declaration_digest,
)
from zacai.intelligence.fragment_review_retention import _parts
from zacai.interfaces.named_session_binding import (
    NamedSessionContinuity,
    NamedSessionOperation,
    VerifiedNamedSession,
)
from zacai.interfaces.private_web import _USER, _cookie

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from zacai.contextual_protection import PersonalHistoryFragmentProtector
    from zacai.intelligence.fragment_publication_admission import (
        PersonalFragmentPublicationAdmissionReceiptV1,
        RetainedFragmentPublicationAdmission,
    )
    from zacai.intelligence.fragment_publication_review import (
        CanonicalFragmentPublicationReviewAuthorization,
        PersonalFragmentRetainedAssessment,
    )
    from zacai.intelligence.fragment_review_prompt_counter import (
        OllamaQwenFragmentReviewTokenCounter,
    )
    from zacai.intelligence.fragment_review_retention import PersonalFragmentDeclarationReceiptV2
    from zacai.intelligence.fragment_review_runtime import (
        FragmentReviewRuntimeProfile,
        _LocalFragmentReviewRuntime,
        _MechanicalReviewResult,
    )
    from zacai.intelligence.fragment_review_withdrawal import (
        HistoricalFragmentDeclarationTarget,
        RetainedFragmentWithdrawal,
    )
    from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
    from zacai.interfaces.host_clock import HostObservedClock

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_ACTION_SEAL = object()
_ACTIONS: dict[str, Literal["APPROVE", "WITHDRAW"]] = {
    "approve_fragment_publication": "APPROVE",
    "withdraw_fragment_publication": "WITHDRAW",
}


class FragmentPublicationWebError(ValueError):
    """Fixed host acknowledgment error without source or session locals."""


def _assert_fragment_publication_configuration(
    publication: FragmentGenerationReviewDeclarationV2, *,
    generation_counter: OllamaQwenContextualTokenCounter,
    review_counter: OllamaQwenFragmentReviewTokenCounter,
    review_runtime_profile: FragmentReviewRuntimeProfile,
    rubric_utf8: bytes, template_utf8: bytes,
) -> None:
    """Pure local configured-byte/pin fit, never owner/protection permission."""
    result = None
    try:
        from pathlib import Path

        from zacai.intelligence import fragment_review_preparation as prep
        from zacai.intelligence import fragment_review_wire as wire
        from zacai.intelligence.fragment_publication_generation import (
            _assert_publication_review_provenance,
        )
        from zacai.intelligence.fragment_publication_review import (
            _assert_publication_review_record_fit,
        )
        from zacai.intelligence.fragment_review_prompt_counter import (
            OllamaQwenFragmentReviewTokenCounter,
        )
        from zacai.intelligence.fragment_review_runtime import (
            FragmentReviewRuntimeProfile,
            fragment_review_runtime_digest,
        )
        from zacai.intelligence.local_contextual_runtime import (
            fragment_contextual_counter_pins,
            fragment_contextual_runtime_digest,
        )
        from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

        if (type(publication) is not FragmentGenerationReviewDeclarationV2
            or type(generation_counter) is not OllamaQwenContextualTokenCounter
            or type(review_counter) is not OllamaQwenFragmentReviewTokenCounter
            or type(review_runtime_profile) is not FragmentReviewRuntimeProfile
            or publication.review is None):
            raise FragmentPublicationWebError("exact configured publication profile required")
        prep._text(rubric_utf8)
        prep._text(template_utf8)
        _, g, q = _parts(publication)
        _assert_publication_review_provenance(publication)
        _assert_publication_review_record_fit(publication,
            rubric_utf8=rubric_utf8, template_utf8=template_utf8)
        r = publication.review
        profile = review_runtime_profile
        if (r is None
            or (
                g.model_digest,
                g.tokenizer_digest,
                g.template_digest,
                g.renderer_digest,
                g.runtime_digest,
            )
                != (
                generation_counter.model_digest,
                *fragment_contextual_counter_pins(generation_counter),
                fragment_contextual_runtime_digest(),
            )
            or (
                r.model_digest,
                r.tokenizer_digest,
                r.renderer_digest,
                r.runtime_digest,
            )
                != (
                review_counter.model_digest,
                review_counter.tokenizer_digest,
                review_counter.renderer_digest,
                fragment_review_runtime_digest(),
            )
            or (
                profile.model_digest,
                profile.tokenizer_digest,
                profile.template_digest,
                profile.renderer_digest,
                profile.implementation_digest,
            )
                != (
                r.model_digest,
                r.tokenizer_digest,
                review_counter.template_digest,
                r.renderer_digest,
                r.runtime_digest,
            )
            or r.context_window_tokens != wire.CONTEXT_TOKENS
            or r.route.identity.model_id != wire.MODEL
            or profile.runtime_id != r.route.identity.runtime_id
            or r.rubric_digest != content_hash_of(rubric_utf8)
            or r.template_digest != content_hash_of(template_utf8)
            or r.reviewer_wire_digest != content_hash_of(Path(wire.__file__).read_bytes())
            or r.body_derivation_digest != content_hash_of(Path(prep.__file__).read_bytes())
            or q.route != g.route
        ):
            raise FragmentPublicationWebError("exact configured publication profile required")
        result = True
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationWebError("exact configured publication profile required")


@dataclass(frozen=True, repr=False)
class _FragmentPostObservation:
    purpose: Literal["APPROVE", "WITHDRAW"]
    publication: FragmentGenerationReviewDeclarationV2 = field(repr=False)
    reference: EvidenceReference
    operation: NamedSessionOperation = field(repr=False)
    current_session: VerifiedNamedSession = field(repr=False)
    observed_at: datetime


class _PostedFragmentAction:
    """One-use internal HTTP observation, neither constructor nor JSON approval.

    There is no public constructor or supplied approval bool. Only the validated
    concrete HTTP observation function below mints the instance. Trusted Python
    with access to private implementation state is outside this boundary.
    """

    _seal: object
    _used: bool
    _observation: _FragmentPostObservation

    def __init__(self) -> None:
        raise FragmentPublicationWebError("validated browser action required")


def _same_current(a: VerifiedNamedSession, b: VerifiedNamedSession) -> bool:
    return (
        a.principal == b.principal
        and a.binding_digest == b.binding_digest
        and a.issued_at == b.issued_at
        and a.expires_at == b.expires_at
        and a.effective_expires_at == b.effective_expires_at
    )


def _observe_fragment_http_post(
    *,
    request: Request,
    body: bytes,
    continuity: NamedSessionContinuity,
    publication: FragmentGenerationReviewDeclarationV2,
    reference: EvidenceReference,
) -> _PostedFragmentAction:
    """Actual handler seam after bounded streaming; independently checks HTTP.

    Caller must pass the actual ASGI request and its exact body, never fabricated
    client declarations or a replaced pre-parsed action. Runtime/input readiness
    and canonical target checks remain necessary in the consuming controller.
    """
    result = None
    try:
        if (
            type(request) is not Request
            or type(continuity) is not NamedSessionContinuity
            or type(body) is not bytes
            or not 0 < len(body) <= 2048
            or request.method != "POST"
            or request.url.path != "/ask-caz-locally"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed original POST required")
        import json

        origin = json.loads(continuity._context)["origin"]
        from urllib.parse import urlsplit

        if request.headers.getlist("host") != [urlsplit(origin).netloc] or request.headers.getlist(
            "origin"
        ) != [origin]:
            raise ValueError("original host/origin required")
        raw_cookie = _cookie(request, _USER)
        operation = continuity.for_cookie(raw_cookie)
        before = operation.establish()
        current = continuity._sessions.peek_user(raw_cookie, continuity._clock())
        if current is None or current.identity != before.principal.identity:
            raise ValueError("current actual browser session required")
        fields = parse_qs(
            body.decode("ascii", errors="strict"), keep_blank_values=True, strict_parsing=True
        )
        if set(fields) != {"action", "csrf", "publication_digest", "source_id"} or any(
            len(v) != 1 for v in fields.values()
        ):
            raise ValueError("closed exact action fields required")
        purpose = _ACTIONS.get(fields["action"][0])
        if (
            purpose is None
            or _TOKEN.fullmatch(fields["csrf"][0]) is None
            or not secrets.compare_digest(fields["csrf"][0], current.csrf)
            or fields["publication_digest"][0]
            != fragment_generation_review_declaration_digest(publication)
            or fields["source_id"][0] != str(reference.source_id)
        ):
            raise ValueError("exact published target/CSRF required")
        raw, g, _ = _parts(publication)
        from zacai.ingestion.artifact_store import content_hash_of

        if reference.content_hash != content_hash_of(raw):
            raise ValueError("exact immutable target required")
        actual = operation.recheck(before.binding_digest)
        observed_at = continuity._clock()
        if (
            not _same_current(before, actual)
            or actual.principal.scopes != _SCOPE
            or (actual.principal.identity.issuer, actual.principal.identity.subject)
            != (g.owner_issuer, g.owner_subject)
            or not actual.issued_at <= observed_at < actual.effective_expires_at
        ):
            raise ValueError("current exact owner required")
        if purpose == "APPROVE" and (
            actual.binding_digest != g.original_session_binding
            or actual.issued_at != g.original_session_issued_at
            or actual.effective_expires_at != g.original_session_expires_at
            or not g.approved_at <= observed_at < g.expires_at
        ):
            raise ValueError("original publication session/window required")
        observation = _FragmentPostObservation(
            purpose, publication, reference, operation, actual, observed_at
        )
        result = object.__new__(_PostedFragmentAction)
        result._seal = _ACTION_SEAL
        result._used = False
        result._observation = observation
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationWebError("validated browser publication action unavailable")
    return result


def _consume_fragment_post(
    action: _PostedFragmentAction, *, purpose: Literal["APPROVE", "WITHDRAW"]
) -> _FragmentPostObservation:
    """Consume once before callbacks; wrong purpose cannot consume another action.

    A WITHDRAW observation may use a fresh current same-owner cookie after the
    original processing window. It never replaces or renews original processing.
    The withdrawal writer must separately prove its historical canonical target.
    """
    result = None
    try:
        if (
            type(action) is not _PostedFragmentAction
            or action._seal is not _ACTION_SEAL
            or action._used is not False
            or type(action._observation) is not _FragmentPostObservation
            or action._observation.purpose != purpose
        ):
            raise ValueError("exact one-use HTTP observation required")
        action._used = True
        observation = action._observation
        actual = observation.operation.recheck(observation.current_session.binding_digest)
        _, g, _ = _parts(observation.publication)
        if (
            not _same_current(actual, observation.current_session)
            or actual.principal.scopes != _SCOPE
            or (actual.principal.identity.issuer, actual.principal.identity.subject)
            != (g.owner_issuer, g.owner_subject)
            or not actual.issued_at
            <= observation.operation.host_clock()
            < actual.effective_expires_at
        ):
            raise ValueError("current exact action owner required")
        if purpose == "APPROVE":
            from zacai.contextual_authorization import _fragment_decision_owner

            _fragment_decision_owner(observation.operation, observation.operation.host_clock, g)
        result = observation
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationWebError("validated browser publication action unavailable")
    return result


@dataclass(frozen=True, repr=False)
class FragmentPublicationPage:
    html: str = field(repr=False)
    deadline: datetime
    publication_digest: str
    receipt: PersonalFragmentDeclarationReceiptV2 | None = field(repr=False)
    target: HistoricalFragmentDeclarationTarget | None = field(default=None, repr=False)
    rows: tuple[tuple[tuple[str, object], ...], ...] = field(default=(), repr=False)


@dataclass(frozen=True, repr=False)
class ProtectedFragmentPublicationAction:
    retained: RetainedFragmentPublicationAdmission = field(repr=False)
    receipt: PersonalFragmentPublicationAdmissionReceiptV1 = field(repr=False)
    deadline: datetime


@dataclass(frozen=True, repr=False)
class ObservedFragmentCancellation:
    withdrawal: RetainedFragmentWithdrawal = field(repr=False)
    rows: tuple[tuple[tuple[str, object], ...], ...] = field(repr=False)
    deadline: datetime


@dataclass(frozen=True, repr=False)
class _RetainedFragmentTask:
    html: str = field(repr=False)
    authorization: CanonicalFragmentPublicationReviewAuthorization = field(repr=False)
    assessment: PersonalFragmentRetainedAssessment = field(repr=False)
    deadline: datetime
    runtime: _LocalFragmentReviewRuntime = field(repr=False)
    review_result: _MechanicalReviewResult = field(repr=False)


class FragmentPublicationWeb:
    """Concrete browser action custody; task execution requires explicit host opt-in.

    The server fixes the entire publication and canonical locator. Readiness
    observes actual configured code/files/model metadata. Future complete answer
    fit and the concrete once-only review producer remain mandatory gates.
    No caller approval bool, generic success callback or inferred review exists.
    """

    def __init__(
        self,
        *,
        continuity: NamedSessionContinuity,
        publication: FragmentGenerationReviewDeclarationV2,
        reference: EvidenceReference,
        protector: PersonalHistoryFragmentProtector,
        generation_counter: OllamaQwenContextualTokenCounter,
        review_counter: OllamaQwenFragmentReviewTokenCounter,
        review_runtime_profile: FragmentReviewRuntimeProfile,
        rubric_utf8: bytes,
        template_utf8: bytes,
        run_approved_task: bool = False,
    ) -> None:
        from zacai.contextual_protection import PersonalHistoryFragmentProtector
        from zacai.intelligence.fragment_review_prompt_counter import (
            OllamaQwenFragmentReviewTokenCounter,
        )
        from zacai.intelligence.fragment_review_runtime import (
            FragmentReviewRuntimeProfile,
        )
        from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

        if (
            type(run_approved_task) is not bool
            or type(continuity) is not NamedSessionContinuity
            or type(protector) is not PersonalHistoryFragmentProtector
            or protector._clock is not continuity._clock
            or (run_approved_task and (
                type(getattr(protector, "_operation", None)) is not NamedSessionOperation
                or protector._operation._source is not continuity
            ))
            or type(generation_counter) is not OllamaQwenContextualTokenCounter
            or type(review_counter) is not OllamaQwenFragmentReviewTokenCounter
            or type(review_runtime_profile) is not FragmentReviewRuntimeProfile
            or publication.review is None
            or type(rubric_utf8) is not bytes
            or not 0 < len(rubric_utf8) <= 16000
            or type(template_utf8) is not bytes
            or not 0 < len(template_utf8) <= 16000
        ):
            raise FragmentPublicationWebError("concrete full-purpose configuration required")
        _parts(publication)
        self._continuity, self._publication, self._reference = continuity, publication, reference
        self._protector = protector
        self._generation_counter, self._review_counter = generation_counter, review_counter
        self._review_profile = review_runtime_profile
        self._rubric, self._template = rubric_utf8, template_utf8
        self._graph = (
            continuity,
            protector,
            generation_counter,
            review_counter,
            review_runtime_profile,
        )
        self._run_approved_task = run_approved_task
        self._approval_entered = False
        self._cleanup_uncertain = False
        self._task_entered = False
        self._task_held = False
        self._task_result: _RetainedFragmentTask | None = None
        self._task_lock = Lock()
        self._recovery_lock = RLock()
        self._raw = encode_fragment_generation_review_declaration(publication)
        self._settings = (reference, rubric_utf8, template_utf8, run_approved_task)
        self._pins()

    @property
    def host_clock(self) -> HostObservedClock:
        return self._continuity._clock

    def _pins(self) -> None:
        self._require_cleanup_known()
        p = self._publication
        _assert_fragment_publication_configuration(p,
            generation_counter=self._generation_counter, review_counter=self._review_counter,
            review_runtime_profile=self._review_profile,
            rubric_utf8=self._rubric, template_utf8=self._template)
        self._protector._configuration()
        if (
            self._raw != encode_fragment_generation_review_declaration(p)
            or self._settings != (self._reference, self._rubric, self._template, self._run_approved_task)
            or any(
                a is not b
                for a, b in zip(
                    self._graph,
                    (self._continuity, self._protector, self._generation_counter,
                     self._review_counter, self._review_profile), strict=True,
                )
            )
            or self._protector._clock is not self.host_clock
            or (self._run_approved_task and self._protector._operation._source is not self._continuity)
            or self._reference.content_hash != content_hash_of(self._raw)
        ):
            raise FragmentPublicationWebError("exact configured publication profile required")

    def _require_cleanup_known(self) -> None:
        with self._task_lock:
            if self._cleanup_uncertain:
                raise PersonalFragmentCleanupUncertain(
                    "PERSONAL recovery cleanup uncertain; operator review required"
                )

    def _latch_cleanup_uncertain(self) -> None:
        with self._task_lock:
            self._cleanup_uncertain = True

    def _ready(self, cookie: str) -> PersonalFragmentDeclarationReceiptV2:
        import time

        from zacai.contextual_authorization import (
            _assert_fragment_generation_unconsumed,
            _fragment_decision_owner,
        )
        from zacai.intelligence.fragment_review_runtime import inspect_fragment_review_readiness
        from zacai.intelligence.local_contextual_runtime import (
            _context_tokens,
            _fragment_verify_runtime,
        )
        from zacai.intelligence.local_review_runtime import _http, verify_model
        from zacai.review_authorization import _lock

        _, g, q = _parts(self._publication)
        p = self._publication
        self._pins()
        operation = self._continuity.for_cookie(cookie)
        _fragment_decision_owner(operation, self.host_clock, g)
        with self._protector._factory() as session:
            session.begin()
            _lock(session, g.id)
            _assert_fragment_generation_unconsumed(session, g.id)
        count = self._generation_counter.count_prompt_tokens(q.prompt_body.encode("utf-8"))
        self._pins()
        if (
            type(count) is not int
            or count != g.prompt_tokens
            or count + g.max_output_tokens > _context_tokens(g.route)
        ):
            raise FragmentPublicationWebError("original generation budget does not fit")
        _fragment_verify_runtime(self._generation_counter)
        verify_model(g.route.identity.model_id, g.model_digest, _http)
        self._pins()
        r = p.review
        if r is None:
            raise FragmentPublicationWebError("full-purpose review required")
        # Clock callback precedes readiness; this bounded interval never extends
        # the original processing expiry, which is checked again afterwards.
        now = self.host_clock()
        remaining = (g.expires_at - now).total_seconds()
        if remaining * 1000 < q.task.max_latency_ms + r.max_latency_ms:
            raise FragmentPublicationWebError("original publication expired")
        deadline = time.monotonic() + min(remaining, r.max_latency_ms / 1000)
        observation = inspect_fragment_review_readiness(
            profile=self._review_profile,
            token_counter=self._review_counter,
            deadline_monotonic=deadline,
            max_latency_ms=r.max_latency_ms,
        )
        if (
            observation.profile != self._review_profile
            or observation.deadline_monotonic != deadline
        ):
            raise FragmentPublicationWebError("review readiness observation differs")
        self._pins()
        _fragment_decision_owner(operation, self.host_clock, g)
        # Existing complete input proof is read-only. The admission append will
        # stale it; only the new admission checkpoint is used after capture.
        receipt = self._protector.recheck_declaration(
            reference=self._reference, expected_declaration=p
        )
        self._pins()
        return receipt

    def scalar_release(
        self,
        receipt: PersonalFragmentDeclarationReceiptV2
        | PersonalFragmentPublicationAdmissionReceiptV1,
    ) -> None:
        """Callback-free full canonical Source/journal check, after owner/clock.

        This is freshness for the concrete protected result, never authority.
        """
        if (
            content_hash_of(self._protector._plan().rows) != receipt.full_plan_digest
            or content_hash_of(self._protector._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest
        ):
            raise FragmentPublicationWebError("protected publication became stale")

    def page(self, *, cookie: str) -> FragmentPublicationPage:
        # Cancellation does not perform recovery or grant processing. It stays
        # reachable during approval's pre-phase and after cleanup is uncertain.
        with self._task_lock:
            cancel_only = self._approval_entered or self._task_entered or self._cleanup_uncertain
        if cancel_only or not self._recovery_lock.acquire(blocking=False):
            return self.cancellation_page(cookie=cookie)
        try:
            with self._task_lock:
                cancel_only = self._approval_entered or self._task_entered or self._cleanup_uncertain
            if cancel_only:
                return self.cancellation_page(cookie=cookie)
            return self._page(cookie=cookie)
        finally:
            self._recovery_lock.release()

    def _page(self, *, cookie: str) -> FragmentPublicationPage:
        from html import escape

        if self.host_clock() >= self._publication.expires_at:
            return self.cancellation_page(cookie=cookie)
        try:
            receipt = self._ready(cookie)
        except PersonalFragmentCleanupUncertain:
            self._latch_cleanup_uncertain()
            raise
        except Exception:  # noqa: BLE001 - cancellation is a separate concrete action, not approval fallback
            return self.cancellation_page(cookie=cookie)
        _, g, request = _parts(self._publication)
        user = self._continuity._sessions.peek_user(cookie, self.host_clock())
        if user is None:
            raise FragmentPublicationWebError("original signed session unavailable")
        digest = fragment_generation_review_declaration_digest(self._publication)
        processing = (
            "Approving starts one local generation and independent full-answer review. "
            "A failed fit or review holds the reply without retry. "
            "Running the task repeats these checkpoints. "
            if self._run_approved_task else
            "Recording this action does not start processing or establish a reviewed reply."
        )
        html = (
            '<section class="decision-card"><h1>Approve this local context task</h1>'
            '<pre class="task-instruction">'
            + escape(request.original_task.instruction) + '</pre>'
            '<details><summary>Exact request identity</summary><code>'
            + escape(g.request_digest) + '</code></details>'
            +
            "<p>Generation and independent review use the complete publication below. "
            "The future answer must still pass its exact reviewer token-fit check. "
            + processing + "</p>"
            "<p>Approval makes an encrypted backup of the full PERSONAL inventory "
            "and retains local plaintext recovery copies. Opening this card "
            "rechecks the existing full "
            "PERSONAL recovery copy locally.</p>"
            "<details><summary>Full publication, sources and original budgets</summary><pre>"
            + escape(self._raw.decode("utf-8"))
            + "</pre></details>"
            '<form method="post" action="/ask-caz-locally">'
            '<input type="hidden" name="action" value="approve_fragment_publication">'
            '<input type="hidden" name="csrf" value="' + escape(user.csrf, quote=True) + '">'
            '<input type="hidden" name="publication_digest" value="' + digest + '">'
            '<input type="hidden" name="source_id" value="' + str(self._reference.source_id) + '">'
            '<button type="submit">Approve the full publication</button></form>'
            '<form method="post" action="/ask-caz-locally">'
            '<input type="hidden" name="action" value="withdraw_fragment_publication">'
            '<input type="hidden" name="csrf" value="' + escape(user.csrf, quote=True) + '">'
            '<input type="hidden" name="publication_digest" value="' + digest + '">'
            '<input type="hidden" name="source_id" value="' + str(self._reference.source_id) + '">'
            '<button type="submit">Cancel this published task</button></form></section>'
        )
        return FragmentPublicationPage(html, g.expires_at, digest, receipt)

    def submit(
        self, *, request: Request, body: bytes
    ) -> ProtectedFragmentPublicationAction | ObservedFragmentCancellation | _RetainedFragmentTask:
        try:
            return self._submit(request=request, body=body)
        except PersonalFragmentCleanupUncertain:
            self._latch_cleanup_uncertain()
            raise

    def _submit(
        self, *, request: Request, body: bytes
    ) -> ProtectedFragmentPublicationAction | ObservedFragmentCancellation | _RetainedFragmentTask:
        from zacai.intelligence.fragment_publication_admission import (
            _record_posted_fragment_admission,
        )

        action = _observe_fragment_http_post(
            request=request,
            body=body,
            continuity=self._continuity,
            publication=self._publication,
            reference=self._reference,
        )
        if action._observation.purpose == "WITHDRAW":
            from zacai.intelligence.fragment_review_withdrawal import withdraw_fragment_publication

            retained_withdrawal = withdraw_fragment_publication(
                factory=self._protector._factory,
                artifacts=self._protector._artifacts,
                action=action,
            )
            operation = self._continuity.for_cookie(_cookie(request, _USER))
            current = operation.establish()
            with self._protector._factory() as session:
                session.begin()
                rows = self._cancellation_rows(session, retained_withdrawal)
            return ObservedFragmentCancellation(
                retained_withdrawal, rows, current.effective_expires_at
            )
        if action._observation.purpose != "APPROVE":
            raise FragmentPublicationWebError("approval action required")
        with self._task_lock:
            if self._approval_entered:
                raise FragmentPublicationWebError("original approval already entered")
            self._approval_entered = True
        self._require_cleanup_known()
        self._ready(_cookie(request, _USER))
        retained = _record_posted_fragment_admission(
            factory=self._protector._factory,
            artifacts=self._protector._artifacts,
            action=action,
            clock=self.host_clock,
        )
        receipt = self._protector.protect_publication_admission(
            reference=retained.reference,
            expected_admission=retained.admission,
            expected_publication=self._publication,
        )
        self._pins()
        protected = ProtectedFragmentPublicationAction(retained, receipt, self._publication.expires_at)
        if self._run_approved_task:
            return self._run_task(cookie=_cookie(request, _USER), action=protected)
        return protected

    def recheck_result(
        self,
        *,
        cookie: str,
        result: ProtectedFragmentPublicationAction | ObservedFragmentCancellation | _RetainedFragmentTask,
    ) -> ProtectedFragmentPublicationAction | ObservedFragmentCancellation | _RetainedFragmentTask:
        try:
            return self._recheck_result(cookie=cookie, result=result)
        except PersonalFragmentCleanupUncertain:
            self._latch_cleanup_uncertain()
            raise

    def _recheck_result(
        self,
        *,
        cookie: str,
        result: ProtectedFragmentPublicationAction | ObservedFragmentCancellation | _RetainedFragmentTask,
    ) -> ProtectedFragmentPublicationAction | ObservedFragmentCancellation | _RetainedFragmentTask:
        from zacai.contextual_authorization import _fragment_decision_owner

        if type(result) is not ObservedFragmentCancellation:
            self._require_cleanup_known()
        if type(result) is _RetainedFragmentTask:
            self._recheck_task(cookie=cookie, result=result)
            return result
        if type(result) is ObservedFragmentCancellation:
            from zacai.intelligence.fragment_review_withdrawal import (
                load_fragment_publication_withdrawal,
            )

            current = self._cancel_session(cookie)
            with self._protector._factory() as session:
                session.begin()
                returned = load_fragment_publication_withdrawal(
                    session,
                    artifacts=self._protector._artifacts,
                    publication_reference=self._reference,
                    expected_declaration=self._publication,
                )
                if (
                    returned != result.withdrawal
                    or self._cancellation_rows(session, returned) != result.rows
                ):
                    raise FragmentPublicationWebError("exact committed cancellation required")
            if current.effective_expires_at != result.deadline:
                raise FragmentPublicationWebError("cancellation session changed")
            return result
        if type(result) is not ProtectedFragmentPublicationAction:
            raise FragmentPublicationWebError("exact protected action required")
        self._pins()
        _, g, _ = _parts(self._publication)
        _fragment_decision_owner(self._continuity.for_cookie(cookie), self.host_clock, g)
        receipt = self._protector.recheck_publication_admission(
            reference=result.retained.reference,
            expected_admission=result.retained.admission,
            expected_publication=self._publication,
        )
        if receipt != result.receipt or result.deadline != g.expires_at:
            raise FragmentPublicationWebError("exact original action checkpoint required")
        self._pins()
        return result

    def _run_task(
        self, *, cookie: str, action: ProtectedFragmentPublicationAction
    ) -> _RetainedFragmentTask:
        with self._recovery_lock:
            return self._run_task_serialized(cookie=cookie, action=action)

    def _run_task_serialized(
        self, *, cookie: str, action: ProtectedFragmentPublicationAction
    ) -> _RetainedFragmentTask:
        """Only the actual protected APPROVE POST enters the concrete chain.

        Host opt-in is configuration, never admission. Called by submit in the
        existing ASGI worker thread, not on the event loop. No deadline/budget
        is changed, and cancellation uses the separate existing POST branch.
        """
        from html import escape

        from zacai.intelligence.contextual_evaluation import (
            ContextualOutcome,
            check_history_fragment_contextual_evaluation,
        )
        from zacai.intelligence.contextual_review import render_contextual_preview
        from zacai.intelligence.fragment_publication_generation import (
            CanonicalPersonalFragmentPublicationAuthorization,
            retain_personal_fragment_publication_output,
        )
        from zacai.intelligence.fragment_publication_review import (
            CanonicalFragmentPublicationReviewAuthorization,
            capture_fragment_publication_assessment,
            invoke_personal_fragment_publication_review,
        )
        from zacai.intelligence.fragment_review_runtime import _LocalFragmentReviewRuntime
        from zacai.intelligence.history_fragment_contextual_codec import (
            render_history_fragment_packet_preview,
        )
        from zacai.intelligence.local_contextual_runtime import FragmentLocalContextualRuntime

        with self._task_lock:
            if not self._run_approved_task or self._task_entered:
                self._task_held = True
                self._task_result = None
                raise FragmentPublicationWebError("local context task consumed")
            self._task_entered = True  # Includes every failure; no retry/repair.
        self.recheck_result(cookie=cookie, result=action)
        self._original_task_session(cookie)
        _, g, q = _parts(self._publication)
        parent = CanonicalPersonalFragmentPublicationAuthorization(
            factory=self._protector._factory, artifacts=self._protector._artifacts,
            publication=self._publication, admission_reference=action.retained.reference,
            admission=action.retained.admission, request=q, protector=self._protector,
            operation=self._protector._operation, clock=self.host_clock,
        )
        generation = FragmentLocalContextualRuntime(
            route=g.route, model_digest=g.model_digest, tokenizer_digest=g.tokenizer_digest,
            runtime_digest=g.runtime_digest, template_digest=g.template_digest,
            renderer_digest=g.renderer_digest, token_counter=self._generation_counter,
            recheck=parent.recheck,
        )
        parent.bind_runtime(generation)
        generation.preflight_fragment(q)
        draft = generation.generate_fragment(q)
        output = retain_personal_fragment_publication_output(parent, runtime=generation, request=q, draft=draft)
        reviewer = CanonicalFragmentPublicationReviewAuthorization(
            generation_authorization=parent, associated_output=output,
            rubric_utf8=self._rubric, template_utf8=self._template,
        )
        reviewer.prepare_review()
        engine = _LocalFragmentReviewRuntime(profile=self._review_profile, token_counter=self._review_counter)
        reviewer.bind_review_runtime(engine)
        judgments = invoke_personal_fragment_publication_review(reviewer, runtime=engine)
        assessed = capture_fragment_publication_assessment(reviewer, runtime=engine, result=judgments)
        if reviewer._packet_raw is None:
            raise FragmentPublicationWebError("complete retained review input required")
        outcome = check_history_fragment_contextual_evaluation(
            assessed.assessment.evaluation, reviewer._packet_raw,
        )
        if outcome not in (ContextualOutcome.REVIEWED_PASS, ContextualOutcome.NEEDS_CLARIFICATION):
            raise FragmentPublicationWebError("local context reply held for review")
        title = "Reviewed reply" if outcome is ContextualOutcome.REVIEWED_PASS else "Clarification needed"
        text = render_contextual_preview(output.retained.packet.review, q.context())
        evidence = render_history_fragment_packet_preview(output.retained.packet.review, q)
        html = ('<section class="decision-card"><h1>' + title + '</h1>'
                '<p>Historical evidence with its original dates and gaps; this is not current-fact approval.</p>'
                '<pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + escape(text) + '</pre>'
                '<details><summary>Sources, dates and gaps</summary>'
                '<pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + escape(evidence)
                + '</pre></details></section>')
        returned = _RetainedFragmentTask(html, reviewer, assessed, g.expires_at, engine, judgments)
        self._pins()
        self._original_task_session(cookie)
        reviewer._terminal(assessed.recovery_receipt, assessed.reference, "ASSESSMENT")
        self._review_origin(returned)
        self._task_release_time(reviewer)
        with self._task_lock:
            if self._task_held:
                raise FragmentPublicationWebError("local context task held")
            self._task_result = returned
        return returned

    def _original_task_session(self, cookie: str) -> None:
        # Preserve the actual protector operation object. A fresh equal operation
        # may compare the current cookie, but must never replace the authority graph.
        if self._protector._operation._source is not self._continuity:
            raise FragmentPublicationWebError("original operation source differs")
        current = self._continuity.for_cookie(cookie).establish()
        original = self._protector._operation.recheck(current.binding_digest)
        if original != current:
            raise FragmentPublicationWebError("original task session changed")

    def _recheck_task(self, *, cookie: str, result: _RetainedFragmentTask) -> None:
        from zacai.intelligence.fragment_publication_review import (
            load_fragment_publication_assessment,
            recheck_publication_assessment,
        )

        if result is not self._task_result or result.deadline != self._publication.expires_at:
            raise FragmentPublicationWebError("exact retained task required")
        self._review_origin(result)
        self._pins()
        self._original_task_session(cookie)
        gate, retained = result.authorization, result.assessment
        parent = gate._generation
        with parent._factory() as session:
            session.begin()
            loaded = load_fragment_publication_assessment(
                session, authorization=gate, reference=retained.reference, expected=retained.assessment,
            )
            if loaded != retained.assessment:
                raise FragmentPublicationWebError("exact retained assessment required")
        receipt = recheck_publication_assessment(
            self._protector, authorization=gate, reference=retained.reference,
            expected_assessment=retained.assessment,
        )
        if receipt != retained.recovery_receipt:
            raise FragmentPublicationWebError("original assessment checkpoint changed")
        self._original_task_session(cookie)
        gate._terminal(receipt, retained.reference, "ASSESSMENT")
        self._review_origin(result)
        self._task_release_time(gate)

    @staticmethod
    def _review_origin(result: _RetainedFragmentTask) -> None:
        if (result.authorization._runtime is not result.runtime
            or result.runtime._authenticated_held
            or result.runtime._authenticated_result is not result.review_result):
            raise FragmentPublicationWebError("original review producer unavailable")

    @staticmethod
    def _task_release_time(gate: CanonicalFragmentPublicationReviewAuthorization) -> None:
        from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

        # prepare_review caps this original interval by consent expiry; that
        # expiry is itself capped by the original effective signed-session expiry.
        # Trusted builtin scalar only: no mutating host callback after final SQL.
        if (gate._phase != "ASSESSMENT_RETAINED"
            or gate._deadline_monotonic is None
            or _AUTHENTICATED_MONOTONIC() >= gate._deadline_monotonic):
            raise FragmentPublicationWebError("original review/display interval expired")

    def cancellation_page(self, *, cookie: str) -> FragmentPublicationPage:
        from html import escape

        from zacai.intelligence.fragment_review_withdrawal import (
            _snapshot,
            load_historical_fragment_declaration_target,
        )

        current = self._cancel_session(cookie)
        _, g, _ = _parts(self._publication)
        if current.principal.scopes != _SCOPE or (
            current.principal.identity.issuer,
            current.principal.identity.subject,
        ) != (g.owner_issuer, g.owner_subject):
            raise FragmentPublicationWebError(
                "original actor/current cancellation session required"
            )
        with self._protector._factory() as session:
            session.begin()
            target = load_historical_fragment_declaration_target(
                session,
                artifacts=self._protector._artifacts,
                reference=self._reference,
                expected_declaration=self._publication,
            )
            rows = _snapshot(session, target, (self._reference,))
        user = self._continuity._sessions.peek_user(cookie, self.host_clock())
        if user is None:
            raise FragmentPublicationWebError("current cancellation session required")
        digest = fragment_generation_review_declaration_digest(self._publication)
        with self._task_lock:
            cleanup_uncertain = self._cleanup_uncertain
        warning = (
            "<p>PERSONAL cleanup uncertain. Stop and reconcile; do not retry processing. "
            "You can still cancel this task.</p>" if cleanup_uncertain else ""
        )
        html = (
            '<section class="decision-card"><h1>Cancel this published task</h1>'
            + warning +
            "<p>Cancellation does not renew the original processing window or change source custody.</p>"
            "<details><summary>Exact historical publication</summary><pre>"
            + escape(self._raw.decode())
            + "</pre></details>"
            '<form method="post" action="/ask-caz-locally">'
            '<input type="hidden" name="action" value="withdraw_fragment_publication">'
            '<input type="hidden" name="csrf" value="' + escape(user.csrf, quote=True) + '">'
            '<input type="hidden" name="publication_digest" value="' + digest + '">'
            '<input type="hidden" name="source_id" value="' + str(self._reference.source_id) + '">'
            '<button type="submit">Cancel this published task</button></form></section>'
        )
        return FragmentPublicationPage(
            html, current.effective_expires_at, digest, None, target, rows
        )

    @staticmethod
    def _cancellation_rows(
        session: Session, value: RetainedFragmentWithdrawal
    ) -> tuple[tuple[tuple[str, object], ...], ...]:
        from zacai.intelligence.fragment_review_retention import _physical, _same
        from zacai.intelligence.fragment_review_withdrawal import _snapshot, _withdrawal_ids

        entry = _physical(session)
        if _withdrawal_ids(session, value.target.generation.id) != (value.reference.source_id,):
            raise FragmentPublicationWebError("exact cancellation identity required")
        rows = _snapshot(session, value.target, (value.target.reference, value.reference))
        _same(session, entry)
        return rows

    def scalar_response(
        self,
        value: FragmentPublicationPage
        | ProtectedFragmentPublicationAction
        | ObservedFragmentCancellation
        | _RetainedFragmentTask,
    ) -> None:
        if type(value) is _RetainedFragmentTask:
            self._review_origin(value)
            if value is not self._task_result or value.authorization._phase != "ASSESSMENT_RETAINED":
                raise FragmentPublicationWebError("exact retained task required")
            value.authorization._terminal(
                value.assessment.recovery_receipt, value.assessment.reference, "ASSESSMENT"
            )
            self._review_origin(value)
            self._task_release_time(value.authorization)
            return
        if type(value) is ObservedFragmentCancellation:
            with self._protector._factory() as session:
                session.begin()
                if self._cancellation_rows(session, value.withdrawal) != value.rows:
                    raise FragmentPublicationWebError("canonical cancellation changed")
        elif type(value) is FragmentPublicationPage and value.receipt is None:
            from zacai.intelligence.fragment_review_withdrawal import _snapshot

            if value.target is None:
                raise FragmentPublicationWebError("exact historical target required")
            with self._protector._factory() as session:
                session.begin()
                if _snapshot(session, value.target, (self._reference,)) != value.rows:
                    raise FragmentPublicationWebError("historical cancellation target changed")
        else:
            if not isinstance(value, (FragmentPublicationPage, ProtectedFragmentPublicationAction)):
                raise FragmentPublicationWebError("exact response family required")
            if value.receipt is None:
                raise FragmentPublicationWebError("exact protected publication required")
            self.scalar_release(value.receipt)

    def _cancel_session(self, cookie: str) -> VerifiedNamedSession:
        current = self._continuity.for_cookie(cookie).establish()
        _, g, _ = _parts(self._publication)
        if current.principal.scopes != _SCOPE or (
            current.principal.identity.issuer,
            current.principal.identity.subject,
        ) != (g.owner_issuer, g.owner_subject):
            raise FragmentPublicationWebError(
                "original actor/current cancellation session required"
            )
        return current
