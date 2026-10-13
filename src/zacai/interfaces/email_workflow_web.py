"""Optional finite original-owner app email flow; no listeners, send or retries.

Cold concrete host dependencies bind once to the first actual authenticated GET.
Server-held evidence selections remain exact.
Forms/URLs carry correlation only. Existing observed POST, canonical Source,
protection, consumed processing claim and human assessment remain authoritative.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from html import escape
from threading import RLock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from starlette.requests import Request

from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.gmail_app_observation import GmailAppObservationPreparationV1
from zacai.intelligence.email_draft import EmailDraftPacketV1, EmailRecipientComparisonV1
from zacai.intelligence.email_processing_runtime import FixedLocalEmailRuntimeV1
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.interfaces.email_app_input import EmailAppInputSelectionV1
from zacai.interfaces.email_input import CanonicalBrainstormEmailInput, observe_email_input_post
from zacai.interfaces.email_input_protection import BrainstormEmailInputProtection
from zacai.interfaces.email_owner_review import (
    CanonicalBrainstormEmailOwnerReview,
    OwnerCheckedEmailV1,
    SavedEmailOwnerAssessmentV1,
    observe_email_owner_assessment_post,
)
from zacai.interfaces.email_owner_review_contracts import CONFIRMATION, EmailOwnerReviewManifestV1
from zacai.interfaces.email_owner_review_protection import BrainstormEmailOwnerReviewProtection
from zacai.interfaces.email_processing import (
    CanonicalBrainstormEmailProcessing,
    RetainedEmailInvocationV1,
    observe_email_processing_post,
)
from zacai.interfaces.email_processing_contracts import ACTION, EmailProcessingManifestV1
from zacai.interfaces.email_processing_protection import BrainstormEmailProcessingProtection
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.private_web import _USER, _cookie

_RELEASE = "Make this checked draft available for manual use. Do not send it."
_PATHS = frozenset(
    {
        "/prepare-caz-email",
        "/generate-caz-email",
        "/review-caz-email",
        "/caz-email-result",
        "/release-caz-email",
    }
)


class EmailWorkflowWebError(ValueError):
    """Fixed private-safe hold; canonical pending custody needs host reconciliation."""


@dataclass(frozen=True)
class EmailWorkflowPage:
    html: str
    deadline: datetime


def _hidden(name: str, value: str) -> str:
    return (
        '<input type="hidden" name="'
        + escape(name, quote=True)
        + '" value="'
        + escape(value, quote=True)
        + '">'
    )


def _packet_html(packet: EmailDraftPacketV1) -> str:
    """Show whole immutable draft/evidence, all untrusted fields escaped."""
    spec, candidate = packet.specification(), packet.candidate
    recipient = (
        (spec.recipient.display_name + " <" + spec.recipient.address + ">")
        if spec.recipient
        else "Recipient unresolved"
    )
    result = "<p>Recipient: " + escape(recipient) + "</p>"
    result += (
        "<pre>"
        + escape(packet.rendered_preview)
        + "</pre><details><summary>Supporting evidence</summary>"
    )
    for detail in candidate.evidence_detail:
        result += (
            "<p>"
            + escape(detail.target + ": " + detail.support_kind + ". " + detail.explanation)
            + "</p>"
        )
        for quote in detail.quotes:
            result += "<pre>" + escape(quote.text) + "</pre>"
    if candidate.blocking_question:
        for quote in candidate.blocking_question.quotes:
            result += "<pre>" + escape(quote.text) + "</pre>"
    result += "</details><details><summary>Complete selected source context</summary>"
    for item in spec.task().context:
        result += "<pre>" + escape(item.untrusted_text) + "</pre>"
    return result + "</details>"


class EmailWorkflowWeb:
    """One existing original-session workflow, explicitly configured by the host.

    Construction grants nothing and performs no source read/model call. A genuine
    authenticated GET binds the original operation once; a different cookie holds. This is
    not a fresh-session/historical reader or an acquisition-account authenticator.
    A failed entered POST holds this controller; it never retries inference.
    """

    def __init__(
        self,
        *,
        continuity: NamedSessionContinuity,
        protector: BrainstormContextualProtector,
        runtime: FixedLocalEmailRuntimeV1,
        preparations: tuple[GmailAppObservationPreparationV1, ...],
        recipient: EmailRecipientComparisonV1 | None,
        max_output_tokens: int = 1000,
        max_latency_ms: int = 120000,
    ) -> None:
        if (
            type(continuity) is not NamedSessionContinuity
            or type(protector) is not BrainstormContextualProtector
            or type(runtime) is not FixedLocalEmailRuntimeV1
            or type(preparations) is not tuple
            or not 1 <= len(preparations) <= 2
            or any(type(p) is not GmailAppObservationPreparationV1 for p in preparations)
            or type(max_output_tokens) is not int
            or not 1 <= max_output_tokens <= 2048
            or type(max_latency_ms) is not int
            or not 1 <= max_latency_ms <= 120000
        ):
            raise EmailWorkflowWebError("email workflow configuration unavailable")
        self.continuity, self._protector, self._runtime = continuity, protector, runtime
        self.host_clock = continuity._clock
        self._operation: NamedSessionOperation | None = None
        self._inputs: CanonicalBrainstormEmailInput | None = None
        self._processing: CanonicalBrainstormEmailProcessing | None = None
        self._review: CanonicalBrainstormEmailOwnerReview | None = None
        self._binding: str | None = None
        self._binding_started = False
        self._cold_graph = self._cold_graph_now()
        self._preparations, self._recipient = preparations, recipient
        self._tokens, self._latency = max_output_tokens, max_latency_ms
        self._request_id = uuid4()
        self._selection: EmailAppInputSelectionV1 | None = None
        self._manifest: EmailProcessingManifestV1 | None = None
        self._output: RetainedEmailInvocationV1 | None = None
        self._review_manifest: EmailOwnerReviewManifestV1 | None = None
        self._assessment: SavedEmailOwnerAssessmentV1 | None = None
        self._release: OwnerCheckedEmailV1 | None = None
        self._phase = "NEW"
        self._lock = RLock()
        self._graph: tuple[object, ...] | None = None

    def _cold_graph_now(self) -> tuple[object, ...]:
        c = self.continuity
        return (
            c,
            self._protector,
            self._runtime,
            self.host_clock,
            c._sessions,
            c._owner,
            c._clock,
            c._context,
            c._key,
        )

    def _bind(self, request: Request) -> None:
        if self._binding_started or request.method != "GET":
            raise ValueError("one actual original GET binding required")
        self._binding_started = True
        operation = self.continuity.for_cookie(_cookie(request, _USER))
        original = operation.establish()
        inputs = CanonicalBrainstormEmailInput(
            BrainstormEmailInputProtection(
                protector=self._protector,
                operation=operation,
                original_binding=original.binding_digest,
            )
        )
        processing = CanonicalBrainstormEmailProcessing(
            inputs=inputs,
            protection=BrainstormEmailProcessingProtection(
                protector=self._protector,
                operation=operation,
                original_binding=original.binding_digest,
            ),
            runtime=self._runtime,
        )
        review = CanonicalBrainstormEmailOwnerReview(
            processing=processing,
            protection=BrainstormEmailOwnerReviewProtection(
                protector=self._protector,
                operation=operation,
                original_binding=original.binding_digest,
            ),
        )
        if operation.recheck(original.binding_digest) != original or any(
            a is not b for a, b in zip(self._cold_graph, self._cold_graph_now(), strict=True)
        ):
            raise ValueError("original cold assembly changed")
        self._operation, self._inputs, self._processing, self._review = (
            operation,
            inputs,
            processing,
            review,
        )
        self._binding = original.binding_digest
        self._graph = self._graph_now()

    def _graph_now(self) -> tuple[object, ...]:
        assert (
            self._inputs is not None
            and self._processing is not None
            and self._review is not None
            and self._operation is not None
        )
        i, p, r, o, c = (
            self._inputs,
            self._processing,
            self._review,
            self._operation,
            self.continuity,
        )
        return (
            i,
            p,
            r,
            o,
            c,
            self.host_clock,
            i._operation,
            p._operation,
            r._operation,
            p._inputs,
            r._processing,
            p._runtime,
            p._clock,
            i._factory,
            p._factory,
            r._factory,
            i._artifacts,
            p._artifacts,
            r._artifacts,
            i._protection,
            p._protection,
            r._protection,
            i._protection._protector,
            p._protection._protector,
            r._protection._protector,
            c._sessions,
            c._owner,
            c._clock,
            o._read,
            o._host_clock,
            o._source,
        )

    def _identity(self, request: Request) -> tuple[str, datetime]:
        if any(a is not b for a, b in zip(self._cold_graph, self._cold_graph_now(), strict=True)):
            raise ValueError("cold email host dependencies changed")
        if (
            type(request) is not Request
            or request.url.path not in _PATHS
            or request.scope.get("query_string", b"")
            or request.headers.getlist("host")
            != [urlsplit(json.loads(self.continuity._context)["origin"]).netloc]
        ):
            raise ValueError("closed original email request required")
        if self._operation is None:
            self._bind(request)
        assert self._operation is not None and self._binding is not None and self._graph is not None
        if any(a is not b for a, b in zip(self._graph, self._graph_now(), strict=True)):
            raise ValueError("original concrete email graph changed")
        original = self._operation.recheck(self._binding)
        cookie = _cookie(request, _USER)
        actual = self.continuity.for_cookie(cookie).recheck(self._binding)
        current = self.continuity._sessions.peek_user(cookie, self.host_clock())
        final = self._operation.recheck(self._binding)
        if (
            original != actual
            or final != original
            or current is None
            or current.identity != final.principal.identity
        ):
            raise ValueError("current original owner session required")
        return current.csrf, final.effective_expires_at

    def _page(self, request: Request) -> EmailWorkflowPage:
        csrf, deadline = self._identity(request)
        assert (
            self._inputs is not None and self._processing is not None and self._review is not None
        )
        if request.url.path == "/caz-email-result" and self._output is None:
            raise ValueError("completed protected output absent")
        html = "<h1>Email follow-up</h1><p>App observation serialization. Mailbox account and sender identity are unverified. One selected body per message, incomplete thread and missing attachments. No email is sent.</p>"
        if self._phase == "HELD":
            raise ValueError("entered workflow held; reconcile canonical custody")
        if self._phase == "NEW":
            selected = self._inputs.prepare_app_selection(
                preparations=self._preparations,
                recipient=self._recipient,
                max_output_tokens=self._tokens,
                max_latency_ms=self._latency,
                max_estimated_cost_usd=0.0,
            )
            if self._selection is not None and selected != self._selection:
                raise ValueError("published selection changed")
            self._selection = selected
            html += "<p>Capture the exact selected observations and your instruction with encrypted recovery. This does not approve AI processing.</p>"
            if self._recipient:
                html += (
                    "<p>Selected recipient: "
                    + escape(self._recipient.display_name + " <" + self._recipient.address + ">")
                    + "</p>"
                )
            else:
                html += "<p>Recipient unresolved. A draft must ask for clarification.</p>"
            for preparation in self._preparations:
                html += (
                    "<details><summary>Selected unverified body</summary><pre>"
                    + escape(preparation.literal_text)
                    + "</pre></details>"
                )
            html += (
                '<form method="post" action="/prepare-caz-email" accept-charset="UTF-8">'
                + _hidden("csrf", csrf)
                + _hidden("request_id", str(self._request_id))
                + _hidden("selection_digest", selected.digest())
                + '<label>Exact instruction<textarea name="instruction" maxlength="2000" required></textarea></label><button>Capture for review</button></form>'
            )
        elif self._output is None:
            if self._manifest is None:
                raise ValueError("protected prepared input absent")
            self._processing._fresh_inputs(self._manifest)
            html += (
                '<p>Protected input captured. Generate this exact candidate once locally for your review. No automatic retry.</p><form method="post" action="/generate-caz-email">'
                + _hidden("csrf", csrf)
                + _hidden("action_id", str(self._manifest.action_id))
                + _hidden("manifest_digest", self._manifest.digest())
                + _hidden("action", ACTION)
                + "<button>Generate once locally</button></form>"
            )
        else:
            # This reader preserves original output ownership after generator
            # consent expiry; it never renews processing or performs inference.
            read = self._review.read_output(self._output.reference, self._output.receipt)
            html += "<p>Candidate held for your semantic review.</p>" + _packet_html(read.packet)
            if self._assessment is None:
                if self._review_manifest is None:
                    raise ValueError("published review absent")
                m = self._review_manifest
                html += (
                    '<form method="post" action="/review-caz-email">'
                    + _hidden("csrf", csrf)
                    + _hidden("action_id", str(m.action_id))
                    + _hidden("manifest_digest", m.digest())
                    + '<label>Decision<select name="decision">'
                )
                choices = (
                    ("ACCEPT", "DECLINE", "DEFER")
                    if read.packet.candidate.blocking_question is None
                    else ("DEFER", "DECLINE")
                )
                html += (
                    "".join("<option>" + choice + "</option>" for choice in choices)
                    + '</select></label><label>Reason<textarea name="reason" maxlength="2000" required></textarea></label><label>Semantic confirmation<select name="confirmation"><option value="">No acceptance confirmation</option><option value="'
                    + escape(CONFIRMATION, quote=True)
                    + '">'
                    + escape(CONFIRMATION)
                    + "</option></select></label><p>Choose no acceptance confirmation for decline or defer.</p><button>Record assessment</button></form>"
                )
            else:
                saved = self._review.load_assessment(
                    self._assessment.reference, self._assessment.receipt
                )
                html += "<p>Assessment: " + escape(saved.record.decision) + ".</p>"
                if self._release is not None:
                    released = self._review.load_release(
                        self._release.reference, self._release.receipt
                    )
                    html += (
                        "<p>Checked draft available for manual use. Sending is not authorized.</p>"
                        + _packet_html(released.packet)
                    )
                elif saved.record.decision == "ACCEPT":
                    html += (
                        '<form method="post" action="/release-caz-email">'
                        + _hidden("csrf", csrf)
                        + _hidden("assessment_digest", saved.reference.content_hash)
                        + _hidden("action", _RELEASE)
                        + "<button>Release for manual use</button></form>"
                    )
                else:
                    html += "<p>Manual-use release held. A new assessment or edited candidate requires a separately prepared workflow.</p>"
        assert self._graph is not None
        if any(a is not b for a, b in zip(self._graph, self._graph_now(), strict=True)) or any(
            a is not b for a, b in zip(self._cold_graph, self._cold_graph_now(), strict=True)
        ):
            raise ValueError("email dependencies changed during final read")
        if self.host_clock() >= deadline:
            raise ValueError("original page session expired")
        return EmailWorkflowPage(html, deadline)

    def page(self, request: Request) -> EmailWorkflowPage:
        if not self._lock.acquire(blocking=False):
            raise EmailWorkflowWebError("email workflow unavailable")
        interruption: type[BaseException] | None = None
        code: int | None = 1
        result = None
        try:
            result = self._page(request)
        except BaseException as error:  # noqa: BLE001 - no private/cancellation arguments escape
            interruption = type(error)
            if isinstance(error, SystemExit):
                code = error.code if error.code is None or type(error.code) is int else 1
        finally:
            self._lock.release()
        _raise_interruption(interruption, code)
        if result is None:
            raise EmailWorkflowWebError("email workflow unavailable")
        return result

    def submit(self, request: Request, body: bytes) -> EmailWorkflowPage:
        if not self._lock.acquire(blocking=False):
            raise EmailWorkflowWebError("email workflow unavailable")
        interruption: type[BaseException] | None = None
        code: int | None = 1
        result = None
        entered = False
        try:
            self._identity(request)
            assert (
                self._inputs is not None
                and self._processing is not None
                and self._review is not None
                and self._operation is not None
            )
            if type(body) is not bytes or not 0 < len(body) <= 12000:
                raise ValueError("bounded exact body required")
            if request.method != "POST":
                raise ValueError("POST required")
            if (
                request.url.path == "/prepare-caz-email"
                and self._phase == "NEW"
                and self._selection
            ):
                post = observe_email_input_post(
                    request,
                    body=body,
                    operation=self._operation,
                    request_id=self._request_id,
                    selection=self._selection,
                    app_preparations=self._preparations,
                )
                entered = True
                self._phase = "ENTERED"
                saved = self._inputs.capture(post)
                self._manifest = self._processing.prepare(
                    saved, action_id=uuid4(), builder_id=uuid4()
                )
                self._phase = "PREPARED"
            elif (
                request.url.path == "/generate-caz-email"
                and self._phase == "PREPARED"
                and self._manifest
            ):
                post_generation = observe_email_processing_post(
                    request, body=body, operation=self._operation, manifest=self._manifest
                )
                entered = True
                self._phase = "ENTERED"
                ref, receipt = self._processing.record(post_generation)
                self._output = self._processing.generate(ref, receipt)
                self._review_manifest = self._review.prepare(
                    self._output.reference, self._output.receipt, action_id=uuid4()
                )
                self._phase = "OUTPUT"
            elif (
                request.url.path == "/review-caz-email"
                and self._phase == "OUTPUT"
                and self._review_manifest
            ):
                post_review = observe_email_owner_assessment_post(
                    request, body=body, operation=self._operation, manifest=self._review_manifest
                )
                entered = True
                self._phase = "ENTERED"
                self._assessment = self._review.record_assessment(post_review)
                self._phase = "ASSESSED"
            elif (
                request.url.path == "/release-caz-email"
                and self._phase == "ASSESSED"
                and self._assessment
            ):
                csrf, _ = self._identity(request)
                values = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
                origin = json.loads(self.continuity._context)["origin"]
                if (
                    request.headers.getlist("origin") != [origin]
                    or request.headers.getlist("content-type")
                    != ["application/x-www-form-urlencoded"]
                    or set(values) != {"csrf", "assessment_digest", "action"}
                    or any(len(v) != 1 for v in values.values())
                    or not secrets.compare_digest(values["csrf"][0], csrf)
                    or values["assessment_digest"][0] != self._assessment.reference.content_hash
                    or values["action"][0] != _RELEASE
                ):
                    raise ValueError("exact checked release POST required")
                entered = True
                self._phase = "ENTERED"
                self._release = self._review.release(self._assessment)
                self._phase = "RELEASED"
            else:
                raise ValueError("workflow action unavailable or already consumed")
            result = self._page(request)
        except BaseException as error:  # noqa: BLE001 - preserve consumed actions, sanitize interruption
            if entered:
                self._phase = "HELD"
            interruption = type(error)
            if isinstance(error, SystemExit):
                code = error.code if error.code is None or type(error.code) is int else 1
        finally:
            self._lock.release()
        _raise_interruption(interruption, code)
        if result is None:
            raise EmailWorkflowWebError("email workflow not acknowledged; review protected custody")
        return result
