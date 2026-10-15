"""One-attempt complete LOCAL generation, only through its concrete canonical gate.

No enabled host, optional approval hook, fallback or absent-authority arm.
Runtime observations/model metadata are not processing permission or review.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Literal
from uuid import UUID, uuid4

from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_generation import ContextualDraft
from zacai.intelligence.contracts import ModelRoute, UsageObservation
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualRequestV1,
    encode_history_contextual_request,
)
from zacai.intelligence.history_generation_review_declaration import prepare_history_generation_wire
from zacai.intelligence.local_contextual_runtime import (
    _context_tokens,
    _fragment_http_post,
    _fragment_verify_runtime,
    _parse_history_response,
    fragment_contextual_counter_pins,
)
from zacai.intelligence.local_review_runtime import _http, verify_model
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.policy import Destination

if TYPE_CHECKING:
    from zacai.intelligence.history_publication_generation import (
        CanonicalPersonalHistoryPublicationAuthorization,
    )

_NATIVE_MONOTONIC = time.monotonic


class HistoryContextualRuntimeError(ValueError):
    """Fixed safe HOLD; instance and original claim may be consumed."""


@dataclass(frozen=True, repr=False)
class HistoryContextualDispatchDescriptor:
    phase: Literal["PRE_DISPATCH", "RELEASE"]
    attempt_id: UUID
    retained_request_digest: str
    body_digest: str
    route_digest: str
    model_digest: str
    tokenizer_digest: str
    runtime_digest: str
    template_digest: str
    renderer_digest: str
    prompt_tokens: int
    requested_output_tokens: int
    deadline_monotonic: float
    output_digest: str | None = None
    usage_digest: str | None = None


def history_contextual_runtime_digest() -> str:
    root = Path(__file__).parent.parent
    names = (
        "intelligence/history_contextual_runtime.py",
        "intelligence/history_publication_generation.py",
        "intelligence/history_publication_protection.py",
        "intelligence/history_publication_review.py",
        "intelligence/history_review_runtime.py",
        "intelligence/history_review_preparation.py",
        "intelligence/history_review_wire.py",
        "intelligence/history_review_prompt_counter.py",
        "intelligence/history_publication_admission.py",
        "interfaces/history_publication_action.py",
        "intelligence/history_review_retention.py",
        "intelligence/history_generation_review_declaration.py",
        "__init__.py",
        "claude_historical_fragment.py",
        "ingestion/__init__.py",
        "intelligence/__init__.py",
        "intelligence/contextual_evaluation.py",
        "intelligence/eligibility.py",
        "intelligence/evidence.py",
        "intelligence/history_fragment_contextual_codec.py",
        "intelligence/project_review_context.py",
        "intelligence/review_audit.py",
        "intelligence/review_freshness.py",
        "intelligence/review_host.py",
        "intelligence/runtime_diagnostics.py",
        "intelligence/history_contextual_codec.py",
        "claude_large_original_message.py",
        "claude_history_index.py",
        "claude_custody_selection.py",
        "history_manifest.py",
        "claude_message_projection.py",
        "claude_original_read.py",
        "claude_original_capture.py",
        "intelligence/review_evaluation.py",
        "intelligence/history_context_metadata.py",
        "intelligence/native_context_metadata.py",
        "intelligence/contextual_generation.py",
        "intelligence/contextual_storage.py",
        "intelligence/local_contextual_runtime.py",
        "intelligence/local_review_runtime.py",
        "intelligence/ollama_token_counter.py",
        "intelligence/native_prompt_counter.py",
        "contextual_protection.py",
        "contextual_authorization.py",
        "state_repository.py",
        "state.py",
        "backup_artifacts.py",
        "backup.py",
        "review_protection.py",
        "ingestion/artifact_store.py",
        "interfaces/named_session_binding.py",
        "owner_authority.py",
        "interfaces/private_web.py",
        "interfaces/session_store.py",
        "interfaces/oidc_identity.py",
        "host_clock.py",
        "interfaces/host_clock.py",
        "policy.py",
        "gateway.py",
        "review_authorization.py",
        "claude_local_protection.py",
        "intelligence/fragment_review_retention.py",
        "intelligence/fragment_publication_generation.py",
        "intelligence/review_context.py",
        "intelligence/contracts.py",
        "intelligence/contextual_review.py",
        "intelligence/contextual_diagnostics.py",
        "intelligence/meeting_review.py",
        "intelligence/review_generation.py",
    )
    return hashlib.sha256(
        b"zac-history-complete-consumer-runtime-v1\0"
        + canonical_bytes(
            {
                "files": [
                    (name, hashlib.sha256((root / name).read_bytes()).hexdigest()) for name in names
                ]
            }
        )
    ).hexdigest()


def _route_digest(route: ModelRoute) -> str:
    value = route.model_dump(mode="json")
    value["capabilities"] = sorted(route.capabilities)
    return content_hash_of(canonical_bytes(value))


class LocalHistoryContextualRuntime:
    """A concrete gate is mandatory. Construction/preflight grant no permission."""

    def __init__(
        self, *, route: ModelRoute, model_digest: str, counter: OllamaQwenContextualTokenCounter
    ) -> None:
        if (
            type(route) is not ModelRoute
            or type(counter) is not OllamaQwenContextualTokenCounter
            or route.destination is not Destination.LOCAL
            or not route.available
            or counter.model_digest != model_digest
        ):
            raise HistoryContextualRuntimeError("complete local runtime configuration unavailable")
        self._route = route
        self._model_digest = model_digest
        self._counter = counter
        self._counter_identity = counter._tokenizer
        self._lock = Lock()
        self._attempted = False
        self._did_transport_attempt = False
        self._authorization: CanonicalPersonalHistoryPublicationAuthorization | None = None
        self._prepared: tuple[bytes, bytes, int, float] | None = None
        self._started: float | None = None
        self._preflight_entered = False
        self._attempt_id: UUID | None = None
        self._result: tuple[ContextualDraft, UsageObservation] | None = None
        self._released: HistoryContextualDispatchDescriptor | None = None

    def configuration(self) -> tuple[str, str, str, str, str, str]:
        if (
            type(self._counter) is not OllamaQwenContextualTokenCounter
            or self._counter._tokenizer is not self._counter_identity
        ):
            raise HistoryContextualRuntimeError("complete counter changed")
        pins = fragment_contextual_counter_pins(self._counter)
        return (
            self._model_digest,
            *pins,
            history_contextual_runtime_digest(),
            _route_digest(self._route),
        )

    def preflight(self, request: HistoryContextualRequestV1) -> None:
        failed = False
        interruption: BaseException | None = None
        try:
            gate = self._authorization
            if (
                self._preflight_entered
                or self._attempted
                or gate is None
                or gate._runtime is not self
            ):
                raise ValueError("original complete bound gate required")
            self._preflight_entered = True
            started = gate._started
            self._started = started
            gate._graph_check()
            if request is not gate._request:
                raise ValueError("original request identity required")
            retained = encode_history_contextual_request(request)
            body = prepare_history_generation_wire(
                request, generation_wire_format=gate._consent.generation_wire_format
            )
            if request.route != self._route:
                raise ValueError("actual route differs")
            count = self._counter.count_prompt_tokens(body)
            if (
                type(count) is not int
                or count <= 0
                or count != gate._consent.prompt_tokens
                or count + request.task.max_output_tokens > _context_tokens(self._route)
            ):
                raise ValueError("complete actual wire reservation does not fit")
            _fragment_verify_runtime(self._counter)
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            gate._graph_check()
            if self.configuration() != gate._runtime_configuration:
                raise ValueError("complete runtime pins changed")
            deadline = min(started + request.task.max_latency_ms / 1000, gate._deadline_monotonic)
            if _NATIVE_MONOTONIC() >= deadline:
                raise ValueError("original complete preflight interval expired")
            self._prepared = (retained, body, count, deadline)
        except BaseException as error:  # noqa: BLE001 - burn then preserve interruption
            failed = True
            if not isinstance(error, Exception):
                interruption = error
        if failed:
            self._attempted = True
            self._prepared = None
            if self._authorization is not None:
                self._authorization._hold()
            if interruption is not None:
                raise type(interruption)() from None
            raise HistoryContextualRuntimeError("complete local preflight held")

    def _descriptor(
        self,
        phase: Literal["PRE_DISPATCH", "RELEASE"],
        draft: ContextualDraft | None = None,
        usage: UsageObservation | None = None,
    ) -> HistoryContextualDispatchDescriptor:
        if self._prepared is None or self._attempt_id is None:
            raise ValueError("original prepared attempt required")
        retained, body, count, deadline = self._prepared
        model, tokenizer, template, renderer, runtime, route = self.configuration()
        if (phase == "RELEASE") != (draft is not None and usage is not None):
            raise ValueError("closed phase observations required")
        return HistoryContextualDispatchDescriptor(
            phase,
            self._attempt_id,
            content_hash_of(retained),
            content_hash_of(body),
            route,
            model,
            tokenizer,
            runtime,
            template,
            renderer,
            count,
            self._route.max_output_tokens
            if self._authorization is None
            else self._authorization._request.task.max_output_tokens,
            deadline,
            None
            if draft is None
            else content_hash_of(canonical_bytes(draft.model_dump(mode="json"))),
            None
            if usage is None
            else content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
        )

    def _unchanged(
        self,
        request: HistoryContextualRequestV1,
        bound: tuple[bytes, bytes, int, float],
        configuration: tuple[str, str, str, str, str, str],
    ) -> None:
        if (
            self._authorization is None
            or self._prepared is not bound
            or encode_history_contextual_request(request) != bound[0]
            or prepare_history_generation_wire(
                request, generation_wire_format=self._authorization._consent.generation_wire_format
            )
            != bound[1]
            or self.configuration() != configuration
        ):
            raise ValueError("complete original body or pins changed")

    def generate(self, request: HistoryContextualRequestV1) -> ContextualDraft:
        from zacai.intelligence.history_publication_generation import (
            CanonicalPersonalHistoryPublicationAuthorization,
        )

        acquired = self._lock.acquire(blocking=False)
        failed = False
        uncertain = False
        interruption: BaseException | None = None
        try:
            if not acquired or self._attempted:
                raise ValueError("complete attempt already entered")
            self._attempted = True
            self._attempt_id = uuid4()
            gate = self._authorization
            if (
                type(gate) is not CanonicalPersonalHistoryPublicationAuthorization
                or gate._runtime is not self
                or gate._request is not request
                or self._prepared is None
                or self._started is None
            ):
                raise ValueError("actual complete gate/preflight required")
            bound = self._prepared
            configuration = self.configuration()
            _fragment_verify_runtime(self._counter)
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            if self._counter.count_prompt_tokens(bound[1]) != bound[2]:
                raise ValueError("complete actual count changed")
            self._unchanged(request, bound, configuration)
            gate.recheck_generation_dispatch(request, self._descriptor("PRE_DISPATCH"))
            self._unchanged(request, bound, configuration)
            remaining = bound[3] - _NATIVE_MONOTONIC()
            if remaining <= 0:
                raise ValueError("original complete interval expired before POST")
            self._did_transport_attempt = True
            reply = _fragment_http_post(bound[1], remaining)
            elapsed = (_NATIVE_MONOTONIC() - self._started) * 1000
            draft, usage = _parse_history_response(reply, request, self._route, elapsed, bound[2])
            _reject_generated_em_dashes(draft)
            if usage.output_tokens <= 0:
                raise ValueError("nonempty generation needs positive reported output")
            _fragment_verify_runtime(self._counter)
            verify_model(self._route.identity.model_id, self._model_digest, _http)
            if self._counter.count_prompt_tokens(bound[1]) != bound[2]:
                raise ValueError("complete post count differs")
            self._unchanged(request, bound, configuration)
            descriptor = self._descriptor("RELEASE", draft, usage)
            gate.recheck_generation_dispatch(request, descriptor)
            self._unchanged(request, bound, configuration)
            terminal = _NATIVE_MONOTONIC()
            if terminal >= bound[3] or terminal < self._started:
                raise ValueError("original complete release interval expired")
            self._released = descriptor
            self._result = (draft, usage)
            return draft
        except PersonalFragmentCleanupUncertain:
            uncertain = True
            failed = True
        except BaseException as error:  # noqa: BLE001 - no private cause escapes
            failed = True
            if not isinstance(error, Exception):
                interruption = error
        finally:
            if failed:
                self._result = None
                self._released = None
                self._prepared = None
                if self._authorization is not None:
                    self._authorization._hold()
            if acquired:
                self._lock.release()
        if uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL complete generation cleanup uncertain; operator review required"
            )
        if interruption is not None:
            raise type(interruption)() from None
        raise HistoryContextualRuntimeError("complete local generation held")


from zacai.intelligence.contextual_diagnostics import (
    ContextualGenerationError,
    ContextualReviewInvalid,
    GenerationFailure,
    ReviewRejection,
)
from zacai.intelligence.contextual_generation import (
    DraftConnection,
    DraftQuestion,
    _prepare_contextual_catalog,
)
from zacai.intelligence.contextual_review import (
    Clarification,
    ContextualReview,
    EvidenceConflict,
    ProvisionalConnection,
    validate_contextual_review,
)
from zacai.intelligence.meeting_review import Claim, ReviewItem
from zacai.intelligence.review_generation import DraftClaim


def _resolve_complete_draft(
    draft: ContextualDraft, request: HistoryContextualRequestV1
) -> ContextualReview:
    """Resolve host identities and exact quotes; edited request/catalog rejects."""
    from zacai.intelligence.history_contextual_codec import (
        HistoryContextualRequestV1,
        encode_history_contextual_request,
    )

    failure = GenerationFailure.REQUEST
    rejection = None
    try:
        if type(request) is not HistoryContextualRequestV1:
            raise ValueError("unsupported contextual request family")
        encode_history_contextual_request(request)
        expected = _prepare_contextual_catalog(request.context())
        failure = GenerationFailure.DRAFT_SCHEMA
        draft = ContextualDraft.model_validate(draft)
        failure = GenerationFailure.CITATION
        quotes = dict(expected.quotes)

        def claim(value: DraftClaim | DraftConnection) -> Claim:
            if len(set(value.evidence_ids)) != len(value.evidence_ids):
                raise ValueError("duplicate evidence IDs")
            return Claim(
                text=value.text,
                inferred=value.inferred,
                quotes=tuple(quotes[eid] for eid in value.evidence_ids),
            )

        def question(value: DraftQuestion, conflict: bool) -> Clarification:
            cls = EvidenceConflict if conflict else Clarification
            return cls(**claim(value).model_dump(), question=value.question, reason=value.reason)

        # Resolve first: unknown IDs remain a citation failure.
        overview = tuple(claim(v) for v in draft.overview)
        background = tuple(claim(v) for v in draft.background)
        continuity = tuple(claim(v) for v in draft.continuity)
        items = tuple((v, claim(v)) for v in draft.items)
        conflicts = tuple(question(v, True) for v in draft.conflicts)
        clarifications = tuple(question(v, False) for v in draft.clarifications)
        failure = GenerationFailure.VALIDATION
        review = ContextualReview(
            format="zac-contextual-review-v1",
            task_id=expected.context.task.task_id,
            data_classification=expected.context.task.event.data_classification,
            overview=overview,
            background=background,
            continuity=tuple(ProvisionalConnection(**v.model_dump()) for v in continuity),
            items=tuple(
                ReviewItem(**resolved.model_dump(), kind=v.kind, owner=v.owner, due_date=v.due_date)
                for v, resolved in items
            ),
            conflicts=conflicts,
            clarifications=clarifications,
        )
        return validate_contextual_review(review, expected.context)
    except ContextualReviewInvalid as error:
        rejection = error.reason if failure == GenerationFailure.VALIDATION else None
    except Exception:  # noqa: BLE001 - no private model/catalog errors
        if failure == GenerationFailure.VALIDATION:
            rejection = ReviewRejection.CONSTRUCTION
    raise ContextualGenerationError(
        failure, "contextual draft unavailable or invalid", rejection=rejection
    )


def _reject_generated_em_dashes(draft: ContextualDraft) -> None:
    """Complete generated fields only; exact catalog/source quotes are separate.

    No task/source rewrite and no authentic-voice or semantic adequacy proof.
    """
    if type(draft) is not ContextualDraft:
        raise ValueError("exact complete generated draft required")

    def check(value: object) -> None:
        if isinstance(value, str) and "\u2014" in value:
            raise ValueError("complete generated prose violates original style requirement")
        if isinstance(value, dict):
            for child in value.values():
                check(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                check(child)

    check(draft.model_dump(mode="json"))
