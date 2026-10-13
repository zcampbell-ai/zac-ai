"""Exact complete review transport called only by its concrete original child gate."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from time import monotonic as _NATIVE_MONOTONIC
from typing import TYPE_CHECKING, Literal, cast
from uuid import UUID, uuid4

from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_review_wire as wire
from zacai.intelligence import local_review_runtime as base
from zacai.intelligence import ollama_token_counter as base_counter
from zacai.intelligence.contracts import UsageObservation
from zacai.intelligence.fragment_review_runtime import _loopback
from zacai.intelligence.history_review_preparation import (
    HistoryReviewJudgments,
    PreparedHistoryReviewRequest,
)
from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter

if TYPE_CHECKING:
    from zacai.intelligence.history_publication_review import (
        CanonicalPersonalHistoryReviewAuthorization,
    )


def history_review_runtime_digest() -> str:
    from zacai.intelligence.history_publication_review import (
        history_publication_review_graph_digest,
    )

    return content_hash_of(
        b"zac-history-complete-review-runtime-v1\0"
        + history_publication_review_graph_digest().encode()
    )


def history_review_wire_digest() -> str:
    from pathlib import Path

    return content_hash_of(
        b"zac-history-complete-review-wire-implementation-v1\0"
        + Path(wire.__file__).read_bytes()
        + canonical_bytes(HistoryReviewJudgments.model_json_schema())
    )


def history_review_derivation_digest() -> str:
    from pathlib import Path

    from zacai.intelligence import (
        history_context_metadata,
        history_contextual_codec,
        history_review_preparation,
    )

    return content_hash_of(
        b"zac-history-complete-review-derivation-v1\0"
        + canonical_bytes(
            {
                "files": [
                    (module.__name__, content_hash_of(Path(module.__file__ or "").read_bytes()))
                    for module in (
                        history_review_preparation,
                        history_contextual_codec,
                        history_context_metadata,
                    )
                ]
            }
        )
    )


@dataclass(frozen=True, slots=True, repr=False)
class HistoryReviewDispatchDescriptor:
    phase: Literal["PRE_DISPATCH", "RELEASE"]
    attempt_id: UUID
    request_digest: str
    packet_digest: str
    wire_body_digest: str
    configuration: tuple[str, ...]
    model_metadata_digest: str
    measured_input_tokens: int
    requested_output_tokens: int
    deadline_monotonic: float
    judgments_digest: str | None = None
    usage_digest: str | None = None


def descriptor_digest(d: HistoryReviewDispatchDescriptor) -> str:
    return content_hash_of(
        canonical_bytes(
            {
                "phase": d.phase,
                "attempt_id": str(d.attempt_id),
                "request_digest": d.request_digest,
                "packet_digest": d.packet_digest,
                "wire_body_digest": d.wire_body_digest,
                "configuration": d.configuration,
                "model_metadata_digest": d.model_metadata_digest,
                "measured_input_tokens": d.measured_input_tokens,
                "requested_output_tokens": d.requested_output_tokens,
                "deadline_monotonic": d.deadline_monotonic,
                "judgments_digest": d.judgments_digest,
                "usage_digest": d.usage_digest,
            }
        )
    )


@dataclass(frozen=True, slots=True, repr=False)
class ObservedHistoryReview:
    judgments: HistoryReviewJudgments
    usage: UsageObservation
    descriptor: HistoryReviewDispatchDescriptor


class HistoryReviewRuntimeError(ValueError):
    """Fixed safe complete review HOLD."""


class LocalHistoryReviewRuntime:
    def __init__(self, *, counter: OllamaQwenHistoryReviewTokenCounter) -> None:
        if type(counter) is not OllamaQwenHistoryReviewTokenCounter:
            raise HistoryReviewRuntimeError("exact complete review counter required")
        self._counter = counter
        self._tokenizer = counter._tokenizer
        self._lock = Lock()
        self._entered = False
        self._authorization: CanonicalPersonalHistoryReviewAuthorization | None = None
        self._prepared: PreparedHistoryReviewRequest | None = None
        self._body: bytes | None = None
        self._descriptor: HistoryReviewDispatchDescriptor | None = None
        self._result: ObservedHistoryReview | None = None
        self._did_transport = False
        self._started: float | None = None
        self._transport = _loopback
        self._original_transport = self._transport

    def configuration(self) -> tuple[str, ...]:
        if (
            type(self._counter) is not OllamaQwenHistoryReviewTokenCounter
            or self._counter._tokenizer is not self._tokenizer
            or self._transport is not self._original_transport
        ):
            raise ValueError("complete original review runtime graph changed")
        return (
            self._counter.model_digest,
            self._counter.tokenizer_digest,
            self._counter.template_digest,
            self._counter.renderer_digest,
            history_review_runtime_digest(),
        )

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - _NATIVE_MONOTONIC()
        if remaining <= 0:
            raise ValueError("original complete reviewer interval exhausted")
        return remaining

    def _metadata(self, deadline: float, model_digest: str) -> str:
        version = base._json(
            self._transport("GET", "/api/version", None, self._remaining(deadline))
        )
        tags = base._json(self._transport("GET", "/api/tags", None, self._remaining(deadline)))
        show = base._json(
            self._transport(
                "POST",
                "/api/show",
                canonical_bytes({"model": wire.MODEL}),
                self._remaining(deadline),
            )
        )
        if type(version) is not dict or version.get("version") != base_counter._VERSION:
            raise ValueError("declared complete review server version unavailable")
        models = tags.get("models") if type(tags) is dict else None
        if (
            type(models) is not list
            or sum(
                type(row) is dict
                and row.get("name") == wire.MODEL
                and row.get("digest") == model_digest
                for row in models
            )
            != 1
        ):
            raise ValueError("declared complete review model unavailable")
        if type(show) is not dict or show.get("remote_host") or show.get("remote_model"):
            raise ValueError("unsupported complete review metadata")
        return content_hash_of(canonical_bytes({"version": version, "tags": tags, "show": show}))

    def _wire(self, gate: CanonicalPersonalHistoryReviewAuthorization) -> bytes:
        assert gate._prepared is not None
        return wire.serialize_history_review_wire(
            gate._prepared,
            packet_raw=gate._packet_raw,
            expected_request=gate._generation._request,
            rubric_utf8=gate._rubric,
            template_utf8=gate._template,
        )

    def invoke(self, gate: CanonicalPersonalHistoryReviewAuthorization) -> ObservedHistoryReview:
        from zacai.intelligence.history_publication_review import (
            CanonicalPersonalHistoryReviewAuthorization,
        )

        acquired = self._lock.acquire(blocking=False)
        result = None
        uncertain = False
        interrupted = None
        if not acquired:
            self._result = None
            if self._authorization is not None:
                self._authorization._hold()
            raise HistoryReviewRuntimeError("complete reviewer reentry held")
        try:
            if (
                type(gate) is not CanonicalPersonalHistoryReviewAuthorization
                or self._authorization is not gate
                or self._entered
                or gate._runtime is not self
                or gate._phase != "PREPARED"
                or gate._prepared is None
            ):
                raise ValueError("actual original complete review gate required")
            self._entered = True
            self._result = None
            self._started = gate._started
            prepared = gate._prepared
            config = self.configuration()
            deadline = gate._deadline
            body = self._wire(gate)
            count = self._counter.count_prompt_tokens(body)
            if cast(Callable[[], object], self._counter.verify_runtime)() is not None:
                raise ValueError("review runtime verification changed")
            metadata = self._metadata(deadline, prepared.model_digest)
            if self.configuration() != config or self._wire(gate) != body:
                raise ValueError("complete review preflight drift")
            pre = HistoryReviewDispatchDescriptor(
                "PRE_DISPATCH",
                uuid4(),
                prepared.request_digest,
                prepared.packet_digest,
                content_hash_of(body),
                config,
                metadata,
                count,
                prepared.max_output_tokens,
                deadline,
            )
            self._prepared, self._body, self._descriptor = prepared, body, pre
            gate.recheck_review_dispatch(prepared, pre)
            if (
                self._descriptor is not pre
                or self._prepared is not prepared
                or self._body != body
                or self.configuration() != config
                or self._wire(gate) != body
            ):
                raise ValueError("complete review dispatch snapshot changed")
            remaining = self._remaining(deadline)
            self._did_transport = True
            raw = self._transport("POST", "/api/chat", body, remaining)
            parsed = wire.parse_history_review_response(
                raw, requested_output_tokens=prepared.max_output_tokens
            )
            if cast(Callable[[], object], self._counter.verify_runtime)() is not None:
                raise ValueError("complete review counter changed")
            after = self._metadata(deadline, prepared.model_digest)
            if (
                after != metadata
                or self.configuration() != config
                or self._wire(gate) != body
                or self._counter.count_prompt_tokens(body) != count
                or parsed.reported_input_tokens != count
            ):
                raise ValueError("complete review actual usage or metadata changed")
            at = _NATIVE_MONOTONIC()
            if at >= deadline or at < gate._started:
                raise ValueError("original complete review deadline expired")
            usage = UsageObservation(
                input_tokens=count,
                output_tokens=parsed.reported_output_tokens,
                latency_ms=(at - gate._started) * 1000,
                cost_usd=0.0,
            )
            release = HistoryReviewDispatchDescriptor(
                "RELEASE",
                pre.attempt_id,
                prepared.request_digest,
                prepared.packet_digest,
                pre.wire_body_digest,
                config,
                metadata,
                count,
                prepared.max_output_tokens,
                deadline,
                content_hash_of(canonical_bytes(parsed.judgments.model_dump(mode="json"))),
                content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
            )
            gate.recheck_review_dispatch(prepared, release)
            if (
                self._prepared is not prepared
                or self._body != body
                or self._descriptor is not pre
                or self.configuration() != config
                or self._wire(gate) != body
                or gate._released is not release
            ):
                raise ValueError("complete review released provenance changed")
            self._remaining(deadline)
            result = ObservedHistoryReview(parsed.judgments, usage, release)
            self._result = result
            return result
        except PersonalFragmentCleanupUncertain:
            uncertain = True
        except (KeyboardInterrupt, SystemExit) as error:
            interrupted = error
        except Exception:  # noqa: BLE001,S110
            pass
        finally:
            if result is None:
                self._result = None
                if type(gate) is CanonicalPersonalHistoryReviewAuthorization:
                    gate._hold()
            self._lock.release()
        if uncertain:
            raise PersonalFragmentCleanupUncertain("PERSONAL complete review cleanup uncertain")
        if interrupted is not None:
            raise type(interrupted)() from None
        raise HistoryReviewRuntimeError("complete reviewer invocation held")
