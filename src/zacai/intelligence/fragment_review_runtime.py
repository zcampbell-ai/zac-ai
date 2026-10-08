"""Dormant LOCAL fragment review mechanics, with no enabled dispatch consumer.

Only profile/preflight data are public. The internal one-attempt operation is
for a future canonical host and offline tests. There is deliberately no approval
callback, public generate method or active route. A mechanical result is not an
authenticated assessment. Trusted counters/transports are not a callback sandbox.
Never export exception traceback locals, which can contain complete review text.
"""

from __future__ import annotations

import hashlib
import http.client
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast
from uuid import UUID, uuid4

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_review_preparation as prep
from zacai.intelligence import fragment_review_prompt_counter as counter_module
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence import ollama_token_counter as base_counter
from zacai.intelligence.contracts import UsageObservation
from zacai.intelligence.local_review_runtime import _json

if TYPE_CHECKING:
    from zacai.intelligence.fragment_publication_review import (
        CanonicalFragmentPublicationReviewAuthorization,
    )

# Authenticated dispatch never invokes an injected clock after canonical gates.
_AUTHENTICATED_MONOTONIC = time.monotonic


class FragmentReviewRuntimeError(ValueError):
    """Fixed, cause-free mechanical failure; never a permission decision."""


class FragmentReviewCounter(Protocol):
    @property
    def model_digest(self) -> str: ...
    @property
    def tokenizer_digest(self) -> str: ...
    @property
    def template_digest(self) -> str: ...
    @property
    def renderer_digest(self) -> str: ...
    def count_prompt_tokens(self, serialized_body: bytes) -> int: ...
    def verify_runtime(self) -> None: ...


@dataclass(frozen=True)
class FragmentReviewRuntimeProfile:
    runtime_id: str
    implementation_digest: str
    model_digest: str
    tokenizer_digest: str
    template_digest: str
    renderer_digest: str
    reported_server_version: str = base_counter._VERSION


def fragment_review_runtime_digest() -> str:
    """Direct mechanical closure only; not a canonical host/policy admission pin."""
    from zacai.intelligence import local_review_runtime

    paths = (
        Path(__file__),
        Path(str(prep.__file__)),
        Path(str(wire.__file__)),
        Path(str(counter_module.__file__)),
        Path(str(base_counter.__file__)),
        Path(str(local_review_runtime.__file__)),
    )
    return hashlib.sha256(
        b"zac-fragment-review-mechanics-v1\x00"
        + canonical_bytes(
            {"files": [(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]}
        )
    ).hexdigest()


@dataclass(frozen=True, repr=False)
class FragmentReviewDispatchDescriptor:
    """Exact mechanical observation. Future issuer must independently authenticate it."""

    request_digest: str
    packet_digest: str
    body_digest: str
    route_digest: str
    profile: FragmentReviewRuntimeProfile
    model_metadata_digest: str
    measured_input_tokens: int
    requested_output_tokens: int
    deadline_monotonic: float


@dataclass(frozen=True, repr=False)
class AuthenticatedFragmentReviewDispatchDescriptor:
    """Immutable observations for a concrete issuer; construction grants nothing."""

    phase: Literal["PRE_DISPATCH", "RELEASE"]
    run_id: UUID
    attempt_id: UUID
    mechanical: FragmentReviewDispatchDescriptor
    body: bytes
    authorization_graph_digest: str
    judgments_digest: str | None = None
    usage_digest: str | None = None


@dataclass(frozen=True, repr=False)
class _MechanicalReviewResult:
    judgments: prep.FragmentReviewJudgments
    usage: UsageObservation
    descriptor: FragmentReviewDispatchDescriptor
    judgments_digest: str
    usage_digest: str
    processing_authorized: bool = False
    reviewer_authenticated: bool = False


_Transport = Callable[[str, str, bytes | None, float], bytes]


def _loopback(method: str, path: str, body: bytes | None, remaining: float) -> bytes:
    """Literal endpoint, bounded response and remaining timeout; no redirect/proxy/retry.

    Socket timeout limits individual blocking operations, not a hard process kill.
    Final elapsed checks withhold late output; no server cancellation guarantee.
    """
    if remaining <= 0 or (method, path) not in {
        ("GET", "/api/version"),
        ("GET", "/api/tags"),
        ("POST", "/api/show"),
        ("POST", "/api/chat"),
    }:
        raise ValueError("closed local operation")
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=remaining)
    try:
        connection.request(method, path, body, {"Content-Type": "application/json"})
        reply = connection.getresponse()
        if reply.status != 200 or reply.getheader("Content-Encoding", "identity") != "identity":
            raise ValueError("local unavailable")
        limit = wire.MAX_REPLY_BYTES if path == "/api/chat" else 64_000
        raw = reply.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("bounded local reply")
        return raw
    finally:
        connection.close()


class _LocalFragmentReviewRuntime:
    """Internal mechanical engine only. Constructing/preflighting grants no authority.

    No active host imports this engine. `_attempt_mechanical` must not be wired
    into private dispatch until real once-only review claim PRE_DISPATCH/RELEASE,
    original owner/withdrawal/deadline, full publication/Source ACL and protected
    output/evaluation recovery joins are implemented and independently accepted.
    The instance burn is mechanical and does not substitute a global durable burn.
    """

    def __init__(
        self,
        *,
        profile: FragmentReviewRuntimeProfile,
        token_counter: FragmentReviewCounter,
        _transport: _Transport = _loopback,
        _clock: Callable[[], float] = time.monotonic,
    ) -> None:
        valid = False
        try:
            valid = type(profile) is FragmentReviewRuntimeProfile and (
                profile.runtime_id == wire.RUNTIME
                and type(profile.reported_server_version) is str
                and profile.reported_server_version == base_counter._VERSION
                and all(
                    type(p) is str and re.fullmatch(r"[0-9a-f]{64}", p)
                    for p in (
                        profile.implementation_digest,
                        profile.model_digest,
                        profile.tokenizer_digest,
                        profile.template_digest,
                        profile.renderer_digest,
                    )
                )
                and profile.implementation_digest == fragment_review_runtime_digest()
            )
        except Exception:  # noqa: BLE001,S110
            pass
        if not valid:
            raise FragmentReviewRuntimeError("fragment review configuration unavailable")
        self._profile = profile
        self._counter = token_counter
        self._transport = _transport
        self._clock = _clock
        self._lock = threading.Lock()
        self._attempted = False
        self._preflight_attempted = False
        self._started: float | None = None
        self._prepared: FragmentReviewDispatchDescriptor | None = None
        self._usage: UsageObservation | None = None
        self._did_transport_attempt = False

    @property
    def profile(self) -> FragmentReviewRuntimeProfile:
        return self._profile

    @property
    def usage(self) -> UsageObservation | None:
        return self._usage

    @property
    def did_transport_attempt(self) -> bool:
        return self._did_transport_attempt

    def _now(self) -> float:
        result = self._clock()
        if type(result) not in (int, float) or not math.isfinite(result):
            raise ValueError("clock unavailable")
        return result

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._now()
        if remaining <= 0:
            raise ValueError("deadline expired")
        return remaining

    def _pins(self) -> None:
        if (
            self._profile.implementation_digest != fragment_review_runtime_digest()
            or self._counter.model_digest != self._profile.model_digest
            or self._counter.tokenizer_digest != self._profile.tokenizer_digest
            or self._counter.template_digest != self._profile.template_digest
            or self._counter.renderer_digest != self._profile.renderer_digest
        ):
            raise ValueError("mechanical pin changed")

    def _metadata(self, deadline: float) -> str:
        raw_version = self._transport("GET", "/api/version", None, self._remaining(deadline))
        if type(raw_version) is not bytes or not 0 < len(raw_version) <= 64_000:
            raise ValueError("bounded runtime version")
        version = _json(raw_version)
        if version.get("version") != self._profile.reported_server_version:
            raise ValueError("unsupported reported runtime version")
        raw_tags = self._transport("GET", "/api/tags", None, self._remaining(deadline))
        if type(raw_tags) is not bytes or not 0 < len(raw_tags) <= 64_000:
            raise ValueError("bounded model metadata")
        models = _json(raw_tags)
        matches = [m for m in models["models"] if m.get("name") == wire.MODEL]
        if len(matches) != 1 or matches[0].get("digest") != self._profile.model_digest:
            raise ValueError("model pin unavailable")
        raw = self._transport(
            "POST", "/api/show", canonical_bytes({"model": wire.MODEL}), self._remaining(deadline)
        )
        if type(raw) is not bytes or not 0 < len(raw) <= 64_000:
            raise ValueError("bounded model metadata")
        data = _json(raw)
        if data.get("remote_model") or data.get("remote_host"):
            raise ValueError("remote unavailable")
        self._remaining(deadline)
        return hashlib.sha256(
            canonical_bytes({"version": version, "registration": matches[0], "show": data})
        ).hexdigest()

    def _describe(
        self,
        prepared: prep.PreparedFragmentReviewRequest,
        *,
        packet_raw: bytes,
        rubric_utf8: bytes,
        template_utf8: bytes,
        count: int,
        deadline: float,
        metadata_digest: str,
    ) -> tuple[bytes, FragmentReviewDispatchDescriptor]:
        body = wire.serialize_fragment_review_wire(
            prepared, packet_raw=packet_raw, rubric_utf8=rubric_utf8, template_utf8=template_utf8
        )
        if (
            prepared.model_digest != self._profile.model_digest
            or type(count) is not int
            or count <= 0
            or count + prepared.max_output_tokens > wire.CONTEXT_TOKENS
        ):
            raise ValueError("exact count and reservation required")
        route = prepared.route.model_dump(mode="json")
        route["capabilities"] = sorted(route["capabilities"])
        descriptor = FragmentReviewDispatchDescriptor(
            prepared.request_digest,
            prepared.packet_digest,
            hashlib.sha256(body).hexdigest(),
            hashlib.sha256(canonical_bytes(route)).hexdigest(),
            self._profile,
            metadata_digest,
            count,
            prepared.max_output_tokens,
            deadline,
        )
        return body, descriptor

    def preflight(
        self,
        prepared: prep.PreparedFragmentReviewRequest,
        *,
        packet_raw: bytes,
        rubric_utf8: bytes,
        template_utf8: bytes,
        deadline_monotonic: float,
    ) -> FragmentReviewDispatchDescriptor:
        """Mechanical readiness only; no permission, claim, model inference or renewal.

        Caller supplies an already bounded remaining deadline; it cannot exceed
        the originally requested max_latency from this preflight's entry clock.
        Only one preflight attempt is allowed, including failures. All metadata
        IO consumes that same window. Reported adapter latency includes preflight,
        caller delay and attempt overhead from this first entry, never a renewed clock.
        """
        if not self._lock.acquire(blocking=False):
            raise FragmentReviewRuntimeError("fragment review operation unavailable")
        result = None
        try:
            self._prepared = None
            if self._preflight_attempted:
                raise ValueError("preflight consumed")
            self._preflight_attempted = True
            if self._attempted or type(prepared) is not prep.PreparedFragmentReviewRequest:
                raise ValueError("exact unused preparation required")
            now = self._now()
            self._started = now
            if (
                type(deadline_monotonic) not in (float, int)
                or not math.isfinite(deadline_monotonic)
                or not now < deadline_monotonic <= now + prepared.max_latency_ms / 1000
            ):
                raise ValueError("original bounded deadline required")
            body, initial = self._describe(
                prepared,
                packet_raw=packet_raw,
                rubric_utf8=rubric_utf8,
                template_utf8=template_utf8,
                count=1,
                deadline=deadline_monotonic,
                metadata_digest="0" * 64,
            )
            self._pins()
            count = self._counter.count_prompt_tokens(body)
            self._counter.verify_runtime()
            metadata = self._metadata(deadline_monotonic)
            self._pins()
            final_body, result = self._describe(
                prepared,
                packet_raw=packet_raw,
                rubric_utf8=rubric_utf8,
                template_utf8=template_utf8,
                count=count,
                deadline=deadline_monotonic,
                metadata_digest=metadata,
            )
            if final_body != body or initial.request_digest != result.request_digest:
                raise ValueError("preflight callback mutation")
            self._remaining(deadline_monotonic)
            self._prepared = result
        except Exception:  # noqa: BLE001 - private-safe failure outside handler
            result = None
        finally:
            self._lock.release()
        if result is None:
            raise FragmentReviewRuntimeError("fragment review preflight unavailable")
        return result

    def _attempt_mechanical(
        self,
        prepared: prep.PreparedFragmentReviewRequest,
        *,
        packet_raw: bytes,
        rubric_utf8: bytes,
        template_utf8: bytes,
    ) -> _MechanicalReviewResult:
        """INTERNAL dormant operation; no canonical gate exists and no host may enable it.

        One chat POST including failures, structural judgments only. Future host
        must insert real canonical gates after all pre-dispatch callbacks and
        before release. This method alone is never processing admission.
        """
        if not self._lock.acquire(blocking=False):
            raise FragmentReviewRuntimeError("fragment review operation unavailable")
        result = None
        try:
            if self._attempted:
                raise ValueError("attempt consumed")
            self._attempted = True
            bound = self._prepared
            if bound is None:
                raise ValueError("preflight required")
            started = self._started
            if started is None:
                raise ValueError("original start missing")
            self._remaining(bound.deadline_monotonic)
            body, observed = self._describe(
                prepared,
                packet_raw=packet_raw,
                rubric_utf8=rubric_utf8,
                template_utf8=template_utf8,
                count=bound.measured_input_tokens,
                deadline=bound.deadline_monotonic,
                metadata_digest=bound.model_metadata_digest,
            )
            self._pins()
            count = self._counter.count_prompt_tokens(body)
            self._counter.verify_runtime()
            metadata = self._metadata(bound.deadline_monotonic)
            self._pins()
            final_body, observed = self._describe(
                prepared,
                packet_raw=packet_raw,
                rubric_utf8=rubric_utf8,
                template_utf8=template_utf8,
                count=count,
                deadline=bound.deadline_monotonic,
                metadata_digest=metadata,
            )
            if final_body != body or observed != bound:
                raise ValueError("exact preflight changed")
            remaining = self._remaining(bound.deadline_monotonic)
            self._did_transport_attempt = True
            raw = self._transport("POST", "/api/chat", body, remaining)
            response = wire.parse_fragment_review_response(
                raw, requested_output_tokens=prepared.max_output_tokens
            )
            self._counter.verify_runtime()
            metadata = self._metadata(bound.deadline_monotonic)
            release_count = self._counter.count_prompt_tokens(body)
            self._pins()
            final_body, observed = self._describe(
                prepared,
                packet_raw=packet_raw,
                rubric_utf8=rubric_utf8,
                template_utf8=template_utf8,
                count=count,
                deadline=bound.deadline_monotonic,
                metadata_digest=metadata,
            )
            if (
                observed != bound
                or final_body != body
                or release_count != count
                or response.reported_input_tokens != count
            ):
                raise ValueError("release binding changed")
            terminal = self._now()
            if not started <= terminal < bound.deadline_monotonic:
                raise ValueError("terminal observation outside original window")
            usage = UsageObservation(
                input_tokens=count,
                output_tokens=response.reported_output_tokens,
                latency_ms=(terminal - started) * 1000,
                cost_usd=0.0,
            )
            self._usage = usage
            result = _MechanicalReviewResult(
                response.judgments,
                usage,
                bound,
                hashlib.sha256(
                    canonical_bytes(response.judgments.model_dump(mode="json"))
                ).hexdigest(),
                hashlib.sha256(canonical_bytes(usage.model_dump(mode="json"))).hexdigest(),
            )
        except Exception:  # noqa: BLE001 - no raw transport/provider/source diagnostic
            result = None
        finally:
            self._lock.release()
        if result is None:
            raise FragmentReviewRuntimeError("fragment review operation unavailable")
        return result


    def _observe_authenticated_clock(self) -> float:
        """Exact builtin clock, for concrete gate observation before owner checks."""
        bound = self._prepared
        if (self._clock is not _AUTHENTICATED_MONOTONIC or bound is None
            or self._started is None):
            raise FragmentReviewRuntimeError("fragment review clock unavailable")
        now = _AUTHENTICATED_MONOTONIC()
        if not self._started <= now < bound.deadline_monotonic:
            raise FragmentReviewRuntimeError("fragment review original deadline expired")
        return now

    def _authenticated_graph(self) -> tuple[object, ...]:
        """Callback-free instance/configuration snapshot; no source authorization."""
        c = self._counter
        p = self._profile
        if type(c) is not counter_module.OllamaQwenFragmentReviewTokenCounter:
            raise ValueError("exact installed fragment review counter required")
        # Fixed file checks do not invoke a counter/metadata/host callback.
        base_counter._read(c._manifest, c._digest, 1_000_000)
        for path, digest, maximum in c._files:
            base_counter._read(path, digest, maximum)
        return (
            fragment_review_runtime_digest(),
            id(c), id(self._transport), id(self._clock),
            p.runtime_id, p.implementation_digest, p.model_digest,
            p.tokenizer_digest, p.template_digest, p.renderer_digest,
            p.reported_server_version,
            c._digest, c._manifest, tuple(c._files), id(c._tokenizer),
            tuple(sorted((key, id(value)) for key, value in vars(c).items()
                         if callable(value))),
        )

    def _attempt_authenticated(
        self,
        prepared: prep.PreparedFragmentReviewRequest,
        *,
        packet_raw: bytes,
        rubric_utf8: bytes,
        template_utf8: bytes,
        authorization: CanonicalFragmentPublicationReviewAuthorization,
    ) -> _MechanicalReviewResult:
        """Concrete gate inside one local attempt, not an activated host route.

        PRE/RELEASE are effectful checks on the exact canonical issuer, not a
        supplied callable/boolean permission. Its actual owner/source/recovery
        checks remain necessary. Mechanical output is not authenticated review.
        Builtin monotonic observations after gates account for gate elapsed time
        without invoking a host callback or restarting the original deadline.
        Socket timeout is not a server cancellation or hard process kill.
        """
        from zacai.contextual_protection import PersonalFragmentCleanupUncertain
        from zacai.intelligence.fragment_publication_review import (
            CanonicalFragmentPublicationReviewAuthorization,
            fragment_publication_review_graph_digest,
        )

        if not self._lock.acquire(blocking=False):
            self._authenticated_held = True
            self._authenticated_result = None
            raise FragmentReviewRuntimeError("fragment review operation unavailable")
        result = None
        cleanup_uncertain = False
        try:
            if self._attempted or getattr(self, "_authenticated_held", False):
                raise ValueError("attempt consumed")
            self._attempted = True
            self._authenticated_held = False
            self._usage = None
            self._authenticated_result = None
            if (type(authorization) is not CanonicalFragmentPublicationReviewAuthorization
                or self._clock is not _AUTHENTICATED_MONOTONIC
                or type(prepared) is not prep.PreparedFragmentReviewRequest):
                raise ValueError("concrete original review admission required")
            bound, started = self._prepared, self._started
            if bound is None or started is None:
                raise ValueError("original preflight required")
            original_bound = replace(bound, profile=replace(bound.profile))
            authorization_graph = fragment_publication_review_graph_digest()
            if (type(authorization_graph) is not str or len(authorization_graph) != 64
                or any(c not in "0123456789abcdef" for c in authorization_graph)):
                raise ValueError("exact authenticated graph required")
            attempt_id = uuid4()
            self._authenticated_attempt_id = attempt_id
            self._observe_authenticated_clock()
            body, observed = self._describe(
                prepared, packet_raw=packet_raw, rubric_utf8=rubric_utf8,
                template_utf8=template_utf8, count=bound.measured_input_tokens,
                deadline=bound.deadline_monotonic,
                metadata_digest=bound.model_metadata_digest,
            )
            self._pins()
            count = self._counter.count_prompt_tokens(body)
            if cast(Callable[[], object], self._counter.verify_runtime)() is not None:
                raise ValueError("runtime verification contract changed")
            metadata = self._metadata(bound.deadline_monotonic)
            self._pins()
            final_body, observed = self._describe(
                prepared, packet_raw=packet_raw, rubric_utf8=rubric_utf8,
                template_utf8=template_utf8, count=count,
                deadline=bound.deadline_monotonic, metadata_digest=metadata,
            )
            if final_body != body or observed != original_bound or bound != original_bound:
                raise ValueError("exact preflight changed")
            self._observe_authenticated_clock()
            graph = self._authenticated_graph()
            pre = AuthenticatedFragmentReviewDispatchDescriptor(
                "PRE_DISPATCH", prepared.run_id, attempt_id, bound, body, authorization_graph,
            )
            if fragment_publication_review_graph_digest() != authorization_graph:
                raise ValueError("authenticated graph changed")
            authorization.recheck_review_dispatch(prepared, pre)
            # Only exact builtin time and closed reconstruction after this gate.
            self._observe_authenticated_clock()
            check_body, check_descriptor = self._describe(
                prepared, packet_raw=packet_raw, rubric_utf8=rubric_utf8,
                template_utf8=template_utf8, count=count,
                deadline=bound.deadline_monotonic, metadata_digest=metadata,
            )
            if (fragment_publication_review_graph_digest() != authorization_graph
                or self._authenticated_graph() != graph or check_body != body
                or check_descriptor != original_bound or self._prepared != original_bound
                or bound != original_bound
                or self._started != started or self._authenticated_attempt_id != attempt_id
                or self._authenticated_held
                or pre != AuthenticatedFragmentReviewDispatchDescriptor(
                    "PRE_DISPATCH", prepared.run_id, attempt_id, bound, body, authorization_graph)):
                raise ValueError("pre-dispatch binding changed")
            remaining = bound.deadline_monotonic - self._observe_authenticated_clock()
            self._did_transport_attempt = True
            raw = self._transport("POST", "/api/chat", body, remaining)
            response = wire.parse_fragment_review_response(
                raw, requested_output_tokens=prepared.max_output_tokens,
            )
            if cast(Callable[[], object], self._counter.verify_runtime)() is not None:
                raise ValueError("runtime verification contract changed")
            metadata = self._metadata(bound.deadline_monotonic)
            release_count = self._counter.count_prompt_tokens(body)
            self._pins()
            final_body, observed = self._describe(
                prepared, packet_raw=packet_raw, rubric_utf8=rubric_utf8,
                template_utf8=template_utf8, count=release_count,
                deadline=bound.deadline_monotonic, metadata_digest=metadata,
            )
            if (observed != original_bound or bound != original_bound or final_body != body or release_count != count
                or response.reported_input_tokens != count):
                raise ValueError("release binding changed")
            terminal = self._observe_authenticated_clock()
            usage = UsageObservation(
                input_tokens=count, output_tokens=response.reported_output_tokens,
                latency_ms=(terminal - started) * 1000, cost_usd=0.0,
            )
            judgments_digest = hashlib.sha256(
                canonical_bytes(response.judgments.model_dump(mode="json"))).hexdigest()
            usage_digest = hashlib.sha256(
                canonical_bytes(usage.model_dump(mode="json"))).hexdigest()
            release = AuthenticatedFragmentReviewDispatchDescriptor(
                "RELEASE", prepared.run_id, attempt_id, bound, body, authorization_graph,
                judgments_digest, usage_digest,
            )
            graph = self._authenticated_graph()
            if fragment_publication_review_graph_digest() != authorization_graph:
                raise ValueError("authenticated graph changed")
            authorization.recheck_review_dispatch(prepared, release)
            self._observe_authenticated_clock()
            check_body, check_descriptor = self._describe(
                prepared, packet_raw=packet_raw, rubric_utf8=rubric_utf8,
                template_utf8=template_utf8, count=count,
                deadline=bound.deadline_monotonic, metadata_digest=metadata,
            )
            if (fragment_publication_review_graph_digest() != authorization_graph
                or self._authenticated_graph() != graph or check_body != body
                or check_descriptor != original_bound or self._prepared != original_bound
                or bound != original_bound
                or self._started != started or self._authenticated_attempt_id != attempt_id
                or self._authenticated_held
                or release != AuthenticatedFragmentReviewDispatchDescriptor(
                    "RELEASE", prepared.run_id, attempt_id, bound, body, authorization_graph,
                    hashlib.sha256(canonical_bytes(
                        response.judgments.model_dump(mode="json"))).hexdigest(),
                    hashlib.sha256(canonical_bytes(usage.model_dump(mode="json"))).hexdigest())):
                raise ValueError("release observation changed")
            self._observe_authenticated_clock()
            self._usage = usage
            result = _MechanicalReviewResult(
                response.judgments, usage, original_bound, judgments_digest, usage_digest,
            )
            self._authenticated_result = result
        except PersonalFragmentCleanupUncertain:
            cleanup_uncertain = True
            result = None
        except Exception:  # noqa: BLE001 - fixed private-safe error outside handler
            result = None
        finally:
            if result is None:
                self._authenticated_held = True
                self._usage = None
                self._authenticated_result = None
            self._lock.release()
        if result is None:
            if cleanup_uncertain:
                raise PersonalFragmentCleanupUncertain(
                    "PERSONAL review cleanup uncertain; operator review required"
                )
            raise FragmentReviewRuntimeError("fragment review operation unavailable")
        return result


@dataclass(frozen=True, repr=False)
class FragmentReviewReadinessObservation:
    """Reported mechanical availability at one instant, never processing admission.

    No packet/answer is supplied or fabricated. Whole-answer prompt fit and
    requested output reservation must be checked later on the actual full answer.
    The host must derive the deadline from the original observed approval window;
    this observation neither authenticates nor renews that window.
    """

    profile: FragmentReviewRuntimeProfile
    model_metadata_digest: str
    observed_monotonic: float
    deadline_monotonic: float
    processing_authorized: bool = False
    reviewer_authenticated: bool = False
    full_answer_fit_measured: bool = False


def inspect_fragment_review_readiness(
    *,
    profile: FragmentReviewRuntimeProfile,
    token_counter: counter_module.OllamaQwenFragmentReviewTokenCounter,
    deadline_monotonic: float,
    max_latency_ms: int,
) -> FragmentReviewReadinessObservation:
    """Bounded public metadata-only prerequisite with fixed concrete LOCAL IO.

    Uses the exact supported counter, actual bounded local manifest/blob hashes,
    and literal loopback version/tags/show. No model inference, fabricated packet,
    tokenizer count, approval callback, canonical write, receipt or authority.
    Reported model metadata cannot establish backend locality/template parity.
    An untrusted supplied deadline is only comparison data; original owner/expiry
    remains a separate authenticated host check. Do not loop/retry on failure.
    """
    result = None
    try:
        if (
            type(token_counter) is not counter_module.OllamaQwenFragmentReviewTokenCounter
            or type(max_latency_ms) is not int
            or not 0 < max_latency_ms <= 60_000
        ):
            raise ValueError("exact supported readiness profile required")
        clock = time.monotonic
        entered = clock()
        if (
            type(deadline_monotonic) not in (int, float)
            or not math.isfinite(deadline_monotonic)
            or not entered < deadline_monotonic <= entered + max_latency_ms / 1000
        ):
            raise ValueError("original bounded readiness deadline required")
        engine = _LocalFragmentReviewRuntime(
            profile=profile, token_counter=token_counter, _transport=_loopback, _clock=clock
        )
        engine._pins()
        base_counter._read(token_counter._manifest, profile.model_digest, 1_000_000)
        for path, digest, limit in token_counter._files:
            base_counter._read(path, digest, limit)
        metadata = engine._metadata(deadline_monotonic)
        engine._pins()
        # No packet/count surrogate. Reobserve all actual constructor-verified
        # tokenizer files after the final metadata callback, before return.
        base_counter._read(token_counter._manifest, profile.model_digest, 1_000_000)
        for path, digest, limit in token_counter._files:
            base_counter._read(path, digest, limit)
        terminal = clock()
        if not entered <= terminal < deadline_monotonic:
            raise ValueError("readiness expired")
        result = FragmentReviewReadinessObservation(profile, metadata, terminal, deadline_monotonic)
    except Exception:  # noqa: BLE001 - fixed cause-free readiness failure
        result = None
    if result is None:
        raise FragmentReviewRuntimeError("fragment review readiness unavailable")
    return result
