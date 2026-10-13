"""Internally gated one-attempt LOCAL email runtime; no public generation bypass.

Trusted host code, not a Python sandbox. No construction I/O, endpoint override,
retry, cloud fallback, pull or enabled service. Metadata reporting is not hardware
attestation. Existing joined transport bounds sockets, not tokenizer/model CPU.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import email_draft, email_generation, email_local_wire, ollama_token_counter
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.email_generation import EmailGenerationRequestV1
from zacai.intelligence.email_local_wire import (
    count_email_local_prompt,
    prepare_email_local_payload,
)
from zacai.intelligence.followup_prompt_counter import OllamaQwenFollowupTokenCounter
from zacai.intelligence.followup_transport import FollowupLoopbackTransport, _json, _request
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.intelligence.local_review_runtime import Transport, verify_model
from zacai.intelligence.ollama_token_counter import OllamaQwenEmailTokenCounter
from zacai.interfaces.named_runtime_binding import _tokenizer_inventory

if TYPE_CHECKING:
    from zacai.interfaces.email_processing import CanonicalBrainstormEmailProcessing, _EmailAttempt


class EmailProcessingRuntimeError(ValueError):
    """Fixed public diagnostics; suppress traceback-local capture."""


class EmailLoopbackTransport(FollowupLoopbackTransport):
    def _restrict_deadline(self, deadline: float) -> None:
        """May shorten the original absolute bound; never renew a socket window."""
        if type(deadline) not in (float, int) or not math.isfinite(deadline):
            raise ValueError("finite original permission deadline required")
        self._deadline = min(self._deadline, deadline)

    def _validate_request(self, method: str, path: str, body: bytes | None) -> None:
        if (method, path) != ("POST", "/api/chat"):
            _request(method, path, body)
            return
        if type(body) is not bytes or not 0 < len(body) <= 64000:
            raise ValueError("bounded email wire required")
        value = _json(body)
        if type(value) is not dict or type(value.get("options")) is not dict:
            raise ValueError("closed email wire required")
        options = value["options"]
        if (
            value.get("model") != email_local_wire.MODEL
            or options.get("num_ctx") != 8192
            or type(options.get("num_ctx")) is not int
            or type(options.get("num_predict")) is not int
            or not 1 <= options["num_predict"] <= 2048
            or canonical_bytes(value.get("format", {}))
            != canonical_bytes(email_generation.EmailModelOutputV1.model_json_schema())
        ):
            raise ValueError("fixed email model/schema/capacity required")
        # Reuse unchanged closed legacy protocol checks for every other field.
        # Only these two already-validated email capacities differ. The original
        # body is sent unchanged; this copy is validation only, never dispatch.
        value["options"] = {
            **options,
            "num_ctx": 16384,
            "num_predict": min(1024, options["num_predict"]),
        }
        _request(method, path, json.dumps(value, ensure_ascii=False).encode())


@dataclass(frozen=True)
class EmailRuntimePinsV1:
    tokenizer_digest: str
    implementation_digest: str


class FixedLocalEmailRuntimeV1:
    """Concrete email counter/profile pins; metadata preflight grants no permission."""

    def __init__(
        self, *, route: ModelRoute, model_digest: str, counter: OllamaQwenEmailTokenCounter
    ) -> None:
        if (
            type(route) is not ModelRoute
            or type(counter) is not OllamaQwenEmailTokenCounter
            or type(model_digest) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", model_digest)
            or counter.model_digest != model_digest
            or route.estimated_cost_usd != 0
        ):
            raise EmailProcessingRuntimeError("fixed email runtime configuration rejected")
        self.route, self.model_digest, self._counter = route, model_digest, counter

    def pins(self) -> EmailRuntimePinsV1:
        try:
            # Shared helper only reads verified manifest/config/tokenizer/template blobs;
            # the explicit email counter is a distinct renderer over those same blobs.
            inventory = _tokenizer_inventory(cast(OllamaQwenFollowupTokenCounter, self._counter))
            modules = (email_draft, email_generation, email_local_wire, ollama_token_counter)
            files = [Path(m.__file__) for m in modules if m.__file__ is not None]
            files += [Path(__file__)]
            from zacai.intelligence import (
                contracts,
                followup_prompt_counter,
                followup_transport,
                local_followup_runtime,
                local_review_runtime,
            )
            from zacai.interfaces import named_runtime_binding

            files += [
                Path(m.__file__)
                for m in (
                    contracts,
                    followup_prompt_counter,
                    followup_transport,
                    local_followup_runtime,
                    local_review_runtime,
                    named_runtime_binding,
                )
                if m.__file__ is not None
            ]
            entries = []
            for path in files:
                raw = path.read_bytes()
                if not 0 < len(raw) <= 2000000:
                    raise ValueError("bounded implementation required")
                entries.append((path.name, content_hash_of(raw)))
            return EmailRuntimePinsV1(
                content_hash_of(canonical_bytes({"email-tokenizer-v1": inventory})),
                content_hash_of(canonical_bytes({"email-implementation-v1": entries})),
            )
        except Exception:  # noqa: BLE001,S110
            pass
        raise EmailProcessingRuntimeError("email runtime pins unavailable")

    def _transport(self, deadline: float) -> Transport:
        return EmailLoopbackTransport(deadline=deadline, monotonic=time.perf_counter)

    def _metadata(self, transport: Transport) -> None:
        def metadata(method: str, path: str, body: bytes | None = None) -> object:
            if (method, path) in (("GET", "/api/version"), ("GET", "/api/tags")) and body is None:
                return transport(method, path, None)
            if (method, path) == ("POST", "/api/show") and body == json.dumps(
                {"model": self.route.identity.model_id}
            ).encode():
                return transport(method, path, body)
            raise ValueError("metadata-only preflight required")

        OllamaQwenFollowupTokenCounter.verify_runtime_with_transport(
            cast(OllamaQwenFollowupTokenCounter, self._counter), metadata
        )
        verify_model(self.route.identity.model_id, self.model_digest, metadata)

    def prepare(self, request: EmailGenerationRequestV1) -> tuple[bytes, int, EmailRuntimePinsV1]:
        """Offline exact envelope for publication; no transport even metadata."""
        before = self.pins()
        body = prepare_email_local_payload(request, self.route, self.model_digest)
        count = count_email_local_prompt(request, self.route, self.model_digest, self._counter)
        if self.pins() != before:
            raise EmailProcessingRuntimeError("email runtime changed during preparation")
        return body, count, before

    def _invoke(self, host: CanonicalBrainstormEmailProcessing, attempt: _EmailAttempt) -> bytes:
        """Only the exact concrete host's protected live attempt can reach chat."""
        from zacai.interfaces.email_processing import (
            CanonicalBrainstormEmailProcessing,
            _EmailAttempt,
        )

        result: bytes | None = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if type(host) is not CanonicalBrainstormEmailProcessing or host._runtime is not self:
                raise ValueError("actual email processing host required")
            if type(attempt) is not _EmailAttempt or attempt is not host._attempt:
                raise ValueError("actual host attempt required")
            attempt.consume()
            m = attempt.consent.manifest
            request = email_generation.prepare_email_generation_request(m.specification)
            body, count, pins = self.prepare(request)
            transport = self._transport(host._deadline(attempt))
            if type(transport) is not EmailLoopbackTransport:
                raise ValueError("exact fixed email transport required")
            self._metadata(transport)
            if (
                count != m.full_prompt_tokens
                or content_hash_of(body) != m.body_digest
                or pins != EmailRuntimePinsV1(m.tokenizer_digest, m.implementation_digest)
            ):
                raise ValueError("admitted wire/count/pins changed")
            host._gate(attempt)  # Actual consent+claim recovery, owner, final row preimages.
            # Callback-free exact serialization immediately before actual transport.
            if (
                prepare_email_local_payload(request, self.route, self.model_digest) != body
                or self.route != m.route
                or self.model_digest != m.model_digest
                or self.pins() != pins
            ):
                raise ValueError("final outgoing bytes or pins changed")
            host._final_rows(attempt)
            transport._restrict_deadline(host._deadline(attempt))
            reply = transport("POST", "/api/chat", body)
            # The transport returns duplicate-rejecting bounded JSON. Encode only
            # that object; runtime wire parser independently checks the closed family.
            result = json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode()
            self._metadata(transport)
            if self.pins() != pins:
                raise ValueError("runtime changed after inference")
            host._gate(attempt)
            host._deadline(attempt)
        except BaseException as error:  # noqa: BLE001 - sanitized cancellation after handler
            result = None
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailProcessingRuntimeError("email generation held; attempt consumed")
        return result
