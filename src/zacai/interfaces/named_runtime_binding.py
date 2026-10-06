"""Fixed-profile metadata-only runtime binding; never generation permission.

Pins v1 cover actual verified manifest/config/tokenizer/optional template blobs,
plus whole implementation-file hashes for serializer/schema/rendering. A source
edit intentionally changes the pin and requires a new published action. Trusted
host construction only; no browser-configurable endpoint/profile or fallback.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import (
    contracts,
    followup_generation,
    followup_prompt_counter,
    local_followup_runtime,
    ollama_token_counter,
    text_followup,
)
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.followup_generation import FollowupRequest
from zacai.intelligence.followup_prompt_counter import OllamaQwenFollowupTokenCounter
from zacai.intelligence.followup_transport import FollowupLoopbackTransport
from zacai.intelligence.local_followup_runtime import prepare_payload
from zacai.intelligence.local_review_runtime import Transport, verify_model
from zacai.intelligence.ollama_token_counter import _read
from zacai.interfaces.named_followup_decision import (
    NamedFollowupManifest,
    decode_named_manifest,
    encode_named_manifest,
)
from zacai.policy import Destination

_ENDPOINT = "http://127.0.0.1:11434"
_SOURCE_MODULES = (
    contracts,
    followup_generation,
    followup_prompt_counter,
    local_followup_runtime,
    ollama_token_counter,
    text_followup,
)


class NamedRuntimeBindingError(ValueError):
    """Fixed closed runtime diagnostic; no payload/path/backend exception."""


@dataclass(frozen=True)
class NamedRuntimePins:
    tokenizer_digest: str
    request_template_digest: str


def _digest(domain: str, data: object) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\x00" + canonical_bytes({"inventory": data})
    ).hexdigest()


def _implementation_inventory() -> tuple[tuple[str, str], ...]:
    result = []
    for module in _SOURCE_MODULES:
        # Fixed already imported implementations; never a client-supplied path.
        if type(module.__file__) is not str:
            raise ValueError("implementation unavailable")
        path = Path(module.__file__)
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise ValueError("implementation unavailable")
        raw = path.read_bytes()
        if len(raw) > 2_000_000:
            raise ValueError("implementation exceeds bound")
        result.append((module.__name__, hashlib.sha256(raw).hexdigest()))
    return tuple(result)


def _tokenizer_inventory(counter: OllamaQwenFollowupTokenCounter) -> tuple[tuple[str, str], ...]:
    raw = _read(counter._manifest, counter.model_digest, 1_000_000)
    manifest = json.loads(raw)
    entries = [("manifest", counter.model_digest)]
    # The counter verified these config/tokenizer blobs at construction, and
    # validates the same immutable bytes on every count. Label by declaration,
    # not installation path, so a safe machine-local relocation changes no pin.
    declarations = [("config", manifest["config"])]
    declarations.extend(
        (layer["name"], layer)
        for layer in manifest["layers"]
        if layer.get("name") in ("tokenizer.json", "tokenizer_config.json")
        or "template" in str(layer.get("name", "")).lower()
    )
    labels = set()
    root = counter._manifest.parents[4]
    for label, layer in declarations:
        if type(label) is not str or label in labels:
            raise ValueError("ambiguous tokenizer declaration")
        labels.add(label)
        digest = layer["digest"]
        if type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid tokenizer digest")
        limit = 16_000_000 if label == "tokenizer.json" else 100_000
        body = _read(root / "blobs" / digest.replace(":", "-"), digest[7:], limit)
        if type(layer["size"]) is not int or len(body) != layer["size"]:
            raise ValueError("tokenizer size differs")
        entries.append((label, digest[7:]))
    if not {"config", "tokenizer.json", "tokenizer_config.json"} <= labels:
        raise ValueError("tokenizer inventory incomplete")
    return tuple(sorted(entries))


class FixedLocalNamedRuntimeBinding:
    def __init__(
        self,
        *,
        route: ModelRoute,
        model_digest: str,
        counter: OllamaQwenFollowupTokenCounter,
        transport_factory: Callable[
            [FollowupRequest, float], Transport
        ] = local_followup_runtime._deadline_transport,
    ) -> None:
        if (
            type(route) is not ModelRoute
            or type(counter) is not OllamaQwenFollowupTokenCounter
            or type(model_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", model_digest) is None
            or counter.model_digest != model_digest
            or not callable(transport_factory)
            or route.identity.model_id != "qwen3.8:27b-mlx"
            or route.identity.runtime_id != "mac-loopback-packet-followup-16k"
            or route.destination is not Destination.LOCAL
            or route.capabilities != frozenset({"packet_followup"})
            or not route.available
            or route.estimated_cost_usd != 0
        ):
            raise NamedRuntimeBindingError("fixed local runtime binding unavailable")
        self.route, self.model_digest = route, model_digest
        self._counter, self._transport_factory = counter, transport_factory

    def pins(self) -> NamedRuntimePins:
        result = None
        try:
            result = NamedRuntimePins(
                _digest("zac-named-tokenizer-inventory-v1", _tokenizer_inventory(self._counter)),
                _digest("zac-named-followup-implementation-v1", _implementation_inventory()),
            )
        except Exception:  # noqa: BLE001,S110 - no installation-path diagnostics
            pass
        if result is None:
            raise NamedRuntimeBindingError("fixed local runtime pins unavailable")
        return result

    def verify(
        self,
        request: FollowupRequest,
        *,
        endpoint: str,
        tokenizer_digest: str,
        request_template_digest: str,
    ) -> None:
        okay = False
        try:
            started = time.perf_counter()
            if endpoint != _ENDPOINT:
                raise ValueError("fixed endpoint required")
            before = self.pins()
            if before != NamedRuntimePins(tokenizer_digest, request_template_digest):
                raise ValueError("published pins differ")
            body = prepare_payload(request, self.route, self.model_digest)
            count = self._counter.count_prompt_tokens(body)
            if (
                type(count) is not int
                or count <= 0
                or count + request.context.task.max_output_tokens > 16384
            ):
                raise ValueError("token budget exceeded")
            transport = self._transport_factory(request, started)

            def metadata(method: str, path: str, payload: bytes | None = None) -> object:
                if (method, path) in (
                    ("GET", "/api/version"),
                    ("GET", "/api/tags"),
                ) and payload is None:
                    return transport(method, path, None)
                expected = json.dumps({"model": self.route.identity.model_id}).encode()
                if (method, path) == ("POST", "/api/show") and payload == expected:
                    return transport(method, path, payload)
                raise NamedRuntimeBindingError("metadata-only runtime request required")

            self._counter.verify_runtime_with_transport(metadata)
            verify_model(self.route.identity.model_id, self.model_digest, metadata)
            if (
                self.pins() != before
                or not 0
                <= (time.perf_counter() - started) * 1000
                <= request.context.task.max_latency_ms
            ):
                raise ValueError("runtime binding changed or exceeded deadline")
            okay = True
        except Exception:  # noqa: BLE001,S110 - no runtime/backend/payload diagnostics
            pass
        if not okay:
            raise NamedRuntimeBindingError("fixed local runtime binding unavailable")

    def verify_published(self, manifest: NamedFollowupManifest) -> None:
        """Fixed metadata only before question exists; no synthetic request/count.

        Actual question token capacity is checked later against its real payload.
        All metadata calls share one absolute deadline, with no chat route.
        """
        okay = False
        try:
            started = time.perf_counter()
            manifest = decode_named_manifest(encode_named_manifest(manifest))
            before = self.pins()
            if (
                manifest.route != self.route
                or manifest.model_digest != self.model_digest
                or manifest.runtime_endpoint != _ENDPOINT
                or before
                != NamedRuntimePins(manifest.tokenizer_digest, manifest.request_template_digest)
                or (
                    manifest.max_latency_ms,
                    manifest.max_output_tokens,
                    manifest.max_estimated_cost_usd,
                )
                != (60_000, 512, 0.0)
            ):
                raise ValueError("published fixed runtime differs")
            transport = FollowupLoopbackTransport(
                deadline=started + manifest.max_latency_ms / 1000, monotonic=time.perf_counter
            )

            def metadata(method: str, path: str, payload: bytes | None = None) -> object:
                if (method, path) in (
                    ("GET", "/api/version"),
                    ("GET", "/api/tags"),
                ) and payload is None:
                    return transport(method, path, None)
                if (method, path) == ("POST", "/api/show") and payload == json.dumps(
                    {"model": self.route.identity.model_id}
                ).encode():
                    return transport(method, path, payload)
                raise NamedRuntimeBindingError("published metadata only required")

            self._counter.verify_runtime_with_transport(metadata)
            verify_model(self.route.identity.model_id, self.model_digest, metadata)
            if (
                self.pins() != before
                or not 0 <= (time.perf_counter() - started) * 1000 <= manifest.max_latency_ms
            ):
                raise ValueError("published runtime changed or exceeded deadline")
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedRuntimeBindingError("published runtime metadata unavailable")
