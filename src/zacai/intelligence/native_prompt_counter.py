"""Offline narrow native prompt counting, never permission or backend parity.

Reuses the existing declared Qwen3.8/Ollama0.35.1 text-only renderer. Schema
instructions and native noncitable metadata are actual message text; output
grammar is not an additional prompt. No weights/downloads/model calls occur
while counting. Inherited verify_runtime is a separate network metadata check;
the trusted host must compose it under its original deadline before dispatch.
"""

from __future__ import annotations

import hashlib
import json
from importlib.metadata import version
from pathlib import Path

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence import ollama_token_counter as base
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    OllamaQwenContextualTokenCounter,
    render_contextual_prompt,
)

_TEMPLATE = (
    "<|im_start|>system\n{system}<|im_end|>\n"
    "<|im_start|>user\n{user}<|im_end|>\n"
    "<|im_start|>assistant\n<think>\n\n</think>\n\n"
)


def render_native_prompt(serialized_body: bytes) -> str:
    """Closed native input family; structural checks do not authenticate evidence."""
    try:
        prompt = render_contextual_prompt(serialized_body)
        body = local._json(serialized_body)
        data = local._json(body["messages"][1]["content"])
        if (
            type(data) is not dict
            or set(data) != {"format", "provider_passages", "untrusted_noncitable_metadata"}
            or data["format"] != "zac-native-contextual-request-v2"
            or type(data["provider_passages"]) is not list
            or not data["provider_passages"]
        ):
            raise ValueError("native shape")
        metadata = data["untrusted_noncitable_metadata"]
        if (
            type(metadata) is not dict
            or set(metadata) != {"format", "entries"}
            or metadata["format"] != "zac-native-context-sidecar-v1"
            or type(metadata["entries"]) is not list
            or not metadata["entries"]
        ):
            raise ValueError("metadata shape")
        # No reserialization: count precisely the original message characters.
        return prompt
    except Exception:  # noqa: BLE001,S110 - never expose provider text or parser errors
        pass
    raise LocalTokenCounterError("unsupported native local prompt")


class OllamaQwenNativeContextualTokenCounter(OllamaQwenContextualTokenCounter):
    """Exact inherited file verification and rendering, with prospective pins.

    Pins describe this narrow counter, not an approved model profile or complete
    host policy. Actual native conformance and canonical authority remain gates.
    """

    def _render(self, serialized_body: bytes) -> str:
        return render_native_prompt(serialized_body)

    @property
    def tokenizer_digest(self) -> str:
        try:
            return hashlib.sha256(
                b"zac-native-tokenizer-v1\x00"
                + canonical_bytes(
                    {
                        "model_manifest": self.model_digest,
                        "blobs": sorted((digest, limit) for _, digest, limit in self._files),
                        "tokenizers_version": version("tokenizers"),
                        "add_special_tokens": False,
                        "padding": False,
                        "truncation": False,
                    }
                )
            ).hexdigest()
        except Exception:  # noqa: BLE001,S110 - no installation details in diagnostic
            pass
        raise LocalTokenCounterError("native local tokenizer pin unavailable")

    @property
    def template_digest(self) -> str:
        return hashlib.sha256(
            b"zac-native-template-v1\x00"
            + canonical_bytes(
                {
                    "model": base._MODEL,
                    "version": base._VERSION,
                    "text": _TEMPLATE,
                    "trim_space": base._SPACE,
                }
            )
        ).hexdigest()

    @property
    def renderer_digest(self) -> str:
        # Bind actual implementation bytes, not merely an import statement.
        # Dispatch serializer/resolver/host pins remain separately required.
        try:
            files = (
                Path(__file__).resolve(),
                Path(base.__file__).resolve(),
                Path(local.__file__).resolve(),
            )
            rows = [(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]
            return hashlib.sha256(
                b"zac-native-renderer-v1\x00" + json.dumps(rows, separators=(",", ":")).encode()
            ).hexdigest()
        except Exception:  # noqa: BLE001,S110 - fixed private-safe failure
            pass
        raise LocalTokenCounterError("native local renderer pin unavailable")
