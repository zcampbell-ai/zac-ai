"""D034K narrow offline Qwen3.8 counter for verified Ollama 0.35.1.

No model weights, downloads, template execution or evidence network calls.
The explicit model manifest binds tokenizer/config blobs. Source for the text-only
renderer: ollama/ollama v0.35.1 model/renderers/qwen35.go. This does not generalize
other models, versions, tools, images, conversations or thinking modes.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import import_module
from pathlib import Path
from typing import Any

from zacai.intelligence import local_review_runtime as local
from zacai.intelligence.contextual_generation import contextual_draft_schema
from zacai.intelligence.review_generation import ReviewDraft

_MODEL = "qwen3.8:27b-mlx"
_VERSION = "0.35.1"
# Go unicode.IsSpace, used by strings.TrimSpace; Python strip has extra controls.
_SPACE = "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


class LocalTokenCounterError(ValueError):
    """Fixed errors, never echo inputs, paths or tokenizer diagnostics."""


def _read(path: Path, digest: str, limit: int) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("file integrity failed")
    return raw


def render_review_prompt(serialized_body: bytes) -> str:
    return _render_prompt(serialized_body, ReviewDraft.model_json_schema())


def render_contextual_prompt(serialized_body: bytes) -> str:
    """Explicit contextual schema; compact counting does not accept it."""
    return _render_prompt(
        serialized_body,
        contextual_draft_schema(),
        alternate_schemas=(contextual_draft_schema(related_citable=False),),
        context_tokens=frozenset({8192, 16384}),
    )


def _render_prompt(
    serialized_body: bytes,
    schema: dict[str, Any],
    *,
    context_tokens: frozenset[int] = frozenset({8192}),
    alternate_schemas: tuple[dict[str, Any], ...] = (),
) -> str:
    """Only the exact two-turn no-thinking review payload is supported."""
    try:
        if len(serialized_body) > 64_000:
            raise ValueError("oversize")
        body = local._json(serialized_body)
        if (
            set(body)
            != {
                "model",
                "stream",
                "think",
                "truncate",
                "shift",
                "keep_alive",
                "format",
                "messages",
                "options",
            }
            or body["model"] != _MODEL
            or any(body[k] is not False for k in ("stream", "think", "truncate", "shift"))
            or type(body["keep_alive"]) is not int
            or body["keep_alive"] != 0
            or not any(
                json.dumps(body["format"], sort_keys=True, separators=(",", ":"))
                == json.dumps(option, sort_keys=True, separators=(",", ":"))
                for option in (schema, *alternate_schemas)
            )
        ):
            raise ValueError("unsupported payload")
        options = body["options"]
        if (
            set(options) != {"temperature", "num_predict", "num_ctx"}
            or type(options["temperature"]) is not int
            or options["temperature"] != 0
            or type(options["num_ctx"]) is not int
            or options["num_ctx"] not in context_tokens
            or type(options["num_predict"]) is not int
            or not 0 < options["num_predict"] < 8192
        ):
            raise ValueError("unsupported options")
        messages = body["messages"]
        if not isinstance(messages, list) or len(messages) != 2:
            raise ValueError("unsupported turns")
        contents = []
        for message, role in zip(messages, ("system", "user"), strict=True):
            if (
                set(message) != {"role", "content"}
                or message["role"] != role
                or not isinstance(message["content"], str)
            ):
                raise ValueError("unsupported message")
            content = message["content"].strip(_SPACE)
            if not content or (
                role == "user"
                and content.startswith("<tool_response>")
                and content.endswith("</tool_response>")
            ):
                raise ValueError("missing query")
            contents.append(content)
        return (
            "<|im_start|>system\n"
            + contents[0]
            + "<|im_end|>\n"
            + "<|im_start|>user\n"
            + contents[1]
            + "<|im_end|>\n"
            + "<|im_start|>assistant\n<think>\n\n</think>\n\n"
        )
    except Exception:  # noqa: BLE001, S110
        pass
    raise LocalTokenCounterError("unsupported local review prompt")


class OllamaQwenReviewTokenCounter:
    """Explicit installed manifest + in-memory tokenizer, no provider ownership.

    Hash-verify original manifest/blobs on every count; counts never call a model.
    Runtime metadata is checked separately before and after generation by the host
    adapter. Trusted runtime reporting is not defense against a hostile machine.
    """

    def __init__(self, *, models_root: Path, model_digest: str) -> None:
        try:
            if not re.fullmatch(r"[0-9a-f]{64}", model_digest):
                raise ValueError("invalid pin")
            self._digest = model_digest
            self._manifest = models_root / "manifests/registry.ollama.ai/library/qwen3.8/27b-mlx"
            raw = _read(self._manifest, model_digest, 1_000_000)
            manifest = local._json(raw)
            if manifest["schemaVersion"] != 2:
                raise ValueError("unsupported manifest")
            self._files: list[tuple[Path, str, int]] = []
            config = self._blob(models_root, manifest["config"], 100_000)
            if local._json(config).get("renderer") != "qwen3.8":
                raise ValueError("unsupported renderer")
            tokenizer_raw = None
            for name, limit in (("tokenizer.json", 16_000_000), ("tokenizer_config.json", 100_000)):
                layers = [x for x in manifest["layers"] if x.get("name") == name]
                if len(layers) != 1:
                    raise ValueError("ambiguous tokenizer")
                blob = self._blob(models_root, layers[0], limit)
                if name == "tokenizer.json":
                    tokenizer_raw = blob
                elif local._json(blob).get("add_bos_token") is not False:
                    raise ValueError("unsupported BOS")
            # The optional dependency is imported only for this explicit adapter.
            tokenizer_class = import_module("tokenizers").Tokenizer

            assert tokenizer_raw is not None
            self._tokenizer = tokenizer_class.from_str(tokenizer_raw.decode())
            self._tokenizer.no_truncation()
            self._tokenizer.no_padding()
            return
        except Exception:  # noqa: BLE001, S110
            pass
        raise LocalTokenCounterError("local tokenizer unavailable")

    def _blob(self, root: Path, layer: dict[str, Any], limit: int) -> bytes:
        digest = layer["digest"]
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid blob")
        path = root / "blobs" / digest.replace(":", "-")
        raw = _read(path, digest[7:], limit)
        if type(layer["size"]) is not int or len(raw) != layer["size"]:
            raise ValueError("size mismatch")
        self._files.append((path, digest[7:], limit))
        return raw

    @property
    def model_digest(self) -> str:
        return self._digest

    def verify_runtime(self) -> None:
        try:
            if local._http("GET", "/api/version", None).get("version") != _VERSION:
                raise ValueError("unverified runtime")
            return
        except Exception:  # noqa: BLE001, S110
            pass
        raise LocalTokenCounterError("local tokenizer runtime mismatch")

    def _render(self, serialized_body: bytes) -> str:
        return render_review_prompt(serialized_body)

    def count_prompt_tokens(self, serialized_body: bytes) -> int:
        try:
            _read(self._manifest, self.model_digest, 1_000_000)
            for path, digest, limit in self._files:
                _read(path, digest, limit)
            prompt = self._render(serialized_body)
            # Registered special-token strings in untrusted message contents can
            # forge chat-template boundaries even with add_special_tokens=False.
            messages = local._json(serialized_body)["messages"]
            controls = tuple(
                token.content
                for token in self._tokenizer.get_added_tokens_decoder().values()
                if token.special
            )
            if any(control in message["content"] for control in controls for message in messages):
                raise ValueError("special token in message content")
            return len(self._tokenizer.encode(prompt, add_special_tokens=False).ids)
        except Exception:  # noqa: BLE001, S110
            pass
        raise LocalTokenCounterError("local prompt counting failed")


class OllamaQwenContextualTokenCounter(OllamaQwenReviewTokenCounter):
    """Same verified local tokenizer/template, explicit contextual payload only."""

    def _render(self, serialized_body: bytes) -> str:
        return render_contextual_prompt(serialized_body)
