"""Explicit compact ReviewDraft counter for qwen3.5:9b-mlx / Ollama0.35.1.

No weights, downloads, inference or new transport. This fixed two-turn text-only
think=false subset follows ollama/ollama v0.35.1 model/renderers/renderer.go
(qwen3.5 registration) and qwen35.go. Runtime prompt-count parity is NOT established
by offline mechanics. Existing 27B counter/renderers and profile pins stay intact.
"""

from __future__ import annotations

import json
import re
from importlib import import_module
from pathlib import Path

from zacai.intelligence import local_review_runtime as local
from zacai.intelligence.ollama_token_counter import (
    _SPACE,
    LocalTokenCounterError,
    OllamaQwenReviewTokenCounter,
    _read,
)
from zacai.intelligence.review_generation import ReviewDraft

_MODEL = "qwen3.5:9b-mlx"


def render_qwen35_nine_b_review_prompt(serialized_body: bytes) -> str:
    """Exact original 9B wire, never relabelled as another model for validation.

    The deliberately narrow parallel gate avoids changing historical 27B source
    hashes. Shared golden tests bind identical supported output bytes; no tools,
    images, assistant history, thinking modes or other workflow schemas are added.
    """
    try:
        if type(serialized_body) is not bytes or not 0 < len(serialized_body) <= 64000:
            raise ValueError("bounded original wire required")
        body = local._json(serialized_body)
        if (
            type(body) is not dict
            or set(body)
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
            or any(body[key] is not False for key in ("stream", "think", "truncate", "shift"))
            or type(body["keep_alive"]) is not int
            or body["keep_alive"] != 0
            or json.dumps(body["format"], sort_keys=True, separators=(",", ":"))
            != json.dumps(ReviewDraft.model_json_schema(), sort_keys=True, separators=(",", ":"))
        ):
            raise ValueError("unsupported compact 9B payload")
        options = body["options"]
        if (
            type(options) is not dict
            or set(options) != {"temperature", "num_predict", "num_ctx"}
            or type(options["temperature"]) is not int
            or options["temperature"] != 0
            or type(options["num_ctx"]) is not int
            or options["num_ctx"] != 8192
            or type(options["num_predict"]) is not int
            or not 0 < options["num_predict"] < 8192
        ):
            raise ValueError("unsupported compact options")
        messages = body["messages"]
        if type(messages) is not list or len(messages) != 2:
            raise ValueError("exact two text turns required")
        contents = []
        for message, role in zip(messages, ("system", "user"), strict=True):
            if (
                type(message) is not dict
                or set(message) != {"role", "content"}
                or message["role"] != role
                or type(message["content"]) is not str
            ):
                raise ValueError("unsupported text turn")
            content = message["content"].strip(_SPACE)
            if not content or (
                role == "user"
                and content.startswith("<tool_response>")
                and content.endswith("</tool_response>")
            ):
                raise ValueError("actual nonempty user query required")
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
    except Exception:  # noqa: BLE001,S110 - no private wire diagnostics
        pass
    raise LocalTokenCounterError("unsupported local 9B review prompt")


class OllamaQwen35NineBReviewTokenCounter(OllamaQwenReviewTokenCounter):
    """Fixed manifest family, inherited exact-hash/count/runtime safeguards.

    Supplied manifest digest comes from separately reviewed host configuration;
    an instance is not model approval. Every count rechecks original files and
    rejects registered special-token injection, padding and truncation. Runtime
    version, locality, capacity, usage and one-attempt checks remain the existing
    LocalReviewRuntime's responsibility. No contextual/email/history support.
    """

    def __init__(self, *, models_root: Path, model_digest: str) -> None:
        try:
            if type(model_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", model_digest):
                raise ValueError("exact host manifest pin required")
            self._digest = model_digest
            self._manifest = models_root / "manifests/registry.ollama.ai/library/qwen3.5/9b-mlx"
            manifest = local._json(_read(self._manifest, model_digest, 1_000_000))
            if (
                type(manifest) is not dict
                or type(manifest.get("schemaVersion")) is not int
                or manifest["schemaVersion"] != 2
            ):
                raise ValueError("unsupported manifest")
            self._files: list[tuple[Path, str, int]] = []
            config = local._json(self._blob(models_root, manifest["config"], 100000))
            if config.get("renderer") != "qwen3.5" or config.get("parser") != "qwen3.5":
                raise ValueError("exact reviewed renderer/parser required")
            tokenizer_raw = None
            for name, limit in (("tokenizer.json", 16_000_000), ("tokenizer_config.json", 100000)):
                layers = [layer for layer in manifest["layers"] if layer.get("name") == name]
                if len(layers) != 1:
                    raise ValueError("unique tokenizer layer required")
                raw = self._blob(models_root, layers[0], limit)
                if name == "tokenizer.json":
                    tokenizer_raw = raw
                elif local._json(raw).get("add_bos_token") is not False:
                    raise ValueError("unsupported BOS")
            tokenizer_class = import_module("tokenizers").Tokenizer
            assert tokenizer_raw is not None
            self._tokenizer = tokenizer_class.from_str(
                tokenizer_raw.decode("utf-8", errors="strict")
            )
            self._tokenizer.no_truncation()
            self._tokenizer.no_padding()
            return
        except Exception:  # noqa: BLE001,S110 - tokenizer/file locals must not be captured
            pass
        raise LocalTokenCounterError("local 9B tokenizer unavailable")

    def _render(self, serialized_body: bytes) -> str:
        return render_qwen35_nine_b_review_prompt(serialized_body)
