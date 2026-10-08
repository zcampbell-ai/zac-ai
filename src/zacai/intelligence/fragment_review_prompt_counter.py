"""Offline exact fragment-review wire counting; no dispatch or permission.

Uses the existing declared Qwen3.8/Ollama0.35.1 renderer and installed tokenizer
files. Schema instructions are actual message text; output grammar is not an
extra prompt. Synthetic tests establish local counting mechanics, never actual
backend template parity, model suitability or authenticated reviewer consent.
Inherited verify_runtime is a separate network metadata call, not called here.
"""

from __future__ import annotations

import hashlib
from importlib.metadata import version
from pathlib import Path
from types import ModuleType
from uuid import UUID

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_review_preparation as preparation
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence import ollama_token_counter as base
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    OllamaQwenReviewTokenCounter,
)


def render_fragment_review_prompt(serialized_body: bytes) -> str:
    """Reconstruct exact declared wire, then render all messages without omission.

    Hashes, IDs and packet fields are structural declarations. Reconstruction
    does not authenticate their original sources, current rights or reviewer.
    """
    result = None
    try:
        if (
            type(serialized_body) is not bytes
            or not 0 < len(serialized_body) <= wire.MAX_WIRE_BYTES
        ):
            raise ValueError("bounded exact wire required")
        body = local._json(serialized_body)
        data = local._json(body["messages"][1]["content"])
        packet_raw = canonical_bytes(data["packet"])
        rubric_raw = data["rubric"].encode("utf-8")
        template_raw = data["review_instruction"].encode("utf-8")
        prepared = preparation.prepare_fragment_review_request(
            packet_raw,
            expected_packet_digest=data["packet_digest"],
            expected_task_id=UUID(data["task_id"]),
            expected_builder_id=UUID(data["builder_id"]),
            reviewer_id=UUID(data["reviewer_id"]),
            run_id=UUID(data["run_id"]),
            route=ModelRoute.model_validate(data["route"]),
            max_output_tokens=data["review_budgets"]["max_output_tokens"],
            max_latency_ms=data["review_budgets"]["max_latency_ms"],
            rubric_utf8=rubric_raw,
            template_utf8=template_raw,
            expected_rubric_digest=data["rubric_digest"],
            expected_template_digest=data["template_digest"],
            model_digest=data["model_digest"],
            reviewer_wire_digest=data["reviewer_wire_digest"],
        )
        if (
            wire.serialize_fragment_review_wire(
                prepared, packet_raw=packet_raw, rubric_utf8=rubric_raw, template_utf8=template_raw
            )
            != serialized_body
        ):
            raise ValueError("exact complete wire mismatch")
        result = base._render_prompt(
            serialized_body,
            preparation.FragmentReviewJudgments.model_json_schema(),
            context_tokens=frozenset({wire.CONTEXT_TOKENS}),
        )
    except Exception:  # noqa: BLE001,S110 - never expose source or installation diagnostics
        pass
    if result is None:
        raise LocalTokenCounterError("unsupported fragment review local prompt")
    return result


class OllamaQwenFragmentReviewTokenCounter(OllamaQwenReviewTokenCounter):
    """Exact offline count and prospective narrow pins, not an approved profile.

    Full rendered input plus requested output must fit 16384 tokens. This is not
    an elapsed-time, runtime, model, custody or semantic review guarantee. No
    active host recognizes this new family. Dispatch/admission must separately
    bind exact wire, deadline, current owner/rights and independent reviewer.
    """

    def _render(self, serialized_body: bytes) -> str:
        return render_fragment_review_prompt(serialized_body)

    def count_prompt_tokens(self, serialized_body: bytes) -> int:
        result = None
        try:
            if (
                type(serialized_body) is not bytes
                or not 0 < len(serialized_body) <= wire.MAX_WIRE_BYTES
            ):
                raise ValueError("bounded exact wire required")
            body = local._json(serialized_body)
            declared = local._json(body["messages"][1]["content"])
            if declared["model_digest"] != self.model_digest:
                raise ValueError("declared installed model manifest mismatch")
            count = super().count_prompt_tokens(serialized_body)
            requested = local._json(serialized_body)["options"]["num_predict"]
            if count + requested > wire.CONTEXT_TOKENS:
                raise ValueError("whole prompt plus reservation exceeds context")
            result = count
        except Exception:  # noqa: BLE001,S110 - cause-free public error
            pass
        if result is None:
            raise LocalTokenCounterError(
                "fragment review local prompt unavailable or exceeds capacity"
            )
        return result

    @property
    def tokenizer_digest(self) -> str:
        result = None
        try:
            result = hashlib.sha256(
                b"zac-fragment-review-tokenizer-v1\x00"
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
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise LocalTokenCounterError("fragment review tokenizer pin unavailable")
        return result

    @property
    def template_digest(self) -> str:
        # Bind the actual shared renderer implementation instead of a duplicate
        # template string that could drift without changing the used renderer.
        return self._implementation_digest(b"zac-fragment-review-template-v1\x00", (base,))

    @property
    def renderer_digest(self) -> str:
        # Narrow direct rendering/reconstruction implementation pins, not dispatch policy.
        # Transitive packet/contract/profile admission needs its own host policy pins.
        # Tokenizer semantics/version are separately bound by tokenizer_digest.
        return self._implementation_digest(
            b"zac-fragment-review-renderer-v1\x00",
            (base, local, preparation, wire),
            own=True,
        )

    @staticmethod
    def _implementation_digest(
        domain: bytes, modules: tuple[ModuleType, ...], *, own: bool = False
    ) -> str:
        result = None
        try:
            paths = []
            for module in modules:
                if module.__file__ is None:
                    raise ValueError("implementation unavailable")
                paths.append(Path(module.__file__).resolve())
            if own:
                paths.append(Path(__file__).resolve())
            rows = [(path.name, hashlib.sha256(path.read_bytes()).hexdigest()) for path in paths]
            result = hashlib.sha256(domain + canonical_bytes({"files": rows})).hexdigest()
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise LocalTokenCounterError("fragment review renderer pin unavailable")
        return result
