"""PUBLIC invented inputs only; verify offline/runtime prompt-count agreement.

No input files, source IDs, credentials, private transcript or approval issuer.
Run explicitly with the already installed model store. Never auto-pull models.
"""

import json
from argparse import ArgumentParser
from pathlib import Path

from compact_meeting_review import CASES, packet

from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.local_review_runtime import LocalReviewRuntime, prepare_payload
from zacai.intelligence.ollama_token_counter import OllamaQwenReviewTokenCounter
from zacai.intelligence.review_generation import prepare_review_request
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B

PIN = "5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e"


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--models-root", type=Path, required=True)
    args = parser.parse_args()
    counter = OllamaQwenReviewTokenCounter(models_root=args.models_root, model_digest=PIN)
    route = ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "qwen3.8:27b-mlx",
            "runtime_id": "mac-loopback-tokenizer-probe",
        },
        destination=Destination.LOCAL,
        capabilities=frozenset({"compact_meeting_review"}),
        max_input_characters=60000,
        max_output_tokens=1600,
        estimated_latency_ms=60000.0,
        estimated_cost_usd=0.0,
        available=True,
    )
    cases = {
        "continuing_project": CASES["project_across_contracts"],
        "unicode": (
            "Élodie: We agreed to test the café report.\n李: I will check the totals on 2026-10-09.\nSam: Keep release on hold until testing passes.\nSam: The value €1,234.56 is an invented test value.",
            None,
        ),
        "longer": (
            CASES["follow_up"][0]
            + "\n"
            + "\n".join(
                "Invented historical test notes: " + "The sample report needs reconciliation. " * 28
                for _ in range(8)
            ),
            CASES["follow_up"][1],
        ),
    }
    for name, texts in cases.items():
        context = packet(texts)
        assert context.task.event.trust_boundary == B.SHARED
        assert context.task.event.data_classification == C.PUBLIC
        assert all(
            item.reference.effective_classification == C.PUBLIC for item in context.task.context
        )
        request = prepare_review_request(context)
        expected = counter.count_prompt_tokens(prepare_payload(request, route, PIN))
        runtime = LocalReviewRuntime(route=route, model_digest=PIN, token_counter=counter)
        runtime.preflight(request)
        runtime.generate(request)
        assert runtime.usage is not None and runtime.usage.input_tokens == expected
        print(
            json.dumps(
                {
                    "case": name,
                    "synthetic_only": True,
                    "offline_count": expected,
                    "runtime_count": runtime.usage.input_tokens,
                    "match": True,
                    "latency_ms": runtime.usage.latency_ms,
                    "model_digest": PIN,
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
