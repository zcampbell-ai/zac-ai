"""PUBLIC invented 16k profile conformance; never reads private inputs."""

import json
from argparse import ArgumentParser
from pathlib import Path

from compact_meeting_review import packet

from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.contracts import IntelligenceTask, ModelRoute
from zacai.intelligence.local_contextual_runtime import LocalContextualRuntime, prepare_payload
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B

PIN = "5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e"


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--models-root", type=Path, required=True)
    args = parser.parse_args()
    # Generated PUBLIC content only. No path for files, credentials or provider records.
    sample = (
        "Alex: We agreed to keep this invented rehearsal on hold until synthetic checks pass.\n"
        + "\n".join(
            f"PUBLIC invented rehearsal row {i}: synthetic sample checks remain incomplete."
            for i in range(530)
        )
        + "\nSam: I will test the invented sample tomorrow. No real clients or projects are involved."
    )
    base = packet((sample, None))
    task = IntelligenceTask.model_validate(
        base.task.model_copy(
            update={
                "required_capabilities": frozenset({"contextual_meeting_review"}),
                "max_output_tokens": 1600,
            }
        )
    )
    context = ReviewContext(task, base.meeting_source_id, base.related_source_ids)
    if (
        context.task.event.trust_boundary != B.SHARED
        or context.task.event.data_classification != C.PUBLIC
        or any(
            item.reference.trust_boundary != B.SHARED
            or item.reference.effective_classification != C.PUBLIC
            for item in context.task.context
        )
    ):
        raise ValueError("PUBLIC invented context required")
    route = ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "qwen3.8:27b-mlx",
            "runtime_id": "mac-loopback-contextual-16k",
        },
        destination=Destination.LOCAL,
        capabilities=frozenset({"contextual_meeting_review"}),
        max_input_characters=64000,
        max_output_tokens=1600,
        estimated_latency_ms=120000,
        estimated_cost_usd=0,
        available=True,
    )
    request = prepare_contextual_request(context)
    counter = OllamaQwenContextualTokenCounter(models_root=args.models_root, model_digest=PIN)
    expected = counter.count_prompt_tokens(prepare_payload(request, route, PIN))
    if not 8192 < expected or expected + 1600 > 16384:
        raise ValueError("probe must exercise larger context with full output reservation")
    runtime = LocalContextualRuntime(route=route, model_digest=PIN, token_counter=counter)
    runtime.preflight(request)
    runtime.generate(request)
    if runtime.usage is None or runtime.usage.input_tokens != expected:
        raise ValueError("token count mismatch")
    print(
        json.dumps(
            {
                "format": "zac-public-contextual-profile-probe-v1",
                "synthetic_only": True,
                "profile": route.identity.runtime_id,
                "model_digest": PIN,
                "context_limit": 16384,
                "offline_count": expected,
                "runtime_count": runtime.usage.input_tokens,
                "match": runtime.usage.input_tokens == expected,
                "usage": runtime.usage.model_dump(),
                "private_source_reads": 0,
                "canonical_writes": 0,
                "semantic_usefulness_proven": False,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 - fixed operator diagnostics
        print(
            json.dumps(
                {"profile_probe": "FAILED", "synthetic_only": True, "private_source_reads": 0}
            )
        )
        raise SystemExit(1)
