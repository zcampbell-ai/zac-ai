"""Synthetic actual tokenizer + mocked metadata/transport, never model authority."""
from types import SimpleNamespace

from tests.test_fragment_review_wire import reply
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import fragment_review_runtime as runtime
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence import local_review_runtime as local


def configured_runtime(prepared, packet_raw, rubric, template, counter, monkeypatch):
    """Use caller's actual concrete gate-prepared request without mutation."""
    monkeypatch.setattr(local, "_http", lambda *a: {"version": "0.35.1"})
    profile = runtime.FragmentReviewRuntimeProfile(
        wire.RUNTIME, runtime.fragment_review_runtime_digest(), counter.model_digest,
        counter.tokenizer_digest, counter.template_digest, counter.renderer_digest,
    )
    state = SimpleNamespace(posts=[], metadata=[], response=None, callback=lambda: None)

    def transport(method, path, body, remaining):
        if path == "/api/version":
            state.metadata.append(path)
            return canonical_bytes({"version": "0.35.1"})
        if path == "/api/tags":
            state.metadata.append(path)
            return canonical_bytes({"models": [{"name": wire.MODEL, "digest": counter.model_digest}]})
        if path == "/api/show":
            state.metadata.append(path)
            return canonical_bytes({"details": {"family": "qwen"}})
        assert method == "POST" and path == "/api/chat" and remaining > 0
        state.posts.append(body)
        state.callback()
        response = reply() if state.response is None else state.response
        response = response | {"prompt_eval_count": counter.count_prompt_tokens(body)}
        return canonical_bytes(response)

    engine = runtime._LocalFragmentReviewRuntime(
        profile=profile, token_counter=counter, _transport=transport,
        _clock=runtime._AUTHENTICATED_MONOTONIC,
    )
    kwargs = {"packet_raw": packet_raw, "rubric_utf8": rubric, "template_utf8": template}
    return engine, kwargs, state
