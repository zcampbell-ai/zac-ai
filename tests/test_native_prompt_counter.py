"""Invented provider inputs/synthetic tokenizer; no actual model fit or probes."""

import json

import pytest

from tests.test_local_contextual_runtime import route
from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_derivation_admission import projection
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import local_contextual_runtime as runtime
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence.native_prompt_counter import (
    OllamaQwenNativeContextualTokenCounter,
    render_native_prompt,
)
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    render_contextual_prompt,
)


def body(fixture, prepared, installed):
    request = generation.prepare_native_contextual_request(projection(fixture, prepared))
    r = route()
    r = r.model_copy(
        update={"identity": r.identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"})}
    )
    return runtime.prepare_native_payload(request, r, installed[2])


def test_full_native_schema_metadata_template_count_without_network(
    fixture,
    prepared,
    installed,
    monkeypatch,
):
    monkeypatch.setattr(local, "_http", lambda *args: pytest.fail("unexpected model call"))
    raw = body(fixture, prepared, installed)
    counter = OllamaQwenNativeContextualTokenCounter(
        models_root=installed[0],
        model_digest=installed[2],
    )
    prompt = render_native_prompt(raw)
    assert prompt == render_contextual_prompt(raw)
    assert "untrusted_noncitable_metadata" in prompt
    assert "Output JSON schema:" in prompt
    assert prompt.endswith("<|im_start|>assistant\n<think>\n\n</think>\n\n")
    tok = installed[3]
    tok.no_padding()
    tok.no_truncation()
    assert counter.count_prompt_tokens(raw) == len(tok.encode(prompt, add_special_tokens=False).ids)
    assert all(
        len(pin) == 64
        for pin in (
            counter.model_digest,
            counter.tokenizer_digest,
            counter.template_digest,
            counter.renderer_digest,
        )
    )
    assert len({counter.tokenizer_digest, counter.template_digest, counter.renderer_digest}) == 3


@pytest.mark.parametrize("fault", ["family", "metadata", "schema", "messages", "duplicate"])
def test_closed_native_renderer_denies_with_no_private_cause(
    fixture,
    prepared,
    installed,
    fault,
):
    data = json.loads(body(fixture, prepared, installed))
    evidence = json.loads(data["messages"][1]["content"])
    if fault == "family":
        evidence["format"] = "legacy-private"
    elif fault == "metadata":
        evidence["untrusted_noncitable_metadata"]["format"] = "private-invalid"
    elif fault == "schema":
        data["format"]["properties"]["continuity"]["maxItems"] = True
    elif fault == "messages":
        data["messages"].append({"role": "assistant", "content": "private-extra"})
    if fault == "duplicate":
        data["messages"][1]["content"] = '{"format":"private","format":"private"}'
    else:
        data["messages"][1]["content"] = json.dumps(evidence)
    with pytest.raises(LocalTokenCounterError) as error:
        render_native_prompt(json.dumps(data).encode())
    assert str(error.value) == "unsupported native local prompt"
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_metadata_is_counted_verbatim_not_removed(fixture, prepared, installed):
    data = json.loads(body(fixture, prepared, installed))
    before = render_native_prompt(json.dumps(data).encode())
    evidence = json.loads(data["messages"][1]["content"])
    evidence["untrusted_noncitable_metadata"]["entries"][0]["relevance"] = (
        "INVENTED_NONCITABLE_SELECTION_RATIONALE"
    )
    data["messages"][1]["content"] = json.dumps(evidence)
    after = render_native_prompt(json.dumps(data).encode())
    assert before != after
    assert "INVENTED_NONCITABLE_SELECTION_RATIONALE" in after
    # Counting accepts message structure, not factual authenticity or authority.


@pytest.mark.parametrize("target", ["manifest", "tokenizer"])
def test_changed_pinned_assets_hold_before_count(fixture, prepared, installed, target):
    raw = body(fixture, prepared, installed)
    counter = OllamaQwenNativeContextualTokenCounter(
        models_root=installed[0],
        model_digest=installed[2],
    )
    assert counter.count_prompt_tokens(raw) > 0
    path = installed[1]
    if target == "tokenizer":
        manifest = json.loads(path.read_bytes())
        layer = next(x for x in manifest["layers"] if x["name"] == "tokenizer.json")
        path = installed[0] / "blobs" / layer["digest"].replace(":", "-")
    path.write_bytes(b"private-corrupt")
    with pytest.raises(LocalTokenCounterError) as error:
        counter.count_prompt_tokens(raw)
    assert str(error.value) == "local prompt counting failed"
    assert error.value.__context__ is None
