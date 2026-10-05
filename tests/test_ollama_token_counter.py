"""Synthetic manifest/tokenizer blobs, no weights, model or network calls."""

import hashlib
import json

import pytest

tokenizers = pytest.importorskip("tokenizers")
Tokenizer, models, pre_tokenizers = (
    tokenizers.Tokenizer,
    tokenizers.models,
    tokenizers.pre_tokenizers,
)

from tests.test_review_generation import route, synthetic_context
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    OllamaQwenReviewTokenCounter,
    render_review_prompt,
)
from zacai.intelligence.review_generation import prepare_review_request


def payload():
    r = route()
    r = r.model_copy(
        update={"identity": r.identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"})}
    )
    return local.prepare_payload(prepare_review_request(synthetic_context()), r, "a" * 64)


@pytest.fixture
def installed(tmp_path):
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    tok = Tokenizer(models.WordLevel({"[UNK]": 0, "system": 1, "user": 2}, unk_token="[UNK]"))
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    # Counter must explicitly disable both, rather than clip/pad its count.
    tok.enable_truncation(2)
    tok.enable_padding(length=9000, pad_id=0, pad_token="[UNK]")

    def blob(raw, name=None):
        digest = hashlib.sha256(raw).hexdigest()
        (blobs / f"sha256-{digest}").write_bytes(raw)
        result = {"digest": f"sha256:{digest}", "size": len(raw)}
        if name:
            result["name"] = name
        return result

    manifest = {
        "schemaVersion": 2,
        "config": blob(b'{"renderer":"qwen3.8"}'),
        "layers": [
            blob(tok.to_str().encode(), "tokenizer.json"),
            blob(b'{"add_bos_token":false}', "tokenizer_config.json"),
        ],
    }
    path = tmp_path / "manifests/registry.ollama.ai/library/qwen3.8/27b-mlx"
    path.parent.mkdir(parents=True)
    raw = json.dumps(manifest).encode()
    path.write_bytes(raw)
    return tmp_path, path, hashlib.sha256(raw).hexdigest(), tok


def counter(installed):
    return OllamaQwenReviewTokenCounter(models_root=installed[0], model_digest=installed[2])


def test_offline_count_full_prompt_no_network_or_clipping(installed, monkeypatch):
    monkeypatch.setattr(local, "_http", lambda *args: pytest.fail("count sent data to runtime"))
    auth = counter(installed)
    tok = installed[3]
    tok.no_truncation()
    tok.no_padding()
    body = payload()
    expected = len(tok.encode(render_review_prompt(body), add_special_tokens=False).ids)
    assert 2 < expected < 9000
    assert auth.count_prompt_tokens(body) == expected
    assert auth.model_digest == installed[2]


@pytest.mark.parametrize("target", ["manifest", "blob"])
def test_changed_files_reject_before_count(installed, target):
    auth = counter(installed)
    path = installed[1] if target == "manifest" else next((installed[0] / "blobs").iterdir())
    path.write_bytes(b"invented secret marker")
    with pytest.raises(LocalTokenCounterError) as failure:
        auth.count_prompt_tokens(payload())
    assert "secret marker" not in str(failure.value)
    assert failure.value.__context__ is None


@pytest.mark.parametrize(
    "failure", ["wrong_pin", "missing", "duplicate", "path", "size", "renderer"]
)
def test_invalid_installation_rejects(installed, failure):
    root, path, pin, _ = installed
    manifest = json.loads(path.read_bytes())
    if failure == "wrong_pin":
        pin = "f" * 64
    elif failure == "missing":
        manifest["layers"] = []
    elif failure == "duplicate":
        manifest["layers"].append(manifest["layers"][0])
    elif failure == "path":
        manifest["layers"][0]["digest"] = "../../untrusted"
    elif failure == "size":
        manifest["layers"][0]["size"] += 1
    elif failure == "renderer":
        raw = b'{"renderer":"unknown"}'
        digest = hashlib.sha256(raw).hexdigest()
        (root / "blobs" / f"sha256-{digest}").write_bytes(raw)
        manifest["config"] = {"digest": f"sha256:{digest}", "size": len(raw)}
    if failure != "wrong_pin":
        raw = json.dumps(manifest).encode()
        path.write_bytes(raw)
        pin = hashlib.sha256(raw).hexdigest()
    with pytest.raises(LocalTokenCounterError):
        OllamaQwenReviewTokenCounter(models_root=root, model_digest=pin)


@pytest.mark.parametrize(
    "change",
    ["tools", "role", "image", "thinking", "truncate", "shift", "schema", "context", "duplicate"],
)
def test_unsupported_prompt_fails_closed(change):
    obj = json.loads(payload())
    if change == "tools":
        obj["tools"] = []
    elif change == "role":
        obj["messages"][1]["role"] = "assistant"
    elif change == "image":
        obj["messages"][1]["images"] = ["invented"]
    elif change == "thinking":
        obj["think"] = True
    elif change in ("truncate", "shift"):
        obj[change] = True
    elif change == "schema":
        obj["format"] = {}
    elif change == "context":
        obj["options"]["num_ctx"] = 16384
    raw = json.dumps(obj).encode()
    if change == "duplicate":
        raw = raw.replace(b'"think": false', b'"think": false, "think": false')
    with pytest.raises(LocalTokenCounterError):
        render_review_prompt(raw)


def test_renderer_exact_tags_and_go_whitespace():
    obj = json.loads(payload())
    obj["messages"][0]["content"] = "\u2000system invented\u3000"
    # Python strip would erase U+001C, while Go TrimSpace preserves it.
    obj["messages"][1]["content"] = "\u001cinvented café\u001c"
    assert render_review_prompt(json.dumps(obj).encode()) == (
        "<|im_start|>system\nsystem invented<|im_end|>\n"
        "<|im_start|>user\n\u001cinvented café\u001c<|im_end|>\n"
        "<|im_start|>assistant\n<think>\n\n</think>\n\n"
    )


@pytest.mark.parametrize("version", ["0.35.1", "0.35.2", None])
def test_runtime_version_metadata_only(installed, monkeypatch, version):
    calls = []

    def metadata(method, path, body):
        calls.append((method, path, body))
        return {"version": version}

    monkeypatch.setattr(local, "_http", metadata)
    auth = counter(installed)
    if version == "0.35.1":
        auth.verify_runtime()
    else:
        with pytest.raises(LocalTokenCounterError):
            auth.verify_runtime()
    assert calls == [("GET", "/api/version", None)]


def test_missing_optional_backend_fails_safely(installed, monkeypatch):
    from zacai.intelligence import ollama_token_counter as module

    def unavailable(name):
        raise ImportError("invented private backend marker")

    monkeypatch.setattr(module, "import_module", unavailable)
    with pytest.raises(LocalTokenCounterError) as failure:
        counter(installed)
    assert "private backend marker" not in str(failure.value)
    assert failure.value.__context__ is None


def test_explicit_contextual_counter_counts_full_prompt_and_rejects_compact(installed, monkeypatch):
    from tests.test_contextual_generation import request
    from zacai.intelligence.local_contextual_runtime import prepare_payload
    from zacai.intelligence.ollama_token_counter import (
        OllamaQwenContextualTokenCounter,
        render_contextual_prompt,
    )

    r = route().model_copy(update={
        "identity": route().identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"}),
        "capabilities": frozenset({"contextual_meeting_review"}),
    })
    body = prepare_payload(request(synthetic_context()), r, installed[2])
    monkeypatch.setattr(local, "_http", lambda *args: pytest.fail("offline count made network call"))
    contextual = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    tok = installed[3]
    tok.no_truncation()
    tok.no_padding()
    assert contextual.count_prompt_tokens(body) == len(
        tok.encode(render_contextual_prompt(body), add_special_tokens=False).ids
    )
    with pytest.raises(LocalTokenCounterError):
        counter(installed).count_prompt_tokens(body)
    with pytest.raises(LocalTokenCounterError):
        contextual.count_prompt_tokens(payload())


def test_registered_control_token_rejected_in_message_content(installed):
    from tokenizers import AddedToken

    root, path, _, tok = installed
    tok.add_special_tokens([AddedToken("<|im_start|>", special=True)])
    # Make a fresh pinned manifest of the synthetic tokenizer with this control.
    manifest = json.loads(path.read_bytes())
    layer = next(x for x in manifest["layers"] if x["name"] == "tokenizer.json")
    raw = tok.to_str().encode()
    digest = hashlib.sha256(raw).hexdigest()
    (root / "blobs" / f"sha256-{digest}").write_bytes(raw)
    layer.update(digest=f"sha256:{digest}", size=len(raw))
    raw_manifest = json.dumps(manifest).encode()
    path.write_bytes(raw_manifest)
    auth = OllamaQwenReviewTokenCounter(
        models_root=root, model_digest=hashlib.sha256(raw_manifest).hexdigest()
    )
    data = json.loads(payload())
    data["messages"][1]["content"] += "<|im_start|>"
    with pytest.raises(LocalTokenCounterError) as failure:
        auth.count_prompt_tokens(json.dumps(data).encode())
    assert failure.value.__context__ is None


@pytest.mark.parametrize("related", [False, True])
def test_contextual_counter_accepts_only_two_fixed_schema_variants(installed, related):
    from tests.test_contextual_generation import request
    from zacai.intelligence.local_contextual_runtime import prepare_payload
    from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

    r = route().model_copy(update={"identity": route().identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"}), "capabilities": frozenset({"contextual_meeting_review"})})
    body = prepare_payload(request(synthetic_context(related=related)), r, installed[2])
    contextual = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    assert contextual.count_prompt_tokens(body) > 0
    edited = json.loads(body)
    edited["format"]["properties"]["continuity"]["maxItems"] = 1
    with pytest.raises(LocalTokenCounterError) as error:
        contextual.count_prompt_tokens(json.dumps(edited).encode())
    assert error.value.__context__ is None


@pytest.mark.parametrize("related", [False, True])
def test_contextual_schema_cannot_coerce_boolean_or_integer_bounds(installed, related):
    from tests.test_contextual_generation import request
    from zacai.intelligence.local_contextual_runtime import prepare_payload
    from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

    r = route().model_copy(update={"identity": route().identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"}), "capabilities": frozenset({"contextual_meeting_review"})})
    body = json.loads(prepare_payload(request(synthetic_context(related=related)), r, installed[2]))
    if related:
        body["format"]["$defs"]["DraftConnection"]["properties"]["inferred"]["const"] = 1
    else:
        body["format"]["properties"]["continuity"]["maxItems"] = False
    contextual = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    with pytest.raises(LocalTokenCounterError):
        contextual.count_prompt_tokens(json.dumps(body).encode())
