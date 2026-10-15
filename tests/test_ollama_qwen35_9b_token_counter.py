"""Invented tiny tokenizer/manifests and mocked transport only, no real model.

These checks prove gate/pin mechanics, not installed tokenizer/runtime parity or
quality. No actual tokenizer metadata, full tokenizer, weights or providers read.
"""

import hashlib
import json

import pytest

tokenizers = pytest.importorskip("tokenizers")

from tests.test_ollama_token_counter import installed as installed27  # noqa: F401
from tests.test_review_generation import draft, route, synthetic_context
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence import ollama_qwen35_9b_token_counter as m
from zacai.intelligence.ollama_token_counter import (
    LocalTokenCounterError,
    OllamaQwenReviewTokenCounter,
    render_review_prompt,
)
from zacai.intelligence.review_generation import prepare_review_request

MODEL = "qwen3.5:9b-mlx"


def route9():
    r = route()
    return r.model_copy(update={"identity": r.identity.model_copy(update={"model_id": MODEL})})


def payload(pin="a" * 64):
    return local.prepare_payload(prepare_review_request(synthetic_context()), route9(), pin)


@pytest.fixture
def installed(tmp_path):
    tmp_path = tmp_path / "nine-b"
    tmp_path.mkdir()
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    tokenizer = tokenizers.Tokenizer(
        tokenizers.models.WordLevel({"[UNK]": 0, "system": 1, "user": 2}, unk_token="[UNK]")
    )
    tokenizer.pre_tokenizer = tokenizers.pre_tokenizers.Whitespace()
    tokenizer.add_special_tokens([tokenizers.AddedToken("<|im_start|>", special=True)])
    tokenizer.enable_truncation(2)
    tokenizer.enable_padding(length=9000, pad_id=0, pad_token="[UNK]")

    def blob(raw, name=None):
        digest = hashlib.sha256(raw).hexdigest()
        (blobs / ("sha256-" + digest)).write_bytes(raw)
        return {"digest": "sha256:" + digest, "size": len(raw), **({"name": name} if name else {})}

    manifest = {
        "schemaVersion": 2,
        "config": blob(b'{"renderer":"qwen3.5","parser":"qwen3.5"}'),
        "layers": [
            blob(tokenizer.to_str().encode(), "tokenizer.json"),
            blob(b'{"add_bos_token":false}', "tokenizer_config.json"),
        ],
    }
    path = tmp_path / "manifests/registry.ollama.ai/library/qwen3.5/9b-mlx"
    path.parent.mkdir(parents=True)

    def save():
        raw = json.dumps(manifest).encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    return {
        "root": tmp_path,
        "path": path,
        "manifest": manifest,
        "blob": blob,
        "save": save,
        "pin": save(),
        "tokenizer": tokenizer,
    }


def counter(f):
    return m.OllamaQwen35NineBReviewTokenCounter(models_root=f["root"], model_digest=f["pin"])


def test_counts_full_prompt_offline_disables_padding_and_truncation(installed, monkeypatch):
    monkeypatch.setattr(
        local, "_http", lambda *args: pytest.fail("offline count attempted provider call")
    )
    c = counter(installed)
    raw = payload(installed["pin"])
    expected = installed["tokenizer"]
    expected.no_padding()
    expected.no_truncation()
    assert c._tokenizer.padding is None and c._tokenizer.truncation is None
    count = c.count_prompt_tokens(raw)
    assert count == len(
        expected.encode(m.render_qwen35_nine_b_review_prompt(raw), add_special_tokens=False).ids
    )
    assert 2 < count < 9000 and c.model_digest == installed["pin"]


@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "duplicate",
        "wrong_pin",
        "renderer",
        "parser",
        "bos",
        "size",
        "path",
        "schema_bool",
    ],
)
def test_constructor_rejects_unbound_or_wrong_model_metadata(installed, failure):
    f = installed
    manifest = f["manifest"]
    if failure == "missing":
        manifest["layers"] = []
    elif failure == "duplicate":
        manifest["layers"].append(manifest["layers"][0])
    elif failure == "renderer":
        manifest["config"] = f["blob"](b'{"renderer":"qwen3.8","parser":"qwen3.5"}')
    elif failure == "parser":
        manifest["config"] = f["blob"](b'{"renderer":"qwen3.5","parser":"other"}')
    elif failure == "bos":
        manifest["layers"][1] = f["blob"](b'{"add_bos_token":true}', "tokenizer_config.json")
    elif failure == "size":
        manifest["layers"][0]["size"] += 1
    elif failure == "path":
        manifest["layers"][0]["digest"] = "../../untrusted"
    elif failure == "schema_bool":
        manifest["schemaVersion"] = True
    f["pin"] = f["save"]() if failure != "wrong_pin" else "f" * 64
    with pytest.raises(LocalTokenCounterError, match="^local 9B tokenizer unavailable$") as error:
        counter(f)
    assert error.value.__context__ is None


@pytest.mark.parametrize("which", ["manifest", "config", "tokenizer.json", "tokenizer_config.json"])
def test_each_count_rechecks_original_manifest_and_blobs(installed, which):
    c = counter(installed)
    if which == "manifest":
        path = installed["path"]
    else:
        layer = (
            installed["manifest"]["config"]
            if which == "config"
            else next(x for x in installed["manifest"]["layers"] if x["name"] == which)
        )
        path = installed["root"] / "blobs" / layer["digest"].replace(":", "-")
    path.write_bytes(b"invented private diagnostic")
    with pytest.raises(LocalTokenCounterError) as error:
        c.count_prompt_tokens(payload())
    assert "private diagnostic" not in str(error.value) and error.value.__context__ is None


@pytest.mark.parametrize(
    "change",
    [
        "model27",
        "othermodel",
        "tools",
        "image",
        "think",
        "stream",
        "truncate",
        "shift",
        "turn",
        "role",
        "schema",
        "context",
        "predict_bool",
        "temperature_float",
        "keepalive_bool",
        "empty",
        "toolresponse",
        "duplicate",
        "oversize",
        "notbytes",
    ],
)
def test_closed_original_wire_rejections(change):
    body = json.loads(payload())
    if change == "model27":
        body["model"] = "qwen3.8:27b-mlx"
    elif change == "othermodel":
        body["model"] = "qwen3.5:9b-mlx:cloud"
    elif change == "tools":
        body["tools"] = []
    elif change == "image":
        body["messages"][1]["images"] = ["invented"]
    elif change in {"think", "stream", "truncate", "shift"}:
        body[change] = True
    elif change == "turn":
        body["messages"].append({"role": "assistant", "content": "invented"})
    elif change == "role":
        body["messages"][1]["role"] = "developer"
    elif change == "schema":
        body["format"] = {}
    elif change == "context":
        body["options"]["num_ctx"] = 16384
    elif change == "predict_bool":
        body["options"]["num_predict"] = True
    elif change == "temperature_float":
        body["options"]["temperature"] = 0.0
    elif change == "keepalive_bool":
        body["keep_alive"] = False
    elif change == "empty":
        body["messages"][1]["content"] = " \n"
    elif change == "toolresponse":
        body["messages"][1]["content"] = "<tool_response>text</tool_response>"
    raw = json.dumps(body).encode()
    if change == "duplicate":
        raw = raw.replace(b'"think": false', b'"think": false, "think": false')
    elif change == "oversize":
        raw += b" " * 64001
    elif change == "notbytes":
        raw = raw.decode()
    with pytest.raises(
        LocalTokenCounterError, match="^unsupported local 9B review prompt$"
    ) as error:
        m.render_qwen35_nine_b_review_prompt(raw)
    assert error.value.__context__ is None


def test_registered_special_token_injection_rejected_before_encode(installed):
    c = counter(installed)
    body = json.loads(payload())
    body["messages"][1]["content"] += "<|im_start|>"
    with pytest.raises(LocalTokenCounterError):
        c.count_prompt_tokens(json.dumps(body).encode())


def test_restricted_renderer_golden_parity_without_relabelling_original_payload():
    body = json.loads(payload())
    body["messages"][0]["content"] = "\u2000invented system\u3000"
    body["messages"][1]["content"] = "\u001cinvented café\u001c"
    raw = json.dumps(body, ensure_ascii=False).encode()
    expected = "<|im_start|>system\ninvented system<|im_end|>\n<|im_start|>user\n\u001cinvented café\u001c<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
    assert m.render_qwen35_nine_b_review_prompt(raw) == expected
    old = dict(body, model="qwen3.8:27b-mlx")
    assert render_review_prompt(json.dumps(old, ensure_ascii=False).encode()) == expected
    assert json.loads(raw)["model"] == MODEL
    with pytest.raises(LocalTokenCounterError):
        render_review_prompt(raw)


def test_27b_manifest_and_counter_remain_separate(installed, installed27):  # noqa: F811
    c = counter(installed)
    old = OllamaQwenReviewTokenCounter(models_root=installed27[0], model_digest=installed27[2])
    with pytest.raises(LocalTokenCounterError):
        old.count_prompt_tokens(payload())
    body = json.loads(payload())
    body["model"] = "qwen3.8:27b-mlx"
    with pytest.raises(LocalTokenCounterError):
        c.count_prompt_tokens(json.dumps(body).encode())


@pytest.mark.parametrize("version", ["0.35.1", "0.35.2", None])
def test_runtime_version_is_existing_explicit_pin_not_model_requires(
    installed, monkeypatch, version
):
    calls = []

    def fake(method, path, body=None):
        calls.append((method, path, body))
        return {"version": version}

    monkeypatch.setattr(local, "_http", fake)
    if version == "0.35.1":
        counter(installed).verify_runtime()
    else:
        with pytest.raises(LocalTokenCounterError):
            counter(installed).verify_runtime()
    assert calls == [("GET", "/api/version", None)]


def runtime_case(f, monkeypatch):
    c = counter(f)
    request = prepare_review_request(synthetic_context())
    r = route9()
    raw = local.prepare_payload(request, r, f["pin"])
    count = c.count_prompt_tokens(raw)
    calls = []
    state = {"version": "0.35.1", "digest": f["pin"], "remote": False, "usage": count}

    def fake(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/version":
            return {"version": state["version"]}
        if path == "/api/tags":
            return {"models": [{"name": MODEL, "digest": state["digest"]}]}
        if path == "/api/show":
            return {"remote_model": "remote"} if state["remote"] else {}
        assert path == "/api/chat" and json.loads(body)["model"] == MODEL
        return {
            "model": MODEL,
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": state["usage"],
            "eval_count": 100,
            "message": {"role": "assistant", "content": draft().model_dump_json()},
        }

    monkeypatch.setattr(local, "_http", fake)
    return (
        local.LocalReviewRuntime(route=r, model_digest=f["pin"], token_counter=c),
        request,
        c,
        calls,
        state,
        count,
    )


def test_existing_runtime_uses_actual_counter_and_one_attempt(installed, monkeypatch):
    runtime, request, _counter, calls, _state, count = runtime_case(installed, monkeypatch)
    runtime.preflight(request)
    assert all(path != "/api/chat" for _, path, _ in calls)
    assert runtime.generate(request).summary
    assert runtime.usage.input_tokens == count
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert [path for _, path, _ in calls].count("/api/chat") == 1


@pytest.mark.parametrize("failure", ["version", "manifest", "remote", "capacity", "usage"])
def test_existing_runtime_blocks_drift_overflow_and_usage_mismatch(installed, monkeypatch, failure):
    runtime, request, c, calls, state, count = runtime_case(installed, monkeypatch)
    runtime.preflight(request)
    calls.clear()
    if failure == "version":
        state["version"] = "0.35.2"
    elif failure == "manifest":
        state["digest"] = "f" * 64
    elif failure == "remote":
        state["remote"] = True
    elif failure == "capacity":
        monkeypatch.setattr(c, "count_prompt_tokens", lambda body: 8192)
    else:
        state["usage"] = count + 1
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert runtime.usage is None
    chat_count = [path for _, path, _ in calls].count("/api/chat")
    assert chat_count == (1 if failure == "usage" else 0)
    with pytest.raises(local.LocalReviewRuntimeError):
        runtime.generate(request)
    assert [path for _, path, _ in calls].count("/api/chat") == chat_count


def test_missing_optional_tokenizer_backend_fails_without_diagnostic_leak(installed, monkeypatch):
    def unavailable(name):
        raise ImportError("invented private tokenizer diagnostic")

    monkeypatch.setattr(m, "import_module", unavailable)
    with pytest.raises(LocalTokenCounterError) as error:
        counter(installed)
    assert error.value.__context__ is None
    assert "private tokenizer diagnostic" not in str(error.value)
