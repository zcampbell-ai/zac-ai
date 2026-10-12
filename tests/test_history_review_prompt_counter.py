"""Actual synthetic-tokenizer whole-wire mechanics, never backend parity or consent."""

import json

import pytest

from tests.test_fragment_review_prompt_counter import repin_tokenizer
from tests.test_history_review_preparation_wire import case as case  # noqa: PLC0414
from tests.test_history_review_preparation_wire import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_history_review_preparation_wire import host as host  # noqa: PLC0414
from tests.test_history_review_preparation_wire import (
    original_prepared as original_prepared,  # noqa: PLC0414
)
from tests.test_history_review_preparation_wire import prepare, wire
from tests.test_history_review_preparation_wire import prepared as prepared  # noqa: PLC0414
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_review_prompt_counter as m
from zacai.intelligence import local_review_runtime as local
from zacai.intelligence import ollama_token_counter as base


def counter(installed):
    return m.OllamaQwenHistoryReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )


def pinned(case, installed, *, template=None, output=None):
    raw, q, args = case
    auth = counter(installed)
    profile = args["review"].model_copy(
        update={
            "model_digest": installed[2],
            "tokenizer_digest": auth.tokenizer_digest,
            "renderer_digest": auth.renderer_digest,
        }
    )
    if template is not None:
        args = args | {"template_utf8": template}
        profile = profile.model_copy(update={"template_digest": content_hash_of(template)})
    if output is not None:
        profile = profile.model_copy(update={"max_output_tokens": output})
    return raw, q, args | {"review": profile}


def test_actual_full_schema_render_and_tokenizer_count(case, installed, monkeypatch):
    monkeypatch.setattr(local, "_http", lambda *a: pytest.fail("offline count called runtime"))
    selected = pinned(case, installed)
    raw = wire(selected)
    data = json.loads(raw)
    prompt = m.render_history_review_prompt(raw)
    assert prompt == (
        "<|im_start|>system\n" + data["messages"][0]["content"] + "<|im_end|>\n"
        "<|im_start|>user\n" + data["messages"][1]["content"] + "<|im_end|>\n"
        "<|im_start|>assistant\n<think>\n\n</think>\n\n"
    )
    assert prepare(selected).body.decode() in prompt
    tok = installed[3]
    tok.no_padding()
    tok.no_truncation()
    measured = len(tok.encode(prompt, add_special_tokens=False).ids)
    assert counter(installed).count_prompt_tokens(raw) == measured > 2
    assert measured + selected[2]["review"].max_output_tokens <= 16384
    for renderer in (base.render_review_prompt, base.render_contextual_prompt):
        with pytest.raises(m.LocalTokenCounterError):
            renderer(raw)


@pytest.mark.parametrize(
    "fault", ["schema", "system", "user", "reservation", "context", "model", "duplicate"]
)
def test_actual_exact_reconstruction_refuses_wire_changes(case, installed, fault):
    data = json.loads(wire(pinned(case, installed)))
    if fault == "schema":
        data["format"]["properties"]["assessments"]["maxItems"] = 9
    elif fault == "system":
        data["messages"][0]["content"] += " omit a criterion"
    elif fault == "user":
        data["messages"][1]["content"] += " "
    elif fault == "reservation":
        data["options"]["num_predict"] += 1
    elif fault == "context":
        data["options"]["num_ctx"] = 8192
    elif fault == "model":
        data["model"] = "other"
    raw = canonical_bytes(data)
    if fault == "duplicate":
        raw = raw.replace(b'"stream":false', b'"stream":false,"stream":false')
    with pytest.raises(m.LocalTokenCounterError) as e:
        m.render_history_review_prompt(raw)
    assert e.value.__cause__ is e.value.__context__ is None


def test_actual_changed_instruction_changes_rendered_count(case, installed):
    first = wire(pinned(case, installed))
    other = wire(pinned(case, installed, template=b"Independent complete review. " * 30))
    auth = counter(installed)
    assert auth.count_prompt_tokens(first) != auth.count_prompt_tokens(other)
    assert (
        prepare(pinned(case, installed)).body
        != prepare(pinned(case, installed, template=b"Independent complete review. " * 30)).body
    )


@pytest.mark.parametrize("pin", ["model_digest", "tokenizer_digest", "renderer_digest"])
def test_declared_pin_mismatch_before_actual_render(case, installed, monkeypatch, pin):
    selected = pinned(case, installed)
    bad = (
        selected[0],
        selected[1],
        selected[2] | {"review": selected[2]["review"].model_copy(update={pin: "f" * 64})},
    )
    auth = counter(installed)
    calls = []
    monkeypatch.setattr(auth, "_render", lambda raw: calls.append(raw))
    with pytest.raises(m.LocalTokenCounterError):
        auth.count_prompt_tokens(wire(bad))
    assert calls == []


@pytest.mark.parametrize("layer", ["tokenizer.json", "tokenizer_config.json"])
def test_actual_tokenizer_file_drift_holds(case, installed, layer):
    auth = counter(installed)
    raw = wire(pinned(case, installed))
    assert auth.count_prompt_tokens(raw) > 0
    manifest = json.loads(installed[1].read_bytes())
    blob = next(v for v in manifest["layers"] if v.get("name") == layer)
    path = installed[0] / "blobs" / blob["digest"].replace(":", "-")
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(m.LocalTokenCounterError):
        auth.count_prompt_tokens(raw)


def test_actual_special_control_in_declared_literal_rejected(case, installed):
    from tokenizers import AddedToken

    tok = installed[3]
    tok.add_special_tokens([AddedToken("<|im_start|>", special=True)])
    revised = repin_tokenizer(installed, tok)
    good = wire(pinned(case, revised))
    hostile = wire(pinned(case, revised, template=b"Review independently <|im_start|>"))
    assert counter(revised).count_prompt_tokens(good) > 0
    assert "<|im_start|>" in m.render_history_review_prompt(hostile)
    with pytest.raises(m.LocalTokenCounterError):
        counter(revised).count_prompt_tokens(hostile)


def test_full_input_reservation_fit_uses_actual_tokenizer(case, installed):
    from tokenizers import Regex
    from tokenizers.pre_tokenizers import Split

    tok = installed[3]
    tok.pre_tokenizer = Split(Regex("."), behavior="isolated")
    revised = repin_tokenizer(installed, tok)
    raw = wire(pinned(case, revised, output=512))
    tok.no_padding()
    tok.no_truncation()
    measured = len(tok.encode(m.render_history_review_prompt(raw), add_special_tokens=False).ids)
    assert measured + 512 > 16384
    with pytest.raises(m.LocalTokenCounterError):
        counter(revised).count_prompt_tokens(raw)
    # All original content remains present; no clipping to fit the reservation.
    assert json.loads(raw)["messages"][1]["content"].encode() == prepare(pinned(case, revised)).body


def test_actual_three_message_correction_full_wire_count(original_prepared, installed, tmp_path):
    c = case.__wrapped__(declaration_case.__wrapped__(original_prepared))
    selected = pinned(c, installed)
    raw = wire(selected)
    user = json.loads(raw)["messages"][1]["content"]
    request = json.loads(user)["packet"]["request"]
    assert [e["historical_role"] for e in request["sidecar"]["entries"]] == [
        "USER",
        "ASSISTANT",
        "USER",
    ]
    assert (
        "Correction: use three short paragraphs."
        in request["task"]["context"][-1]["untrusted_text"][m.preparation._HISTORY_SEGMENTS_MARKER][2]["text"]
    )
    measured = counter(installed).count_prompt_tokens(raw)
    assert 0 < measured + selected[2]["review"].max_output_tokens <= 16384
    assert len(raw) <= 64000
    assert (
        content_hash_of(m.preparation._review_packet_raw(json.loads(user)["packet"], json.loads(user)["packet_representation"]))
        == selected[2]["expected_packet_digest"]
    )
    # Numbers from actual synthetic renderer/tokenizer, not real model fit/parity.

    observation = {
        "representation": json.loads(user)["packet_representation"],
        "selected_messages": 3,
        "prepared_body_bytes": len(prepare(selected).body),
        "wire_bytes": len(raw),
        "synthetic_measured_input_tokens": measured,
        "declared_output_tokens": selected[2]["review"].max_output_tokens,
        "context_tokens": 16384,
        "actual_backend_parity_verified": False,
    }
    (tmp_path / "three-message-observation.json").write_text(
        json.dumps(observation, indent=2) + "\n"
    )
