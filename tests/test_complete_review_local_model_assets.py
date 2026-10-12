"""Explicit opt-in LOCAL offline Mac asset evidence, never CI/model inference.

CAZ_RUN_LOCAL_MODEL_ASSET_TESTS=1 and CAZ_LOCAL_MODELS_ROOT are required.
Existing root actual-count proof remains separate from synthetic core tests.
"""

import os
from pathlib import Path

import pytest

from tests.test_complete_review_lossless import case as case  # noqa: PLC0414
from tests.test_complete_review_lossless import prepared, real_case, wire
from zacai.ingestion.artifact_store import content_hash_of as sha
from zacai.intelligence import history_review_preparation as p
from zacai.intelligence.history_review_prompt_counter import (
    LocalTokenCounterError,
    OllamaQwenHistoryReviewTokenCounter,
    render_history_review_prompt,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("CAZ_RUN_LOCAL_MODEL_ASSET_TESTS") != "1",
    reason="explicit local offline asset integration only",
)


@pytest.fixture
def local_counter():
    root = os.environ.get("CAZ_LOCAL_MODELS_ROOT")
    if not root:
        pytest.skip("explicit CAZ_LOCAL_MODELS_ROOT required; no home discovery")
    return OllamaQwenHistoryReviewTokenCounter(
        models_root=Path(root),
        model_digest="5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e",
    )


def test_local_original_full_target_fit_and_legacy_overcap(case, local_counter):
    selected = real_case(case, local_counter)
    value = prepared(selected)
    count = local_counter.count_prompt_tokens(wire(selected, value))
    assert count + 512 <= 16384
    raw, kw = selected
    old = p.prepare_history_review_request(
        raw, **kw, packet_representation=p.LEGACY_PACKET_REPRESENTATION
    )
    with pytest.raises(LocalTokenCounterError):
        local_counter.count_prompt_tokens(wire(selected, old))


def test_local_registered_control_literal_refusal(case, local_counter):
    raw, kw = real_case(case, local_counter)
    template = kw["template_utf8"] + b" <|im_start|>"
    changed = (
        raw,
        kw
        | {
            "template_utf8": template,
            "review": kw["review"].model_copy(update={"template_digest": sha(template)}),
        },
    )
    body = wire(changed)
    assert "<|im_start|>" in render_history_review_prompt(body)
    with pytest.raises(LocalTokenCounterError):
        local_counter.count_prompt_tokens(body)


def test_local_copied_source_drift_before_tokenization(case, local_counter, monkeypatch, tmp_path):
    body = wire(real_case(case, local_counter))
    copied = tmp_path / "changed_preparation.py"
    copied.write_bytes(Path(p.__file__).read_bytes() + b"\n# copied local source drift\n")
    monkeypatch.setattr(p, "__file__", str(copied))
    calls = []
    monkeypatch.setattr(local_counter, "_render", lambda body: calls.append(body))
    with pytest.raises(LocalTokenCounterError):
        local_counter.count_prompt_tokens(body)
    assert calls == []
