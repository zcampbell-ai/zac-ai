"""Invented full packet; real offline tokenizer only, no authority/SQL/dispatch."""

import copy
import json
from pathlib import Path

import pytest

from zacai.ingestion.artifact_store import canonical_bytes as cb
from zacai.ingestion.artifact_store import content_hash_of as sha
from zacai.intelligence import history_review_preparation as p
from zacai.intelligence import history_review_wire as w
from zacai.intelligence.history_contextual_codec import decode_history_contextual_packet
from zacai.intelligence.history_generation_review_declaration import HistoryReviewPurposeProfileV1
from zacai.intelligence.history_review_prompt_counter import (
    LocalTokenCounterError,
    render_history_review_prompt,
)

BASE = Path(__file__).parent / "fixtures/complete_review_public"


@pytest.fixture
def case():
    raw = (BASE / "supported-packet.json").read_bytes()
    packet = decode_history_contextual_packet(raw)
    profile = json.loads((BASE / "review-profile.json").read_bytes())
    kwargs = {
        "expected_packet_digest": sha(raw),
        "expected_task_id": packet.request().task.task_id,
        "expected_builder_id": packet.builder_id,
        "expected_request": packet.request(),
        "review": HistoryReviewPurposeProfileV1.model_validate(profile),
        "rubric_utf8": (BASE / "rubric.txt").read_bytes(),
        "template_utf8": (BASE / "template.txt").read_bytes(),
    }
    return raw, kwargs


def prepared(case):
    raw, kwargs = case
    return p.prepare_history_review_request(raw, **kwargs)


def wire(case, value=None):
    raw, kw = case
    return w.serialize_history_review_wire(
        value or prepared(case),
        packet_raw=raw,
        expected_request=kw["expected_request"],
        rubric_utf8=kw["rubric_utf8"],
        template_utf8=kw["template_utf8"],
    )


def test_full_original_packet_bytes_and_correction_preserved(case):
    raw, kw = case
    value = prepared(case)
    data = json.loads(value.body)
    assert data["packet_representation"] == p.LOSSLESS_PACKET_REPRESENTATION
    assert p._review_packet_raw(data["packet"], data["packet_representation"]) == raw
    q = kw["expected_request"]
    assert [e.historical_role for e in q.sidecar.entries] == ["USER", "ASSISTANT", "USER"]
    assert len({e.reported_created_at for e in q.sidecar.entries}) == 3
    transmitted = data["packet"]["request"]
    assert "prompt_body" not in transmitted
    segments = transmitted["task"]["context"][-1]["untrusted_text"][p._HISTORY_SEGMENTS_MARKER]
    assert [seg["historical_role"] for seg in segments] == ["USER", "ASSISTANT", "USER"]
    assert [seg["reported_created_at"] for seg in segments] == [
        e["reported_created_at"] for e in transmitted["sidecar"]["entries"]
    ]
    assert "Correction: Maya is the requester" in segments[2]["text"]
    assert "long essay" in segments[1]["text"]
    from zacai.intelligence.history_context_metadata import _WARNING

    assert _WARNING in json.loads(wire(case))["messages"][0]["content"]
    assert value.max_latency_ms == 60000 and value.max_output_tokens == 512
    assert value.processing_authorized is value.reviewer_authenticated is False


def test_legacy_complete_preparation_and_wire_exact(case):
    raw, kw = case
    value = p.prepare_history_review_request(
        raw, **kw, packet_representation=p.LEGACY_PACKET_REPRESENTATION
    )
    assert (
        sha(value.body)
        == json.loads((BASE / "legacy-pins.json").read_bytes())["supported-prepared-body.json"]
    )
    assert (
        sha(wire(case, value))
        == json.loads((BASE / "legacy-pins.json").read_bytes())["supported-wire.json"]
    )
    assert render_history_review_prompt(wire(case, value))


@pytest.mark.parametrize(
    "fault", ["unknown", "conflict", "digest", "correction", "marker", "duplicate_marker"]
)
def test_changed_representation_cannot_render(case, fault):
    body = json.loads(wire(case))
    data = json.loads(body["messages"][1]["content"])
    request = data["packet"]["request"]
    if fault == "unknown":
        request["extra"] = "unrecognized"
    elif fault == "conflict":
        request["prompt_body"] = "conflicting"
    elif fault == "digest":
        request[p._PROMPT_MARKER]["sha256"] = "0" * 64
    elif fault == "correction":
        request["sidecar"]["entries"].pop()
    elif fault == "marker":
        data["packet_representation"] = "unknown-v3"
    else:
        request[p._PROMPT_MARKER][p._JSON_STRING_MARKER] = {}
    body["messages"][1]["content"] = cb(data).decode()
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(body))


def test_unicode_typed_profile_strings_leave_source_json_literal():
    literal = cb({"role": "USER", "text": 'Correction: Cedar 😀 café; "quoted".'}).decode()
    value = {
        "request": {
            "projection_profiles": [literal],
            "task": {"instruction": literal, "context": [{"untrusted_text": literal}]},
        },
        "review": {"text": literal},
    }
    result = p._parse_canonical_strings(value)
    assert p._restore_canonical_strings(result) == value
    assert (
        result["request"]["projection_profiles"][0][p._JSON_STRING_MARKER]["text"]
        == 'Correction: Cedar 😀 café; "quoted".'
    )
    assert result["request"]["task"] == value["request"]["task"]
    assert result["review"] == value["review"]


def test_conflicting_canonical_string_marker_refused():
    value = {"request": {"projection_profiles": [{p._JSON_STRING_MARKER: {}, "other": 1}]}}
    with pytest.raises(ValueError, match="closed canonical profile marker"):
        p._restore_canonical_strings(value)


def test_duplicate_wire_json_refused(case):
    raw = wire(case).replace(b'"stream":false', b'"stream":false,"stream":false')
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(raw)


def test_ten_judgment_parser_unchanged():
    from zacai.intelligence.contextual_evaluation import ContextualCriterion

    value = {
        "format": "zac-history-complete-review-judgments-v1",
        "assessments": [
            {"criterion": c.value, "judgment": "UNREVIEWED"} for c in ContextualCriterion
        ],
    }
    assert len(p.parse_history_review_judgments(cb(value)).assessments) == 10
    with pytest.raises(p.HistoryReviewPreparationError):
        p.parse_history_review_judgments(cb(value | {"owner_approved": True}))


@pytest.fixture
def synthetic_assets(tmp_path):
    from tokenizers import AddedToken

    from tests.complete_review_test_support import repin_synthetic_tokenizer
    from tests.test_ollama_token_counter import installed as original_installed

    assets = original_installed.__wrapped__(tmp_path)
    assets[3].add_special_tokens([AddedToken("<|im_start|>", special=True)])
    return repin_synthetic_tokenizer(assets, assets[3])


@pytest.fixture
def actual_counter(synthetic_assets):
    from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter

    return OllamaQwenHistoryReviewTokenCounter(
        models_root=synthetic_assets[0], model_digest=synthetic_assets[2]
    )


def real_case(case, actual_counter):
    raw, kw = case
    profile = kw["review"].model_copy(
        update={
            "model_digest": actual_counter.model_digest,
            "renderer_digest": actual_counter.renderer_digest,
            "tokenizer_digest": actual_counter.tokenizer_digest,
        }
    )
    return raw, kw | {"review": profile}


def test_synthetic_full_target_count_uses_exact_schema_no_clipping(case, actual_counter):
    selected = real_case(case, actual_counter)
    value = prepared(selected)
    raw = wire(selected, value)
    count = actual_counter.count_prompt_tokens(raw)
    measured = len(
        actual_counter._tokenizer.encode(
            render_history_review_prompt(raw), add_special_tokens=False
        ).ids
    )
    assert count == measured and 0 < count + 512 <= 16384
    assert (
        p._review_packet_raw(json.loads(value.body)["packet"], p.LOSSLESS_PACKET_REPRESENTATION)
        == case[0]
    )


def test_real_source_file_drift_holds_before_tokenization(
    case, actual_counter, monkeypatch, tmp_path
):
    selected = real_case(case, actual_counter)
    raw = wire(selected)
    copied = tmp_path / "changed_preparation.py"
    copied.write_bytes(Path(p.__file__).read_bytes() + b"\n# actual copied-file byte drift\n")
    monkeypatch.setattr(p, "__file__", str(copied))
    calls = []
    monkeypatch.setattr(actual_counter, "_render", lambda body: calls.append(body))
    with pytest.raises(LocalTokenCounterError):
        actual_counter.count_prompt_tokens(raw)
    assert calls == []


def test_actual_special_control_stays_literal_and_holds(case, actual_counter):
    raw, kw = real_case(case, actual_counter)
    template = kw["template_utf8"] + b" <|im_start|>"
    altered = (
        raw,
        kw
        | {
            "template_utf8": template,
            "review": kw["review"].model_copy(update={"template_digest": sha(template)}),
        },
    )
    wire_raw = wire(altered)
    assert "<|im_start|>" in render_history_review_prompt(wire_raw)
    with pytest.raises(LocalTokenCounterError):
        actual_counter.count_prompt_tokens(wire_raw)


def test_whole_unicode_packet_roundtrip_and_correction(case):
    from zacai.intelligence.history_contextual_codec import encode_history_contextual_packet

    raw, kw = case
    packet = decode_history_contextual_packet(raw)
    claim = packet.review.overview[0].model_copy(
        update={"text": packet.review.overview[0].text + ' Café 😀 "quoted".'}
    )
    review = packet.review.model_copy(update={"overview": (claim,)})
    revised = encode_history_contextual_packet(
        review, packet.request(), builder_id=packet.builder_id, created_at=packet.created_at
    )
    value = p.prepare_history_review_request(
        revised, **(kw | {"expected_packet_digest": sha(revised)})
    )
    data = json.loads(value.body)
    assert p._review_packet_raw(data["packet"], data["packet_representation"]) == revised
    assert "Café 😀" in data["packet"]["review"]["overview"][0]["text"]
    request_view = data["packet"]["request"]
    assert "prompt_body" not in request_view
    segments = request_view["task"]["context"][-1]["untrusted_text"][p._HISTORY_SEGMENTS_MARKER]
    assert "Correction: Maya is the requester" in segments[2]["text"]
    assert [seg["historical_role"] for seg in segments] == ["USER", "ASSISTANT", "USER"]


@pytest.mark.parametrize("fault", ["raw_string", "extra_key", "changed_profile_field"])
def test_actual_profile_marker_fault_in_full_wire(case, fault):
    body = json.loads(wire(case))
    data = json.loads(body["messages"][1]["content"])
    profiles = data["packet"]["request"]["projection_profiles"]
    if fault == "raw_string":
        profiles[0] = cb(profiles[0][p._JSON_STRING_MARKER]).decode()
    elif fault == "extra_key":
        profiles[0]["extra"] = 1
    else:
        profiles[0][p._JSON_STRING_MARKER]["character_start"] = 999
    if fault != "changed_profile_field":
        with pytest.raises(ValueError, match="closed canonical profile marker"):
            p._restore_canonical_strings(data["packet"])
    body["messages"][1]["content"] = cb(data).decode()
    with pytest.raises(LocalTokenCounterError, match="unsupported history review local prompt"):
        render_history_review_prompt(cb(body))


@pytest.mark.parametrize("fault", ["role", "date", "extra", "text", "reorder"])
def test_exact_visible_segment_binding_fault_holds(case, fault):
    body = json.loads(wire(case))
    data = json.loads(body["messages"][1]["content"])
    segments = data["packet"]["request"]["task"]["context"][-1]["untrusted_text"][
        p._HISTORY_SEGMENTS_MARKER
    ]
    if fault == "role":
        segments[1]["historical_role"] = "USER"
    elif fault == "date":
        segments[2]["reported_created_at"] = segments[0]["reported_created_at"]
    elif fault == "extra":
        segments[0]["extra"] = 1
    elif fault == "text":
        segments[2]["text"] = "No correction."
    else:
        segments.reverse()
    if fault in ("role", "date"):
        with pytest.raises(ValueError, match="visible history role/date/identity differs"):
            p._review_packet_raw(data["packet"], p.LOSSLESS_PACKET_REPRESENTATION)
    body["messages"][1]["content"] = cb(data).decode()
    with pytest.raises(LocalTokenCounterError, match="unsupported history review local prompt"):
        render_history_review_prompt(cb(body))


def test_literal_multiline_segment_restore_is_exact_and_role_bound():
    texts = [
        "First USER line\nsecond 😀 line",
        'ASSISTANT {"suggestion":"not a preference"}',
        "Later USER correction\nfinal line",
    ]
    offset = 0
    entries = []
    for i, text in enumerate(texts):
        entries.append(
            {
                "message_id": str(i + 1),
                "historical_role": ["USER", "ASSISTANT", "USER"][i],
                "reported_created_at": f"2026-10-0{i + 1}",
                "reported_updated_at": f"2026-10-0{i + 1}",
                "context_character_start": offset,
                "context_character_end": offset + len(text),
            }
        )
        offset += len(text) + 1
    original = {
        "request": {
            "sidecar": {"entries": entries},
            "task": {"context": [{"untrusted_text": "\n".join(texts)}]},
        }
    }
    view = copy.deepcopy(original)
    p._segment_history_tail(view)
    segments = view["request"]["task"]["context"][-1]["untrusted_text"][p._HISTORY_SEGMENTS_MARKER]
    assert [s["text"] for s in segments] == texts
    p._restore_history_tail(view)
    assert view == original


def test_v2_representation_remains_exactly_reconstructable(case):
    from zacai.intelligence import history_review_preparation as prep
    from zacai.intelligence.history_review_wire import serialize_history_review_wire

    raw, kw = case
    value = prep.prepare_history_review_request(
        raw, **kw, packet_representation=prep.PREVIOUS_LOSSLESS_PACKET_REPRESENTATION
    )
    data = json.loads(value.body)
    assert prep._review_packet_raw(data["packet"], data["packet_representation"]) == raw
    assert isinstance(data["packet"]["request"]["task"]["context"][-1]["untrusted_text"], str)
    with pytest.raises(
        w.HistoryReviewWireError, match="history review wire unavailable or mismatched"
    ):
        serialize_history_review_wire(
            value,
            packet_raw=raw,
            expected_request=kw["expected_request"],
            rubric_utf8=kw["rubric_utf8"],
            template_utf8=kw["template_utf8"],
        )
    p.verify_history_review_request(
        value,
        packet_raw=raw,
        expected_request=kw["expected_request"],
        rubric_utf8=kw["rubric_utf8"],
        template_utf8=kw["template_utf8"],
    )


def test_same_join_wrong_multiline_split_is_not_canonical_view():
    texts = ["USER first\nUSER second", "ASSISTANT suggestion", "USER correction"]
    offset = 0
    entries = []
    for i, text in enumerate(texts):
        entries.append(
            {
                "message_id": str(i + 1),
                "historical_role": ["USER", "ASSISTANT", "USER"][i],
                "reported_created_at": f"2026-10-0{i + 1}",
                "reported_updated_at": f"2026-10-0{i + 1}",
                "context_character_start": offset,
                "context_character_end": offset + len(text),
            }
        )
        offset += len(text) + 1
    canonical = {
        "request": {
            "sidecar": {"entries": entries},
            "task": {"context": [{"untrusted_text": "\n".join(texts)}]},
        }
    }
    p._segment_history_tail(canonical)
    altered = copy.deepcopy(canonical)
    segments = altered["request"]["task"]["context"][-1]["untrusted_text"][
        p._HISTORY_SEGMENTS_MARKER
    ]
    segments[0]["text"] = "USER first"
    segments[1]["text"] = "USER second\nASSISTANT suggestion"
    reconstructed = copy.deepcopy(altered)
    p._restore_history_tail(reconstructed)
    assert reconstructed["request"]["task"]["context"][-1]["untrusted_text"] == "\n".join(texts)
    p._segment_history_tail(reconstructed)
    assert reconstructed == canonical and reconstructed != altered
    # This exact canonical-forward equality is mandatory in _review_packet_raw.


def test_v2_exact_historical_wire_is_refused_by_renderer_and_counter(case, actual_counter):
    selected = real_case(case, actual_counter)
    raw, kw = selected
    prepared_v2 = p.prepare_history_review_request(
        raw, **kw, packet_representation=p.PREVIOUS_LOSSLESS_PACKET_REPRESENTATION
    )
    # Build the formerly permitted wire without calling its now-refusing serializer.
    old_wire = json.loads(wire(selected))
    old_wire["messages"][1]["content"] = prepared_v2.body.decode()
    from zacai.intelligence.history_context_metadata import _WARNING

    old_wire["messages"][0]["content"] = old_wire["messages"][0]["content"].replace(_WARNING, "", 1)
    historical = cb(old_wire)
    assert (
        p._review_packet_raw(
            json.loads(prepared_v2.body)["packet"], p.PREVIOUS_LOSSLESS_PACKET_REPRESENTATION
        )
        == raw
    )
    with pytest.raises(LocalTokenCounterError, match="unsupported history review local prompt"):
        render_history_review_prompt(historical)
    with pytest.raises(LocalTokenCounterError):
        actual_counter.count_prompt_tokens(historical)


def test_synthetic_full_packet_overcap_holds_without_clipping(case, synthetic_assets):
    from tokenizers import Regex
    from tokenizers.pre_tokenizers import Split

    from tests.complete_review_test_support import repin_synthetic_tokenizer
    from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter

    tokenizer = synthetic_assets[3]
    tokenizer.pre_tokenizer = Split(Regex("."), behavior="isolated")
    assets = repin_synthetic_tokenizer(synthetic_assets, tokenizer)
    counter = OllamaQwenHistoryReviewTokenCounter(models_root=assets[0], model_digest=assets[2])
    selected = real_case(case, counter)
    body = wire(selected)
    measured = len(
        counter._tokenizer.encode(render_history_review_prompt(body), add_special_tokens=False).ids
    )
    assert measured + 512 > 16384
    with pytest.raises(LocalTokenCounterError):
        counter.count_prompt_tokens(body)
    assert (
        p._review_packet_raw(
            json.loads(prepared(selected).body)["packet"], p.LOSSLESS_PACKET_REPRESENTATION
        )
        == case[0]
    )
