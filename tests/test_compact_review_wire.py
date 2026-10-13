"""Invented lossless framing only; no SQL, runtime, processing or reviewer claim."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tests.test_complete_review_lossless import actual_counter as actual_counter  # noqa: PLC0414
from tests.test_complete_review_lossless import case as case  # noqa: PLC0414
from tests.test_complete_review_lossless import (
    synthetic_assets as synthetic_assets,  # noqa: PLC0414
)
from zacai.ingestion.artifact_store import canonical_bytes as cb
from zacai.ingestion.artifact_store import content_hash_of as sha
from zacai.intelligence import history_review_preparation as p
from zacai.intelligence import history_review_wire as w
from zacai.intelligence.history_review_prompt_counter import (
    LocalTokenCounterError,
    render_history_review_prompt,
)


def compact_case(case, counter=None):
    raw, kw = case
    profile = kw["review"]
    updates = {
        "route": profile.route.model_copy(
            update={
                "identity": profile.route.identity.model_copy(
                    update={"runtime_id": w.COMPACT_RUNTIME}
                ),
            }
        )
    }
    if counter is not None:
        updates.update(
            model_digest=counter.model_digest,
            tokenizer_digest=counter.tokenizer_digest,
            renderer_digest=counter.renderer_digest,
        )
    return raw, kw | {"review": profile.model_copy(update=updates)}


def serialize(case, representation=p.LOSSLESS_PACKET_REPRESENTATION):
    raw, kw = case
    prepared = p.prepare_history_review_request(raw, **kw, packet_representation=representation)
    wire = w.serialize_history_review_wire(
        prepared,
        packet_raw=raw,
        expected_request=kw["expected_request"],
        rubric_utf8=kw["rubric_utf8"],
        template_utf8=kw["template_utf8"],
    )
    return prepared, wire


def wrapper_wire(case):
    prepared, raw = serialize(compact_case(case))
    wire = json.loads(raw)
    wrapper = json.loads(wire["messages"][1]["content"])
    return prepared, wire, wrapper


@pytest.mark.parametrize(
    "name,representation",
    [
        ("default", p.LOSSLESS_PACKET_REPRESENTATION),
        ("legacy", p.LEGACY_PACKET_REPRESENTATION),
    ],
)
def test_exact_installed_old_body_and_wire_bytes(case, name, representation):
    baseline = json.loads(
        (Path(__file__).parent / "fixtures/compact_review_baseline_hashes.json").read_bytes()
    )[name]
    prepared, raw = serialize(case, representation)
    assert sha(prepared.body) == baseline["body_sha256"]
    assert sha(raw) == baseline["wire_sha256"]
    assert len(raw) == baseline["wire_bytes"] and len(prepared.body) == baseline["body_bytes"]
    assert json.loads(raw)["messages"][1]["content"] == prepared.body.decode()
    assert render_history_review_prompt(raw)


def test_exact_complete_body_and_packet_restore(case):
    prepared, wire, wrapper = wrapper_wire(case)
    restored = w.decode_history_review_wire_body(wrapper)
    assert cb(restored) == prepared.body
    assert p._review_packet_raw(restored["packet"], restored["packet_representation"]) == case[0]
    assert len(wrapper["evidence_reference_table"]) < len(w._reference_slots(restored))
    assert wire["format"] == p.HistoryReviewJudgments.model_json_schema()
    original_prepared, original_raw = serialize(case)
    original_wire = json.loads(original_raw)
    baseline = json.loads(
        (Path(__file__).parent / "fixtures/compact_review_baseline_hashes.json").read_bytes()
    )["default"]
    assert wire["options"] == original_wire["options"] == baseline["budgets"]["options"]
    assert (
        wire["options"]["num_predict"]
        == prepared.max_output_tokens
        == original_prepared.max_output_tokens
    )
    assert wire["options"]["num_ctx"] == prepared.purpose.context_window_tokens
    assert (
        restored["review_budgets"]["max_latency_ms"]
        == prepared.max_latency_ms
        == original_prepared.max_latency_ms
        == baseline["budgets"]["max_latency_ms"]
        == 60000
    )
    assert (
        prepared.purpose.expiry_rule
        == original_prepared.purpose.expiry_rule
        == baseline["budgets"]["expiry_rule"]
    )
    assert len(cb(wire)) < len(original_raw)
    assert not prepared.processing_authorized and not prepared.reviewer_authenticated
    assert render_history_review_prompt(cb(wire))


def test_real_synthetic_counter_restores_before_counting(case, actual_counter):
    prepared, raw = serialize(compact_case(case, actual_counter))
    count = actual_counter.count_prompt_tokens(raw)
    rendered = render_history_review_prompt(raw)
    assert count == len(actual_counter._tokenizer.encode(rendered, add_special_tokens=False).ids)
    assert 0 < count + prepared.max_output_tokens <= prepared.purpose.context_window_tokens


@pytest.mark.parametrize(
    "fault",
    [
        "bool",
        "negative",
        "out-of-range",
        "float",
        "string",
        "marker-extra",
        "marker-missing",
        "marker-name",
        "table-duplicate",
        "table-unused",
        "table-type",
        "table-extra-field",
        "table-bad-hash",
        "wrapper-extra",
        "wrapper-format",
        "slot-tamper",
        "outside-slot-marker",
    ],
)
def test_malformed_unknown_unused_duplicate_and_tampered_payloads_hold(case, fault):
    _, wire, wrapper = wrapper_wire(case)
    parent, key = w._reference_slots(wrapper["body"])[0]
    if fault in ("bool", "negative", "out-of-range", "float", "string"):
        parent[key] = {
            "evidence_reference_index": {
                "bool": True,
                "negative": -1,
                "out-of-range": len(wrapper["evidence_reference_table"]),
                "float": 0.0,
                "string": "0",
            }[fault]
        }
    elif fault == "marker-extra":
        parent[key]["unknown"] = 1
    elif fault == "marker-missing":
        parent[key] = {}
    elif fault == "marker-name":
        parent[key] = {"unknown_reference_index": 0}
    elif fault == "table-duplicate":
        wrapper["evidence_reference_table"].append(
            copy.deepcopy(wrapper["evidence_reference_table"][0])
        )
    elif fault == "table-unused":
        new = copy.deepcopy(wrapper["evidence_reference_table"][0])
        new["source_id"] = "00000000-0000-0000-0000-000000000999"
        wrapper["evidence_reference_table"].append(new)
    elif fault == "table-type":
        wrapper["evidence_reference_table"] = {}
    elif fault == "table-extra-field":
        wrapper["evidence_reference_table"][0]["extra"] = True
    elif fault == "table-bad-hash":
        wrapper["evidence_reference_table"][0]["content_hash"] = "bad"
    elif fault == "wrapper-extra":
        wrapper["extra"] = True
    elif fault == "wrapper-format":
        wrapper["format"] = "unknown-compact"
    elif fault == "slot-tamper":
        parent[key] = {
            "evidence_reference_index": (parent[key]["evidence_reference_index"] + 1)
            % len(wrapper["evidence_reference_table"])
        }
    else:
        wrapper["body"]["packet"]["review"]["overview"][0]["unknown"] = {
            "evidence_reference_index": 0
        }
    wire["messages"][1]["content"] = cb(wrapper).decode()
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(wire))


@pytest.mark.parametrize(
    "field,new", [("content_hash", "f" * 64), ("trust_boundary", "BRAINSTORM")]
)
def test_conflicting_same_immutable_source_references_refused(case, field, new):
    prepared, _, _ = wrapper_wire(case)
    body = json.loads(prepared.body)
    slots = w._reference_slots(body)
    original = slots[0][0][slots[0][1]]
    parent, key = next(
        (parent, key)
        for parent, key in slots[1:]
        if parent[key]["source_id"] == original["source_id"]
    )
    parent[key] = original | {field: new}
    # Direct compaction before a table exists isolates the immutable-ID conflict.
    with pytest.raises(ValueError, match="^conflicting immutable reference$"):
        w._compact_review_body(body)


def test_historical_current_classification_difference_is_retained(case):
    prepared, _, _ = wrapper_wire(case)
    body = json.loads(prepared.body)
    slots = w._reference_slots(body)
    original = slots[0][0][slots[0][1]]
    target = next(
        (parent, key)
        for parent, key in slots[1:]
        if parent[key]["source_id"] == original["source_id"]
    )
    target[0][target[1]] = original | {"effective_classification": "CONFIDENTIAL"}
    projected = w._compact_review_body(body)
    assert w.decode_history_review_wire_body(projected) == body
    classes = {
        ref["effective_classification"]
        for ref in projected["evidence_reference_table"]
        if ref["source_id"] == original["source_id"]
    }
    assert classes == {original["effective_classification"], "CONFIDENTIAL"}


def test_source_string_marker_is_literal_and_never_parsed(case):
    prepared, _, _ = wrapper_wire(case)
    body = json.loads(prepared.body)
    text = '{"evidence_reference_index":0,"format":"unknown"}'
    body["packet"]["request"]["task"]["context"][0]["untrusted_text"] = text
    assert w.decode_history_review_wire_body(w._compact_review_body(body)) == body


def test_runtime_opt_in_is_exact_and_compact_legacy_representation_refused(case):
    selected = compact_case(case)
    with pytest.raises(w.HistoryReviewWireError):
        serialize(selected, p.LEGACY_PACKET_REPRESENTATION)
    raw, kw = selected
    profile = kw["review"]
    unknown = profile.model_copy(
        update={
            "route": profile.route.model_copy(
                update={
                    "identity": profile.route.identity.model_copy(
                        update={"runtime_id": w.COMPACT_RUNTIME + "-unknown"}
                    ),
                }
            )
        }
    )
    with pytest.raises(w.HistoryReviewWireError):
        serialize((raw, kw | {"review": unknown}))
    _, legacy = serialize(case)
    payload = json.loads(legacy)
    data = json.loads(payload["messages"][1]["content"])
    data["route"]["identity"]["runtime_id"] = w.COMPACT_RUNTIME
    payload["messages"][1]["content"] = cb(data).decode()
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(payload))


def test_remapped_table_order_still_refused_as_noncanonical(case):
    _, wire, wrapper = wrapper_wire(case)
    wrapper["evidence_reference_table"][0], wrapper["evidence_reference_table"][1] = (
        wrapper["evidence_reference_table"][1],
        wrapper["evidence_reference_table"][0],
    )
    for parent, key in w._reference_slots(wrapper["body"]):
        i = parent[key]["evidence_reference_index"]
        if i in (0, 1):
            parent[key]["evidence_reference_index"] = 1 - i
    wire["messages"][1]["content"] = cb(wrapper).decode()
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(wire))


def test_duplicate_serialized_wrapper_key_refused(case):
    _, wire, _ = wrapper_wire(case)
    content = wire["messages"][1]["content"]
    wire["messages"][1]["content"] = content[:-1] + ',"format":"' + w.COMPACT_BODY_FORMAT + '"}'
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(wire))


@pytest.mark.parametrize(
    "runtime,representation",
    [
        (w.RUNTIME, p.LOSSLESS_PACKET_REPRESENTATION),
        (w.RUNTIME, p.LEGACY_PACKET_REPRESENTATION),
        (w.COMPACT_RUNTIME, p.LOSSLESS_PACKET_REPRESENTATION),
    ],
)
def test_old_installed_renderer_pin_holds_before_tokenization(
    case, actual_counter, monkeypatch, runtime, representation
):
    provenance = json.loads(
        (Path(__file__).parent / "fixtures/compact_review_baseline_provenance.json").read_bytes()
    )
    old_pin = provenance["installed_renderer_digest"]
    assert snapshot_renderer_digest(provenance) == old_pin
    assert actual_counter.renderer_digest != old_pin
    raw, kw = compact_case(case, actual_counter)
    profile = kw["review"]
    profile = profile.model_copy(
        update={
            "renderer_digest": old_pin,
            "route": profile.route.model_copy(
                update={
                    "identity": profile.route.identity.model_copy(update={"runtime_id": runtime})
                }
            ),
        }
    )
    _, serialized = serialize((raw, kw | {"review": profile}), representation)
    calls = []
    monkeypatch.setattr(actual_counter, "_render", lambda body: calls.append(body))
    with pytest.raises(LocalTokenCounterError):
        actual_counter.count_prompt_tokens(serialized)
    assert calls == []


def snapshot_renderer_digest(provenance):
    # Exact _implementation_digest order: base, local, preparation, wire, own
    # counter file. Rows use path.name and plain content SHA256, then canonical
    # encoding with the exact NUL-terminated renderer domain.
    base = Path(__file__).parent / "fixtures/.compact_review_installed_snapshot"
    expected = [
        "ollama_token_counter.py",
        "local_review_runtime.py",
        "history_review_preparation.py",
        "history_review_wire.py",
        "history_review_prompt_counter.py",
    ]
    paths = provenance["renderer_digest_source_order"]
    assert [Path(path).name for path in paths] == expected
    rows = [(Path(path).name, sha((base / path).read_bytes())) for path in paths]
    return hashlib.sha256(b"zac-history-review-renderer-v1\x00" + cb({"files": rows})).hexdigest()


def test_baseline_source_commit_snapshots_and_fixture_hashes_are_verifiable():
    provenance = json.loads(
        (Path(__file__).parent / "fixtures/compact_review_baseline_provenance.json").read_bytes()
    )
    assert provenance["source_commit"] == "7099d8ccb028564ad2066a8baff1ffc78b1e8b96"
    assert snapshot_renderer_digest(provenance) == provenance["installed_renderer_digest"]
    base = Path(__file__).parent / "fixtures/.compact_review_installed_snapshot"
    for path, pins in provenance["source_snapshots"].items():
        raw = (base / path).read_bytes()
        assert sha(raw) == pins["sha256"] == pins["commit_content_sha256"]
        assert provenance["git_object_format"] == "sha1"
        assert (
            hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()
            == pins["git_blob_oid"]
        )
    for name, digest in provenance["fixture_inputs"].items():
        assert (
            sha((Path(__file__).parent / "fixtures/complete_review_public" / name).read_bytes())
            == digest
        )
    # Deadline computation is not changed by either candidate module.
    stage = Path(__file__).parent.parent
    for path in (
        "src/zacai/intelligence/history_review_runtime.py",
        "src/zacai/intelligence/history_publication_review.py",
    ):
        assert sha((stage / path).read_bytes()) == provenance["source_snapshots"][path]["sha256"]


def test_decoder_is_only_inverse_full_reprepare_comparison_remains_required(case):
    _, wire, wrapper = wrapper_wire(case)
    wrapper["body"]["packet"]["review"]["overview"][0]["unknown"] = {"evidence_reference_index": 0}
    restored = w.decode_history_review_wire_body(wrapper)
    assert restored["packet"]["review"]["overview"][0]["unknown"] == {"evidence_reference_index": 0}
    wire["messages"][1]["content"] = cb(wrapper).decode()
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(wire))
    unknown = {"format": "unknown-review-body", "unexpected": True}
    assert w.decode_history_review_wire_body(unknown) is unknown
    wire["messages"][1]["content"] = cb(unknown).decode()
    with pytest.raises(LocalTokenCounterError):
        render_history_review_prompt(cb(wire))


def test_v3_required_typed_slots_full_reference_shape_and_grammar(case):
    from zacai.claude_large_original_message import ClaudeLargeOriginalMessageProfile
    from zacai.intelligence.contextual_evaluation import ContextualCriterion
    from zacai.intelligence.contracts import EvidenceReference
    from zacai.intelligence.history_context_metadata import ClaudeMessageMetadata

    fields = (
        "current_original_reference",
        "current_companion_reference",
        "original_binding_reference",
        "companion_binding_reference",
    )
    for model in (ClaudeLargeOriginalMessageProfile, ClaudeMessageMetadata):
        assert all(model.model_fields[field].is_required() for field in fields)
    assert all(field.is_required() for field in EvidenceReference.model_fields.values())
    prepared, wire, _ = wrapper_wire(case)
    body = json.loads(prepared.body)
    assert all(w._reference(parent[key]) == parent[key] for parent, key in w._reference_slots(body))
    request = body["packet"]["request"]
    expected = sum(
        len(request[name]["context"]) + len(request[name]["event"]["provenance"])
        for name in ("original_task", "task")
    ) + 4 * (len(request["sidecar"]["entries"]) + len(request["projection_profiles"]))
    assert len(w._reference_slots(body)) == expected
    # One-entry typed-array inverse works without nullable shortcuts. This sliced
    # structural view is not asserted to be a valid complete canonical packet.
    minimal = copy.deepcopy(body)
    minimal["packet"]["request"]["sidecar"]["entries"] = request["sidecar"]["entries"][:1]
    minimal["packet"]["request"]["projection_profiles"] = request["projection_profiles"][:1]
    assert w.decode_history_review_wire_body(w._compact_review_body(minimal)) == minimal
    schema = wire["format"]
    assert (
        schema["properties"]["assessments"]["minItems"]
        == schema["properties"]["assessments"]["maxItems"]
        == len(ContextualCriterion)
        == 10
    )
    assert set(schema["$defs"]["ContextualCriterion"]["enum"]) == {
        v.value for v in ContextualCriterion
    }
