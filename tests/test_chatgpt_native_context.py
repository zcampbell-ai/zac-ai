import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest

from tests.test_chatgpt_native_view import fixture_body, raw, run
from zacai.chatgpt_native_source import LoadedChatGPTNativeView
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.chatgpt_native_context import (
    ChatGPTNativeContextError,
    bind_chatgpt_native_citation,
    prepare_chatgpt_native_context,
)
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.contracts import (
    ContextItem,
    EvidenceReference,
    IntelligenceTask,
    ModelRoute,
    ZacEvent,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import render_contextual_prompt, render_review_prompt
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B


def inputs(literal="  A dated suggestion still needs confirmation. 🙂\n ", role="USER"):
    body = fixture_body()
    if role == "USER":
        body["turns"][0]["items"][0]["content"][0]["text"] = literal
        pointer = "/turns/0/items/0/content/0/text"
    else:
        body["turns"][0]["items"][1]["text"] = literal
        pointer = "/turns/0/items/1/text"
    wire = raw(body)
    c = run(wire, start=0, end=len(literal), selected_pointer=pointer)
    companion = EvidenceReference(
        source_id=UUID(int=2),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
        content_hash=content_hash_of(canonical_bytes(c.model_dump(mode="json"))),
    )
    at = datetime(2026, 10, 11, tzinfo=UTC)
    loaded = LoadedChatGPTNativeView(
        UUID(int=3), c.original_reference, companion, c, literal, (at, at)
    )
    ref = EvidenceReference(
        source_id=UUID(int=10),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
        content_hash="a" * 64,
    )
    event = ZacEvent(
        event_id=UUID(int=11),
        event_type="invented.owner.task",
        producer="invented.fixture",
        occurred_at=at,
        observed_at=at,
        trust_boundary=B.PERSONAL,
        data_classification=C.HIGHLY_RESTRICTED,
        provenance=(ref,),
        correlation_id=UUID(int=12),
        importance="FYI",
        confidence=1.0,
    )
    task = IntelligenceTask(
        task_id=UUID(int=13),
        event=event,
        context=(
            ContextItem(
                reference=ref,
                untrusted_text="A current work item needs a dated source-backed follow-up.",
            ),
        ),
        instruction="Prepare one concise follow-up; ask one scope question if context is insufficient.",
        required_capabilities=frozenset({"contextual_meeting_review"}),
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
        max_output_tokens=512,
    )
    original = ReviewContext(task, ref.source_id, frozenset())
    route = ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "qwen3.8:27b-mlx",
            "runtime_id": "mac-loopback-contextual-16k",
        },
        destination=Destination.LOCAL,
        capabilities=frozenset({"contextual_meeting_review"}),
        max_input_characters=100000,
        max_output_tokens=1600,
        estimated_latency_ms=100.0,
        estimated_cost_usd=0.0,
        available=True,
    )
    return original, loaded, route


def prepare(literal="  A dated suggestion still needs confirmation. 🙂\n ", role="USER"):
    original, loaded, route = inputs(literal, role)
    return prepare_chatgpt_native_context(original, loaded, capture_id=UUID(int=3), route=route)


@pytest.mark.parametrize("role", ["USER", "ASSISTANT"])
def test_actual_contextual_renderer_preserves_full_literal_warning_and_owner_task(role):
    literal = " \n" + ("Dated draft suggestion needs confirmation. " * 12 + "\n") * 25 + " \n"
    p = prepare(literal, role)
    assert len(literal) > 8000
    render = render_contextual_prompt(p.body)
    user_turn = render.split("<|im_start|>user\n", 1)[1].split("<|im_end|>", 1)[0]
    data = json.loads(user_turn)
    assert data["selected_returned_field"]["literal"] == literal
    assert data["selected_returned_field"]["sha256"] == content_hash_of(literal.encode())
    assert "ASSISTANT history is dated draft/suggestion context, never owner views" in render
    assert data["original_owner_task_id"] == str(p.profile.original_task.task_id)
    assert data["original_owner_task_instruction"] == p.profile.original_task.instruction
    assert p.context.task.instruction == p.profile.original_task.instruction
    assert p.context.task.event.correlation_id == p.profile.original_task.event.correlation_id
    assert p.context.task.event.occurred_at == p.profile.original_task.event.occurred_at
    assert p.profile.companion.selected_field.reported_role == role
    assert not p.processing_authorized and not p.profile.source_authenticity_verified
    assert p.body_digest == content_hash_of(p.body)
    # Correct concrete contextual schema renderer; compact renderer must reject.
    with pytest.raises(ValueError):
        render_review_prompt(p.body)
    with pytest.raises(ValueError):
        prepare_contextual_request(p.context)  # default legacy route rejects derived native marker


def test_native_citation_maps_exact_pointer_role_and_nonwire_offsets():
    p = prepare()
    eid = next(
        e
        for e, q in p._catalog.quotes
        if q.source_id == p.profile.current_original_reference.source_id
    )
    citation = bind_chatgpt_native_citation(p, eid)
    assert citation.reported_role == "USER"
    assert citation.native_pointer == "/turns/0/items/0/content/0/text"
    assert (
        p.selected_text[citation.decoded_field_start : citation.decoded_field_end]
        == citation.quote.text
    )
    assert citation.decoded_utf8_start == len(
        p.selected_text[: citation.decoded_field_start].encode()
    )
    assert citation.decoded_utf8_end == len(p.selected_text[: citation.decoded_field_end].encode())
    assert citation.original_reference == p.profile.current_original_reference
    assert citation.companion_reference == p.profile.current_companion_reference
    assert not citation.processing_authorized
    other = next(
        e
        for e, q in p._catalog.quotes
        if q.source_id != p.profile.current_original_reference.source_id
    )
    with pytest.raises(ChatGPTNativeContextError):
        bind_chatgpt_native_citation(p, other)


def test_original_task_words_are_in_projection_identity_without_redefining_task():
    original, loaded, route = inputs()
    first = prepare_chatgpt_native_context(original, loaded, capture_id=UUID(int=3), route=route)
    changed = ReviewContext(
        original.task.model_copy(update={"instruction": "Different exact owner work."}),
        original.meeting_source_id,
        original.related_source_ids,
    )
    second = prepare_chatgpt_native_context(changed, loaded, capture_id=UUID(int=3), route=route)
    assert first.profile.original_task.task_id == second.profile.original_task.task_id
    assert first.context.task.task_id != second.context.task.task_id
    assert second.context.task.instruction == changed.task.instruction


def test_new_selection_event_is_caused_by_original_not_already_processed():
    original, loaded, route = inputs()
    data = original.task.model_dump(mode="json")
    data["event"]["processing_status"] = "PROCESSED"
    data["event"]["causation_id"] = str(UUID(int=99))
    original = ReviewContext(
        IntelligenceTask.model_validate(data),
        original.meeting_source_id,
        original.related_source_ids,
    )
    p = prepare_chatgpt_native_context(original, loaded, capture_id=UUID(int=3), route=route)
    assert p.context.task.event.processing_status.value == "NEW"
    assert p.context.task.event.causation_id == original.task.event.event_id
    assert p.profile.original_task.event.processing_status.value == "PROCESSED"
    assert p.profile.original_task.event.causation_id == UUID(int=99)


def test_real_contextual_counter_counts_this_exact_rendered_body(tmp_path):
    import hashlib

    from tokenizers import Tokenizer, models, pre_tokenizers

    from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

    # Existing counter's synthetic installation convention. No real model assets.
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    tokenizer = Tokenizer(models.WordLevel({"[UNK]": 0, "system": 1, "user": 2}, unk_token="[UNK]"))
    tokenizer.pre_tokenizer = pre_tokenizers.Whitespace()
    tokenizer.enable_truncation(2)
    tokenizer.enable_padding(length=9000, pad_id=0, pad_token="[UNK]")

    def blob(value, name=None):
        digest = hashlib.sha256(value).hexdigest()
        (blobs / f"sha256-{digest}").write_bytes(value)
        record = {"digest": f"sha256:{digest}", "size": len(value)}
        if name:
            record["name"] = name
        return record

    manifest = {
        "schemaVersion": 2,
        "config": blob(b'{"renderer":"qwen3.8"}'),
        "layers": [
            blob(tokenizer.to_str().encode(), "tokenizer.json"),
            blob(b'{"add_bos_token":false}', "tokenizer_config.json"),
        ],
    }
    path = tmp_path / "manifests/registry.ollama.ai/library/qwen3.8/27b-mlx"
    path.parent.mkdir(parents=True)
    raw_manifest = json.dumps(manifest).encode()
    path.write_bytes(raw_manifest)
    counter = OllamaQwenContextualTokenCounter(
        models_root=tmp_path, model_digest=hashlib.sha256(raw_manifest).hexdigest()
    )
    literal = " \n" + ("Dated draft suggestion needs confirmation. " * 12 + "\n") * 25 + " \n"
    p = prepare(literal)
    rendered = render_contextual_prompt(p.body)
    assert counter._render(p.body) == rendered
    tokenizer.no_truncation()
    tokenizer.no_padding()
    expected = len(tokenizer.encode(rendered, add_special_tokens=False).ids)
    assert 2 < expected < 9000
    assert counter.count_prompt_tokens(p.body) == expected
    user = json.loads(rendered.split("<|im_start|>user\n", 1)[1].split("<|im_end|>", 1)[0])
    assert user["selected_returned_field"]["literal"] == literal


@pytest.mark.parametrize("mutation", ["literal", "profile", "body", "context", "catalog"])
def test_changed_prepared_graph_cannot_resolve_native_citation(mutation):
    p = prepare()
    eid = next(
        e
        for e, q in p._catalog.quotes
        if q.source_id == p.profile.current_original_reference.source_id
    )
    if mutation == "literal":
        p = replace(p, selected_text=p.selected_text + "changed")
    elif mutation == "profile":
        p = replace(p, profile=p.profile.model_copy(update={"derived_task_id": UUID(int=44)}))
    elif mutation == "body":
        wire = json.loads(p.body)
        wire["messages"][0]["content"] = "No provenance warning"
        body = canonical_bytes(wire)
        p = replace(p, body=body, body_digest=content_hash_of(body))
    elif mutation == "context":
        task = p.context.task.model_copy(update={"instruction": "Changed work"})
        p = replace(
            p,
            context=ReviewContext(task, p.context.meeting_source_id, p.context.related_source_ids),
        )
    else:
        p = replace(p, _catalog=replace(p._catalog, quotes=()))
    with pytest.raises(ChatGPTNativeContextError) as caught:
        bind_chatgpt_native_citation(p, eid)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize(
    "mutation",
    ["literal", "hash", "scope", "wording-class", "cloud", "routecap", "framecap", "linecap"],
)
def test_unfit_or_mismatched_input_holds_without_clipping(mutation):
    original, loaded, route = inputs()
    if mutation == "literal":
        loaded = replace(loaded, selected_text=loaded.selected_text + "altered")
    elif mutation == "hash":
        loaded = replace(
            loaded,
            companion_reference=loaded.companion_reference.model_copy(
                update={"content_hash": "f" * 64}
            ),
        )
    elif mutation == "scope":
        loaded = replace(
            loaded,
            original_reference=loaded.original_reference.model_copy(
                update={"trust_boundary": B.BRAINSTORM}
            ),
        )
    elif mutation == "wording-class":
        data = original.task.model_dump(mode="json")
        data["event"]["data_classification"] = C.CONFIDENTIAL.value
        data["event"]["provenance"][0]["effective_classification"] = C.CONFIDENTIAL.value
        data["context"][0]["reference"]["effective_classification"] = C.CONFIDENTIAL.value
        original = ReviewContext(
            IntelligenceTask.model_validate(data),
            original.meeting_source_id,
            original.related_source_ids,
        )
    elif mutation == "cloud":
        route = route.model_copy(update={"destination": Destination.EXTERNAL})
    elif mutation == "routecap":
        route = route.model_copy(update={"max_input_characters": 1000})
    elif mutation == "framecap":
        original, loaded, route = inputs("x" * 100000)
    else:
        original, loaded, route = inputs("x" * 1501)
    with pytest.raises(ChatGPTNativeContextError):
        prepare_chatgpt_native_context(original, loaded, capture_id=UUID(int=3), route=route)


def test_capture_identity_cannot_change_between_loader_result_and_preparation():
    original, loaded, route = inputs()
    assert loaded.capture_id == UUID(int=3)
    with pytest.raises(ChatGPTNativeContextError):
        prepare_chatgpt_native_context(original, loaded, capture_id=UUID(int=4), route=route)


def test_assistant_citation_and_adjacent_literal_metadata():
    p = prepare(role="ASSISTANT")
    field = json.loads(json.loads(p.body)["messages"][1]["content"])["selected_returned_field"]
    assert field["reported_role"] == "ASSISTANT"
    assert field["native_pointer"] == "/turns/0/items/1/text"
    assert field["literal"] == p.selected_text
    assert (
        field["reported_turn_started_at"]
        == p.profile.companion.selected_field.reported_turn_started_at
    )
    eid = next(
        e
        for e, q in p._catalog.quotes
        if q.source_id == p.profile.current_original_reference.source_id
    )
    c = bind_chatgpt_native_citation(p, eid)
    assert c.reported_role == "ASSISTANT" and c.native_pointer == field["native_pointer"]
    assert c.quote.text == p.selected_text[c.decoded_field_start : c.decoded_field_end]
    metadata = json.loads(json.loads(p.body)["messages"][1]["content"])["chatgpt_native_metadata"]
    assert "original_task" not in metadata
    assert metadata["original_task_id"] == str(p.profile.original_task.task_id)
    assert metadata["original_task_digest"] == content_hash_of(
        canonical_bytes(p.profile.original_task.model_dump(mode="json"))
    )


@pytest.mark.parametrize("place", ["context", "meeting", "related"])
def test_native_source_collisions_across_complete_original_context_hold(place):
    original, loaded, route = inputs()
    native = loaded.original_reference
    task = IntelligenceTask.model_validate(
        {
            **original.task.model_dump(),
            "event": {
                **original.task.event.model_dump(),
                "provenance": (*original.task.event.provenance, native),
            },
            "context": (
                *original.task.context,
                ContextItem(reference=native, untrusted_text="Dated invented contextual evidence."),
            ),
        }
    )
    original = ReviewContext(
        task,
        native.source_id if place == "meeting" else original.meeting_source_id,
        frozenset({native.source_id}) if place == "related" else original.related_source_ids,
    )
    with pytest.raises(ChatGPTNativeContextError):
        prepare_chatgpt_native_context(original, loaded, capture_id=UUID(int=3), route=route)
