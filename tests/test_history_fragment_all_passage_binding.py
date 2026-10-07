"""Invented exact provider catalog; metadata IDs grant no citation/processing."""

import json

import pytest

from tests.test_history_fragment_family_catalog import make
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog
from zacai.intelligence.history_contextual_codec import HistoryContextualCodecError
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_request,
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_generation import prepare_review_request


@pytest.mark.parametrize("text", ["x", "Invented citable passage\nx"])
def test_every_fragment_provider_id_has_historical_caveat_binding(text):
    original, f, value = make(text)
    assert original.related_source_ids
    assert f.profile.current_original_reference.source_id not in original.related_source_ids
    full = prepare_review_request(value.context())
    namespace = review_context_digest(value.context())[:32]
    expected_ids = [
        f"{namespace}:related:{eid}"
        for eid, q in full.quotes
        if q.source_id == f.profile.current_original_reference.source_id
    ]
    other_related_ids = {
        f"{namespace}:related:{eid}"
        for eid, q in full.quotes
        if q.source_id in original.related_source_ids
    }
    assert expected_ids and other_related_ids
    wire = json.loads(value.prompt_body)
    payload = json.loads(wire["messages"][1]["content"])
    metadata = payload["history_fragment_metadata"]
    assert metadata["passage_ids"] == expected_ids
    assert not other_related_ids.intersection(metadata["passage_ids"])
    rows = {row["id"]: row for row in payload["provider_passages"]}
    assert all(eid in rows for eid in expected_ids)
    assert rows[expected_ids[-1]]["text"] == "x"
    assert rows[expected_ids[-1]]["citable"] is False
    citable_ids = {eid for eid, _ in _prepare_contextual_catalog(value.context()).quotes}
    assert expected_ids[-1] not in citable_ids
    if "\n" in text:
        assert rows[expected_ids[0]]["citable"] is True
        assert expected_ids[0] in citable_ids
    else:
        assert not citable_ids.intersection(expected_ids)
    assert (
        metadata["citable"] is metadata["current_fact"] is metadata["sender_authenticated"] is False
    )
    assert metadata["lineage_complete"] is metadata["thread_context_complete"] is False
    raw = encode_history_fragment_contextual_request(value)
    assert decode_history_fragment_contextual_request(raw) == value
    assert (
        value.processing_authorized
        is value.recovery_verified
        is value.current_facts_verified
        is False
    )


def test_missing_nonquote_caveat_id_cannot_be_reencoded():
    from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of

    _, _, value = make("Invented citable passage\nx")
    wire = json.loads(value.prompt_body)
    payload = json.loads(wire["messages"][1]["content"])
    assert len(payload["history_fragment_metadata"]["passage_ids"]) == 2
    wire["messages"][1]["content"] = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    assert canonical_bytes(wire).decode() == value.prompt_body
    payload["history_fragment_metadata"]["passage_ids"].pop()
    wire["messages"][1]["content"] = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    body = canonical_bytes(wire).decode()
    altered = value.model_copy(
        update={"prompt_body": body, "prompt_digest": content_hash_of(body.encode())}
    )
    with pytest.raises(HistoryContextualCodecError):
        encode_history_fragment_contextual_request(altered)
