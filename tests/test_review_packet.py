"""Invented evidence only: exact reload, tampering and safe error boundaries."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_review_evaluation import packet
from zacai.intelligence.review_evaluation import EvaluationOutcome, check_review_evaluation
from zacai.intelligence.review_packet import decode_review_packet, encode_review_packet


def test_round_trip_retains_full_context_and_exact_evaluation_binding():
    context, review, evaluation = packet()
    encoded = encode_review_packet(review, context)
    restored = decode_review_packet(encoded)
    assert restored.review == review
    assert restored.context() == context
    assert encode_review_packet(restored.review, restored.context()) == encoded
    assert (
        check_review_evaluation(evaluation, restored.review, restored.context())
        == EvaluationOutcome.NEEDS_REVIEW
    )
    assert not hasattr(restored, "approved")


@pytest.mark.parametrize(
    "change", ["text", "role", "draft", "hash", "context_hash", "instruction", "task", "extra"]
)
def test_changed_evidence_roles_or_draft_cannot_reuse_packet_digests(change):
    context, review, _ = packet()
    data = json.loads(encode_review_packet(review, context))
    if change == "text":
        data["task"]["context"][0]["untrusted_text"] += " Private sentinel."
    elif change == "role":
        data["related_source_ids"] = []
    elif change == "draft":
        data["review"]["summary"][0]["text"] = "Private sentinel."
    elif change == "hash":
        data["review_digest"] = "0" * 64
    elif change == "context_hash":
        data["context_digest"] = "0" * 64
    elif change == "instruction":
        data["task"]["instruction"] = "Different task instruction."
    elif change == "task":
        data["task"]["task_id"] = str(uuid4())
    else:
        data["approved"] = True
    with pytest.raises(ValueError, match="^review packet unavailable or invalid$") as error:
        decode_review_packet(json.dumps(data).encode())
    assert "Private sentinel" not in str(error.value)
    assert error.value.__context__ is None


@pytest.mark.parametrize("version", [None, True, "1", 2])
def test_version_is_explicit_and_exact(version):
    context, review, _ = packet()
    data = json.loads(encode_review_packet(review, context))
    if version is None:
        del data["contract_version"]
    else:
        data["contract_version"] = version
    with pytest.raises(ValueError, match="unavailable or invalid"):
        decode_review_packet(json.dumps(data).encode())


@pytest.mark.parametrize(
    "payload", [b"[]", b"\xff", b'{"contract_version":1,"contract_version":1}']
)
def test_invalid_json_and_duplicate_keys_reject_without_echo(payload):
    with pytest.raises(ValueError, match="^review packet unavailable or invalid$"):
        decode_review_packet(payload)


@pytest.mark.parametrize("field", ["task", "event", "review"])
def test_nested_version_cannot_be_defaulted_on_reload(field):
    context, review, _ = packet()
    data = json.loads(encode_review_packet(review, context))
    target = data["task"]["event"] if field == "event" else data[field]
    del target["contract_version"]
    with pytest.raises(ValueError, match="unavailable or invalid"):
        decode_review_packet(json.dumps(data).encode())


def test_noncanonical_whitespace_and_duplicate_set_entries_reject():
    context, review, _ = packet()
    encoded = encode_review_packet(review, context)
    for payload in (b" " + encoded, encoded.replace(b'"instruction":', b'"instruction" :')):
        with pytest.raises(ValueError):
            decode_review_packet(payload)
    data = json.loads(encoded)
    data["related_source_ids"] *= 2
    with pytest.raises(ValueError):
        decode_review_packet(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def test_nested_duplicate_keys_reject():
    context, review, _ = packet()
    encoded = encode_review_packet(review, context)
    bad = encoded.replace(b'"instruction":', b'"instruction":"other","instruction":', 1)
    with pytest.raises(ValueError):
        decode_review_packet(bad)


def test_consistently_reencoded_changes_are_not_authenticated():
    context, review, evaluation = packet()
    changed = replace(context, task=context.task.model_copy(update={"instruction": "New task."}))
    restored = decode_review_packet(encode_review_packet(review, changed))
    assert restored.context() == changed
    # Self-consistency is accepted; an independently retained evaluation rejects it.
    with pytest.raises(ValueError):
        check_review_evaluation(evaluation, restored.review, restored.context())
