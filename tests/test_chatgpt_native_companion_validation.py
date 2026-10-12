import copy

import pytest

from test_chatgpt_native_view import fixture_body, raw, run
from zacai.chatgpt_native_view import (
    MAX_COMPANION_BYTES,
    ChatGPTNativeViewCompanion,
    ChatGPTNativeViewError,
)
from zacai.ingestion.artifact_store import canonical_bytes


@pytest.mark.parametrize("mutation", ["thread", "coordinates", "covers", "membership"])
def test_predecessor_causal_consistency(mutation):
    p = run(raw(fixture_body()))
    d = p.model_dump(mode="json")
    if mutation == "thread":
        d["thread_id"] = "other"
    elif mutation == "coordinates":
        d["selected_end"] = 500
    elif mutation == "covers":
        d["selected_span_covers_returned_field"] = True
    else:
        d["fields"] = d["fields"][1:]
    with pytest.raises(ValueError):
        type(p).model_validate(d)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(thread_id="different"),
        lambda d: d.update(selected_end=500),
        lambda d: d.update(selected_utf8_end=0),
        lambda d: d.update(selected_utf8_end=999),
        lambda d: d.update(selected_utf8_start=0),
        lambda d: d.update(omitted_returned_prefix_codepoints=0),
        lambda d: d.update(omitted_returned_suffix_codepoints=0),
        lambda d: d.update(selected_span_covers_returned_field=True),
        lambda d: d.update(fields=d["fields"][1:]),
        lambda d: d.update(fields=[*d["fields"], d["fields"][0]]),
        lambda d: d.update(projection_observed_at="2026-10-11T00:00:00"),
        lambda d: d.update(returned_turn_count=0),
        lambda d: d.update(returned_item_count=0),
        lambda d: d.update(returned_page_limit=0),
        lambda d: d.update(retention_classification="CONFIDENTIAL"),
        lambda d: d["selected_field"].update(item_id="not-present"),
        lambda d: d["fields"][1].update(pointer="/turns/5/items/1/text"),
        lambda d: d["fields"][1].update(item_id="with spaces"),
        lambda d: d["fields"][1].update(turn_id="different-turn"),
        lambda d: d["fields"][1].update(reported_turn_started_at=4.0),
        lambda d: d["fields"][1].update(field_utf8_bytes=0),
        lambda d: d["fields"][1].update(field_at_20000_codepoints=True),
        lambda d: d["fields"][1].update(reported_turn_started_at=float("nan")),
        lambda d: d["fields"][1].update(reported_turn_completed_at=float("inf")),
    ],
)
def test_inconsistent_companion_is_rejected(change):
    p = run(raw(fixture_body()))
    d = p.model_dump(mode="json")
    change(d)
    with pytest.raises(ValueError):
        ChatGPTNativeViewCompanion.model_validate(d)


def test_full_returned_field_hash_relation():
    p = run(raw(fixture_body()), start=0, end=4)
    assert p.selected_text_hash == p.selected_field.field_hash
    d = p.model_dump(mode="json")
    d["selected_text_hash"] = "f" * 64
    with pytest.raises(ValueError):
        ChatGPTNativeViewCompanion.model_validate(d)


def test_empty_item_keeps_returned_count_without_inventing_fields():
    body = fixture_body()
    empty = copy.deepcopy(body["turns"][0]["items"][0])
    empty["id"] = "empty"
    empty["content"] = []
    body["turns"][0]["items"].append(empty)
    p = run(raw(body))
    assert p.returned_item_count == 3 and len(p.fields) == 2
    assert ChatGPTNativeViewCompanion.model_validate(p.model_dump(mode="json")) == p


def test_page_count_and_independent_continuation_observations():
    body = fixture_body()
    body["page"]["hasMore"] = False
    p = run(raw(body))  # do not invent provider hasMore/cursor equivalence
    assert not p.returned_has_more and p.returned_cursor_present
    assert p.pagination_consistency == "NOT_VERIFIED"
    body["page"]["limit"] = 1
    body["turns"].append(copy.deepcopy(body["turns"][0]))
    body["turns"][1]["id"] = "turn-2"
    for item in body["turns"][1]["items"]:
        item["id"] += "-2"
    with pytest.raises(ChatGPTNativeViewError):
        run(raw(body))


def test_integer_native_date_is_deliberately_unsupported():
    body = fixture_body()
    body["turns"][0]["startedAt"] = 1
    with pytest.raises(ChatGPTNativeViewError):
        run(raw(body))


def test_one_item_position_cannot_report_two_roles():
    p = run(raw(fixture_body()))
    d = p.model_dump(mode="json")
    # Each individual field is otherwise valid; both name the same item position.
    d["fields"][1]["pointer"] = "/turns/0/items/0/text"
    d["fields"][1]["item_id"] = d["fields"][0]["item_id"]
    with pytest.raises(ValueError, match="item position differs"):
        type(p).model_validate(d)


def test_reported_turn_status_is_not_completion_authority():
    body = fixture_body()
    body["turns"][0]["status"] = "interrupted"
    p = run(raw(body))
    assert all(f.reported_turn_status == "interrupted" for f in p.fields)
    assert not p.complete_field_verified and not p.complete_account_history
    d = p.model_dump(mode="json")
    d["fields"][1]["reported_turn_status"] = "completed"
    with pytest.raises(ValueError):
        type(p).model_validate(d)


@pytest.mark.parametrize(
    "field,value", [("returned_page_limit", 201), ("attachment_descriptor_count", 101)]
)
def test_public_bounds_match_parser(field, value):
    d = run(raw(fixture_body())).model_dump(mode="json")
    d[field] = value
    with pytest.raises(ValueError):
        ChatGPTNativeViewCompanion.model_validate(d)


def test_companion_byte_boundary_after_all_shape_guards():
    def body_for(count):
        body = fixture_body()
        body["page"]["limit"] = 200
        body["turns"] = []
        for n in range(count):
            turn = copy.deepcopy(fixture_body()["turns"][0])
            turn["id"] = f"turn-{n:03}"
            turn["items"][0]["id"] = f"user-{n:03}"
            turn["items"][1]["id"] = f"agent-{n:03}"
            body["turns"].append(turn)
        return body

    near = None
    # Find the actual serialized boundary; no guessed field-width estimate.
    for count in range(1, 201):
        try:
            p = run(raw(body_for(count)))
        except ChatGPTNativeViewError:
            assert near is not None
            break
        near = p
    else:
        pytest.fail("fixture did not reach bounded companion")
    assert near.returned_turn_count == count - 1
    size = len(canonical_bytes(near.model_dump(mode="json")))
    assert 0 < MAX_COMPANION_BYTES - size < 1500
    body = body_for(count)
    with pytest.raises(ChatGPTNativeViewError):
        run(raw(body))
    # Match the failing producer's metadata shape directly. All other shape/count
    # guards are valid, and public validation identifies the byte-boundary guard.
    d = near.model_dump(mode="json")
    extra = copy.deepcopy(d["fields"][-2:])
    for item in extra:
        item["turn_id"] = f"turn-{count - 1:03}"
        item["item_id"] = (
            "user-" if item["reported_role"] == "USER" else "agent-"
        ) + f"{count - 1:03}"
        item["pointer"] = item["pointer"].replace(f"/turns/{count - 2}/", f"/turns/{count - 1}/")
    d["fields"].extend(extra)
    d["returned_turn_count"] = count
    d["returned_item_count"] = count * 2
    assert len(canonical_bytes(d)) > MAX_COMPANION_BYTES
    with pytest.raises(ValueError, match="bounded companion required"):
        ChatGPTNativeViewCompanion.model_validate(d)
