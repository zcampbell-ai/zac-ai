import copy
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from zacai.chatgpt_native_view import ChatGPTNativeViewError, prepare_chatgpt_native_view
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def fixture_body():
    return {
        "schemaVersion": 1,
        "untrustedDataNotice": "Invented untrusted notice",
        "thread": {
            "id": "thread-1",
            "kind": "chatgpt",
            "title": "Invented",
            "preview": "",
            "cwd": None,
            "status": {},
            "createdAt": 1.0,
            "updatedAt": 2.0,
        },
        "page": {"hasMore": True, "limit": 10, "nextCursor": "opaque", "order": "desc"},
        "turns": [
            {
                "id": "turn-1",
                "status": "completed",
                "error": None,
                "startedAt": 1.0,
                "completedAt": 2.0,
                "durationMs": None,
                "items": [
                    {
                        "type": "userMessage",
                        "id": "user-1",
                        "content": [{"type": "text", "text": " a🙂\n"}],
                    },
                    {"type": "agentMessage", "id": "agent-1", "text": "Invented assistant"},
                ],
            }
        ],
        "attachments": [{"id": "descriptor-only"}],
    }


def raw(body):
    return canonical_bytes(
        {"content": [{"type": "text", "text": json.dumps(body)}], "isError": False}
    )


def run(wire, **kwargs):
    ref = EvidenceReference(
        source_id=UUID(int=1),
        content_hash=content_hash_of(wire),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    arguments = {
        "original_reference": ref,
        "expected_thread_id": "thread-1",
        "selected_pointer": "/turns/0/items/0/content/0/text",
        "start": 1,
        "end": 3,
        "observed_at": datetime(2026, 10, 11, tzinfo=UTC),
    }
    arguments.update(kwargs)
    return prepare_chatgpt_native_view(wire, **arguments)


def test_exact_hashes_roles_and_decoded_coordinates():
    body = fixture_body()
    wire = raw(body)
    p = run(wire)
    assert p.original_reference.content_hash == content_hash_of(wire)
    assert p.decoded_payload_hash == content_hash_of(json.dumps(body).encode())
    assert p.selected_text_hash == content_hash_of("a🙂".encode())
    assert (p.selected_utf8_start, p.selected_utf8_end) == (1, 6)
    assert p.selected_field.field_codepoints == 4 and p.selected_field.field_utf8_bytes == 7
    assert [f.reported_role for f in p.fields] == ["USER", "ASSISTANT"]
    assert p.attachment_descriptor_count == 1 and not p.attachments_downloaded
    assert p.returned_has_more and p.returned_cursor_present
    assert p.ancestry == "NOT_EXPOSED_NOT_VERIFIED"
    assert not any(
        getattr(p, field)
        for field in [
            "account_ownership_verified",
            "authorship_verified",
            "current_facts_verified",
            "capture_authorized",
            "processing_authorized",
            "recovery_verified",
            "complete_field_verified",
            "complete_account_history",
            "current_source_access_verified",
        ]
    )
    assert "Invented assistant" not in p.model_dump_json()


def test_multipart_separate_assistant_selected():
    body = fixture_body()
    body["turns"][0]["items"][0]["content"].append({"type": "text", "text": "second"})
    p = run(raw(body), selected_pointer="/turns/0/items/1/text", start=0, end=8)
    assert len(p.fields) == 3 and p.selected_field.reported_role == "ASSISTANT"
    assert [f.pointer for f in p.fields][:2] == [
        "/turns/0/items/0/content/0/text",
        "/turns/0/items/0/content/1/text",
    ]
    assert p.fields[0].field_hash != p.fields[1].field_hash


def test_20000_observation_is_explicit_clipping_unknown():
    body = fixture_body()
    body["turns"][0]["items"][1]["text"] = "x" * 20000
    p = run(raw(body), selected_pointer="/turns/0/items/1/text")
    assert p.selected_field.field_at_20000_codepoints and not p.complete_field_verified


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schemaVersion=True),
        lambda d: d["thread"].update(id="different"),
        lambda d: d["thread"].update(kind="codex"),
        lambda d: d["turns"][0]["items"][0].update(type="assistant"),
        lambda d: d["turns"][0]["items"][0]["content"][0].update(type="image"),
        lambda d: d["turns"][0]["items"][0]["content"][0].update(text=5),
        lambda d: d["turns"][0]["items"].append(copy.deepcopy(d["turns"][0]["items"][0])),
        lambda d: d["turns"].append(copy.deepcopy(d["turns"][0])),
        lambda d: d["turns"][0].update(startedAt=float("nan")),
        lambda d: d["page"].update(limit=True),
        lambda d: d.update(newGrammar="unsupported"),
    ],
)
def test_shape_holds(change):
    body = fixture_body()
    change(body)
    # stdlib JSON here deliberately allows nan, proving parser refusal.
    wire = json.dumps(
        {"content": [{"type": "text", "text": json.dumps(body)}], "isError": False}
    ).encode()
    with pytest.raises(ChatGPTNativeViewError, match="preparation held") as caught:
        run(wire)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"selected_pointer": "/turns/0/items/0/text"},
        {"end": 500},
        {"start": True},
        {"observed_at": datetime(2026, 10, 11, tzinfo=UTC).replace(tzinfo=None)},
        {"expected_thread_id": "other"},
    ],
)
def test_selection_holds(kwargs):
    with pytest.raises(ChatGPTNativeViewError):
        run(raw(fixture_body()), **kwargs)


def test_stale_and_cross_scope_reference():
    wire = raw(fixture_body())
    for boundary, classification, digest in [
        (B.PERSONAL, C.HIGHLY_RESTRICTED, "f" * 64),
        (B.SHARED, C.HIGHLY_RESTRICTED, content_hash_of(wire)),
        (B.BRAINSTORM, C.PUBLIC, content_hash_of(wire)),
    ]:
        ref = EvidenceReference(
            source_id=UUID(int=1),
            trust_boundary=boundary,
            effective_classification=classification,
            content_hash=digest,
        )
        with pytest.raises(ChatGPTNativeViewError):
            run(wire, original_reference=ref)
    ref = EvidenceReference(
        source_id=UUID(int=1),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.HIGHLY_RESTRICTED,
        content_hash=content_hash_of(wire),
    )
    assert run(wire, original_reference=ref).original_reference == ref  # snapshot only, no ACL


@pytest.mark.parametrize(
    "wire",
    [
        b'{"content":[],"isError":false,"isError":false}',
        b'{"content":[{"type":"text","text":"{\\"schemaVersion\\":1,\\"schemaVersion\\":1}"}],"isError":false}',
        b'{"content":[],"isError":true}',
        b"\xff",
    ],
)
def test_outer_inner_duplicate_error_and_utf8_holds(wire):
    with pytest.raises(ChatGPTNativeViewError):
        run(wire)


def test_false_flags_revalidate():
    p = run(raw(fixture_body()))
    bad = p.model_dump()
    bad["processing_authorized"] = 0
    with pytest.raises(ValueError):
        type(p).model_validate(bad)


def test_noncanonical_wrapper_still_exactly_bound():
    wire = json.dumps(json.loads(raw(fixture_body())), indent=3).encode()
    p = run(wire)
    assert p.original_reference.content_hash == content_hash_of(wire)
    assert p.original_bytes == len(wire)


def test_complete_returned_field_above_8000_is_bound_without_prose():
    body = fixture_body()
    text = " α🙂\n" * 25000  # exactly100000codepoints, well beyond8000
    body["turns"][0]["items"][0]["content"][0]["text"] = text
    wire = raw(body)
    p = run(wire, start=0, end=len(text))
    assert p.selected_field.field_codepoints == 100000
    assert p.selected_field.field_hash == p.selected_text_hash == content_hash_of(text.encode())
    assert p.selected_utf8_start == 0 and p.selected_utf8_end == len(text.encode())
    assert p.selected_span_covers_returned_field
    assert p.omitted_returned_prefix_codepoints == p.omitted_returned_suffix_codepoints == 0
    assert not p.complete_field_verified and not p.complete_account_history
    assert text not in p.model_dump_json()


def test_large_partial_span_preserves_exact_omissions():
    body = fixture_body()
    text = " α🙂\n" * 3000
    body["turns"][0]["items"][0]["content"][0]["text"] = text
    p = run(raw(body), start=1000, end=10000)
    assert p.selected_text_hash == content_hash_of(text[1000:10000].encode())
    assert p.selected_utf8_start == len(text[:1000].encode())
    assert p.selected_utf8_end == len(text[:10000].encode())
    assert not p.selected_span_covers_returned_field
    assert p.omitted_returned_prefix_codepoints == 1000
    assert p.omitted_returned_suffix_codepoints == 2000


def test_oversized_returned_field_and_requested_span_hold():
    body = fixture_body()
    body["turns"][0]["items"][0]["content"][0]["text"] = "x" * 100001
    with pytest.raises(ChatGPTNativeViewError):
        run(raw(body), start=0, end=100001)
    with pytest.raises(ChatGPTNativeViewError):
        run(raw(body), start=0, end=99999)  # partial does not evade full-field bound


@pytest.mark.parametrize("mode", ["wrapper", "field", "companion"])
def test_finite_capacity_holds(mode):
    body = fixture_body()
    if mode == "wrapper":
        wire = b" " * 2000001
    elif mode == "field":
        body["turns"][0]["items"][0]["content"][0]["text"] = "x" * 100001
        wire = raw(body)
    else:
        body["page"]["limit"] = 200
        turns = []
        for n in range(200):
            turn = copy.deepcopy(body["turns"][0])
            turn["id"] = f"turn-{n}"
            turn["items"][0]["id"] = f"user-{n}"
            turn["items"][1]["id"] = f"agent-{n}"
            turns.append(turn)
        body["turns"] = turns
        wire = raw(body)
    with pytest.raises(ChatGPTNativeViewError):
        run(wire)
