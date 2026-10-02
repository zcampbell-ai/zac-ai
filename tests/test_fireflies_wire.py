"""D033A synthetic Fireflies replies only; no account, credential or network."""

import copy
import json

import pytest

from zacai.connectors.fireflies_wire import (
    MAX_RESPONSE_BYTES,
    TRANSCRIPT_QUERY,
    FirefliesWireError,
    build_transcript_request,
    prepare_transcript_reply,
)
from zacai.ingestion.artifact_store import content_hash_of
from zacai.ingestion.fireflies import parse_transcript_payload


def fixture_reply() -> dict[str, object]:
    return {
        "data": {
            "transcript": {
                "id": "synthetic-meeting",
                "title": "Synthetic project review",
                "dateString": "2026-10-02T09:00:00-04:00",
                "privacy": "owner",
                "is_live": False,
                "organizer_email": "owner@example.invalid",
                "participants": ["owner@example.invalid"],
                "user": {"user_id": "synthetic-owner", "email": "owner@example.invalid"},
                "meeting_attendees": [
                    {
                        "name": "Synthetic Owner",
                        "displayName": None,
                        "email": "owner@example.invalid",
                    },
                    {"name": None, "displayName": None, "email": "unresolved@example.invalid"},
                ],
                "sentences": [
                    {"index": 1, "speaker_name": None, "text": "Synthetic follow-up."},
                    {
                        "index": 0,
                        "speaker_name": "Synthetic Speaker",
                        "text": "Synthetic evidence.",
                    },
                ],
            }
        }
    }


def encode(raw: object) -> bytes:
    return json.dumps(raw, indent=2).encode()


def test_exact_bytes_privacy_and_unresolved_attendees_survive_normalization() -> None:
    raw = encode(fixture_reply())
    prepared = prepare_transcript_reply(raw, expected_id="synthetic-meeting")
    assert prepared.response_bytes == raw
    assert prepared.response_hash == content_hash_of(raw)
    assert prepared.transcript.privacy == "owner"
    assert prepared.transcript.user.email == "owner@example.invalid"
    assert prepared.transcript.meeting_attendees[1].email == "unresolved@example.invalid"
    normalized = parse_transcript_payload(prepared.to_ingestion_payload())
    assert normalized.occurred_at.isoformat() == "2026-10-02T13:00:00+00:00"
    assert (
        normalized.transcript_text == "Synthetic Speaker: Synthetic evidence.\nSynthetic follow-up."
    )
    assert len(normalized.attendees) == 1
    # Speaker identity is never inferred from an attendee's email.
    assert normalized.attendees[0].name == "Synthetic Owner"
    assert prepared.response_hash != content_hash_of(encode(prepared.to_ingestion_payload()))
    assert "Synthetic evidence" not in repr(prepared)


def test_request_has_one_fixed_query_and_identifier_cannot_inject_graphql() -> None:
    malicious_id = 'synthetic") { mutation { deleteTranscript } }'
    request = build_transcript_request(malicious_id)
    assert request["query"] == TRANSCRIPT_QUERY
    assert request["variables"] == {"transcriptId": malicious_id}
    assert "mutation" not in TRANSCRIPT_QUERY
    assert "transcripts(" not in TRANSCRIPT_QUERY
    assert "audio_url" not in TRANSCRIPT_QUERY
    assert "Authorization" not in request


@pytest.mark.parametrize("identifier", ["", " ", "x" * 201])
def test_invalid_request_identifier(identifier: str) -> None:
    with pytest.raises(FirefliesWireError):
        build_transcript_request(identifier)


@pytest.mark.parametrize(
    "response",
    [
        b"{",
        b"[]",
        b'{"data":null}',
        b'{"data":{"transcript":null}}',
        b'{"data":{"transcript":null},"data":{}}',
        b'{"data":NaN}',
        b"\xff",
        b"x" * (MAX_RESPONSE_BYTES + 1),
    ],
)
def test_invalid_envelope_and_oversized_reply(response: bytes) -> None:
    with pytest.raises(FirefliesWireError):
        prepare_transcript_reply(response, expected_id="synthetic-meeting")


def test_partial_graphql_data_with_errors_is_never_accepted_or_leaked() -> None:
    raw = fixture_reply()
    raw["errors"] = [{"message": "synthetic sensitive marker do not surface"}]
    with pytest.raises(FirefliesWireError) as failure:
        prepare_transcript_reply(encode(raw), expected_id="synthetic-meeting")
    assert "synthetic sensitive marker" not in str(failure.value)
    assert str(failure.value) == "Fireflies reported a query error"
    assert failure.value.__suppress_context__ is True


def test_overflowing_json_number_is_rejected_even_in_extensions() -> None:
    raw = encode(fixture_reply()).decode().rstrip()
    raw = raw[:-1] + ', "extensions": {"value": 1e400}}'
    with pytest.raises(FirefliesWireError, match="non-finite"):
        prepare_transcript_reply(raw.encode(), expected_id="synthetic-meeting")


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "another-meeting"),
        ("is_live", True),
        ("is_live", "false"),
        ("privacy", "unexpected-new-privacy"),
        ("dateString", "2026-10-02T13:00:00"),
        ("dateString", 0),
        ("dateString", "0"),
        ("title", " "),
        ("sentences", []),
        ("user", None),
        ("participants", "owner@example.invalid"),
        ("permission", "allow all"),
    ],
)
def test_incomplete_or_out_of_scope_transcript_is_rejected(field: str, value: object) -> None:
    raw = fixture_reply()
    data = raw["data"]
    assert isinstance(data, dict)
    transcript = data["transcript"]
    transcript[field] = value
    with pytest.raises(FirefliesWireError):
        prepare_transcript_reply(encode(raw), expected_id="synthetic-meeting")


def test_duplicate_sentence_indices_rejected() -> None:
    raw = fixture_reply()
    data = raw["data"]
    assert isinstance(data, dict)
    sentences = data["transcript"]["sentences"]
    sentences.append(copy.deepcopy(sentences[0]))
    with pytest.raises(FirefliesWireError, match="duplicate sentence"):
        prepare_transcript_reply(encode(raw), expected_id="synthetic-meeting")
