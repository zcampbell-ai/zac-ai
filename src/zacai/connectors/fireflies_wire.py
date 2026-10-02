"""D033A offline preparation for one explicitly selected Fireflies transcript.

No network, credential access, database or filesystem writes. Original response
bytes and observed privacy metadata are retained separately from D030's legacy
normalized payload. A future live orchestrator must persist both with provenance
and backup protection; passing normalized content alone to D030 is insufficient.
This module does not implement approval, credential handling or live ingestion.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, field_validator

from zacai.ingestion.artifact_store import content_hash_of

MAX_RESPONSE_BYTES = 2_000_000
TRANSCRIPT_QUERY = """query ZacSelectedTranscript($transcriptId: String!) {
  transcript(id: $transcriptId) {
    id title dateString privacy is_live organizer_email participants
    user { user_id email }
    meeting_attendees { name displayName email }
    sentences { index speaker_name text }
  }
}"""
_PRIVACY_VALUES = frozenset(
    {
        "link",
        "owner",
        "participants",
        "participatingteammates",
        "teammatesandparticipants",
        "teammates",
    }
)


class FirefliesWireError(ValueError):
    """A sanitized failure; never contains response text or credential material."""


class _WireModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)


class Owner(_WireModel):
    user_id: str = Field(min_length=1, strict=True)
    email: str = Field(min_length=1, strict=True)


class Attendee(_WireModel):
    name: str | None
    displayName: str | None
    email: str | None


class Sentence(_WireModel):
    index: int = Field(ge=0, strict=True)
    speaker_name: str | None
    text: str = Field(min_length=1, strict=True)


class WireTranscript(_WireModel):
    id: str = Field(min_length=1, strict=True)
    title: str = Field(min_length=1, strict=True)
    dateString: AwareDatetime
    privacy: str = Field(strict=True)
    is_live: bool = Field(strict=True)
    organizer_email: str | None
    participants: tuple[str, ...]
    user: Owner
    meeting_attendees: tuple[Attendee, ...]
    sentences: tuple[Sentence, ...] = Field(min_length=1)

    @field_validator("dateString", mode="before")
    @classmethod
    def iso_timestamp(cls, value: object) -> datetime:
        if not isinstance(value, str):
            raise ValueError("dateString must be an ISO timestamp string")  # noqa: TRY004 - Pydantic validation
        return datetime.fromisoformat(value)


@dataclass(frozen=True)
class PreparedTranscript:
    transcript: WireTranscript = field(repr=False)
    response_bytes: bytes = field(repr=False)
    response_hash: str

    def to_ingestion_payload(self) -> dict[str, Any]:
        """D030 mapping only; not an ingestion/storage call or complete provenance.

        Only attendee records with explicit names are mapped. Speaker names are
        never linked to attendee emails by guessing. Original attendee/participant
        fields remain intact in response_bytes, including unresolved identities.
        """
        participants = []
        for attendee in self.transcript.meeting_attendees:
            name = attendee.name or attendee.displayName
            if name and name.strip():
                participants.append({"name": name, "email": attendee.email})
        ordered = sorted(self.transcript.sentences, key=lambda item: item.index)
        text = "\n".join(
            f"{item.speaker_name}: {item.text}" if item.speaker_name else item.text
            for item in ordered
        )
        return {
            "id": self.transcript.id,
            "title": self.transcript.title,
            "date": self.transcript.dateString.astimezone(UTC).isoformat(),
            "participants": participants,
            "transcript_text": text,
        }


def build_transcript_request(transcript_id: str) -> dict[str, object]:
    """Pure fixed query builder; caller must bind the ID to approved host scope.

    No caller-supplied GraphQL, account listing, mutation or credentials. An ID
    supplied here is a request declaration, not an authorization to send it.
    """
    if not isinstance(transcript_id, str) or not transcript_id.strip() or len(transcript_id) > 200:
        raise FirefliesWireError("invalid transcript identifier")
    return {"query": TRANSCRIPT_QUERY, "variables": {"transcriptId": transcript_id}}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FirefliesWireError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise FirefliesWireError("non-finite JSON number")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise FirefliesWireError("non-finite JSON number")
    return parsed


def prepare_transcript_reply(response_bytes: bytes, *, expected_id: str) -> PreparedTranscript:
    """Validate a bounded reply; partial GraphQL errors fail closed.

    Retains exact received bytes, not reserialized or normalized bytes. Privacy
    is an observed snapshot, never permission to disclose or proof of full source
    ACL preservation. Live/unfinished transcripts and unknown privacy fail closed.
    """
    build_transcript_request(expected_id)
    if not isinstance(response_bytes, bytes) or len(response_bytes) > MAX_RESPONSE_BYTES:
        raise FirefliesWireError("invalid response size or type")
    data = parse_graphql_reply(response_bytes, field="transcript")
    try:
        transcript = WireTranscript.model_validate(data)
    except (ValueError, TypeError, ValidationError):
        raise FirefliesWireError("invalid transcript schema") from None
    if transcript.id != expected_id:
        raise FirefliesWireError("response transcript does not match selected ID")
    if transcript.is_live or transcript.privacy not in _PRIVACY_VALUES:
        raise FirefliesWireError("unfinished transcript or unsupported privacy setting")
    if not transcript.title.strip() or any(not item.text.strip() for item in transcript.sentences):
        raise FirefliesWireError("blank title or sentence")
    indices = [sentence.index for sentence in transcript.sentences]
    if len(indices) != len(set(indices)):
        raise FirefliesWireError("duplicate sentence index")
    return PreparedTranscript(
        transcript=transcript,
        response_bytes=response_bytes,
        response_hash=content_hash_of(response_bytes),
    )


def parse_graphql_reply(response_bytes: bytes, *, field: str) -> object:
    """Shared bounded, strict envelope decoder for fixed read-only queries.

    This parses data only; field selection is not request authorization.
    """
    if not isinstance(response_bytes, bytes) or len(response_bytes) > MAX_RESPONSE_BYTES:
        raise FirefliesWireError("invalid response size or type")
    try:
        raw = json.loads(
            response_bytes,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        if not isinstance(raw, dict) or set(raw) - {"data", "errors", "extensions"}:
            raise FirefliesWireError("invalid response envelope")
        if "errors" in raw and raw["errors"] != []:
            raise FirefliesWireError("Fireflies reported a query error")
        data = raw.get("data")
        if not isinstance(data, dict) or set(data) != {field} or data[field] is None:
            raise FirefliesWireError("requested data unavailable")
        return data[field]
    except FirefliesWireError as exc:
        raise FirefliesWireError(str(exc)) from None
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise FirefliesWireError("invalid or unsuccessful response") from None
