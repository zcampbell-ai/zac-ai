"""Fireflies-shaped payload parsing only (D030).

No network client of any kind lives here. This milestone never calls the
real Fireflies API - `zacai.ingestion.pipeline` is always fed a sequence
of synthetic, hand-built fixture dicts matching the shape this module
parses, standing in for a future real `fetch` stage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


class InvalidFirefliesPayloadError(ValueError):
    """Raised when a raw payload is missing a required field or has the
    wrong shape - the D030 ingestion pipeline's "validate" stage."""


@dataclass(frozen=True)
class FirefliesAttendee:
    name: str
    email: str | None


@dataclass(frozen=True)
class FirefliesTranscript:
    """The minimal shape `parse_transcript_payload` requires. Close
    enough to Fireflies' own transcript object to parse a real payload
    later without changing this shape - but this milestone only ever
    constructs one from a synthetic fixture dict."""

    external_id: str
    title: str
    occurred_at: datetime
    attendees: list[FirefliesAttendee]
    transcript_text: str


def parse_transcript_payload(payload: dict[str, Any]) -> FirefliesTranscript:
    """Validates and parses one raw (synthetic-fixture-shaped) Fireflies
    transcript payload. Raises `InvalidFirefliesPayloadError` on any
    missing/malformed required field - never partially parses."""
    try:
        external_id = str(payload["id"])
        title = str(payload["title"])
        occurred_at = datetime.fromisoformat(payload["date"])
        transcript_text = str(payload["transcript_text"])
        raw_attendees = payload["participants"]
    except KeyError as exc:
        raise InvalidFirefliesPayloadError(f"missing required field: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise InvalidFirefliesPayloadError(f"malformed field: {exc}") from exc

    try:
        attendees = [FirefliesAttendee(name=str(item["name"]), email=item.get("email")) for item in raw_attendees]
    except (KeyError, TypeError) as exc:
        raise InvalidFirefliesPayloadError(f"malformed participant entry: {exc}") from exc

    return FirefliesTranscript(
        external_id=external_id,
        title=title,
        occurred_at=occurred_at,
        attendees=attendees,
        transcript_text=transcript_text,
    )


def transcript_to_raw_payload(transcript: FirefliesTranscript) -> dict[str, Any]:
    """The exact dict that gets canonicalized/hashed/stored as this
    transcript's raw artifact bytes (D030) - built from the *parsed*,
    validated transcript, not the raw input dict, so a stored artifact
    always reflects what the pipeline actually understood."""
    return {
        "id": transcript.external_id,
        "title": transcript.title,
        "date": transcript.occurred_at.isoformat(),
        "transcript_text": transcript.transcript_text,
        "participants": [{"name": a.name, "email": a.email} for a in transcript.attendees],
    }
