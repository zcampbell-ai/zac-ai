"""D033B offline single-writer provenance capture, tested with synthetic bytes.

No credential/network access, approval issuance, commit, backup upload or LLM.
The caller owns the transaction and separately establishes approved live scope.
Each artifact precedes its own Source row; rollback may leave D030 orphans.
A savepoint prevents partial source/meeting rows if the caller catches failure.
All three Source artifacts enter existing per-boundary backup inventory. This
is backup eligibility, not proof a capture has actually been backed up.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from zacai.connectors.fireflies_identity import prepare_account_reply
from zacai.connectors.fireflies_wire import FirefliesWireError, prepare_transcript_reply
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)
from zacai.state import Meeting, MeetingRetraction, MeetingSource, MeetingSourceRole, SourceSystem
from zacai.state_repository import (
    MeetingSourceInput,
    create_meeting,
    get_current_source_revision,
    get_effective_source_classification,
    record_source,
    record_unresolved_identity,
)


class FirefliesCaptureError(RuntimeError):
    """Sanitized capture failure; no source content or database exception text."""


@dataclass(frozen=True)
class CaptureReceipt:
    meeting_id: uuid.UUID
    account_source_id: uuid.UUID
    raw_source_id: uuid.UUID
    normalized_source_id: uuid.UUID
    was_new: bool


def capture_selected_transcript(
    session: Session,
    *,
    artifact_store: ArtifactStore,
    requestor_boundaries: frozenset[TrustBoundary],
    data_classification: DataClassification,
    expected_email: str,
    expected_id: str,
    account_response: bytes,
    transcript_response: bytes,
    captured_at: datetime,
) -> CaptureReceipt:
    """Persist validated exact replies plus a versioned, source-linked view.

    Expected email/ID/classification are trusted-host inputs, not fields extracted
    from source content. They are scope declarations, not approval tokens. Only
    BRAINSTORM is supported in this initial capture path. Returned receipts refer
    to uncommitted rows until the caller commits. Existing classifications must
    match exactly; relabeling/elevation requires a separate explicit workflow.
    This single-writer implementation does not claim concurrent ingestion safety.
    """
    boundary = TrustBoundary.BRAINSTORM
    access = AccessRequest(
        data_boundary=boundary,
        data_classification=data_classification,
        requestor_boundaries=requestor_boundaries,
        destination=Destination.LOCAL,
    )
    if not evaluate_access(access).allowed:
        raise FirefliesCaptureError("capture boundary access denied")
    if not isinstance(captured_at, datetime) or captured_at.utcoffset() is None:
        raise FirefliesCaptureError("capture timestamp must be timezone-aware")
    try:
        account = prepare_account_reply(account_response, expected_email=expected_email)
        prepared = prepare_transcript_reply(transcript_response, expected_id=expected_id)
        owner = prepared.transcript.user
        if (
            owner.user_id != account.identity.user_id
            or owner.email.lower() != account.identity.email.lower()
        ):
            raise FirefliesCaptureError("selected transcript owner does not match account")
        # Persist the exact replies before opening the DB savepoint.
        account_location = _put_verified(artifact_store, boundary, account.response_bytes)
        raw_location = _put_verified(artifact_store, boundary, prepared.response_bytes)
        with session.begin_nested():

            def source(ref: str, raw: bytes, location: str) -> uuid.UUID:
                tip = get_current_source_revision(
                    session,
                    system=SourceSystem.FIREFLIES,
                    external_ref=ref,
                    trust_boundary=boundary,
                )
                if (
                    tip is not None
                    and get_effective_source_classification(session, source_id=tip.id)
                    != data_classification
                ):
                    raise FirefliesCaptureError(
                        "source revision classification requires separate review"
                    )
                record, _ = record_source(
                    session,
                    trust_boundary=boundary,
                    data_classification=data_classification,
                    system=SourceSystem.FIREFLIES,
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    external_ref=ref,
                    captured_at=captured_at.astimezone(UTC),
                )
                if (
                    get_effective_source_classification(session, source_id=record.id)
                    != data_classification
                ):
                    raise FirefliesCaptureError(
                        "existing source classification requires separate review"
                    )
                return record.id

            account_id = source(
                f"wire/account/{account.identity.user_id}", account_response, account_location
            )
            raw_id = source(f"wire/transcript/{expected_id}", transcript_response, raw_location)
            normalized = canonical_bytes(
                {
                    "format": "zac-fireflies-normalized-v1",
                    "account_source": {"id": str(account_id), "sha256": account.response_hash},
                    "raw_source": {"id": str(raw_id), "sha256": prepared.response_hash},
                    "payload": prepared.to_ingestion_payload(),
                }
            )
            normalized_location = _put_verified(artifact_store, boundary, normalized)
            normalized_id = source(
                f"normalized-v1/transcript/{expected_id}", normalized, normalized_location
            )
            existing = session.execute(
                select(Meeting)
                .join(MeetingSource, MeetingSource.meeting_id == Meeting.id)
                .where(
                    MeetingSource.source_id == normalized_id,
                    MeetingSource.trust_boundary == boundary,
                    Meeting.trust_boundary == boundary,
                )
            ).scalar_one_or_none()
            if existing is not None:
                if (
                    session.scalar(
                        select(MeetingRetraction.id).where(
                            MeetingRetraction.meeting_id == existing.id
                        )
                    )
                    is not None
                ):
                    raise FirefliesCaptureError(
                        "existing meeting is retracted; separate review required"
                    )
                if existing.data_classification != data_classification:
                    raise FirefliesCaptureError(
                        "existing meeting classification requires separate review"
                    )
                return CaptureReceipt(existing.id, account_id, raw_id, normalized_id, False)
            meeting = create_meeting(
                session,
                trust_boundary=boundary,
                data_classification=data_classification,
                title=prepared.transcript.title,
                occurred_at=prepared.transcript.dateString.astimezone(UTC),
                sources=[
                    MeetingSourceInput(source_id=raw_id, source_role=MeetingSourceRole.TRANSCRIPT),
                    MeetingSourceInput(
                        source_id=normalized_id, source_role=MeetingSourceRole.TRANSCRIPT
                    ),
                ],
            )
            # All attendee records remain explicit unresolved references here.
            # No speaker/email inference or canonical Person merge is attempted.
            for attendee in prepared.transcript.meeting_attendees:
                record_unresolved_identity(
                    session,
                    trust_boundary=boundary,
                    source_id=raw_id,
                    meeting_id=meeting.id,
                    context="fireflies_meeting_attendee",
                    raw_name=attendee.name or attendee.displayName,
                    raw_email=attendee.email,
                )
            return CaptureReceipt(meeting.id, account_id, raw_id, normalized_id, True)
    except FirefliesCaptureError as exc:
        raise FirefliesCaptureError(str(exc)) from None
    except FirefliesWireError:
        raise FirefliesCaptureError("account or transcript validation failed") from None
    except Exception:  # noqa: BLE001 - prevent source/DB/credential leakage at host boundary
        raise FirefliesCaptureError("capture failed; transaction not committed") from None


def _put_verified(store: ArtifactStore, boundary: TrustBoundary, raw: bytes) -> str:
    digest = content_hash_of(raw)
    location = store.put(boundary, digest, raw)
    if content_hash_of(store.get(boundary, location)) != digest:
        raise FirefliesCaptureError("artifact verification failed")
    return location
