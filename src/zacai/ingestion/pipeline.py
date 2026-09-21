"""The deterministic D030 ingestion pipeline: fetch (caller-supplied) ->
validate -> hash/store artifact -> boundary/classification -> Source ->
Meeting/attendees -> cursor/run bookkeeping.

No LLM call anywhere in this module - see `zacai.ingestion.extraction`
for the separate, later extraction stage. No real Fireflies API call,
credential, or network request anywhere in this milestone - callers
supply `payloads` directly (synthetic fixtures in every test).

**Artifact/DB transaction lifecycle (D030)**: `ArtifactStore.put` cannot
participate in the PostgreSQL transaction that records `Source` - the
two are different systems. The order below is deliberate: the artifact
write (and its read-after-write hash verification) always happens
*before* the database transaction opens. If the DB transaction then
fails or rolls back, the artifact write already succeeded and becomes an
**orphan artifact**: a real, valid, correctly-hashed file with no
`Source` row referencing it. This is accepted, not treated as
corruption - see `zacai.ingestion.artifact_store` and
`zacai.state_repository.is_artifact_referenced`. The reverse ordering
(commit the `Source` row first, write the artifact second) would be
worse: it could leave a `Source` row pointing at bytes that were never
actually written - real data loss disguised as success. This module
never attempts filesystem rollback/delete-on-failure, and never builds
garbage collection - both explicitly out of scope for D030.

**Ingestion-run transaction lifecycle (D030)**: three separate
transactions per batch, deliberately not one - `STARTED` is inserted and
committed immediately; the data batch (Source/Meeting writes + cursor
advance) runs in its own transaction; the terminal `SUCCEEDED`/`FAILED`
update runs in a third, fresh transaction opened after the data
transaction has already resolved (committed or rolled back) - so a
rolled-back data transaction can never erase the failure audit record,
and the cursor never advances on failure. See
`zacai.state_repository.start_ingestion_run`/`complete_ingestion_run`/
`fail_ingestion_run` docstrings for the same lifecycle from the
repository side.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.ingestion.fireflies import parse_transcript_payload, transcript_to_raw_payload
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import IngestionRun, MeetingSource, MeetingSourceRole, SourceSystem
from zacai.state_repository import (
    MeetingSourceInput,
    advance_ingestion_cursor,
    complete_ingestion_run,
    create_meeting,
    fail_ingestion_run,
    find_person_by_email,
    record_source,
    record_unresolved_identity,
    start_ingestion_run,
)

FIREFLIES_CONNECTOR = "fireflies"


class ArtifactIntegrityError(RuntimeError):
    """Raised when a just-written artifact does not hash back to the
    value it was written under - the D030 content-hash invariant
    (`sha256(store.get(content_location)) == content_hash`) failed at
    write time. The pipeline aborts before any database write in this
    case."""


def ingest_fireflies_batch(
    session_factory: sessionmaker[Session],
    *,
    trust_boundary: TrustBoundary,
    data_classification: DataClassification,
    artifact_store: ArtifactStore,
    payloads: Sequence[dict[str, Any]],
) -> IngestionRun:
    """Processes one batch of synthetic Fireflies-shaped payloads through
    the full D030 deterministic pipeline. `payloads` stands in for a real
    `fetch` stage, which this milestone never implements."""
    with session_factory() as run_session:
        run = start_ingestion_run(run_session, connector=FIREFLIES_CONNECTOR, trust_boundary=trust_boundary)
        run_id = run.id
        run_session.commit()

    items_fetched = len(payloads)
    items_ingested = 0
    items_skipped = 0

    try:
        with session_factory() as data_session:
            for raw_payload in payloads:
                transcript = parse_transcript_payload(raw_payload)
                exact_bytes = canonical_bytes(transcript_to_raw_payload(transcript))
                hash_value = content_hash_of(exact_bytes)

                # Artifact write happens fully outside the DB transaction -
                # see module docstring.
                content_location = artifact_store.put(trust_boundary, hash_value, exact_bytes)
                if content_hash_of(artifact_store.get(trust_boundary, content_location)) != hash_value:
                    raise ArtifactIntegrityError(
                        f"artifact at {content_location!r} does not hash to {hash_value!r} after write"
                    )

                source, was_new = record_source(
                    data_session,
                    trust_boundary=trust_boundary,
                    data_classification=data_classification,
                    system=SourceSystem.FIREFLIES,
                    content_hash=hash_value,
                    content_location=content_location,
                    external_ref=transcript.external_id,
                    captured_at=transcript.occurred_at,
                    excerpt=transcript.title,
                )
                if not was_new:
                    items_skipped += 1
                    continue

                already_attached = data_session.execute(
                    select(MeetingSource.id).where(MeetingSource.source_id == source.id)
                ).scalar_one_or_none()
                if already_attached is not None:
                    items_skipped += 1
                    continue

                attendee_ids: list[uuid.UUID] = []
                for attendee in transcript.attendees:
                    person = None
                    if attendee.email:
                        person = find_person_by_email(
                            data_session, trust_boundary=trust_boundary, email=attendee.email
                        )
                    if person is not None:
                        attendee_ids.append(person.entity_id)
                    else:
                        record_unresolved_identity(
                            data_session,
                            trust_boundary=trust_boundary,
                            source_id=source.id,
                            context="meeting_attendee",
                            raw_name=attendee.name,
                            raw_email=attendee.email,
                        )

                create_meeting(
                    data_session,
                    trust_boundary=trust_boundary,
                    data_classification=data_classification,
                    title=transcript.title,
                    occurred_at=transcript.occurred_at,
                    sources=[MeetingSourceInput(source_id=source.id, source_role=MeetingSourceRole.TRANSCRIPT)],
                    attendees=attendee_ids,
                )
                items_ingested += 1

            advance_ingestion_cursor(
                data_session,
                connector=FIREFLIES_CONNECTOR,
                trust_boundary=trust_boundary,
                cursor_value=str(items_fetched),
            )
            data_session.commit()
    except Exception as exc:
        with session_factory() as fail_session:
            fail_ingestion_run(fail_session, run_id=run_id, error=str(exc))
            fail_session.commit()
        raise

    with session_factory() as complete_session:
        complete_ingestion_run(
            complete_session,
            run_id=run_id,
            items_fetched=items_fetched,
            items_ingested=items_ingested,
            items_skipped=items_skipped,
            items_failed=0,
        )
        complete_session.commit()
        finished_run = complete_session.get(IngestionRun, run_id)
        if finished_run is None:
            raise RuntimeError(f"ingestion_run {run_id} vanished after completion")
        complete_session.expunge(finished_run)
        return finished_run
