"""LLM extraction stage (D030) - separate from the deterministic
ingestion pipeline (`zacai.ingestion.pipeline`).

This milestone never calls a real LLM: callers (and tests) supply an
`ExtractionFunction` - a plain Python callable - in its place. Output is
always written as an `extraction_candidate` row, never a canonical
Decision/Commitment - see `zacai.state_repository.
approve_extraction_candidate` for the only path a candidate may become
canonical state.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date

from sqlalchemy.orm import Session

from zacai.policy import DataClassification
from zacai.state import ExtractionCandidateType, ExtractionRecordStatus, Meeting, Source
from zacai.state_repository import (
    create_extraction_candidate,
    has_succeeded_extraction,
    record_extraction_attempt,
)


@dataclass(frozen=True)
class CandidateProposal:
    """One piece of extraction output, before it becomes a stored
    `extraction_candidate` row."""

    candidate_type: ExtractionCandidateType
    description: str
    confidence: float
    proposed_classification: DataClassification
    owner_person_id: uuid.UUID | None = None
    due_date: date | None = None
    project_id: uuid.UUID | None = None


ExtractionFunction = Callable[[Source, Meeting], Sequence[CandidateProposal]]


def run_extraction(
    session: Session,
    *,
    source: Source,
    meeting: Meeting,
    model_name: str,
    prompt_version: str,
    extraction_function: ExtractionFunction,
) -> None:
    """Runs `extraction_function` over one Source/Meeting and writes
    exactly one `extraction_record`, plus all of its candidates, in the
    caller's current transaction - all-or-nothing (D030): a crash
    mid-extraction can never leave a partial candidate set attached to a
    record that looks `SUCCEEDED`. A no-op if this exact
    `(source, model_name, prompt_version)` has already `SUCCEEDED` -
    the reprocessing idempotency check. A raised exception from
    `extraction_function` is caught and recorded as a `FAILED`
    `extraction_record` with no candidates - never a partial write."""
    if has_succeeded_extraction(
        session, source_id=source.id, model_name=model_name, prompt_version=prompt_version
    ):
        return

    try:
        proposals = extraction_function(source, meeting)
    except Exception as exc:  # noqa: BLE001 - a caller-supplied extraction
        # function (a real LLM call in production) can fail in ways this
        # module cannot enumerate; converting any such failure into a
        # FAILED extraction_record, rather than crashing the batch, is
        # the deliberate boundary behavior D030 specifies.
        record_extraction_attempt(
            session,
            source_id=source.id,
            trust_boundary=source.trust_boundary,
            model_name=model_name,
            prompt_version=prompt_version,
            status=ExtractionRecordStatus.FAILED,
            error=str(exc),
        )
        return

    record = record_extraction_attempt(
        session,
        source_id=source.id,
        trust_boundary=source.trust_boundary,
        model_name=model_name,
        prompt_version=prompt_version,
        status=ExtractionRecordStatus.SUCCEEDED,
        candidate_count=len(proposals),
    )

    for proposal in proposals:
        create_extraction_candidate(
            session,
            trust_boundary=source.trust_boundary,
            extraction_record_id=record.id,
            candidate_type=proposal.candidate_type,
            source_id=source.id,
            description=proposal.description,
            proposed_classification=proposal.proposed_classification,
            confidence=proposal.confidence,
            meeting_id=meeting.id,
            project_id=proposal.project_id,
            owner_person_id=proposal.owner_person_id,
            due_date=proposal.due_date,
        )
