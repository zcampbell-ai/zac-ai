"""D034E read-only canonical refresh before a future meeting-review dispatch.

This check is not dispatch authorization, a durable audit record or a guarantee
against concurrent changes. The host owns a fresh consistent DB snapshot and
must dispatch immediately through separately approved runtime/security controls.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.project_review_context import (
    ReviewedProjectEvidence,
    assemble_project_review_context,
)
from zacai.intelligence.review_context import MeetingEvidence, assemble_review_context
from zacai.intelligence.review_generation import ReviewRequest, prepare_review_request
from zacai.policy import DataClassification, TrustBoundary


@dataclass(frozen=True)
class ReviewFreshness:
    """Content-free check result, never an authority token or persisted receipt."""

    task_id: UUID
    checked_at: datetime
    context_digest: str


def _digest(context: ReviewContext) -> str:
    # Fresh assembly creates new task/event/correlation IDs and observation time.
    # Everything else, including text/order, labels, versions and limits, is bound.
    data = context.task.model_dump(mode="json")
    del data["task_id"]
    for name in ("event_id", "correlation_id", "observed_at"):
        del data["event"][name]
    data["event"]["provenance"] = sorted(
        data["event"]["provenance"], key=lambda ref: ref["source_id"]
    )
    data["event"]["related_entities"] = sorted(
        data["event"]["related_entities"],
        key=lambda ref: (ref["entity_type"], ref["entity_id"], ref["version"] or 0),
    )
    data["required_capabilities"] = sorted(data["required_capabilities"])
    data["meeting_source_id"] = str(context.meeting_source_id)
    data["related_source_ids"] = sorted(str(sid) for sid in context.related_source_ids)
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def check_review_freshness(
    session: Session,
    *,
    artifacts: ArtifactStore,
    request: ReviewRequest,
    selected: MeetingEvidence,
    earlier: tuple[MeetingEvidence, ...] = (),
    projects: tuple[ReviewedProjectEvidence, ...] = (),
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    checked_at: datetime,
) -> ReviewFreshness:
    """Reassemble exact selections, reject expired, altered or unavailable context.

    The host supplies current permissions, not permissions cached with a request.
    Request age is capped at 120 seconds; negative/naive clocks reject. Repeated
    checks never renew that age. Caller must use a NEW consistent read snapshot
    with no stale ORM identity map (a fresh Session is recommended). Pending ORM
    writes reject before reads, preventing an accidental autoflush. The caller
    must close the assembly transaction before opening that fresh snapshot.

    Empty projects uses the existing schema-0004-compatible assembler. Selected
    project evidence requires the separately protected 0005 rollout. No fallback,
    writes, inference, approval, private rollout or audit persistence happens here.
    Reassemble and regenerate after a rejected check; do not relabel an old draft.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("refresh session contains pending writes")
        context = ReviewContext(
            request.context.task,
            request.context.meeting_source_id,
            request.context.related_source_ids,
        )
        if request != prepare_review_request(context):
            raise ValueError("modified request")
        if checked_at.tzinfo is None:
            raise ValueError("naive clock")
        age = (checked_at - context.task.event.observed_at).total_seconds()
        if not 0 <= age <= 120:
            raise ValueError("expired or future request")
        if not isinstance(projects, tuple):
            raise TypeError("invalid selections")
        if projects:
            fresh = assemble_project_review_context(
                session,
                artifacts=artifacts,
                selected=selected,
                earlier=earlier,
                projects=projects,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                observed_at=checked_at,
            )
        else:
            fresh = assemble_review_context(
                session,
                artifacts=artifacts,
                selected=selected,
                earlier=earlier,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                observed_at=checked_at,
            )
        digest = _digest(fresh)
        if _digest(context) != digest:
            raise ValueError("canonical context changed")
        return ReviewFreshness(context.task.task_id, checked_at.astimezone(UTC), digest)
    except Exception:  # noqa: BLE001 - source/DB/artifact errors may contain private data
        raise ValueError("review context expired, changed or unavailable") from None
