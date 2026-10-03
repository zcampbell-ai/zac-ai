"""D034B read-only canonical context assembly for explicitly selected meetings.

No title matching, source discovery, model call, state write or auto-expansion.
Only normalized Fireflies v1 artifacts are decoded in this first bounded slice.
The host must refresh this context before any later dispatch; it is a snapshot.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contracts import (
    ContextItem,
    EntityReference,
    EvidenceReference,
    Importance,
    IntelligenceTask,
    ZacEvent,
    classification_covers,
)
from zacai.intelligence.evidence import resolve_evidence_reference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary
from zacai.state import MeetingSource, SourceSystem
from zacai.state_repository import get_meeting, get_source


@dataclass(frozen=True)
class MeetingEvidence:
    meeting_id: UUID
    source_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.meeting_id, UUID) or not isinstance(self.source_id, UUID):
            raise TypeError("selection requires canonical UUIDs")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def assemble_review_context(
    session: Session,
    *,
    artifacts: ArtifactStore,
    selected: MeetingEvidence,
    earlier: tuple[MeetingEvidence, ...] = (),
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    observed_at: datetime,
) -> ReviewContext:
    """Resolve exact links, boundary, effective labels, artifact hashes and lineage.

    Selection/relevance is a trusted host decision. Temporal ordering only proves
    earlier occurrence, not that these meetings concern the same project. Labels
    propagate from meetings, normalized artifacts and account/raw dependencies.
    Caller owns a read transaction; use a consistent snapshot and refresh before
    dispatch. No classification is weakened and no oversized source is truncated.
    """
    try:
        return _assemble(
            session,
            artifacts,
            selected,
            earlier,
            authorized_boundaries,
            allowed_classifications,
            observed_at,
        )
    except Exception:  # noqa: BLE001 - artifact/JSON diagnostics can contain private text
        raise ValueError("review context unavailable or outside approved limits") from None


def _assemble(
    session: Session,
    artifacts: ArtifactStore,
    selected: MeetingEvidence,
    earlier: tuple[MeetingEvidence, ...],
    authorized: frozenset[TrustBoundary],
    allowed: frozenset[DataClassification],
    observed_at: datetime,
) -> ReviewContext:
    if observed_at.tzinfo is None or not isinstance(earlier, tuple) or len(earlier) > 7:
        raise ValueError("invalid observation or context count")
    selections = (selected, *earlier)
    for value in selections:
        MeetingEvidence(value.meeting_id, value.source_id)
    if len({value.meeting_id for value in selections}) != len(selections) or len(
        {value.source_id for value in selections}
    ) != len(selections):
        raise ValueError("duplicate selected evidence")
    main = get_meeting(session, meeting_id=selected.meeting_id, requestor_boundaries=authorized)
    if main is None:
        raise ValueError("meeting unavailable")
    references: dict[UUID, EvidenceReference] = {}
    items = []
    entities = []
    label = main.data_classification

    def resolve(source_id: UUID) -> EvidenceReference:
        ref = resolve_evidence_reference(
            session, source_id=source_id, requestor_boundaries=authorized
        )
        if ref.trust_boundary != main.trust_boundary or ref.effective_classification not in allowed:
            raise ValueError("source outside scope")
        outcome = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.READ_DATA,
                access=AccessRequest(
                    data_boundary=ref.trust_boundary,
                    data_classification=ref.effective_classification,
                    requestor_boundaries=authorized,
                    destination=Destination.LOCAL,
                ),
                description="assemble selected meeting evidence",
            )
        )
        if outcome.outcome != GatewayOutcome.ALLOW:
            raise ValueError("read denied")
        references[source_id] = ref
        return ref

    for selection in selections:
        meeting = get_meeting(
            session, meeting_id=selection.meeting_id, requestor_boundaries=authorized
        )
        if (
            meeting is None
            or meeting.trust_boundary != main.trust_boundary
            or (selection != selected and meeting.occurred_at >= main.occurred_at)
            or meeting.data_classification not in allowed
        ):
            raise ValueError("meeting outside selected temporal/boundary scope")
        if not classification_covers(label, meeting.data_classification):
            label = meeting.data_classification
        linked = session.scalar(
            select(MeetingSource.id).where(
                MeetingSource.meeting_id == meeting.id,
                MeetingSource.source_id == selection.source_id,
                MeetingSource.trust_boundary == main.trust_boundary,
            )
        )
        if linked is None:
            raise ValueError("source not linked to selected meeting")
        ref = resolve(selection.source_id)
        source = get_source(session, source_id=selection.source_id, requestor_boundaries=authorized)
        if source is None or source.system != SourceSystem.FIREFLIES or not source.content_location:
            raise ValueError("unsupported source")
        raw = artifacts.get(ref.trust_boundary, source.content_location)
        if len(raw) > 2_000_000 or content_hash_of(raw) != ref.content_hash:
            raise ValueError("artifact integrity or size failure")
        envelope = json.loads(raw, object_pairs_hook=_unique_pairs)
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"format", "payload", "raw_source", "account_source"}
            or envelope["format"] != "zac-fireflies-normalized-v1"
        ):
            raise ValueError("unsupported artifact format")
        payload = envelope["payload"]
        text = payload["transcript_text"]
        if not isinstance(text, str) or not text.strip() or len(text) > 18_000:
            raise ValueError("unsupported text size")
        if source.external_ref != f"normalized-v1/transcript/{payload['id']}":
            raise ValueError("normalized source identity mismatch")
        if datetime.fromisoformat(payload["date"]) != meeting.occurred_at:
            raise ValueError("normalized meeting time mismatch")
        for name in ("raw_source", "account_source"):
            dependency = envelope[name]
            dep_id = UUID(dependency["id"])
            if dep_id == source.id:
                raise ValueError("cyclic dependency")
            dep_ref = resolve(dep_id)
            dep_source = get_source(session, source_id=dep_id, requestor_boundaries=authorized)
            if (
                dep_ref.content_hash != dependency["sha256"]
                or dep_source is None
                or (dep_source.system != SourceSystem.FIREFLIES)
            ):
                raise ValueError("dependency identity/hash mismatch")
            if name == "raw_source":
                raw_link = session.scalar(
                    select(MeetingSource.id).where(
                        MeetingSource.meeting_id == meeting.id,
                        MeetingSource.source_id == dep_id,
                        MeetingSource.trust_boundary == main.trust_boundary,
                    )
                )
                if (
                    dep_source.external_ref != f"wire/transcript/{payload['id']}"
                    or raw_link is None
                ):
                    raise ValueError("raw dependency not linked to selected meeting")
            elif not (dep_source.external_ref or "").startswith("wire/account/"):
                raise ValueError("account dependency has wrong source role")
        items.append(ContextItem(reference=ref, untrusted_text=text))
        entities.append(
            EntityReference(
                entity_type="Meeting", entity_id=meeting.id, trust_boundary=main.trust_boundary
            )
        )
    for ref in references.values():
        if not classification_covers(label, ref.effective_classification):
            label = ref.effective_classification
    if label not in allowed or sum(len(item.untrusted_text) for item in items) > 24_000:
        raise ValueError("combined context outside limits")
    task = IntelligenceTask(
        task_id=uuid4(),
        event=ZacEvent(
            event_id=uuid4(),
            event_type="meeting.review_requested",
            producer="zacai.canonical-review-host",
            occurred_at=main.occurred_at,
            observed_at=observed_at.astimezone(UTC),
            trust_boundary=main.trust_boundary,
            data_classification=label,
            provenance=tuple(references.values()),
            related_entities=tuple(entities),
            correlation_id=uuid4(),
            importance=Importance.FYI,
            confidence=1.0,
        ),
        required_capabilities=frozenset({"compact_meeting_review"}),
        instruction="Prepare a concise contextual meeting review draft.",
        context=tuple(items),
        max_latency_ms=120_000,
        max_estimated_cost_usd=0.0,
        max_output_tokens=1600,
    )
    return ReviewContext(task, selected.source_id, frozenset(value.source_id for value in earlier))
