"""D034D explicit project evidence for bounded canonical meeting-review drafts.

No discovery, ingestion, inference, writes or permission grants. Shared project
identity does not prove topical relevance or make historical facts current.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contracts import (
    ContextItem,
    EntityReference,
    EvidenceReference,
    IntelligenceTask,
    classification_covers,
)
from zacai.intelligence.evidence import resolve_evidence_reference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.review_context import MeetingEvidence, assemble_review_context
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary
from zacai.state import EvidenceStance, MeetingSource, ProjectEvidence, SourceSystem
from zacai.state_repository import get_meeting_project_context, get_source


@dataclass(frozen=True)
class ReviewedProjectEvidence:
    """Exact primary-meeting association and supporting project Source.

    Source must support the exact current/reviewed project version. Selection is
    a trusted host decision, not a model declaration or permission grant.
    """

    association_id: UUID
    source_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.association_id, UUID) or not isinstance(self.source_id, UUID):
            raise TypeError("project selection requires canonical UUIDs")


def assemble_project_review_context(
    session: Session,
    *,
    artifacts: ArtifactStore,
    selected: MeetingEvidence,
    projects: tuple[ReviewedProjectEvidence, ...],
    earlier: tuple[MeetingEvidence, ...] = (),
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    observed_at: datetime,
) -> ReviewContext:
    """Hash-verified explicit project/meeting evidence in a caller-owned snapshot.

    MANUAL UTF-8 project artifacts are the sole new decoder. They remain untrusted
    quoted data. Confirmation and classification dependencies enter provenance
    as metadata only. Primary links must pin the current reviewed version. Earlier
    meetings require an active link to a selected stable project; older version
    pins remain historical, with their evidence sensitivity still respected.
    Relevance is selected independently by the host, never inferred from identity.

    Requires protected schema 0005 rollout. Does not change the existing assembler
    available on schema 0004. Refresh canonical evidence/policy before dispatch.
    """
    try:
        return _assemble(
            session,
            artifacts,
            selected,
            projects,
            earlier,
            authorized_boundaries,
            allowed_classifications,
            observed_at,
        )
    except Exception:  # noqa: BLE001 - diagnostics may contain private content
        raise ValueError("project review context unavailable or outside approved limits") from None


def _assemble(
    session: Session,
    artifacts: ArtifactStore,
    selected: MeetingEvidence,
    projects: tuple[ReviewedProjectEvidence, ...],
    earlier: tuple[MeetingEvidence, ...],
    authorized: frozenset[TrustBoundary],
    allowed: frozenset[DataClassification],
    observed_at: datetime,
) -> ReviewContext:
    if not isinstance(projects, tuple) or not 1 <= len(projects) <= 3:
        raise ValueError("project selection outside limits")
    if not isinstance(earlier, tuple) or len(earlier) > 7:
        raise ValueError("meeting selection outside limits")
    for selection in projects:
        ReviewedProjectEvidence(selection.association_id, selection.source_id)
    if len({p.association_id for p in projects}) != len(projects):
        raise ValueError("duplicate project selection")
    primary_links = get_meeting_project_context(
        session,
        meeting_id=selected.meeting_id,
        requestor_boundaries=authorized,
        allowed_classifications=allowed,
    )
    by_id = {link.association_id: link for link in primary_links}
    chosen = [by_id[p.association_id] for p in projects]
    if len({link.project_id for link in chosen}) != len(chosen):
        raise ValueError("duplicate project identity")
    if any(link.reviewed_project_version != link.current_project_version for link in chosen):
        raise ValueError("primary project changed since review")
    chosen_ids = {link.project_id for link in chosen}
    used_links = list(chosen)
    for meeting in earlier:
        links = get_meeting_project_context(
            session,
            meeting_id=meeting.meeting_id,
            requestor_boundaries=authorized,
            allowed_classifications=allowed,
        )
        shared = [link for link in links if link.project_id in chosen_ids]
        if not shared:
            raise ValueError("earlier meeting lacks reviewed shared project identity")
        used_links.extend(shared)
    boundary_source = get_source(
        session, source_id=chosen[0].confirmation_source_id, requestor_boundaries=authorized
    )
    if boundary_source is None:
        raise ValueError("missing confirmation")
    boundary = boundary_source.trust_boundary
    refs: dict[UUID, EvidenceReference] = {}

    def resolve(source_id: UUID) -> EvidenceReference:
        ref = resolve_evidence_reference(
            session, source_id=source_id, requestor_boundaries=authorized
        )
        if ref.trust_boundary != boundary or ref.effective_classification not in allowed:
            raise ValueError("project evidence outside scope")
        gate = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.READ_DATA,
                access=AccessRequest(
                    data_boundary=boundary,
                    data_classification=ref.effective_classification,
                    requestor_boundaries=authorized,
                    destination=Destination.LOCAL,
                ),
                description="assemble explicitly selected project evidence",
            )
        )
        if gate.outcome != GatewayOutcome.ALLOW:
            raise ValueError("project evidence read denied")
        refs[source_id] = ref
        if len(refs) > 64:
            raise ValueError("project provenance outside limits")
        return ref

    # Close all label dependencies as provenance, without reading their artifacts.
    for link in used_links:
        resolve(link.confirmation_source_id)
        for version in {link.reviewed_project_version, link.current_project_version}:
            source_ids = (
                session.execute(
                    select(ProjectEvidence.source_id).where(
                        ProjectEvidence.project_entity_id == link.project_id,
                        ProjectEvidence.project_version == version,
                        ProjectEvidence.stance == EvidenceStance.SUPPORTS,
                    )
                )
                .scalars()
                .all()
            )
            if not source_ids:
                raise ValueError("project has no supporting evidence")
            for source_id in source_ids:
                resolve(source_id)
    meeting_source_ids = (
        session.execute(
            select(MeetingSource.source_id).where(
                MeetingSource.meeting_id.in_(
                    [selected.meeting_id, *(m.meeting_id for m in earlier)]
                )
            )
        )
        .scalars()
        .all()
    )
    for source_id in meeting_source_ids:
        resolve(source_id)
    confirmation_ids = {link.confirmation_source_id for link in used_links}
    project_sources = []
    selected_project_sources: set[UUID] = set()
    for selection, link in zip(projects, chosen, strict=True):
        if selection.source_id in confirmation_ids:
            raise ValueError("confirmation evidence cannot become project prose")
        supports = session.scalar(
            select(ProjectEvidence.id)
            .where(
                ProjectEvidence.project_entity_id == link.project_id,
                ProjectEvidence.project_version == link.reviewed_project_version,
                ProjectEvidence.source_id == selection.source_id,
                ProjectEvidence.stance == EvidenceStance.SUPPORTS,
            )
            .limit(1)
        )
        source = get_source(session, source_id=selection.source_id, requestor_boundaries=authorized)
        if (
            supports is None
            or source is None
            or source.system != SourceSystem.MANUAL
            or not source.content_location
        ):
            raise ValueError("unsupported or unlinked project artifact")
        ref = resolve(source.id)
        if source.id not in selected_project_sources:
            project_sources.append((source, ref))
            selected_project_sources.add(source.id)
    base = assemble_review_context(
        session,
        artifacts=artifacts,
        selected=selected,
        earlier=earlier,
        authorized_boundaries=authorized,
        allowed_classifications=allowed,
        observed_at=observed_at,
    )
    if base.task.event.trust_boundary != boundary:
        raise ValueError("project and meeting boundaries differ")
    refs.update({ref.source_id: ref for ref in base.task.event.provenance})
    if len(refs) > 64:
        raise ValueError("combined provenance outside limits")
    items = list(base.task.context)
    occupied = {item.reference.source_id for item in items}
    for source, ref in project_sources:
        if source.id in occupied:
            raise ValueError("project and meeting evidence roles overlap")
        location = source.content_location
        if location is None:
            raise ValueError("missing project artifact location")
        raw = artifacts.get(boundary, location)
        if len(raw) > 16_000 or content_hash_of(raw) != ref.content_hash:
            raise ValueError("project artifact integrity or size failure")
        text = raw.decode("utf-8")
        if not text.strip() or len(text) > 8_000 or "\x00" in text:
            raise ValueError("unsupported project text")
        items.append(ContextItem(reference=ref, untrusted_text=text))
    if sum(len(item.untrusted_text) for item in items) > 24_000:
        raise ValueError("combined context outside limits")
    label = base.task.event.data_classification
    for other in [
        *(link.effective_classification for link in used_links),
        *(ref.effective_classification for ref in refs.values()),
    ]:
        if not classification_covers(label, other):
            label = other
    if label not in allowed:
        raise ValueError("combined classification outside scope")
    entities = (
        *base.task.event.related_entities,
        *(
            EntityReference(
                entity_type="Project",
                entity_id=link.project_id,
                version=link.reviewed_project_version,
                trust_boundary=boundary,
            )
            for link in chosen
        ),
    )
    # Revalidate: model_copy(update=...) bypasses contract validation.
    event_data = base.task.event.model_dump()
    event_data.update(
        data_classification=label, provenance=tuple(refs.values()), related_entities=entities
    )
    task_data = base.task.model_dump()
    task_data.update(event=event_data, context=tuple(items))
    task = IntelligenceTask.model_validate(task_data)
    return ReviewContext(
        task,
        base.meeting_source_id,
        base.related_source_ids | frozenset(p.source_id for p in projects),
    )
