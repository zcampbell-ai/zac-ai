"""Explicit candidate research excerpts; no discovery, inference or authority.

Only the contextual host uses this seam. Quotes address the deterministic
projection, not a native provider transcript; original field ranges stay in scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, StrictInt, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import (
    ArtifactStore,
    LocalFilesystemArtifactStore,
    content_hash_of,
)
from zacai.intelligence.contracts import (
    ContextItem,
    Contract,
    Digest,
    EvidenceReference,
    IntelligenceTask,
)
from zacai.intelligence.evidence import resolve_evidence_reference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.project_review_context import ReviewedProjectEvidence
from zacai.intelligence.review_context import MeetingEvidence
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary
from zacai.research_intake import _constant, _float, _pairs, prepare_rendered_fireflies_literal
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import get_source, source_classification_elevation_strength


class ResearchRange(Contract):
    start: StrictInt = Field(ge=0)
    end: StrictInt = Field(gt=0)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.end <= self.start or self.end - self.start > 1200:
            raise ValueError("invalid research range")
        return self


class ResearchEvidence(Contract):
    source_id: UUID
    content_hash: Digest
    field_text_hash: Digest
    original_record_hash: Digest
    approved_proposal_hash: Digest
    field: Literal["text", "description"]
    ranges: tuple[ResearchRange, ...] = Field(min_length=1, max_length=8)
    # Ranges use Python Unicode code points in the exact decoded field, no normalization.
    relevance_reason: str = Field(min_length=1, max_length=500, strict=True)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if (
            not self.relevance_reason.strip()
            or any(second.start <= first.end for first, second in zip(self.ranges, self.ranges[1:]))
            or sum(r.end - r.start for r in self.ranges) > 16_000
        ):
            raise ValueError("ambiguous research selection")
        return self


class ResearchReviewSelection(Contract):
    format: Literal["zac-contextual-research-selection-v1"]
    selected: MeetingEvidence
    earlier: tuple[MeetingEvidence, ...] = Field(default=(), max_length=7)
    projects: tuple[ReviewedProjectEvidence, ...] = Field(default=(), max_length=3)
    research: tuple[ResearchEvidence, ...] = Field(min_length=1, max_length=11)

    @model_validator(mode="after")
    def distinct(self) -> Self:
        ids = [item.source_id for item in self.research]
        other = (
            {self.selected.source_id}
            | {p.source_id for p in self.projects}
            | {m.source_id for m in self.earlier}
        )
        if (
            len(ids) != len(set(ids))
            or set(ids) & other
            or sum(r.end - r.start for item in self.research for r in item.ranges) > 32_000
        ):
            raise ValueError("duplicate or oversized research scope")
        return self


def append_research_context(
    session: Session,
    *,
    artifacts: ArtifactStore,
    context: ReviewContext,
    research: tuple[ResearchEvidence, ...],
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> ReviewContext:
    """Refresh exact MANUAL evidence and project only selected original field spans.

    Caller supplies read authority and a clean consistent session. Neither a
    selection nor the source's original import approval authorizes inference.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("pending writes")
        if not isinstance(research, tuple) or not 1 <= len(research) <= 11:
            raise ValueError("scope capacity")
        selections = tuple(ResearchEvidence.model_validate(x) for x in research)
        source_ids = [x.source_id for x in selections]
        if (
            len(set(source_ids)) != len(source_ids)
            or set(source_ids) & {x.source_id for x in context.task.event.provenance}
            or sum(r.end - r.start for x in selections for r in x.ranges) > 32_000
        ):
            raise ValueError("scope ambiguity")
        if "contextual_meeting_review" not in context.task.required_capabilities:
            raise ValueError("contextual capability required")
        items = list(context.task.context)
        seen_records: set[tuple[str, str]] = set()
        for choice in selections:
            ref = resolve_evidence_reference(
                session, source_id=choice.source_id, requestor_boundaries=authorized_boundaries
            )
            if (
                ref.trust_boundary != TrustBoundary.BRAINSTORM
                or ref.effective_classification != DataClassification.CONFIDENTIAL
                or ref.effective_classification not in allowed_classifications
                or ref.content_hash != choice.content_hash
            ):
                raise ValueError("source scope changed")
            gate = evaluate_gateway(
                ActionRequest(
                    action_type=ActionType.READ_DATA,
                    access=AccessRequest(
                        data_boundary=ref.trust_boundary,
                        data_classification=ref.effective_classification,
                        requestor_boundaries=authorized_boundaries,
                        destination=Destination.LOCAL,
                    ),
                    description="read explicitly selected candidate research evidence",
                )
            )
            if gate.outcome != GatewayOutcome.ALLOW:
                raise ValueError("read denied")
            source = get_source(
                session, source_id=choice.source_id, requestor_boundaries=authorized_boundaries
            )
            if source is None or source.system != SourceSystem.MANUAL:
                raise ValueError("unsupported source")
            raw = _bytes(session, artifacts, source)
            if len(raw) > 32_000:
                raise ValueError("envelope capacity")

            def load(value: bytes | str) -> Any:
                return json.loads(
                    value, object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant
                )

            envelope = load(raw)
            if (
                envelope["format"] != "zac-research-exhibit-v1"
                or envelope["boundary"] != "BRAINSTORM"
                or envelope["classification"] != "CONFIDENTIAL"
                or envelope["native_capture"] is not False
                or envelope["project_connections"] != "UNCONFIRMED"
                or envelope["role"] != "CANDIDATE_CONTEXT"
                or envelope["source_form"]
                != "EXISTING_RESEARCH_EXHIBIT_NOT_NEW_NATIVE_PROVIDER_CAPTURE"
                or envelope["approved_proposal_hash"] != choice.approved_proposal_hash
                or envelope["original_record_hash"] != choice.original_record_hash
                or source.external_ref
                != f"research-exhibit/{envelope['provider']}/{envelope['original_id']}/{choice.approved_proposal_hash}"
            ):
                raise ValueError("envelope scope changed")
            original = envelope["canonical_record_utf8"]
            if content_hash_of(original.encode()) != choice.original_record_hash:
                raise ValueError("record integrity")
            record = load(original)
            original_id = record["id"]
            if (
                not isinstance(original_id, str)
                or not 1 <= len(original_id) <= 100
                or not original_id.isascii()
                or not original_id.isalnum()
            ):
                raise ValueError("unsupported original ID")
            provider = envelope["provider"]
            if (
                record["id"] != envelope["original_id"]
                or (provider, choice.field)
                not in {("FIREFLIES", "text"), ("CLICKUP", "description")}
                or record["source_type"]
                != {"FIREFLIES": "Fireflies transcript", "CLICKUP": "ClickUp task"}[provider]
            ):
                raise ValueError("record identity")
            value = record[choice.field]
            if (
                not isinstance(value, str)
                or not value.strip()
                or content_hash_of(value.encode()) != choice.field_text_hash
            ):
                raise ValueError("missing source text")
            identity = (provider, record["id"])
            if identity in seen_records:
                raise ValueError("duplicate original research record")
            seen_records.add(identity)
            if provider == "FIREFLIES":
                for item in context.task.context:
                    native = get_source(
                        session,
                        source_id=item.reference.source_id,
                        requestor_boundaries=authorized_boundaries,
                    )
                    if (
                        native is None
                        or native.external_ref == f"normalized-v1/transcript/{record['id']}"
                    ):
                        raise ValueError("record already supplied or native evidence unavailable")

            def encoded(value: object) -> str:
                return (
                    json.dumps(value, ensure_ascii=False, sort_keys=True)
                    .replace("\u2028", "\\u2028")
                    .replace("\u2029", "\\u2029")
                    .replace("\u0085", "\\u0085")
                )

            lines = [
                "CANDIDATE RESEARCH SNAPSHOT; not a native capture.",
                "Project connections UNCONFIRMED. Historical metadata is not current status.",
                f"Provider: {provider}; original ID: {json.dumps(record['id'])}",
                f"Research recorded at: {source.captured_at.isoformat()}",
            ]
            if provider == "CLICKUP":
                for name in ("name", "last_updated_ms"):
                    if name in record:
                        lines.append(
                            name
                            + " as captured, not independently verified: "
                            + encoded(record[name])
                        )
            for span in choice.ranges:
                if span.end > len(value):
                    raise ValueError("range outside original field")
                lines.append(
                    f"{choice.field} excerpt [{span.start}:{span.end}] of {len(value)} Unicode code points; outside this range is not supplied:"
                )
                lines.append(
                    "Untrusted excerpt JSON string: " + encoded(value[span.start : span.end])
                )
            projection = "\n".join(lines)
            if any(len(line) > 1500 for line in projection.split("\n")):
                raise ValueError("select shorter explicit passages")
            items.append(ContextItem(reference=ref, untrusted_text=projection))
        data = context.task.model_dump()
        data["context"] = [x.model_dump() for x in items]
        data["event"]["provenance"] = [x.model_dump() for x in context.task.event.provenance] + [
            x.reference.model_dump() for x in items[len(context.task.context) :]
        ]
        task = IntelligenceTask.model_validate(data)
        return ReviewContext(
            task, context.meeting_source_id, context.related_source_ids | frozenset(source_ids)
        )
    except Exception:  # noqa: BLE001, S110 - no private diagnostics
        pass
    raise ValueError("candidate research context unavailable") from None


class RenderedFirefliesSelection(Contract):
    """Three exact current Sources; not permission or a protected scope."""

    detail_reference: EvidenceReference
    metadata_reference: EvidenceReference
    derived_reference: EvidenceReference
    requested_transcript_id: str = Field(min_length=1, max_length=100, strict=True)
    block_index: Literal[0]
    span: ResearchRange

    @model_validator(mode="after")
    def original_scope(self) -> Self:
        refs = (self.detail_reference, self.metadata_reference, self.derived_reference)
        if (
            type(self.block_index) is not int
            or len({r.source_id for r in refs}) != 3
            or not self.requested_transcript_id.isascii()
            or not self.requested_transcript_id.isalnum()
            or len({r.trust_boundary for r in refs}) != 1
            or len({r.effective_classification for r in refs}) != 1
            or any(
                r.trust_boundary not in {TrustBoundary.BRAINSTORM, TrustBoundary.PERSONAL}
                or r.effective_classification
                not in {DataClassification.CONFIDENTIAL, DataClassification.HIGHLY_RESTRICTED}
                for r in refs
            )
        ):
            raise ValueError("rendered research scope")
        return self


@dataclass(frozen=True, repr=False)
class LoadedRenderedFirefliesLiteral:
    """Dormant mechanics; all three originals/derivative required for recovery."""

    selection: RenderedFirefliesSelection
    envelope: bytes
    source_captured_at: tuple[datetime, datetime, datetime]
    recovery_references: tuple[EvidenceReference, EvidenceReference, EvidenceReference]
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def _rendered_source_snapshot(
    session: Session,
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference],
    boundaries: frozenset[TrustBoundary],
    classes: frozenset[DataClassification],
) -> tuple[dict[str, Any], ...]:
    """One callback-free scalar Source/effective-ACL/revision-family observation."""
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(
            source_classification_elevation_strength().desc(),
            SourceClassificationElevation.elevated_at.desc(),
        )
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    bad_elevation = (
        select(SourceClassificationElevation.id)
        .where(
            SourceClassificationElevation.source_id == Source.id,
            SourceClassificationElevation.trust_boundary != Source.trust_boundary,
        )
        .exists()
        .correlate(Source)
    )
    child, sibling, sibling_child = aliased(Source), aliased(Source), aliased(Source)
    current = ~select(child.id).where(child.supersedes_source_id == Source.id).exists().correlate(
        Source
    )
    other_tip = (
        select(sibling.id)
        .where(
            sibling.system == Source.system,
            sibling.external_ref == Source.external_ref,
            sibling.trust_boundary == Source.trust_boundary,
            sibling.id != Source.id,
            ~select(sibling_child.id)
            .where(sibling_child.supersedes_source_id == sibling.id)
            .exists()
            .correlate(sibling),
        )
        .exists()
        .correlate(Source)
    )
    with session.no_autoflush:
        rows = (
            session.execute(
                select(
                    *Source.__table__.columns,
                    func.coalesce(latest, Source.data_classification).label(
                        "effective_classification"
                    ),
                    current.label("current_revision"),
                    other_tip.label("ambiguous_revision"),
                    bad_elevation.label("invalid_elevation_boundary"),
                )
                .where(Source.id.in_([r.source_id for r in references]))
                .order_by(Source.id)
                .limit(4)
            )
            .mappings()
            .all()
        )
    if len(rows) != 3:
        raise ValueError("missing source")
    by_id = {r["id"]: dict(r) for r in rows}
    result = []
    for ref in references:
        row = by_id[ref.source_id]
        if (
            row["system"] is not SourceSystem.MANUAL
            or row["trust_boundary"] != ref.trust_boundary
            or row["trust_boundary"] not in boundaries
            or row["data_classification"]
            not in {DataClassification.CONFIDENTIAL, DataClassification.HIGHLY_RESTRICTED}
            or row["data_classification"] not in classes
            or (
                row["data_classification"] is DataClassification.HIGHLY_RESTRICTED
                and row["effective_classification"] is not DataClassification.HIGHLY_RESTRICTED
            )
            or row["invalid_elevation_boundary"] is not False
            or row["effective_classification"] != ref.effective_classification
            or row["effective_classification"] not in classes
            or row["content_hash"] != ref.content_hash
            or not isinstance(row["content_location"], str)
            or not row["content_location"]
            or not isinstance(row["external_ref"], str)
            or not row["external_ref"]
            or not isinstance(row["captured_at"], datetime)
            or row["captured_at"].utcoffset() is None
            or row["current_revision"] is not True
            or row["ambiguous_revision"] is not False
        ):
            raise ValueError("source scope changed")
        gate = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.READ_DATA,
                access=AccessRequest(
                    data_boundary=ref.trust_boundary,
                    data_classification=ref.effective_classification,
                    requestor_boundaries=boundaries,
                    destination=Destination.LOCAL,
                ),
                description="read explicitly selected rendered research originals",
            )
        )
        if gate.outcome is not GatewayOutcome.ALLOW:
            raise ValueError("read denied")
        result.append(row)
    if result[2]["data_classification"] != references[0].effective_classification:
        raise ValueError("derived raw sensitivity changed")
    return tuple(result)


def load_rendered_fireflies_literal(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    selection: RenderedFirefliesSelection,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> LoadedRenderedFirefliesLiteral:
    """Unused explicit branch, never context dispatch or recovery acknowledgement.

    Caller supplies a clean active READ COMMITTED transaction and read authority.
    Store callbacks are trusted, not sandboxed against direct SQL/durable commits.
    Session-API changes hold; detection cannot undo a malicious prior commit.
    Only the concrete LOCAL bounded filesystem reader is supported; no fallback.
    """
    try:
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete LOCAL bounded artifact store required")
        if type(selection) is not RenderedFirefliesSelection:
            raise ValueError("closed selection")
        choice = RenderedFirefliesSelection.model_validate(selection.model_dump())
        outer = session.get_transaction()
        if outer is None or not outer.is_active or session.get_nested_transaction() is not None:
            raise ValueError("active outer transaction required")

        def clean() -> None:
            if (
                session.new
                or session.dirty
                or session.deleted
                or session.get_transaction() is not outer
                or not outer.is_active
                or session.get_nested_transaction() is not None
            ):
                raise ValueError("transaction changed")

        clean()
        _assert_ledger_isolation(session)
        clean()
        refs = (choice.detail_reference, choice.metadata_reference, choice.derived_reference)
        initial = _rendered_source_snapshot(
            session, refs, authorized_boundaries, allowed_classifications
        )
        clean()
        originals = []
        for index, row in enumerate(initial):
            clean()
            if (
                _rendered_source_snapshot(
                    session, refs, authorized_boundaries, allowed_classifications
                )
                != initial
            ):
                raise ValueError("sources changed before read")
            raw = artifacts.get_bounded(
                refs[index].trust_boundary,
                row["content_location"],
                max_bytes=32_000 if index == 2 else 2_000_000,
            )
            clean()
            if (
                type(raw) is not bytes
                or not 0 < len(raw) <= (32_000 if index == 2 else 2_000_000)
                or content_hash_of(raw) != refs[index].content_hash
            ):
                raise ValueError("artifact changed")
            originals.append(raw)
        reconstructed = prepare_rendered_fireflies_literal(
            detail_raw=originals[0],
            metadata_raw=originals[1],
            detail_reference=refs[0],
            metadata_reference=refs[1],
            block_index=choice.block_index,
            start=choice.span.start,
            end=choice.span.end,
        )
        if (
            reconstructed.requested_transcript_id != choice.requested_transcript_id
            or reconstructed.envelope != originals[2]
        ):
            raise ValueError("derived relation changed")
        clean()
        if (
            _rendered_source_snapshot(session, refs, authorized_boundaries, allowed_classifications)
            != initial
        ):
            raise ValueError("final source scope changed")
        clean()
        return LoadedRenderedFirefliesLiteral(
            choice,
            originals[2],
            (initial[0]["captured_at"], initial[1]["captured_at"], initial[2]["captured_at"]),
            refs,
        )
    except Exception:  # noqa: BLE001, S110 - fixed diagnostics
        pass
    raise ValueError("rendered Fireflies research unavailable") from None
