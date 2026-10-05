"""Explicit candidate research excerpts; no discovery, inference or authority.

Only the contextual host uses this seam. Quotes address the deterministic
projection, not a native provider transcript; original field ranges stay in scope.
"""

from __future__ import annotations

import json
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, StrictInt, model_validator
from sqlalchemy.orm import Session

from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contracts import ContextItem, Contract, Digest, IntelligenceTask
from zacai.intelligence.evidence import resolve_evidence_reference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.project_review_context import ReviewedProjectEvidence
from zacai.intelligence.review_context import MeetingEvidence
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary
from zacai.research_intake import _constant, _float, _pairs
from zacai.review_authorization import _bytes
from zacai.state import SourceSystem
from zacai.state_repository import get_source


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
