"""Initial native context assembly only; no consent, processing, capture or recovery.

A retained binding is exact proposal data, never authenticated authority. The
host must retain it before future approval and revalidate current canonical data
rather than reminting observations or stripping dates/causation. Store callbacks
are trusted; Session API changes hold but cannot undo durable direct-SQL writes.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from zacai.contextual_authorization import prepared_native_contextual_digest
from zacai.ingestion.artifact_store import (
    ArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.native_batch_inventory import (
    NativeBatchRecoverySelection,
    load_native_batch_inventory,
    prepare_native_batch_recovery_selection,
)
from zacai.ingestion.native_proposal_retention import load_retained_native_proposal
from zacai.intelligence.contextual_generation import (
    ContextualRequestV2,
    encode_native_contextual_request,
    prepare_native_contextual_request,
)
from zacai.intelligence.contextual_host import (
    assemble_contextual_context,
    contextual_request_digest,
)
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.native_evidence_context import (
    NativeEvidenceProjection,
    NativeEvidenceSelection,
    append_native_evidence_context,
)
from zacai.intelligence.project_review_context import ReviewedProjectEvidence
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_freshness import review_evidence_digest
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import (
    Meeting,
    MeetingProjectAssociation,
    MeetingProjectAssociationRetraction,
    MeetingRetraction,
    MeetingSource,
    ProjectHead,
    Source,
    SourceClassificationElevation,
)
from zacai.state_repository import get_meeting_project_context

MAX_REFERENCES = 96


class NativeContextualAssemblyError(ValueError):
    """Fixed public hold; hosts must suppress traceback-local capture."""


class NativeContextualSelection(Contract):
    format: Literal["zac-native-contextual-selection-v1"]
    selected: MeetingEvidence
    earlier: tuple[MeetingEvidence, ...] = Field(default=(), max_length=7)
    projects: tuple[ReviewedProjectEvidence, ...] = Field(default=(), max_length=3)
    batch_id: UUID
    batch_reference: EvidenceReference
    intake_instruction_reference: EvidenceReference
    proposal_reference: EvidenceReference
    approved_proposal_hash: Digest
    native: tuple[NativeEvidenceSelection, ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def closed(self) -> Self:
        meetings = (self.selected, *self.earlier)
        if any(type(item) is not MeetingEvidence for item in meetings) or any(
            type(item) is not ReviewedProjectEvidence for item in self.projects
        ):
            raise ValueError("exact base selection required")
        if any(
            type(item.meeting_id) is not UUID or type(item.source_id) is not UUID
            for item in meetings
        ):
            raise ValueError("exact base UUIDs required")
        if any(
            type(item.association_id) is not UUID or type(item.source_id) is not UUID
            for item in self.projects
        ):
            raise ValueError("exact project UUIDs required")
        base_ids = [item.source_id for item in meetings] + [
            item.source_id for item in self.projects
        ]
        controls = (
            self.batch_reference,
            self.intake_instruction_reference,
            self.proposal_reference,
        )
        native_ids = [item.source_id for item in self.native]
        all_ids = base_ids + [item.source_id for item in controls] + native_ids
        if len(set(all_ids)) != len(all_ids) or len({item.meeting_id for item in meetings}) != len(
            meetings
        ):
            raise ValueError("distinct base/control/provider selection required")
        if self.proposal_reference.content_hash != self.approved_proposal_hash or any(
            item.trust_boundary is not B.BRAINSTORM
            or item.effective_classification is not C.CONFIDENTIAL
            for item in controls
        ):
            raise ValueError("fixed native control scope required")
        return self

    def base_selection(self) -> ReviewSelection:
        return ReviewSelection(self.selected, self.earlier, self.projects)


@dataclass(frozen=True, repr=False)
class NativeContextualPreparation:
    selection: NativeContextualSelection
    projection: NativeEvidenceProjection
    request: ContextualRequestV2
    recovery_selection: NativeBatchRecoverySelection
    hashes: tuple[tuple[UUID, str], ...]
    source_fingerprints: tuple[tuple[UUID, str], ...]
    binding_bytes: bytes
    relationship_fingerprint: str
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    facts_confirmed: Literal[False] = field(default=False, init=False)
    complete_history_verified: Literal[False] = field(default=False, init=False)


@contextmanager
def _native_window(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session:
        bind = session.get_bind()
        if not isinstance(bind, Engine) or bind.dialect.name != "postgresql":
            raise ValueError("engine-bound PostgreSQL required")
        if (
            session.in_transaction()
            or session.identity_map
            or session.new
            or session.dirty
            or session.deleted
        ):
            raise ValueError("fresh native session required")
        with session.begin():
            session.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY"))
            yield session


def _session_unchanged(session: Session, transaction: object) -> None:
    if (
        session.get_transaction() is not transaction
        or not session.in_transaction()
        or not getattr(transaction, "is_active", False)
        or session.get_nested_transaction() is not None
        or session.new
        or session.dirty
        or session.deleted
    ):
        raise ValueError("native read transaction changed")


def _base_relationships(
    session: Session, selection: NativeContextualSelection | ReviewSelection
) -> str:
    # Callback-free current canonical reads; no retained/private artifact text.
    if type(selection) not in {NativeContextualSelection, ReviewSelection}:
        raise ValueError("exact canonical relationship selection")
    session.expire_all()
    ids = tuple(item.meeting_id for item in (selection.selected, *selection.earlier))
    meetings = list(
        session.execute(
            select(*Meeting.__table__.columns).where(Meeting.id.in_(ids)).limit(9)
        ).mappings()
    )
    withdrawn = session.scalar(
        select(MeetingRetraction.id).where(MeetingRetraction.meeting_id.in_(ids)).limit(1)
    )
    if withdrawn is not None:
        raise ValueError("selected meeting was retracted")
    if len(meetings) != len(ids):
        raise ValueError("selected meeting relationship missing")
    links = list(
        session.execute(
            select(*MeetingSource.__table__.columns)
            .where(MeetingSource.meeting_id.in_(ids))
            .limit(97)
        ).mappings()
    )
    if len(links) > 96:
        raise ValueError("bounded meeting relationship required")
    observations = {
        "meetings": sorted(_fingerprint(dict(row)) for row in meetings),
        "meeting_sources": sorted(_fingerprint(dict(row)) for row in links),
    }
    if selection.projects:
        associations = list(
            session.execute(
                select(*MeetingProjectAssociation.__table__.columns)
                .where(MeetingProjectAssociation.meeting_id.in_(ids))
                .limit(97)
            ).mappings()
        )
        if len(associations) > 96:
            raise ValueError("bounded project relationship required")
        association_ids = tuple(row["id"] for row in associations)
        project_ids = tuple({row["project_id"] for row in associations})
        retractions = list(
            session.execute(
                select(*MeetingProjectAssociationRetraction.__table__.columns)
                .where(MeetingProjectAssociationRetraction.association_id.in_(association_ids))
                .limit(97)
            ).mappings()
        )
        heads = list(
            session.execute(
                select(*ProjectHead.__table__.columns)
                .where(ProjectHead.entity_id.in_(project_ids))
                .limit(97)
            ).mappings()
        )
        if len(retractions) > 96 or len(heads) > 96:
            raise ValueError("bounded project availability required")
        observations["project_associations"] = sorted(
            _fingerprint(dict(row)) for row in associations
        )
        observations["project_retractions"] = sorted(_fingerprint(dict(row)) for row in retractions)
        observations["project_heads"] = sorted(_fingerprint(dict(row)) for row in heads)
        contexts: list[str] = []
        for mid in ids:
            active = get_meeting_project_context(
                session,
                meeting_id=mid,
                requestor_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
            if len(active) > 96:
                raise ValueError("bounded active project context required")
            contexts.extend(
                _fingerprint(
                    {
                        "meeting_id": mid,
                        "association_id": link.association_id,
                        "project_id": link.project_id,
                        "reviewed_project_version": link.reviewed_project_version,
                        "current_project_version": link.current_project_version,
                        "confirmation_source_id": link.confirmation_source_id,
                        "effective_classification": link.effective_classification,
                    }
                )
                for link in active
            )
        observations["project_links"] = sorted(contexts)
    return content_hash_of(canonical_bytes(observations))


def _merge(*groups: tuple[EvidenceReference, ...]) -> tuple[EvidenceReference, ...]:
    result: dict[UUID, EvidenceReference] = {}
    for group in groups:
        for reference in group:
            if reference.source_id in result and result[reference.source_id] != reference:
                raise ValueError("conflicting exact references")
            result[reference.source_id] = reference
    if not 1 <= len(result) <= MAX_REFERENCES:
        raise ValueError("bounded full dependency union required")
    return tuple(result[sid] for sid in sorted(result, key=str))


def _fingerprint(row: dict[str, object]) -> str:
    def value(item: object) -> object:
        if isinstance(item, UUID):
            return str(item)
        if isinstance(item, datetime):
            return item.astimezone(UTC).isoformat()
        if isinstance(item, Enum):
            return item.value
        return item

    return content_hash_of(canonical_bytes({name: value(item) for name, item in row.items()}))


def _rows(
    session: Session, refs: tuple[EvidenceReference, ...], observed: datetime
) -> dict[UUID, str]:
    expected = {item.source_id: item for item in refs}
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(SourceClassificationElevation.elevated_at.desc())
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    effective = func.coalesce(latest, Source.data_classification).label("effective")
    found: dict[UUID, str] = {}
    for mapping in session.execute(
        select(*Source.__table__.columns, effective)
        .where(Source.id.in_(expected))
        .limit(MAX_REFERENCES + 1)
    ).mappings():
        row = dict(mapping)
        reference = expected[row["id"]]
        if (
            row["trust_boundary"] is not B.BRAINSTORM
            or reference.trust_boundary is not B.BRAINSTORM
            or row["data_classification"] is not C.CONFIDENTIAL
            or row["effective"] != C.CONFIDENTIAL
            or reference.effective_classification is not C.CONFIDENTIAL
            or row["content_hash"] != reference.content_hash
            or not row["content_location"]
            or row["captured_at"].tzinfo is None
            or row["captured_at"] > observed
        ):
            raise ValueError("canonical dependency outside fixed read scope")
        found[row["id"]] = _fingerprint(row)
    if found.keys() != expected.keys():
        raise ValueError("canonical dependency missing")
    return found


class _ScopedReadStore:
    def __init__(
        self,
        session: Session,
        store: ArtifactStore,
        refs: tuple[EvidenceReference, ...],
        observed: datetime,
        transaction: object,
    ):
        self.session, self.store, self.refs = session, store, refs
        self.observed, self.transaction = observed, transaction

    def put(self, trust_boundary: B, content_hash: str, raw_bytes: bytes) -> str:
        raise ValueError("read-only native assembly")

    def get(self, trust_boundary: B, content_location: str) -> bytes:
        _session_unchanged(self.session, self.transaction)
        _rows(self.session, self.refs, self.observed)
        raw = self.store.get(trust_boundary, content_location)
        _session_unchanged(self.session, self.transaction)
        return raw


def assemble_native_contextual_selection(
    factory: sessionmaker[Session],
    *,
    artifacts: ArtifactStore,
    selection: NativeContextualSelection,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
    observed_at: datetime,
    max_output_tokens: int = 1600,
) -> NativeContextualPreparation:
    """One initial assembly; no restart/reapproval or current processing gate."""
    result = None
    try:
        if type(selection) is not NativeContextualSelection:
            raise ValueError("exact native selection required")
        selected = NativeContextualSelection.model_validate(selection)
        if (
            type(authorized_boundaries) is not frozenset
            or authorized_boundaries != frozenset({B.BRAINSTORM})
            or any(type(item) is not B for item in authorized_boundaries)
            or type(allowed_classifications) is not frozenset
            or allowed_classifications != frozenset({C.CONFIDENTIAL})
            or any(type(item) is not C for item in allowed_classifications)
            or type(observed_at) is not datetime
            or observed_at.tzinfo is None
        ):
            raise ValueError("fixed declared scope and aware observation required")
        observed = observed_at.astimezone(UTC)
        # Existing family and its RR/read-only assembly remain untouched.
        base = assemble_contextual_context(
            factory,
            artifacts=artifacts,
            selection=selected.base_selection(),
            authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications,
            now=observed,
            max_output_tokens=max_output_tokens,
        )
        controls = (
            selected.batch_reference,
            selected.intake_instruction_reference,
            selected.proposal_reference,
        )
        initial_refs = _merge(base.task.event.provenance, controls)
        with _native_window(factory) as session:
            transaction = session.get_transaction()
            _session_unchanged(session, transaction)
            initial = _rows(session, initial_refs, observed)
            scoped = _ScopedReadStore(session, artifacts, initial_refs, observed, transaction)
            proposal = load_retained_native_proposal(
                session,
                artifacts=scoped,
                proposal_reference=selected.proposal_reference,
                batch_id=selected.batch_id,
                expected_proposal_hash=selected.approved_proposal_hash,
                as_of=observed,
            )
            inventory = load_native_batch_inventory(
                session,
                artifacts=scoped,
                batch_reference=selected.batch_reference,
                approval_reference=selected.intake_instruction_reference,
                approved_proposal_raw=proposal,
                as_of=observed,
            )
            complete = prepare_native_batch_recovery_selection(
                session,
                artifacts=scoped,
                inventory=inventory,
                proposal_reference=selected.proposal_reference,
                approved_proposal_raw=proposal,
                as_of=observed,
            )
            provider_refs = tuple(ref for group in inventory.artifact_references for ref in group)
            full_refs = _merge(initial_refs, provider_refs)
            if dict(complete.hashes) != {
                r.source_id: r.content_hash for r in _merge(controls, provider_refs)
            }:
                raise ValueError("complete native dependency relationship differs")
            scoped.refs = full_refs
            before = _rows(session, full_refs, observed)
            if any(before[sid] != fingerprint for sid, fingerprint in initial.items()):
                raise ValueError("original control/context observation changed")
            projection = append_native_evidence_context(
                session,
                artifacts=scoped,
                context=base,
                proposal_reference=selected.proposal_reference,
                batch_reference=selected.batch_reference,
                approval_reference=selected.intake_instruction_reference,
                approved_proposal_raw=proposal,
                selections=selected.native,
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                observed_at=observed,
            )
            if (
                projection.original_task != base.task
                or projection.original_event != base.task.event
            ):
                raise ValueError("original assembly identity changed")
            request = prepare_native_contextual_request(projection)
            request_raw = encode_native_contextual_request(request)
            original = projection.original_task.model_dump(mode="json")
            original["required_capabilities"] = sorted(
                projection.original_task.required_capabilities
            )
            # Final external reads rebind the original complete native envelope.
            prepare_native_batch_recovery_selection(
                session,
                artifacts=scoped,
                inventory=inventory,
                proposal_reference=selected.proposal_reference,
                approved_proposal_raw=proposal,
                as_of=observed,
            )
            _session_unchanged(session, transaction)
            relationships = _base_relationships(session, selected)
            fresh_base = assemble_contextual_context(
                factory,
                artifacts=scoped,
                selection=selected.base_selection(),
                authorized_boundaries=authorized_boundaries,
                allowed_classifications=allowed_classifications,
                now=observed,
                max_output_tokens=max_output_tokens,
            )
            if review_evidence_digest(fresh_base) != review_evidence_digest(base):
                raise ValueError("base relationship or evidence changed")
            _session_unchanged(session, transaction)
            if _base_relationships(session, selected) != relationships:
                raise ValueError("base relationship changed during fresh reads")
            final = _rows(session, full_refs, observed)
            if before != final:
                raise ValueError("final complete canonical dependency changed")
            binding = canonical_bytes(
                {
                    "format": "zac-native-contextual-assembly-binding-v2",
                    "selection": selected.model_dump(mode="json"),
                    "original_task": original,
                    "request": json.loads(request_raw),
                    "request_digest": contextual_request_digest(request),
                    "prepared_digest": prepared_native_contextual_digest(request),
                    "relationship_fingerprint": relationships,
                    "source_fingerprints": [
                        [str(sid), digest]
                        for sid, digest in sorted(final.items(), key=lambda item: str(item[0]))
                    ],
                    "hashes": [[str(ref.source_id), ref.content_hash] for ref in full_refs],
                }
            )
            if len(binding) > 512_000:
                raise ValueError("bounded retained binding required")
            prepared = NativeContextualPreparation(
                selected,
                projection,
                request,
                complete,
                tuple((ref.source_id, ref.content_hash) for ref in full_refs),
                tuple(sorted(final.items(), key=lambda item: str(item[0]))),
                binding,
                relationships,
            )
        result = prepared
    except Exception:  # noqa: BLE001,S110 - no private diagnostics or chained input
        pass
    if result is None:
        raise NativeContextualAssemblyError("native contextual assembly held")
    return result
