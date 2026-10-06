"""Explicit native quoted evidence, not current facts, discovery or authority.

Host must independently verify protected recovery and processing permission. Gmail
supports exact UTF-8 RFC822 source spans only: no MIME extraction, authorship or
sent-mail attestation. Slack supports the canonical message's exact text field.
Original bytes stay unchanged. Relevance is a host selection, never an inference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field, StringConstraints, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.ingestion.native_batch_inventory import (
    load_native_batch_inventory,
    verify_native_batch_inventory_rows,
)
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.contracts import (
    ContextItem,
    Contract,
    Digest,
    EvidenceReference,
    IntelligenceTask,
    ProcessingStatus,
    ZacEvent,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)
from zacai.state import Source, SourceClassificationElevation, SourceSystem

B = TrustBoundary
C = DataClassification


class NativeEvidenceContextError(ValueError):
    """Fixed private-safe hold with no exception cause/context."""


class NativeEvidenceSpan(Contract):
    """Python Unicode offsets into the entire exact selected field."""

    start: int = Field(ge=0, le=100_000, strict=True)
    end: int = Field(gt=0, le=100_000, strict=True)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not 0 < self.end - self.start <= 4_000:
            raise ValueError("bounded nonempty span required")
        return self


class NativeEvidenceSelection(Contract):
    source_id: UUID
    content_hash: Digest
    field: Literal["rfc822_utf8", "text"]
    field_text_hash: Digest
    spans: tuple[NativeEvidenceSpan, ...] = Field(min_length=1, max_length=1)
    relevance_reason: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=300)]

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not self.relevance_reason.strip():
            raise ValueError("explicit relevance for one bounded span required")
        return self


class NativeEvidenceMetadata(Contract):
    """Host-derived observation/selection metadata; never a provider citation."""

    reference: EvidenceReference
    source_system: SourceSystem
    external_ref: str
    field: Literal["rfc822_utf8", "text"]
    field_text_hash: Digest
    source_span: NativeEvidenceSpan
    provider_occurred_at: AwareDatetime
    source_captured_at: AwareDatetime
    batch_observed_at: AwareDatetime
    projection_observed_at: AwareDatetime
    relevance_reason: str
    project_link: Literal["UNCONFIRMED"] = "UNCONFIRMED"
    current_fact: Literal[False] = False
    authorship_verified: Literal[False] = False
    sent_approval_verified: Literal[False] = False

    @field_validator(
        "provider_occurred_at",
        "source_captured_at",
        "batch_observed_at",
        "projection_observed_at",
    )
    @classmethod
    def utc_dates(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


@dataclass(frozen=True, repr=False)
class NativeEvidenceProjection:
    context: ReviewContext
    original_task: IntelligenceTask
    original_event: ZacEvent
    metadata: tuple[NativeEvidenceMetadata, ...]
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    facts_confirmed: Literal[False] = field(default=False, init=False)


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


class _ScopedArtifacts:
    """Read-only per-get Source gate around actual public inventory parsing.

    First exact batch bytes disclose only bounded reference metadata. Every
    envelope-discovered dependency gets supplied-scope preflight before originals.
    The public loader independently validates full provider/role/hash semantics.
    """

    def __init__(
        self,
        session: Session,
        artifacts: ArtifactStore,
        references: tuple[EvidenceReference, ...],
        batch: EvidenceReference,
        authorized: frozenset[B],
        allowed: frozenset[C],
        observed: datetime,
    ) -> None:
        self.session, self.artifacts = session, artifacts
        self.refs = {r.source_id: r for r in references}
        self.batch, self.authorized, self.allowed, self.observed = (
            batch,
            authorized,
            allowed,
            observed,
        )

    def put(self, boundary: B, content_hash: str, content: bytes) -> str:
        raise ValueError("read-only projection")

    def get(self, boundary: B, content_location: str) -> bytes:
        if boundary is not B.BRAINSTORM:
            raise ValueError("read boundary differs")
        rows = _snapshot(
            self.session, tuple(self.refs.values()), self.authorized, self.allowed, self.observed
        )
        selected = [row for row in rows.values() if row["content_location"] == content_location]
        if not selected:
            raise ValueError("artifact outside declared references")
        raw = self.artifacts.get(boundary, content_location)
        if type(raw) is not bytes or not 0 < len(raw) <= 4_000_000:
            raise ValueError("artifact capacity")
        if any(content_hash_of(raw) != row["content_hash"] for row in selected):
            raise ValueError("artifact hash changed")
        if content_location == rows[self.batch.source_id]["content_location"]:
            if len(raw) > 256_000:
                raise ValueError("metadata capacity")
            envelope = json.loads(raw, object_pairs_hook=_pairs)
            groups = envelope.get("selections")
            if type(groups) is not list or not 2 <= len(groups) <= 8:
                raise ValueError("bounded dependency groups")
            dependencies: dict[UUID, EvidenceReference] = dict(self.refs)
            for group in groups:
                if type(group) is not dict or type(group.get("artifacts")) is not list:
                    raise ValueError("closed dependency metadata")
                if not 2 <= len(group["artifacts"]) <= 52:
                    raise ValueError("bounded dependency group")
                for artifact in group["artifacts"]:
                    if type(artifact) is not dict or type(artifact.get("reference")) is not dict:
                        raise ValueError("closed dependency reference")
                    ref = EvidenceReference.model_validate(artifact["reference"])
                    if ref.source_id in dependencies and dependencies[ref.source_id] != ref:
                        raise ValueError("conflicting dependency reference")
                    dependencies[ref.source_id] = ref
                    if len(dependencies) > 96:
                        raise ValueError("bounded dependency union")
            # This discovers IDs from hash-pinned metadata only, not permissions.
            # Deny before approval/profile/page/message originals are read.
            _snapshot(
                self.session,
                tuple(dependencies.values()),
                self.authorized,
                self.allowed,
                self.observed,
            )
            self.refs = dependencies
        return raw


def _scope(authorized: frozenset[B], allowed: frozenset[C]) -> None:
    if (
        type(authorized) is not frozenset
        or type(allowed) is not frozenset
        or any(type(v) is not B for v in authorized)
        or any(type(v) is not C for v in allowed)
        or C.CONFIDENTIAL not in allowed
        or not evaluate_access(
            AccessRequest(
                data_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                requestor_boundaries=authorized,
                destination=Destination.LOCAL,
            )
        ).allowed
    ):
        raise ValueError("native read denied")


def _snapshot(
    session: Session,
    refs: tuple[EvidenceReference, ...],
    authorized: frozenset[B],
    allowed: frozenset[C],
    observed: datetime,
) -> dict[UUID, dict[str, Any]]:
    """Actual callback-free scalar metadata, canonical latest-elevation policy."""
    if session.new or session.dirty or session.deleted or not 1 <= len(refs) <= 96:
        raise ValueError("clean bounded read required")
    expected = {r.source_id: r for r in refs}
    if len(expected) != len(refs):
        raise ValueError("duplicate reference")
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(SourceClassificationElevation.elevated_at.desc())
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    effective = func.coalesce(latest, Source.data_classification).label("effective")
    rows = {
        row["id"]: dict(row)
        for row in session.execute(
            select(*Source.__table__.columns, effective).where(Source.id.in_(expected)).limit(97)
        ).mappings()
    }
    if rows.keys() != expected.keys():
        raise ValueError("missing source")
    for sid, row in rows.items():
        ref = expected[sid]
        captured = row["captured_at"]
        if (
            row["trust_boundary"] is not B.BRAINSTORM
            or ref.trust_boundary is not B.BRAINSTORM
            or row["data_classification"] is not C.CONFIDENTIAL
            or row["effective"] != ref.effective_classification.value
            or ref.effective_classification is not C.CONFIDENTIAL
            or row["content_hash"] != ref.content_hash
            or not row["content_location"]
            or captured.utcoffset() is None
            or captured > observed
        ):
            raise ValueError("source metadata/access changed")
        _scope(authorized, allowed)
    return rows


def _read(artifacts: ArtifactStore, row: dict[str, Any], cap: int) -> bytes:
    raw = artifacts.get(B.BRAINSTORM, row["content_location"])
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= cap
        or content_hash_of(raw) != row["content_hash"]
    ):
        raise ValueError("source artifact integrity/capacity")
    return raw


def append_native_evidence_context(
    session: Session,
    *,
    artifacts: ArtifactStore,
    context: ReviewContext,
    batch_reference: EvidenceReference,
    approval_reference: EvidenceReference,
    approved_proposal_raw: bytes,
    selections: tuple[NativeEvidenceSelection, ...],
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
    observed_at: datetime,
) -> NativeEvidenceProjection:
    """Read-only caller transaction; returned snapshot grants no model/action use.

    Public inventory loader reparses actual originals. Every inventory dependency
    remains provenance, not quotable text; only explicit selected spans are added.
    Original event is retained exact. Added provenance lives in an explicit
    deterministic derived snapshot with causation/correlation, not a rewritten
    same-ID event. No persisted Event is created. Original task is retained exact;
    instruction/capabilities/budgets stay exact. A distinct deterministic task
    identity accompanies the distinct NEW event. Metadata is outside citable text. A hold requires caller rollback
    before any further transaction use, especially after a database error.
    observed_at is the host-supplied snapshot observation, not a wall-clock,
    session freshness or processing proof. Original batch instruction/proposal
    bytes remain historical evidence, never append/process permission. Refresh
    host recovery/permission/currentness immediately before later dispatch.
    Supplied access sets are static host declarations, not live authentication
    or revocation checks. The changed derived task bytes need their own exact host
    approval/gateway binding; old task consent cannot be inferred to cover them.
    Selected old revisions remain dated evidence: no forward revision lookup or
    semantic current-fact assertion is supplied by this projection.
    """
    result = None
    try:
        result = _append(
            session,
            artifacts,
            context,
            batch_reference,
            approval_reference,
            approved_proposal_raw,
            selections,
            authorized_boundaries,
            allowed_classifications,
            observed_at,
        )
    except Exception:  # noqa: BLE001,S110 - provider/SQL/body diagnostics remain private
        pass
    if result is None:
        raise NativeEvidenceContextError("native evidence context unavailable")
    return result


def _append(
    session: Session,
    artifacts: ArtifactStore,
    context: ReviewContext,
    batch_reference: EvidenceReference,
    approval_reference: EvidenceReference,
    approved_proposal_raw: bytes,
    selections: tuple[NativeEvidenceSelection, ...],
    authorized: frozenset[B],
    allowed: frozenset[C],
    observed: datetime,
) -> NativeEvidenceProjection:
    _scope(authorized, allowed)
    if (
        type(context) is not ReviewContext
        or type(observed) is not datetime
        or observed.utcoffset() is None
        or type(selections) is not tuple
        or not 1 <= len(selections) <= 4
        or len(context.task.context) > 16
    ):
        raise ValueError("closed bounded inputs required")
    task = IntelligenceTask.model_validate(context.task)
    observed = observed.astimezone(UTC)
    if (
        task.event.trust_boundary is not B.BRAINSTORM
        or task.event.data_classification is not C.CONFIDENTIAL
        or "contextual_meeting_review" not in task.required_capabilities
        or "compact_meeting_review" in task.required_capabilities
    ):
        raise ValueError("fixed event boundary/classification required")
    if any(type(s) is not NativeEvidenceSelection for s in selections):
        raise ValueError("exact constructed selections required")
    chosen = tuple(NativeEvidenceSelection.model_validate(s) for s in selections)
    if (
        len({s.source_id for s in chosen}) != len(chosen)
        or sum(s.end - s.start for c in chosen for s in c.spans) > 8_000
        or sum(len(c.untrusted_text.encode()) for c in task.context) > 48_000
    ):
        raise ValueError("projection capacity/ambiguity")
    if any(s.source_id in {i.reference.source_id for i in task.context} for s in chosen):
        raise ValueError("source already quoted")
    initial = {r.source_id: r for r in task.event.provenance}
    for selected in chosen:
        ref = EvidenceReference(
            source_id=selected.source_id,
            content_hash=selected.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        if ref.source_id in initial and initial[ref.source_id] != ref:
            raise ValueError("initial conflicting reference")
        initial[ref.source_id] = ref
    for control in (batch_reference, approval_reference):
        if type(control) is not EvidenceReference:
            raise ValueError("exact control reference required")
        ref = EvidenceReference.model_validate(control)
        if ref.source_id in initial and initial[ref.source_id] != ref:
            raise ValueError("conflicting control reference")
        initial[ref.source_id] = ref
    prior = _snapshot(session, tuple(initial.values()), authorized, allowed, observed)
    if (
        prior[batch_reference.source_id]["system"] is not SourceSystem.MANUAL
        or not (prior[batch_reference.source_id]["external_ref"] or "").startswith(
            "native-source-batch/"
        )
        or prior[approval_reference.source_id]["system"] is not SourceSystem.USER_INSTRUCTION
    ):
        raise ValueError("batch/instruction source roles differ")
    for selected in chosen:
        row = prior[selected.source_id]
        kind, prefix = (
            (SourceSystem.EMAIL, "gmail/rfc822/")
            if selected.field == "rfc822_utf8"
            else (SourceSystem.SLACK, "slack/message/")
        )
        if row["system"] is not kind or not (row["external_ref"] or "").startswith(prefix):
            raise ValueError("selected field/source role denied before native reads")
    scoped = _ScopedArtifacts(
        session, artifacts, tuple(initial.values()), batch_reference, authorized, allowed, observed
    )
    inventory = load_native_batch_inventory(
        session,
        artifacts=scoped,
        batch_reference=batch_reference,
        approval_reference=approval_reference,
        approved_proposal_raw=approved_proposal_raw,
        as_of=observed,
    )
    references = {ref.source_id: ref for ref in task.event.provenance}
    for ref in (
        inventory.batch_reference,
        inventory.approval_reference,
        *(r for g in inventory.artifact_references for r in g),
    ):
        if ref.source_id in references and references[ref.source_id] != ref:
            raise ValueError("conflicting evidence reference")
        references[ref.source_id] = ref
    union = tuple(references.values())
    rows = _snapshot(session, union, authorized, allowed, observed)
    if any(rows[sid] != row for sid, row in prior.items()):
        raise ValueError("original context changed during native validation")
    batch = json.loads(_read(scoped, rows[inventory.batch_reference.source_id], 256_000))
    # Loader already proves exact canonical envelope/ordered provider groups.
    roles = {
        UUID(a["reference"]["source_id"]): a
        for selection in batch["selections"]
        for a in selection["artifacts"]
    }
    items = list(task.context)
    metadata: list[NativeEvidenceMetadata] = []
    for choice in chosen:
        verify_native_batch_inventory_rows(
            session, artifacts=scoped, inventory=inventory, as_of=observed
        )
        if _snapshot(session, union, authorized, allowed, observed) != rows:
            raise ValueError("source changed before selected field read")
        if choice.source_id not in roles or choice.source_id not in rows:
            raise ValueError("selection outside retained batch")
        row, role = rows[choice.source_id], roles[choice.source_id]
        if choice.content_hash != row["content_hash"]:
            raise ValueError("selected hash differs")
        raw = _read(scoped, row, 1_000_000)
        if choice.field == "rfc822_utf8":
            if role["artifact_kind"] != "decoded-rfc822" or row["system"] is not SourceSystem.EMAIL:
                raise ValueError("exact RFC822 field role required")
            value = raw.decode("utf-8", errors="strict")
        else:
            if (
                role["artifact_kind"] != "canonical-message-json"
                or row["system"] is not SourceSystem.SLACK
            ):
                raise ValueError("exact Slack text role required")
            record = json.loads(raw)
            value = record.get("text")
        if (
            type(value) is not str
            or not value.strip()
            or content_hash_of(value.encode()) != choice.field_text_hash
        ):
            raise ValueError("exact selected field differs")
        if len(value) > 100_000 or any(s.end > len(value) for s in choice.spans):
            raise ValueError("field/span capacity")
        span = choice.spans[0]
        projection = value[span.start : span.end]
        if not projection.strip() or projection != projection.strip():
            raise ValueError("select exact nonblank span boundaries; no silent stripping")
        if any(len(line.rstrip("\r\n")) > 1500 for line in projection.splitlines(keepends=True)):
            raise ValueError("existing passage bound exceeded")
        metadata.append(
            NativeEvidenceMetadata(
                reference=references[choice.source_id],
                source_system=row["system"],
                external_ref=row["external_ref"],
                field=choice.field,
                field_text_hash=choice.field_text_hash,
                source_span=span,
                provider_occurred_at=datetime.fromisoformat(role["provider_occurred_at"]),
                source_captured_at=row["captured_at"],
                batch_observed_at=inventory.original_observed_at,
                projection_observed_at=observed,
                relevance_reason=choice.relevance_reason,
            )
        )
        if len(projection.encode()) > 12_000:
            raise ValueError("encoded projection capacity")
        items.append(ContextItem(reference=references[choice.source_id], untrusted_text=projection))
    if len(items) > 20 or sum(len(i.untrusted_text.encode()) for i in items) > 64_000:
        raise ValueError("closed output capacity")
    data = task.model_dump()
    data["context"] = [i.model_dump() for i in items]
    data["event"]["provenance"] = [r.model_dump() for r in union]
    original_task_data = task.model_dump(mode="json")
    # canonical_bytes sorts object keys, not set-derived JSON arrays.
    original_task_data["required_capabilities"] = sorted(task.required_capabilities)
    derivation = canonical_bytes(
        {
            "format": "zac-native-evidence-projection-v1",
            "original_task": original_task_data,
            "metadata": [m.model_dump(mode="json") for m in metadata],
            "provenance": [r.model_dump(mode="json") for r in union],
            "selected_text": [i.untrusted_text for i in items[len(task.context) :]],
        }
    )
    data["event"]["event_id"] = uuid5(
        task.event.event_id, "native-evidence-projection/" + content_hash_of(derivation)
    )
    data["task_id"] = uuid5(
        task.task_id, "native-evidence-projection-task/" + content_hash_of(derivation)
    )
    data["event"]["processing_status"] = ProcessingStatus.NEW
    data["event"]["causation_id"] = task.event.event_id
    data["event"]["event_type"] = "native.evidence.selected"
    data["event"]["producer"] = "native-evidence-projection-v1"
    data["event"]["observed_at"] = observed
    projected = IntelligenceTask.model_validate(data)
    derived = ReviewContext(
        projected,
        context.meeting_source_id,
        context.related_source_ids | frozenset(c.source_id for c in chosen),
    )
    # Exact existing line terminators/packing/250-passage ceiling, no truncation.
    # Passing preparation does not authorize or dispatch this new task.
    prepare_contextual_request(derived)
    # LAST external artifact callback belongs to public verifier; scalar union
    # after it covers old context, all dependencies, exact rows and current ACL.
    verify_native_batch_inventory_rows(
        session, artifacts=scoped, inventory=inventory, as_of=observed
    )
    if _snapshot(session, union, authorized, allowed, observed) != rows:
        raise ValueError("final source snapshot changed")
    return NativeEvidenceProjection(derived, task, task.event, tuple(metadata))
