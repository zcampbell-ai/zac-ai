"""Bounded read-only reconciliation; never infers delivery or retries a claim."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import BackupObjectStore
from zacai.contextual_attempt import find_failed_attempt_receipt
from zacai.contextual_authorization import _load, contextual_claim_bytes
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes
from zacai.intelligence.contextual_host import ContextualRunScope
from zacai.intelligence.contracts import Contract, Digest
from zacai.intelligence.review_audit import ContextualAuditEvent, ContextualAuditStage
from zacai.intelligence.review_context import _unique_pairs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _bytes, _find
from zacai.state import Source, SourceSystem


class AttemptStatus(str, Enum):
    NO_CLAIM = "NO_CLAIM"  # No durable claim; earlier unclaimed failures may exist.
    INCOMPLETE_ATTEMPT = "INCOMPLETE_ATTEMPT"
    FAILED_RECOVERY_REQUIRED = "FAILED_RECOVERY_REQUIRED"
    FAILED_RECOVERY_VERIFIED = "FAILED_RECOVERY_VERIFIED"
    PACKET_REVIEW_REQUIRED = "PACKET_REVIEW_REQUIRED"


class AttemptReconciliation(Contract):
    approval_id: UUID
    run_id: UUID | None
    status: AttemptStatus
    audit_source_ids: tuple[UUID, ...]
    packet_source_id: UUID | None = None
    packet_digest: Digest | None = None
    # PACKET_REVIEW_REQUIRED does not prove protection or delivery.


class AttemptReconciliationError(RuntimeError):
    """Fixed diagnostics; private trace locals must not be recorded."""


def _audit_rows(session: Session) -> list[Source]:
    return list(
        session.scalars(
            select(Source)
            .where(
                Source.trust_boundary == B.BRAINSTORM,
                Source.system == SourceSystem.MANUAL,
                Source.external_ref.startswith("contextual-run-audit/"),
            )
            .limit(2001)
        )
    )


def reconcile_contextual_approval(
    factory: sessionmaker[Session],
    *,
    artifacts: ArtifactStore,
    approval_id: UUID,
    verification_objects: BackupObjectStore,
    identity_path: Path,
) -> AttemptReconciliation:
    """Inspect canonical claim and bounded audit inventory; no business/source writes.

    Audit refs currently index UUID, not run. Reject an inventory above 2,000
    instead of silently taking a partial sample; a future indexed ledger avoids
    this conservative scan. Only closed audit metadata is read, never transcripts.
    A claimed incomplete attempt always needs operator reconciliation and a new
    explicit approval before another generation; no automatic retry is available.
    """
    try:
        with factory() as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            consent = _load(
                session, artifacts, approval_id
            )  # historical consent, not active authority
            claim = _find(session, f"contextual-claim/{approval_id}", SourceSystem.MANUAL)
            if claim is None:
                return AttemptReconciliation(
                    approval_id=approval_id,
                    run_id=None,
                    status=AttemptStatus.NO_CLAIM,
                    audit_source_ids=(),
                )
            raw = _bytes(session, artifacts, claim)
            data = json.loads(raw, object_pairs_hook=_unique_pairs)
            run_id = UUID(data["run_id"])
            scope = ContextualRunScope(
                run_id,
                consent.builder_id,
                consent.selection,
                consent.authorized_boundaries,
                consent.allowed_classifications,
                consent.route,
                consent.model_digest,
            )
            if raw != contextual_claim_bytes(
                consent, approval_id, scope, data["request_digest"], data["context_digest"]
            ):
                raise ValueError("claim inventory differs")
            rows = _audit_rows(session)
            if len(rows) > 2000:
                raise ValueError("audit inventory outside capacity")
            matched = []
            for source in rows:
                if source.data_classification != C.CONFIDENTIAL:
                    raise ValueError("audit base classification differs")
                raw = _bytes(session, artifacts, source)
                event = ContextualAuditEvent.model_validate(
                    json.loads(raw, object_pairs_hook=_unique_pairs)
                )
                if (
                    raw != canonical_bytes(event.model_dump(mode="json"))
                    or source.external_ref != f"contextual-run-audit/{event.audit_event_id}"
                    or source.captured_at != event.recorded_at
                ):
                    raise ValueError("audit inventory differs")
                if event.run_id != run_id:
                    continue
                if (
                    event.builder_id != consent.builder_id
                    or event.route != consent.route.identity
                    or event.model_digest != consent.model_digest
                    or event.request_digest != data["request_digest"]
                    or event.context_digest != data["context_digest"]
                    or event.trust_boundary != B.BRAINSTORM
                    or event.data_classification != C.CONFIDENTIAL
                ):
                    raise ValueError("claimed run audit differs")
                matched.append((source.id, event))
            stage_order = {
                ContextualAuditStage.REQUEST_PREPARED: 0,
                ContextualAuditStage.DISPATCH_PREPARED: 1,
                ContextualAuditStage.PACKET_CAPTURED: 2,
                ContextualAuditStage.RUN_FAILED: 3,
            }
            matched.sort(key=lambda pair: stage_order[pair[1].stage])
            stages = [event.stage for _, event in matched]
            if len(set(stages)) != len(stages) or len(stages) > 4:
                raise ValueError("ambiguous audit stages")
            captured = [
                event for _, event in matched if event.stage == ContextualAuditStage.PACKET_CAPTURED
            ]
            if captured:
                captured_event = captured[0]
                packet_id, packet_digest = (
                    captured_event.packet_source_id,
                    captured_event.packet_digest,
                )
                if packet_id is None or packet_digest is None:
                    raise ValueError("capture binding unavailable")
                packet_source = session.get(Source, packet_id)
                if (
                    packet_source is None
                    or packet_source.trust_boundary != B.BRAINSTORM
                    or packet_source.content_hash != packet_digest
                    or packet_source.system != SourceSystem.MANUAL
                ):
                    raise ValueError("captured packet differs")
            else:
                packet_id, packet_digest = None, None
            failures = [
                event for _, event in matched if event.stage == ContextualAuditStage.RUN_FAILED
            ]
            if failures and (failures[0].packet_source_id, failures[0].packet_digest) != (
                packet_id,
                packet_digest,
            ):
                raise ValueError("failure event packet differs")
            if ContextualAuditStage.RUN_FAILED in stages:
                receipt = find_failed_attempt_receipt(
                    session,
                    artifacts=artifacts,
                    run_id=run_id,
                    verification_objects=verification_objects,
                    identity_path=identity_path,
                )
                if receipt is not None and (
                    receipt.locator.approval_id != approval_id
                    or receipt.locator.builder_id != consent.builder_id
                    or set(receipt.locator.audit_source_ids) != {sid for sid, _ in matched}
                ):
                    raise ValueError("failed receipt differs from claimed run")
                if receipt is not None:
                    approval_source = session.get(Source, approval_id)
                    if (
                        approval_source is None
                        or approval_source.content_hash is None
                        or claim.content_hash is None
                    ):
                        raise ValueError("authority inventory unavailable")
                    required = {
                        (approval_id, approval_source.content_hash),
                        (claim.id, claim.content_hash),
                    }
                    if packet_id is not None and packet_digest is not None:
                        required.add((packet_id, packet_digest))
                    if not required.issubset(set(receipt.locator.source_hashes)):
                        raise ValueError("failure receipt omits required recovery inventory")
                status = (
                    AttemptStatus.FAILED_RECOVERY_VERIFIED
                    if receipt
                    else AttemptStatus.FAILED_RECOVERY_REQUIRED
                )
            elif stages == [
                ContextualAuditStage.REQUEST_PREPARED,
                ContextualAuditStage.DISPATCH_PREPARED,
                ContextualAuditStage.PACKET_CAPTURED,
            ]:
                status = AttemptStatus.PACKET_REVIEW_REQUIRED
            else:
                status = AttemptStatus.INCOMPLETE_ATTEMPT
            return AttemptReconciliation(
                approval_id=approval_id,
                run_id=run_id,
                status=status,
                audit_source_ids=tuple(sid for sid, _ in matched),
                packet_source_id=packet_id,
                packet_digest=packet_digest,
            )
    except Exception:  # noqa: BLE001, S110
        pass
    raise AttemptReconciliationError("contextual attempt reconciliation unavailable")
