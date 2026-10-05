"""Recovery evidence for failed contextual attempts; never draft or authority.

A canonical locator precedes the snapshot; an independently encrypted receipt
follows full restore. Failure recovery does not retry, reactivate consent, prove
model dispatch or release a captured packet. Error reporters must omit locals.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.orm import Session

from zacai.backup_artifacts import (
    BackupObjectStore,
    age_decrypt,
    age_encrypt,
    backup_object_key_for,
)
from zacai.contextual_authorization import _load, contextual_claim_bytes
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import _recover
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contextual_host import ContextualHostFailure, ContextualRunScope
from zacai.intelligence.contracts import Contract, Digest
from zacai.intelligence.review_audit import (
    ContextualAuditEvent,
    ContextualAuditStage,
    ReviewPreContextAudit,
)
from zacai.intelligence.review_context import _unique_pairs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _bytes, _find, _write
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class AttemptRecoveryError(RuntimeError):
    """Fixed failure diagnostics, no copied private content."""


class AttemptLocator(Contract):
    format: Literal["zac-contextual-failed-attempt-locator-v1"] = (
        "zac-contextual-failed-attempt-locator-v1"
    )
    id: UUID
    run_id: UUID
    builder_id: UUID
    approval_id: UUID
    audit_source_ids: tuple[UUID, ...] = Field(min_length=1, max_length=16)
    source_hashes: tuple[tuple[UUID, Digest], ...] = Field(min_length=2, max_length=20)
    created_at: AwareDatetime

    @model_validator(mode="after")
    def exact_inventory(self) -> Self:
        ids = [sid for sid, _ in self.source_hashes]
        if (
            len(set(ids)) != len(ids)
            or len(set(self.audit_source_ids)) != len(self.audit_source_ids)
            or not set(self.audit_source_ids).issubset(ids)
            or self.approval_id not in ids
        ):
            raise ValueError("invalid attempt inventory")
        return self

    @property
    def receipt_object(self) -> str:
        return f"BRAINSTORM/state/contextual-attempt-{self.id}/receipt.age"


class AttemptRecoveryReceipt(Contract):
    format: Literal["zac-contextual-failed-attempt-receipt-v1"] = (
        "zac-contextual-failed-attempt-receipt-v1"
    )
    locator: AttemptLocator
    locator_source_id: UUID
    locator_digest: Digest
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    state_object: str
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_object: str
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def exact_objects(self) -> Self:
        prefix = f"BRAINSTORM/state/contextual-attempt-{self.locator.id}"
        if (
            self.locator_digest
            != content_hash_of(canonical_bytes(self.locator.model_dump(mode="json")))
            or self.state_object != f"{prefix}/{self.state_ciphertext_hash}.age"
            or self.journal_object != f"{prefix}/journal-{self.journal_ciphertext_hash}.age"
            or self.verified_at < self.locator.created_at
        ):
            raise ValueError("attempt receipt mismatch")
        return self


def protect_failed_attempt(
    protector: BrainstormContextualProtector,
    *,
    failure: ContextualHostFailure,
    approval_id: UUID,
    builder_id: UUID,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> AttemptRecoveryReceipt:
    """Trusted operator only: inspect durable failure, backup, independently restore."""
    try:
        if failure.audit_unavailable or not 1 <= len(failure.audit_source_ids) <= 16:
            raise ValueError("failure audit unavailable")
        hashes: dict[UUID, str] = {}
        with protector._factory() as session:
            consent = _load(session, protector._artifacts, approval_id)
            if consent.builder_id != builder_id:
                raise ValueError("builder differs")
            approval = session.get(Source, approval_id)
            if approval is None or approval.content_hash is None:
                raise ValueError("approval inventory unavailable")
            hashes[approval_id] = approval.content_hash
            events: list[ContextualAuditEvent | ReviewPreContextAudit] = []
            for sid in failure.audit_source_ids:
                source = session.get(Source, sid)
                if (
                    source is None
                    or source.system != SourceSystem.MANUAL
                    or source.data_classification != C.CONFIDENTIAL
                    or source.trust_boundary != B.BRAINSTORM
                ):
                    raise ValueError("audit outside scope")
                raw = _bytes(session, protector._artifacts, source)
                data = json.loads(raw, object_pairs_hook=_unique_pairs)
                pre = data.get("format") == "zac-review-pre-context-audit-v1"
                event = (
                    ReviewPreContextAudit.model_validate(data)
                    if pre
                    else ContextualAuditEvent.model_validate(data)
                )
                prefix = "meeting-review-pre-context-audit" if pre else "contextual-run-audit"
                if (
                    raw != canonical_bytes(event.model_dump(mode="json"))
                    or source.external_ref != f"{prefix}/{event.audit_event_id}"
                    or source.captured_at != event.recorded_at
                    or event.run_id != failure.run_id
                    or event.trust_boundary != B.BRAINSTORM
                    or event.data_classification != C.CONFIDENTIAL
                ):
                    raise ValueError("failure audit mismatch")
                if isinstance(event, ContextualAuditEvent) and (
                    event.builder_id != builder_id
                    or event.route != consent.route.identity
                    or event.model_digest != consent.model_digest
                ):
                    raise ValueError("failure scope mismatch")
                if source.content_hash is None:
                    raise ValueError("audit hash unavailable")
                hashes[sid] = source.content_hash
                events.append(event)
            if isinstance(events[-1], ReviewPreContextAudit):
                if len(events) != 1:
                    raise ValueError("mixed pre-context failure")
            else:
                normal = [e for e in events if isinstance(e, ContextualAuditEvent)]
                stages = [e.stage for e in normal]
                allowed = [
                    ContextualAuditStage.REQUEST_PREPARED,
                    ContextualAuditStage.DISPATCH_PREPARED,
                    ContextualAuditStage.PACKET_CAPTURED,
                ]
                if (
                    len(normal) != len(events)
                    or stages[-1] != ContextualAuditStage.RUN_FAILED
                    or stages[:-1] != allowed[: len(stages) - 1]
                    or len({(e.task_id, e.request_digest, e.context_digest) for e in normal}) != 1
                ):
                    raise ValueError("incomplete or inconsistent failure audit")
                captured = [e for e in normal if e.stage == ContextualAuditStage.PACKET_CAPTURED]
                terminal = normal[-1]
                if captured:
                    event = captured[0]
                    if (
                        event.packet_source_id is None
                        or event.packet_digest is None
                        or (terminal.packet_source_id, terminal.packet_digest)
                        != (event.packet_source_id, event.packet_digest)
                    ):
                        raise ValueError("withheld packet differs from failure")
                    # A classification change can prohibit re-reading the private
                    # packet. Recovery still preserves exact bytes/hash; it never
                    # returns packet contents or validates present access.
                    packet_source = session.get(Source, event.packet_source_id)
                    if (
                        packet_source is None
                        or packet_source.trust_boundary != B.BRAINSTORM
                        or packet_source.system != SourceSystem.MANUAL
                        or packet_source.content_hash != event.packet_digest
                    ):
                        raise ValueError("withheld packet Source differs")
                    hashes[event.packet_source_id] = event.packet_digest
                elif any(
                    e.packet_source_id is not None or e.packet_digest is not None for e in normal
                ):
                    raise ValueError("packet binding precedes capture")
                claim = _find(session, f"contextual-claim/{approval_id}", SourceSystem.MANUAL)
                if claim is not None:
                    raw = _bytes(session, protector._artifacts, claim)
                    scope = ContextualRunScope(
                        failure.run_id,
                        builder_id,
                        consent.selection,
                        consent.authorized_boundaries,
                        consent.allowed_classifications,
                        consent.route,
                        consent.model_digest,
                    )
                    if raw != contextual_claim_bytes(
                        consent,
                        approval_id,
                        scope,
                        normal[0].request_digest,
                        normal[0].context_digest,
                    ):
                        raise ValueError("claim differs from failed attempt")
                    if claim.content_hash is None:
                        raise ValueError("claim hash unavailable")
                    hashes[claim.id] = claim.content_hash
                elif ContextualAuditStage.DISPATCH_PREPARED in stages:
                    raise ValueError("dispatch preparation without claim")
        locator = AttemptLocator(
            id=uuid4(),
            run_id=failure.run_id,
            builder_id=builder_id,
            approval_id=approval_id,
            audit_source_ids=failure.audit_source_ids,
            source_hashes=tuple(sorted(hashes.items(), key=lambda v: str(v[0]))),
            created_at=clock(),
        )
        raw = canonical_bytes(locator.model_dump(mode="json"))
        digest = content_hash_of(raw)
        with protector._factory() as session:
            sid = _write(
                session,
                protector._artifacts,
                f"contextual-failed-attempt/{failure.run_id}/{locator.id}",
                SourceSystem.MANUAL,
                raw,
                locator.created_at,
            )
            session.commit()
        hashes[sid] = digest
        state = protector._protect_state(
            hashes, f"BRAINSTORM/state/contextual-attempt-{locator.id}"
        )
        receipt = AttemptRecoveryReceipt(
            locator=locator,
            locator_source_id=sid,
            locator_digest=digest,
            verified_at=clock(),
            **asdict(state),
        )
        receipt_raw = canonical_bytes(receipt.model_dump(mode="json"))
        ciphertext = age_encrypt(receipt_raw, protector._recipient)
        if protector._reader.exists(locator.receipt_object):
            raise ValueError("attempt receipt already exists")
        protector._put(locator.receipt_object, ciphertext)
        returned = protector._read(locator.receipt_object, 64_000)
        if returned != ciphertext or age_decrypt(returned, protector._identity) != receipt_raw:
            raise ValueError("attempt receipt recovery failed")
        with protector._factory() as session:
            loaded = load_failed_attempt_receipt(
                session,
                locator_source_id=sid,
                expected_locator_digest=digest,
                verification_objects=protector._reader,
                identity_path=protector._identity,
            )
        if loaded != receipt:
            raise ValueError("attempt receipt differs")
        return receipt
    except Exception:  # noqa: BLE001, S110
        pass
    raise AttemptRecoveryError("failed attempt recovery unavailable; no output released")


def load_failed_attempt_receipt(
    session: Session,
    *,
    locator_source_id: UUID,
    expected_locator_digest: str,
    verification_objects: BackupObjectStore,
    identity_path: Path,
) -> AttemptRecoveryReceipt:
    """Fixed BRAINSTORM trusted operator; consistency checks, not dispatch authority.

    Canonical rows must originate from independently verified state. A loader
    checks ciphertext availability but does not substitute for full restore today.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("fresh read-only inventory required")
        source = session.get(Source, locator_source_id)
        if (
            source is None
            or source.system != SourceSystem.MANUAL
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or source.content_hash != expected_locator_digest
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("attempt locator access denied")
        raw = _recover(
            verification_objects,
            backup_object_key_for(B.BRAINSTORM, expected_locator_digest),
            identity_path,
            64_000,
        )
        locator = AttemptLocator.model_validate(json.loads(raw, object_pairs_hook=_unique_pairs))
        if (
            content_hash_of(raw) != expected_locator_digest
            or raw != canonical_bytes(locator.model_dump(mode="json"))
            or source.external_ref != f"contextual-failed-attempt/{locator.run_id}/{locator.id}"
            or source.captured_at != locator.created_at
        ):
            raise ValueError("attempt locator differs")
        for sid, digest in locator.source_hashes:
            inventory_source = session.get(Source, sid)
            if (
                inventory_source is None
                or inventory_source.trust_boundary != B.BRAINSTORM
                or inventory_source.content_hash != digest
            ):
                raise ValueError("failed attempt inventory changed")
        raw = _recover(verification_objects, locator.receipt_object, identity_path, 64_000)
        receipt = AttemptRecoveryReceipt.model_validate(
            json.loads(raw, object_pairs_hook=_unique_pairs)
        )
        if (
            receipt.locator != locator
            or receipt.locator_source_id != source.id
            or receipt.locator_digest != expected_locator_digest
            or raw != canonical_bytes(receipt.model_dump(mode="json"))
        ):
            raise ValueError("attempt receipt differs")
        for key, digest, limit in (
            (receipt.state_object, receipt.state_ciphertext_hash, 65_000_000),
            (receipt.journal_object, receipt.journal_ciphertext_hash, 4_100_000),
        ):
            size = verification_objects.stat(key).size
            if not 0 < size <= limit:
                raise ValueError("attempt recovery object outside capacity")
            ciphertext = verification_objects.get_object(key)
            if len(ciphertext) != size or content_hash_of(ciphertext) != digest:
                raise ValueError("attempt recovery ciphertext differs")
        return receipt
    except Exception:  # noqa: BLE001, S110
        pass
    raise AttemptRecoveryError("failed attempt receipt unavailable")


def find_failed_attempt_receipt(
    session: Session,
    *,
    artifacts: ArtifactStore,
    run_id: UUID,
    verification_objects: BackupObjectStore,
    identity_path: Path,
) -> AttemptRecoveryReceipt | None:
    """Indexed exact-run lookup; skip absent receipts, reject corruption/ambiguity.

    None means no completed receipt found, never no failure or permission to retry.
    Orphan locators remain recovery work. Fixed BRAINSTORM trusted operator only.
    """
    try:
        from sqlalchemy import select

        if session.new or session.dirty or session.deleted:
            raise ValueError("fresh reconciliation inventory required")
        rows = list(
            session.scalars(
                select(Source)
                .where(
                    Source.trust_boundary == B.BRAINSTORM,
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.startswith(f"contextual-failed-attempt/{run_id}/"),
                )
                .limit(17)
            )
        )
        if len(rows) > 16:
            raise ValueError("attempt inventory outside capacity")
        receipts = []
        for source in rows:
            if source.data_classification != C.CONFIDENTIAL:
                raise ValueError("attempt locator classification differs")
            raw = _bytes(session, artifacts, source)
            locator = AttemptLocator.model_validate(
                json.loads(raw, object_pairs_hook=_unique_pairs)
            )
            if (
                locator.run_id != run_id
                or source.content_hash is None
                or raw != canonical_bytes(locator.model_dump(mode="json"))
                or source.external_ref != f"contextual-failed-attempt/{run_id}/{locator.id}"
            ):
                raise ValueError("indexed attempt locator differs")
            if not verification_objects.exists(locator.receipt_object):
                continue
            receipts.append(
                load_failed_attempt_receipt(
                    session,
                    locator_source_id=source.id,
                    expected_locator_digest=source.content_hash,
                    verification_objects=verification_objects,
                    identity_path=identity_path,
                )
            )
        if len(receipts) > 1:
            raise ValueError("ambiguous completed attempt receipts")
        return receipts[0] if receipts else None
    except Exception:  # noqa: BLE001, S110
        pass
    raise AttemptRecoveryError("failed attempt reconciliation unavailable")
