"""Trusted canonical draft choices, never executable approvals or authentication.

Outer host authenticates each request and supplies retained plans/receipts. This
module cannot prove a principal came from a real session. No HTTP, model or tool
execution occurs. No default recovery adapter is enabled: injected trusted
protection must verify actual new artifact AND final canonical state/journal
recovery. Existing packet receipts cannot cover new choice bytes. Never log
locals/payloads. A protected preference remains non-executing user evidence.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, StringConstraints, model_validator
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import backup_object_key_for
from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.briefing_delivery import load_retained_packet
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.work_proposals import (
    WorkChoice,
    WorkPreference,
    WorkProposal,
    packet_fingerprint,
    proposal_fingerprint,
)
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes, _find, _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification, record_source

ActorText = Annotated[str, StringConstraints(min_length=1, max_length=256, strict=True)]


class WorkChoiceCaptureError(ValueError):
    """Fixed diagnostics without private inputs or backend exception context."""


class CapturedWorkChoice(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["caz-work-choice-v1"] = "caz-work-choice-v1"
    request_id: UUID
    issuer: ActorText = Field(repr=False)
    subject: ActorText = Field(repr=False)
    packet_reference: EvidenceReference
    proposal: WorkProposal = Field(repr=False)
    preference: WorkPreference = Field(repr=False)
    packet_receipt_digest: Digest
    recorded_at: AwareDatetime
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL

    @model_validator(mode="after")
    def bound(self) -> Self:
        if (
            self.packet_reference.trust_boundary != self.boundary
            or self.packet_reference.effective_classification != self.classification
            or self.packet_reference.content_hash != self.proposal.packet_digest
            or self.preference.proposal_digest != proposal_fingerprint(self.proposal)
            or (self.preference.choice == WorkChoice.WITH_CHANGES)
            != (self.preference.changes is not None)
        ):
            raise ValueError("choice binding mismatch")
        return self


@dataclass(frozen=True)
class ChoiceCheckpointScope:
    source_id: UUID
    choice_digest: str
    captured_at: datetime
    boundary: B = field(default=B.BRAINSTORM, init=False)
    classification: C = field(default=C.CONFIDENTIAL, init=False)


def choice_receipt_key(source_id: UUID, digest: str) -> str:
    """Strict deterministic key shared by retained receipt and trusted adapter."""
    if (
        type(source_id) is not UUID
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise ValueError("invalid choice receipt identity")
    return f"BRAINSTORM/state/work-choice-{source_id}/receipt-{digest}.age"


class WorkChoiceRecoveryReceipt(Contract):
    """Consistency declaration from independently trusted actual recovery adapter.

    Shape is not proof of recovery; protect/recheck must establish real coverage.
    artifact_ciphertext_hash is the initially observed checksum. Artifact backup
    may re-encrypt its stable plaintext-hash key; canonical decrypted plaintext
    identity is authoritative on recheck. State/journal ciphertext pins persist.
    """

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["caz-work-choice-recovery-v1"] = "caz-work-choice-recovery-v1"
    source_id: UUID
    choice_digest: Digest
    captured_at: AwareDatetime
    verified_at: AwareDatetime
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL
    artifact_backup_run_id: UUID
    artifact_ciphertext_hash: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def chronological(self) -> Self:
        if self.verified_at < self.captured_at:
            raise ValueError("recovery time mismatch")
        return self

    @property
    def receipt_object(self) -> str:
        return choice_receipt_key(self.source_id, self.choice_digest)

    @property
    def artifact_object(self) -> str:
        return backup_object_key_for(B.BRAINSTORM, self.choice_digest)

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/work-choice-{self.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/work-choice-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"


class WorkChoiceProtection(Protocol):
    def protect(self, scope: ChoiceCheckpointScope) -> WorkChoiceRecoveryReceipt:
        """Recover exact new artifact and final state/journal including choice row.

        Called after canonical commit; failure leaves choice pending protection.
        Adapter must serialize/idempotently reconcile retries and retain/read back
        the encrypted receipt at its deterministic receipt_object for cold restore.
        No packet-only receipt, fabricated UUID/hash or reference-string attestation.
        """
        ...

    def recheck(self, scope: ChoiceCheckpointScope, receipt: WorkChoiceRecoveryReceipt) -> None:
        """Verify actual retained recovery evidence/objects, not just receipt shape."""
        ...


@dataclass(frozen=True)
class SavedWorkChoice:
    source_id: UUID
    choice_digest: str
    recovery_receipt: WorkChoiceRecoveryReceipt

    @property
    def recovery_receipt_digest(self) -> str:
        return content_hash_of(canonical_bytes(self.recovery_receipt.model_dump(mode="json")))


def _encode(choice: CapturedWorkChoice) -> bytes:
    return canonical_bytes(CapturedWorkChoice.model_validate(choice).model_dump(mode="json"))


def _decode(raw: bytes) -> CapturedWorkChoice:
    if len(raw) > 32_000:
        raise ValueError("choice capacity exceeded")
    choice = CapturedWorkChoice.model_validate_json(raw)
    if _encode(choice) != raw:
        raise ValueError("noncanonical choice")
    return choice


class CanonicalWorkChoiceCapture:
    """Host-only, READ COMMITTED PostgreSQL advisory-lock serialized capture.

    Caller must supply a current authenticated principal, not browser fields.
    Retained receipt/proposal/configuration are host-owned Python inputs. No
    default protection adapter exists and no status/authority is minted here.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        artifacts: ArtifactStore,
        owner: Callable[[], OwnerGrant],
        protection: WorkChoiceProtection,
        clock: Callable[[], datetime],
    ) -> None:
        self._factory, self._artifacts = factory, artifacts
        self._owner, self._protection, self._clock = owner, protection, clock

    def _principal_scope(self, principal: InterfacePrincipal, now: datetime) -> BoundaryScope:
        if type(principal) is not InterfacePrincipal or now.utcoffset() is None:
            raise ValueError("invalid host principal/time")
        owner = self._owner()
        owner = OwnerGrant(owner.identity, owner.scopes)
        supplied = OwnerGrant(principal.identity, principal.scopes)
        if supplied != owner:
            raise ValueError("owner or grants changed")
        scope = next(s for s in owner.scopes if s.boundary == B.BRAINSTORM)
        if C.CONFIDENTIAL not in scope.classifications:
            raise ValueError("choice classification denied")
        return scope

    def _check(
        self,
        session: Session,
        principal: InterfacePrincipal,
        receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        proposal: WorkProposal,
        now: datetime,
    ) -> None:
        self._principal_scope(principal, now)
        packet = load_retained_packet(
            session,
            artifacts=self._artifacts,
            retained_receipt=receipt,
            expected_receipt_digest=expected_receipt_digest,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            as_of=now,
        )
        proposal = WorkProposal.model_validate(proposal)
        if (
            packet.review.conflicts
            or packet.review.clarifications
            or proposal.packet_digest != packet_fingerprint(packet)
            or proposal.item_index >= len(packet.review.items)
            or packet.review.items[proposal.item_index].kind
            not in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP)
        ):
            raise ValueError("held or changed plan")

    def _read(self, session: Session, source: Source) -> tuple[CapturedWorkChoice, bytes]:
        if (
            source.system != SourceSystem.USER_INSTRUCTION
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("choice access denied")
        raw = _bytes(session, self._artifacts, source)
        choice = _decode(raw)
        if (
            source.external_ref != f"work-choice/{choice.request_id}"
            or source.captured_at != choice.recorded_at
        ):
            raise ValueError("choice source mismatch")
        return choice, raw

    def capture(
        self,
        *,
        principal: InterfacePrincipal,
        request_id: UUID,
        retained_receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        proposal: WorkProposal,
        preference: WorkPreference,
    ) -> SavedWorkChoice:
        result: SavedWorkChoice | None = None
        try:
            with self._factory() as session:
                _lock(session, request_id)
                now = self._clock()
                self._check(
                    session, principal, retained_receipt, expected_receipt_digest, proposal, now
                )
                choice = CapturedWorkChoice(
                    request_id=request_id,
                    issuer=principal.identity.issuer,
                    subject=principal.identity.subject,
                    packet_reference=EvidenceReference(
                        source_id=retained_receipt.locator.packet_source_id,
                        content_hash=retained_receipt.locator.packet_digest,
                        trust_boundary=B.BRAINSTORM,
                        effective_classification=C.CONFIDENTIAL,
                    ),
                    proposal=proposal,
                    preference=preference,
                    packet_receipt_digest=expected_receipt_digest,
                    recorded_at=now,
                )
                source = _find(session, f"work-choice/{request_id}", SourceSystem.USER_INSTRUCTION)
                if source is not None:
                    existing, raw = self._read(session, source)
                    if existing.recorded_at > now or existing != choice.model_copy(
                        update={"recorded_at": existing.recorded_at}
                    ):
                        raise ValueError("conflicting replay")
                else:
                    raw = _encode(choice)
                    digest = content_hash_of(raw)
                    location = self._artifacts.put(B.BRAINSTORM, digest, raw)
                    if self._artifacts.get(B.BRAINSTORM, location) != raw:
                        raise ValueError("choice artifact mismatch")
                    source, _ = record_source(
                        session,
                        trust_boundary=B.BRAINSTORM,
                        data_classification=C.CONFIDENTIAL,
                        system=SourceSystem.USER_INSTRUCTION,
                        content_hash=digest,
                        content_location=location,
                        external_ref=f"work-choice/{request_id}",
                        captured_at=now,
                    )
                    self._read(session, source)
                checkpoint = ChoiceCheckpointScope(
                    source.id, content_hash_of(raw), source.captured_at
                )
                session.commit()
            receipt = WorkChoiceRecoveryReceipt.model_validate(self._protection.protect(checkpoint))
            result = self.load(
                principal=principal,
                source_id=checkpoint.source_id,
                expected_choice_digest=checkpoint.choice_digest,
                retained_receipt=retained_receipt,
                expected_receipt_digest=expected_receipt_digest,
                recovery_receipt=receipt,
            )
        except Exception:  # noqa: BLE001,S110 - no private diagnostics/context
            pass
        if result is None:
            raise WorkChoiceCaptureError("work choice capture unavailable or unprotected")
        return result

    def load(
        self,
        *,
        principal: InterfacePrincipal,
        source_id: UUID,
        expected_choice_digest: str,
        retained_receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        recovery_receipt: WorkChoiceRecoveryReceipt,
    ) -> SavedWorkChoice:
        result: SavedWorkChoice | None = None
        try:
            now = self._clock()
            self._principal_scope(principal, now)
            receipt = WorkChoiceRecoveryReceipt.model_validate(recovery_receipt)
            with self._factory() as session:
                _assert_ledger_isolation(session)
                source = session.get(Source, source_id)
                if source is None or source.content_hash != expected_choice_digest:
                    raise ValueError("choice missing")
                choice, raw = self._read(session, source)
                self._check(
                    session,
                    principal,
                    retained_receipt,
                    expected_receipt_digest,
                    choice.proposal,
                    now,
                )
                checkpoint = ChoiceCheckpointScope(
                    source_id, content_hash_of(raw), source.captured_at
                )
                if (
                    choice.issuer != principal.identity.issuer
                    or choice.subject != principal.identity.subject
                    or choice.packet_receipt_digest != expected_receipt_digest
                    or choice.packet_reference.source_id
                    != retained_receipt.locator.packet_source_id
                    or choice.recorded_at > now
                    or receipt.verified_at > now
                    or receipt.source_id != source_id
                    or receipt.choice_digest != expected_choice_digest
                    or receipt.captured_at != choice.recorded_at
                ):
                    raise ValueError("choice/recovery mismatch")
            # Release initial transaction before cold restoration; final reads
            # use a new READ COMMITTED session after independent recovery.
            self._protection.recheck(checkpoint, receipt)
            final_now = self._clock()
            if (
                final_now.utcoffset() is None
                or final_now < now
                or final_now < choice.recorded_at
                or final_now < receipt.verified_at
            ):
                raise ValueError("host clock moved backward")
            with self._factory() as session:
                _assert_ledger_isolation(session)
                session.expire_all()
                source = session.get(Source, source_id)
                if source is None:
                    raise ValueError("choice removed during protection")
                self._check(
                    session,
                    principal,
                    retained_receipt,
                    expected_receipt_digest,
                    choice.proposal,
                    final_now,
                )
                refreshed_choice, refreshed_raw = self._read(session, source)
                if refreshed_choice != choice or refreshed_raw != raw:
                    raise ValueError("choice changed during protection")
                result = SavedWorkChoice(source_id, expected_choice_digest, receipt)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise WorkChoiceCaptureError("work choice load unavailable or unprotected")
        return result
