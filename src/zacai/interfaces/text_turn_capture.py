"""Canonical bounded user turns; no HTTP, model consent, dispatch or new memory.

The outer trusted host authenticates the principal, selects protected packet and
parent Sources, and classifies the new text before this BRAINSTORM/CONFIDENTIAL
seam. A supplied Python principal is not proof of an HTTP session. Protection is
required, never defaulted: failure after commit leaves a pending turn; retry the
same request/content to protect it, never acknowledge a fabricated receipt.
Direct parents alone are selected. Ancestor references retained in their records
are provenance, not permission to disclose/replay ancestor text. Disable private
exception-local capture/logging. Text is preserved, not made safe for rendering.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from threading import RLock
from typing import Annotated, Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, StringConstraints, model_validator
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import backup_object_key_for
from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.briefing_delivery import load_retained_packet
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes, _find, _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification, record_source

ActorText = Annotated[str, StringConstraints(min_length=1, max_length=256, strict=True)]
OriginalText = Annotated[str, StringConstraints(min_length=1, max_length=2000, strict=True)]


class TextTurnCaptureError(ValueError):
    """Fixed closed errors, without chained private backend diagnostics."""


class TextTurn(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-text-turn-v1"] = "zac-text-turn-v1"
    kind: Literal["user_input"] = "user_input"
    request_id: UUID
    conversation_id: UUID
    issuer: ActorText = Field(repr=False)
    subject: ActorText = Field(repr=False)
    original_text: OriginalText = Field(repr=False)
    packet_reference: EvidenceReference
    packet_receipt_digest: Digest
    parent_references: tuple[EvidenceReference, ...] = Field(default=(), max_length=6)
    recorded_at: AwareDatetime
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL

    @model_validator(mode="after")
    def exact_scope(self) -> Self:
        refs = (self.packet_reference, *self.parent_references)
        if (
            not self.original_text.strip()
            or len(self.original_text.encode("utf-8")) > 8000
            or self.original_text.startswith("\ufeff")
            or len({r.source_id for r in refs}) != len(refs)
            or any(
                r.trust_boundary != B.BRAINSTORM or r.effective_classification != C.CONFIDENTIAL
                for r in refs
            )
        ):
            raise ValueError("invalid turn text or scope")
        return self


def encode_text_turn(turn: TextTurn) -> bytes:
    result: bytes | None = None
    try:
        result = canonical_bytes(TextTurn.model_validate(turn).model_dump(mode="json"))
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise TextTurnCaptureError("text turn unavailable or invalid")
    return result


def decode_text_turn(raw: bytes) -> TextTurn:
    result: TextTurn | None = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 32_000:
            raise ValueError("invalid bounded turn bytes")
        turn = TextTurn.model_validate_json(raw)
        if encode_text_turn(turn) != raw:
            raise ValueError("noncanonical turn bytes")
        result = turn
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise TextTurnCaptureError("text turn unavailable or invalid")
    return result


@dataclass(frozen=True)
class TextTurnCheckpointScope:
    source_id: UUID
    turn_digest: str
    captured_at: datetime
    boundary: B = field(default=B.BRAINSTORM, init=False)
    classification: C = field(default=C.CONFIDENTIAL, init=False)


def text_turn_receipt_key(source_id: UUID, digest: str) -> str:
    if (
        type(source_id) is not UUID
        or type(digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise TextTurnCaptureError("invalid turn receipt identity")
    return f"BRAINSTORM/state/text-turn-{source_id}/receipt-{digest}.age"


class TextTurnRecoveryReceipt(Contract):
    """Shape alone proves no recovery. Trusted adapter verifies actual objects.

    Artifact ciphertext is an initial observation; repair re-encryption may change
    it while exact canonical plaintext remains authoritative. State/journal pins
    and retained immutable receipt bytes remain exact on independent recheck.
    """

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-text-turn-recovery-v1"] = "zac-text-turn-recovery-v1"
    source_id: UUID
    turn_digest: Digest
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
            raise ValueError("turn recovery time mismatch")
        return self

    @property
    def receipt_object(self) -> str:
        return text_turn_receipt_key(self.source_id, self.turn_digest)

    @property
    def artifact_object(self) -> str:
        return backup_object_key_for(B.BRAINSTORM, self.turn_digest)

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/text-turn-{self.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/text-turn-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"


class TextTurnProtection(Protocol):
    def protect(self, scope: TextTurnCheckpointScope) -> TextTurnRecoveryReceipt:
        """Recover new canonical turn + explicit dependencies + final state/journal.

        Serialize real recovery, retain encrypted immutable receipt/readback, and
        reconcile same-request retries. Packet-only receipt is insufficient.
        """
        ...

    def recheck(self, scope: TextTurnCheckpointScope, receipt: TextTurnRecoveryReceipt) -> object:
        """Reverify actual retained objects; raise on hold, return None on success."""
        ...


@dataclass(frozen=True)
class SavedTextTurn:
    source_id: UUID
    turn_digest: str
    turn: TextTurn = field(repr=False)
    recovery_receipt: TextTurnRecoveryReceipt = field(repr=False)

    @property
    def reference(self) -> EvidenceReference:
        return EvidenceReference(
            source_id=self.source_id,
            content_hash=self.turn_digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class CanonicalTextTurnCapture:
    """Trusted host storage seam, serialized request replay; no enabled adapter."""

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        artifacts: ArtifactStore,
        owner: Callable[[], OwnerGrant],
        protection: TextTurnProtection,
        clock: Callable[[], datetime],
    ) -> None:
        self._factory, self._artifacts = factory, artifacts
        self._owner, self._protection, self._clock = owner, protection, clock
        self._clock_lock = RLock()
        self._last_observed: datetime | None = None

    def _now(self) -> datetime:
        """Validate every capture/load/assembly observation in this host instance.

        This local watermark is not a persistent or cross-component clock. The
        real composition must inject the same checked host-clock callable into
        capture and protection; assembly delegates to this method.
        """
        with self._clock_lock:
            now = self._clock()
            if (
                type(now) is not datetime
                or now.utcoffset() is None
                or (self._last_observed is not None and now < self._last_observed)
            ):
                raise ValueError("host clock observation moved backward or is invalid")
            self._last_observed = now
            return now

    def _principal(self, principal: InterfacePrincipal, now: datetime) -> None:
        if (
            type(principal) is not InterfacePrincipal
            or type(now) is not datetime
            or now.utcoffset() is None
        ):
            raise ValueError("host identity/time required")
        owner = self._owner()
        current = OwnerGrant(owner.identity, owner.scopes)
        if OwnerGrant(principal.identity, principal.scopes) != current:
            raise ValueError("owner/grants changed")
        scope = next(s for s in current.scopes if s.boundary == B.BRAINSTORM)
        if C.CONFIDENTIAL not in scope.classifications:
            raise ValueError("turn classification denied")

    def _read(self, session: Session, source: Source) -> tuple[TextTurn, bytes]:
        if (
            source.system != SourceSystem.USER_INSTRUCTION
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("turn source denied")
        raw = _bytes(session, self._artifacts, source)
        turn = decode_text_turn(raw)
        if (
            source.external_ref != f"text-turn/{turn.request_id}"
            or source.captured_at != turn.recorded_at
        ):
            raise ValueError("turn provenance mismatch")
        return turn, raw

    def _check(
        self,
        session: Session,
        principal: InterfacePrincipal,
        turn: TextTurn,
        retained_receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        now: datetime,
        *,
        source_id: UUID | None = None,
    ) -> None:
        self._principal(principal, now)
        packet = load_retained_packet(
            session,
            artifacts=self._artifacts,
            retained_receipt=retained_receipt,
            expected_receipt_digest=expected_receipt_digest,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            as_of=now,
        )
        if (
            turn.issuer != principal.identity.issuer
            or turn.subject != principal.identity.subject
            or turn.recorded_at > now
            or turn.packet_receipt_digest != expected_receipt_digest
            or turn.packet_reference.source_id != retained_receipt.locator.packet_source_id
            or turn.packet_reference.content_hash != retained_receipt.locator.packet_digest
            or packet.created_at > turn.recorded_at
        ):
            raise ValueError("turn owner/packet/time mismatch")
        for ref in turn.parent_references:
            if ref.source_id == source_id:
                raise ValueError("self-parent denied")
            parent_source = session.get(Source, ref.source_id)
            if parent_source is None or parent_source.content_hash != ref.content_hash:
                raise ValueError("parent revision missing")
            parent, _ = self._read(session, parent_source)
            if (
                parent.issuer != turn.issuer
                or parent.subject != turn.subject
                or parent.conversation_id != turn.conversation_id
                or parent.packet_reference != turn.packet_reference
                or parent.packet_receipt_digest != turn.packet_receipt_digest
                or parent.recorded_at > turn.recorded_at
                or parent.request_id == turn.request_id
            ):
                raise ValueError("parent turn binding mismatch")

    def capture(
        self,
        *,
        principal: InterfacePrincipal,
        request_id: UUID,
        conversation_id: UUID,
        original_utf8: bytes,
        retained_receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        parent_references: tuple[EvidenceReference, ...] = (),
    ) -> SavedTextTurn:
        result: SavedTextTurn | None = None
        try:
            if (
                type(request_id) is not UUID
                or type(conversation_id) is not UUID
                or type(original_utf8) is not bytes
                or not 0 < len(original_utf8) <= 8000
            ):
                raise ValueError("bounded host turn input required")
            text = original_utf8.decode("utf-8", errors="strict")
            with self._factory() as session:
                _lock(session, request_id)
                now = self._now()
                self._principal(principal, now)
                turn = TextTurn(
                    request_id=request_id,
                    conversation_id=conversation_id,
                    issuer=principal.identity.issuer,
                    subject=principal.identity.subject,
                    original_text=text,
                    packet_reference=EvidenceReference(
                        source_id=retained_receipt.locator.packet_source_id,
                        content_hash=retained_receipt.locator.packet_digest,
                        trust_boundary=B.BRAINSTORM,
                        effective_classification=C.CONFIDENTIAL,
                    ),
                    packet_receipt_digest=expected_receipt_digest,
                    parent_references=parent_references,
                    recorded_at=now,
                )
                self._check(
                    session, principal, turn, retained_receipt, expected_receipt_digest, now
                )
                source = _find(session, f"text-turn/{request_id}", SourceSystem.USER_INSTRUCTION)
                if source is not None:
                    previous, raw = self._read(session, source)
                    if previous.recorded_at > now or previous != turn.model_copy(
                        update={"recorded_at": previous.recorded_at}
                    ):
                        raise ValueError("conflicting text replay")
                else:
                    raw = encode_text_turn(turn)
                    digest = content_hash_of(raw)
                    location = self._artifacts.put(B.BRAINSTORM, digest, raw)
                    if self._artifacts.get(B.BRAINSTORM, location) != raw:
                        raise ValueError("turn artifact mismatch")
                    source, _ = record_source(
                        session,
                        trust_boundary=B.BRAINSTORM,
                        data_classification=C.CONFIDENTIAL,
                        system=SourceSystem.USER_INSTRUCTION,
                        content_hash=digest,
                        content_location=location,
                        external_ref=f"text-turn/{request_id}",
                        captured_at=now,
                    )
                    self._read(session, source)
                scope = TextTurnCheckpointScope(source.id, content_hash_of(raw), source.captured_at)
                session.commit()
            receipt = TextTurnRecoveryReceipt.model_validate(self._protection.protect(scope))
            result = self.load(
                principal=principal,
                source_id=scope.source_id,
                expected_turn_digest=scope.turn_digest,
                retained_receipt=retained_receipt,
                expected_receipt_digest=expected_receipt_digest,
                recovery_receipt=receipt,
            )
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise TextTurnCaptureError("text turn capture unavailable or unprotected")
        return result

    def load(
        self,
        *,
        principal: InterfacePrincipal,
        source_id: UUID,
        expected_turn_digest: str,
        retained_receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        recovery_receipt: TextTurnRecoveryReceipt,
    ) -> SavedTextTurn:
        result: SavedTextTurn | None = None
        try:
            now = self._now()
            self._principal(principal, now)
            receipt = TextTurnRecoveryReceipt.model_validate(recovery_receipt)
            with self._factory() as session:
                _assert_ledger_isolation(session)
                source = session.get(Source, source_id)
                if source is None or source.content_hash != expected_turn_digest:
                    raise ValueError("turn missing")
                turn, raw = self._read(session, source)
                self._check(
                    session,
                    principal,
                    turn,
                    retained_receipt,
                    expected_receipt_digest,
                    now,
                    source_id=source_id,
                )
                if (
                    receipt.source_id != source_id
                    or receipt.turn_digest != expected_turn_digest
                    or receipt.captured_at != turn.recorded_at
                    or receipt.verified_at > now
                ):
                    raise ValueError("turn recovery mismatch")
                scope = TextTurnCheckpointScope(source_id, content_hash_of(raw), source.captured_at)
            if self._protection.recheck(scope, receipt) is not None:
                raise ValueError("protection returned a boolean authority claim")
            final = self._now()
            if (
                type(final) is not datetime
                or final.utcoffset() is None
                or final < now
                or final < turn.recorded_at
                or final < receipt.verified_at
            ):
                raise ValueError("host clock moved backward")
            with self._factory() as session:
                _assert_ledger_isolation(session)
                source = session.get(Source, source_id)
                if source is None:
                    raise ValueError("turn removed")
                self._check(
                    session,
                    principal,
                    turn,
                    retained_receipt,
                    expected_receipt_digest,
                    final,
                    source_id=source_id,
                )
                fresh, fresh_raw = self._read(session, source)
                if fresh != turn or fresh_raw != raw:
                    raise ValueError("turn changed during protection")
                result = SavedTextTurn(source_id, expected_turn_digest, fresh, receipt)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise TextTurnCaptureError("text turn load unavailable or unprotected")
        return result
