"""Generated follow-up reply records, never human input or execution authority.

An exact MANUAL Source and distinct generated-reply kind preserve provenance.
Metadata, release objects and declared hashes are not authenticated processing
claims. Concrete canonical claim/release gates and actual checkpoint protection
are mandatory before any acknowledgement; no enabled host/model/route exists.
Do not log private records or exception frame locals. Render text escaped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal, Protocol, Self
from uuid import UUID, uuid5

from pydantic import AwareDatetime, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from zacai.backup_artifacts import backup_object_key_for
from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, UsageObservation
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.intelligence.meeting_review import Quote
from zacai.intelligence.text_followup import (
    FollowupDraft,
    FollowupRelease,
    FollowupReleaseGate,
    release_text_followup,
)
from zacai.interfaces.followup_authorization import (
    CanonicalFollowupAuthorization,
    ClaimedFollowup,
    FollowupClaim,
    FollowupConsent,
    _owner_digest,
    followup_content_digest,
)
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.text_followup_context import CanonicalFollowupAssembler
from zacai.interfaces.text_turn_capture import TextTurnRecoveryReceipt
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes, _find, _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification, record_source

_REPLY_NAMESPACE = UUID("a7d6c7f3-56ae-5bf5-91ba-dad4cb759445")


class TextReplyCaptureError(ValueError):
    """Fixed private-safe error without chained record diagnostics."""


def text_reply_request_id(run_id: UUID, claim: EvidenceReference, request_digest: str) -> UUID:
    """Immutable attempt identity; never a caller-selected retry namespace."""
    if (
        type(run_id) is not UUID
        or type(claim) is not EvidenceReference
        or type(request_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", request_digest) is None
    ):
        raise TextReplyCaptureError("reply identity unavailable")
    return uuid5(
        _REPLY_NAMESPACE, f"{run_id}/{claim.source_id}/{claim.content_hash}/{request_digest}"
    )


class ReplyCitation(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    reference: EvidenceReference = Field(repr=False)
    quote: Quote = Field(repr=False)


class TextReply(Contract):
    """Exact persisted generated result; none of these fields grants authority."""

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-text-reply-v1"] = "zac-text-reply-v1"
    kind: Literal["generated_followup_reply"] = "generated_followup_reply"
    request_id: UUID
    claim: FollowupClaim = Field(repr=False)
    claim_reference: EvidenceReference = Field(repr=False)
    usage: UsageObservation = Field(repr=False)
    original_observed_at: AwareDatetime
    recorded_at: AwareDatetime
    draft: FollowupDraft = Field(repr=False)
    display_text: str = Field(strict=True, min_length=1, max_length=1800, repr=False)
    citations: tuple[ReplyCitation, ...] = Field(max_length=12, repr=False)
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL

    @model_validator(mode="after")
    def exact_bindings(self) -> Self:
        scope = self.claim.run_scope
        refs = (
            scope.user_reference,
            scope.packet_reference,
            *scope.parent_references,
            self.claim_reference,
            self.claim.consent_reference,
        )
        if (
            self.request_id
            != text_reply_request_id(scope.run_id, self.claim_reference, self.claim.request_digest)
            or len({r.source_id for r in refs}) != len(refs)
            or any(
                r.trust_boundary != B.BRAINSTORM or r.effective_classification != C.CONFIDENTIAL
                for r in refs
            )
            or self.claim_reference.content_hash
            != content_hash_of(canonical_bytes(self.claim.model_dump(mode="json")))
            or self.usage.output_tokens > scope.max_output_tokens
            or self.usage.latency_ms > scope.max_latency_ms
            or (
                self.usage.cost_usd is not None
                and self.usage.cost_usd > scope.max_estimated_cost_usd
            )
            or self.draft.user_source_id != scope.user_reference.source_id
            or self.draft.user_content_hash != scope.user_reference.content_hash
            or self.draft.packet_digest != scope.packet_reference.content_hash
            or not self.original_observed_at <= self.claim.claimed_at <= self.recorded_at
            or len(self.display_text.split()) > 120
            or any(
                c.reference not in scope.context_references
                or c.quote.source_id != c.reference.source_id
                or c.reference.trust_boundary != B.BRAINSTORM
                or c.reference.effective_classification != C.CONFIDENTIAL
                for c in self.citations
            )
        ):
            raise ValueError("reply bindings invalid")
        self.display_text.encode("utf-8", errors="strict")
        return self


def encode_text_reply(reply: TextReply) -> bytes:
    result: bytes | None = None
    try:
        raw = canonical_bytes(TextReply.model_validate(reply).model_dump(mode="json"))
        if len(raw) <= 32_000:
            result = raw
    except Exception:  # noqa: BLE001,S110 - private diagnostics suppressed
        pass
    if result is None:
        raise TextReplyCaptureError("reply record unavailable")
    return result


def decode_text_reply(raw: bytes) -> TextReply:
    result: TextReply | None = None
    try:
        if type(raw) is bytes and 0 < len(raw) <= 32_000:
            record = TextReply.model_validate_json(raw)
            if encode_text_reply(record) == raw:
                result = record
    except Exception:  # noqa: BLE001,S110 - private diagnostics suppressed
        pass
    if result is None:
        raise TextReplyCaptureError("reply record unavailable")
    return result


def text_reply_receipt_key(source_id: UUID, digest: str) -> str:
    if (
        type(source_id) is not UUID
        or type(digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise TextReplyCaptureError("reply checkpoint identity unavailable")
    return f"BRAINSTORM/state/text-reply-{source_id}/receipt-{digest}.age"


@dataclass(frozen=True)
class TextReplyCheckpointScope:
    source_id: UUID
    reply_digest: str
    captured_at: datetime
    boundary: B = field(default=B.BRAINSTORM, init=False)
    classification: C = field(default=C.CONFIDENTIAL, init=False)


class TextReplyRecoveryReceipt(Contract):
    format: Literal["zac-text-reply-recovery-v1"] = "zac-text-reply-recovery-v1"
    source_id: UUID
    reply_digest: Digest
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
    def chronology(self) -> Self:
        if self.verified_at < self.captured_at:
            raise ValueError("reply recovery time mismatch")
        return self

    @property
    def receipt_object(self) -> str:
        return text_reply_receipt_key(self.source_id, self.reply_digest)

    @property
    def artifact_object(self) -> str:
        return backup_object_key_for(B.BRAINSTORM, self.reply_digest)

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/text-reply-{self.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/text-reply-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"


class TextReplyProtection(Protocol):
    def protect(self, scope: TextReplyCheckpointScope) -> TextReplyRecoveryReceipt: ...
    def recheck(
        self, scope: TextReplyCheckpointScope, receipt: TextReplyRecoveryReceipt
    ) -> object: ...


@dataclass(frozen=True)
class SavedTextReply:
    source_id: UUID
    reply_digest: str
    reply: TextReply = field(repr=False)
    recovery_receipt: TextReplyRecoveryReceipt = field(repr=False)

    @property
    def reference(self) -> EvidenceReference:
        return EvidenceReference(
            source_id=self.source_id,
            content_hash=self.reply_digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class CanonicalTextReplyCapture:
    """Protected initial-result retention; historical display is a separate gate.

    Initial capture/load retain strict processing expiry/cancellation. Expiry
    does not delete canonical history; a future named historical-read gate must
    check owner/ACL/recovery without extending processing authority. This class
    mounts no route and authenticates no supplied Python principal by itself.
    """

    def __init__(
        self,
        *,
        assembler: CanonicalFollowupAssembler,
        authorization: CanonicalFollowupAuthorization,
        release_gate: FollowupReleaseGate,
        protection: TextReplyProtection,
    ) -> None:
        if (
            type(assembler) is not CanonicalFollowupAssembler
            or type(authorization) is not CanonicalFollowupAuthorization
        ):
            raise TextReplyCaptureError("reply host dependencies unavailable")
        self._assembler, self._authorization = assembler, authorization
        self._release_gate, self._protection = release_gate, protection
        self._capture = assembler._capture

    def _read(self, session: Session, source: Source) -> tuple[TextReply, str]:
        if (
            source.system != SourceSystem.MANUAL
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("reply Source denied")
        raw = _bytes(session, self._capture._artifacts, source)
        reply = decode_text_reply(raw)
        if (
            source.content_hash != content_hash_of(raw)
            or source.external_ref != f"text-reply/{reply.request_id}"
            or source.captured_at != reply.recorded_at
        ):
            raise ValueError("reply Source binding mismatch")
        return reply, content_hash_of(raw)

    def _pending_record(
        self, session: Session, *, principal: InterfacePrincipal,
        source_id: UUID, expected_reply_digest: str, now: datetime,
    ) -> tuple[TextReply, str]:
        """Integrity of committed history; deliberately no processing renewal."""
        self._capture._principal(principal, now)
        source = session.get(Source, source_id)
        if source is None:
            raise ValueError("pending reply missing")
        reply, digest = self._read(session, source)
        declared = reply.claim.run_scope
        if (
            digest != expected_reply_digest
            or reply.recorded_at > now
            or declared.actor_issuer != principal.identity.issuer
            or declared.actor_subject != principal.identity.subject
            or declared.owner_grant_digest != _owner_digest(OwnerGrant(principal.identity, principal.scopes))
        ):
            raise ValueError("pending reply identity mismatch")
        for ref in (
            declared.packet_reference, *declared.context_references,
            reply.claim_reference, reply.claim.consent_reference,
        ):
            current = session.get(Source, ref.source_id)
            if (
                current is None or current.content_hash != ref.content_hash
                or current.trust_boundary != B.BRAINSTORM
                or current.data_classification != C.CONFIDENTIAL
                or get_effective_source_classification(session, source_id=current.id) != C.CONFIDENTIAL
            ):
                raise ValueError("pending reply dependency denied")
        claim_source = session.get(Source, reply.claim_reference.source_id)
        consent_source = session.get(Source, reply.claim.consent_reference.source_id)
        if claim_source is None or consent_source is None:
            raise ValueError("original authority missing")
        claim_raw = _bytes(session, self._capture._artifacts, claim_source)
        consent_raw = _bytes(session, self._capture._artifacts, consent_source)
        consent = FollowupConsent.model_validate_json(consent_raw)
        if (
            claim_source.system != SourceSystem.MANUAL
            or claim_source.external_ref != f"packet-followup-claim/{consent_source.id}"
            or claim_source.captured_at != reply.claim.claimed_at
            or claim_raw != canonical_bytes(reply.claim.model_dump(mode="json"))
            or consent_source.system != SourceSystem.USER_INSTRUCTION
            or consent_source.external_ref != f"packet-followup-consent/{consent.id}"
            or consent_source.captured_at != consent.approved_at
            or consent_raw != canonical_bytes(consent.model_dump(mode="json"))
            or consent.scope != declared
            or not consent.approved_at <= reply.claim.claimed_at < consent.expires_at
            or not reply.recorded_at < consent.expires_at
            or not reply.original_observed_at <= reply.claim.claimed_at <= reply.recorded_at <= now
        ):
            raise ValueError("original authority integrity invalid")
        return reply, digest

    def protect_pending(
        self, *, principal: InterfacePrincipal, source_id: UUID, expected_reply_digest: str,
    ) -> TextReplyRecoveryReceipt:
        """Recover already committed history even after processing expiry.

        Receipt only: no draft/display bytes, inference, release-gate call,
        consent renewal or historical-read route. Current owner/ACLs and exact
        original authority integrity remain mandatory before and after recovery.
        Later cancellation does not destroy committed history or authorize its
        display. Normal capture/load retain their expiry/revocation holds.
        """
        result: TextReplyRecoveryReceipt | None = None
        try:
            start = self._capture._now()
            self._capture._principal(principal, start)
            if (
                type(source_id) is not UUID or type(expected_reply_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_reply_digest) is None
            ):
                raise ValueError("pending identity invalid")
            with self._capture._factory() as session:
                _assert_ledger_isolation(session)
                original, digest = self._pending_record(
                    session, principal=principal, source_id=source_id,
                    expected_reply_digest=expected_reply_digest, now=start,
                )
            scope = TextReplyCheckpointScope(source_id, digest, original.recorded_at)
            receipt = TextReplyRecoveryReceipt.model_validate(self._protection.protect(scope))
            if (
                receipt.source_id != source_id or receipt.reply_digest != digest
                or receipt.captured_at != original.recorded_at
            ):
                raise ValueError("pending receipt mismatch")
            if self._protection.recheck(scope, receipt) is not None:
                raise ValueError("pending recovery acknowledgement invalid")
            with self._capture._factory() as session:
                _assert_ledger_isolation(session)
                final = self._capture._now()
                current = self._pending_record(
                    session, principal=principal, source_id=source_id,
                    expected_reply_digest=expected_reply_digest, now=final,
                )
                if current != (original, digest):
                    raise ValueError("pending reply changed during recovery")
            final = self._capture._now()
            self._capture._principal(principal, final)
            if final < start or final < receipt.verified_at or final < original.recorded_at:
                raise ValueError("pending recovery clock invalid")
            result = receipt
        except Exception:  # noqa: BLE001,S110 - never disclose original authority/private reply.
            pass
        if result is None:
            raise TextReplyCaptureError("pending reply recovery unavailable")
        return result

    def _validate(
        self,
        principal: InterfacePrincipal,
        reply: TextReply,
        retained_receipt: ContextualRecoveryReceipt,
        text_receipt: TextTurnRecoveryReceipt,
    ) -> None:
        reply = TextReply.model_validate(reply)
        scope = reply.claim.run_scope
        assembled = self._assembler.assemble(
            principal=principal,
            source_id=scope.user_reference.source_id,
            expected_turn_digest=scope.user_reference.content_hash,
            retained_receipt=retained_receipt,
            expected_receipt_digest=scope.packet_receipt_digest,
            recovery_receipt=text_receipt,
        )
        now = self._capture._now()
        self._capture._principal(principal, now)
        if (
            reply.recorded_at > now
            or principal.identity.issuer != scope.actor_issuer
            or principal.identity.subject != scope.actor_subject
            or assembled.saved_turn.turn.conversation_id != scope.conversation_id
            or content_hash_of(canonical_bytes(text_receipt.model_dump(mode="json")))
            != scope.text_receipt_digest
        ):
            raise ValueError("reply owner/time/recovery mismatch")
        fresh = prepare_followup_request(assembled.context)
        if followup_content_digest(fresh) != scope.content_digest:
            raise ValueError("reply current context changed")
        # Reconstruct only the original observation metadata. All current source
        # text, identities, event fields, instruction and budgets remain exact.
        event = assembled.context.task.event.model_copy(
            update={"observed_at": reply.original_observed_at}
        )
        original = replace(
            assembled.context, task=assembled.context.task.model_copy(update={"event": event})
        )
        request = prepare_followup_request(original)
        if request.digest != reply.claim.request_digest:
            raise ValueError("original reply request changed")
        claimed = ClaimedFollowup(reply.claim, reply.claim_reference)
        self._authorization.recheck(claimed, request)
        released = release_text_followup(assembled.context, reply.draft, gate=self._release_gate)
        if (
            released.text != reply.display_text
            or tuple(
                ReplyCitation(reference=c.reference, quote=c.quote) for c in released.citations
            )
            != reply.citations
        ):
            raise ValueError("reply release changed")
        # A semantic callback cannot leave an expired/revoked canonical claim
        # active. Recheck current trusted scope after that independent gate.
        self._authorization.recheck(claimed, request)
        self._capture._principal(principal, self._capture._now())

    def capture(
        self,
        *,
        principal: InterfacePrincipal,
        request: FollowupRequest,
        claimed: ClaimedFollowup,
        release: FollowupRelease,
        usage: UsageObservation,
        retained_receipt: ContextualRecoveryReceipt,
        text_receipt: TextTurnRecoveryReceipt,
    ) -> SavedTextReply:
        result: SavedTextReply | None = None
        try:
            if (
                type(request) is not FollowupRequest
                or type(claimed) is not ClaimedFollowup
                or type(release) is not FollowupRelease
                or request != prepare_followup_request(request.context)
                or request.digest != claimed.claim.request_digest
            ):
                raise ValueError("exact reply inputs required")
            scope = claimed.claim.run_scope
            request_id = text_reply_request_id(scope.run_id, claimed.reference, request.digest)
            reply = TextReply(
                request_id=request_id,
                claim=claimed.claim,
                claim_reference=claimed.reference,
                usage=usage,
                original_observed_at=request.context.task.event.observed_at,
                recorded_at=self._capture._now(),
                draft=release.draft,
                display_text=release.text,
                citations=tuple(
                    ReplyCitation(reference=c.reference, quote=c.quote) for c in release.citations
                ),
            )
            self._validate(principal, reply, retained_receipt, text_receipt)
            # No recovery callback runs inside this SQL transaction. Advisory
            # request identity serializes conflicting first captures/replays.
            with self._capture._factory() as session:
                _assert_ledger_isolation(session)
                _lock(session, request_id)
                self._capture._principal(principal, self._capture._now())
                existing = _find(session, f"text-reply/{request_id}", SourceSystem.MANUAL)
                if existing is not None:
                    previous, digest = self._read(session, existing)
                    if previous != reply.model_copy(update={"recorded_at": previous.recorded_at}):
                        raise ValueError("reply replay conflict")
                    reply, source_id = previous, existing.id
                else:
                    raw = encode_text_reply(reply)
                    digest = content_hash_of(raw)
                    location = self._capture._artifacts.put(B.BRAINSTORM, digest, raw)
                    source, _ = record_source(
                        session,
                        trust_boundary=B.BRAINSTORM,
                        data_classification=C.CONFIDENTIAL,
                        system=SourceSystem.MANUAL,
                        external_ref=f"text-reply/{request_id}",
                        content_hash=digest,
                        content_location=location,
                        captured_at=reply.recorded_at,
                    )
                    source_id = source.id
                    session.commit()
            receipt = self._protection.protect(
                TextReplyCheckpointScope(source_id, digest, reply.recorded_at)
            )
            result = self.load(
                principal=principal,
                source_id=source_id,
                expected_reply_digest=digest,
                retained_receipt=retained_receipt,
                text_receipt=text_receipt,
                recovery_receipt=receipt,
            )
        except Exception:  # noqa: BLE001,S110 - private callback/record diagnostics
            pass
        if result is None:
            raise TextReplyCaptureError("reply unavailable or pending protection")
        return result

    def load(
        self,
        *,
        principal: InterfacePrincipal,
        source_id: UUID,
        expected_reply_digest: str,
        retained_receipt: ContextualRecoveryReceipt,
        text_receipt: TextTurnRecoveryReceipt,
        recovery_receipt: TextReplyRecoveryReceipt,
    ) -> SavedTextReply:
        result: SavedTextReply | None = None
        try:
            start = self._capture._now()
            self._capture._principal(principal, start)
            if (
                type(source_id) is not UUID
                or type(expected_reply_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_reply_digest) is None
            ):
                raise ValueError("reply identity invalid")
            with self._capture._factory() as session:
                _assert_ledger_isolation(session)
                source = session.get(Source, source_id)
                if source is None:
                    raise ValueError("reply missing")
                reply, digest = self._read(session, source)
                if digest != expected_reply_digest:
                    raise ValueError("reply digest mismatch")
            receipt = TextReplyRecoveryReceipt.model_validate(recovery_receipt)
            if (
                receipt.source_id != source_id
                or receipt.reply_digest != digest
                or receipt.captured_at != reply.recorded_at
                or receipt.verified_at > start
            ):
                raise ValueError("reply recovery binding mismatch")
            scope = TextReplyCheckpointScope(source_id, digest, reply.recorded_at)
            if self._protection.recheck(scope, receipt) is not None:
                raise ValueError("reply recovery acknowledgement invalid")
            self._validate(principal, reply, retained_receipt, text_receipt)
            with self._capture._factory() as session:
                _assert_ledger_isolation(session)
                source = session.get(Source, source_id)
                if source is None or self._read(session, source) != (reply, digest):
                    raise ValueError("reply changed during recovery")
                declared = reply.claim.run_scope
                for ref in (
                    declared.packet_reference,
                    *declared.context_references,
                    reply.claim_reference,
                    reply.claim.consent_reference,
                ):
                    current = session.get(Source, ref.source_id)
                    if (
                        current is None
                        or current.content_hash != ref.content_hash
                        or current.trust_boundary != B.BRAINSTORM
                        or current.data_classification != C.CONFIDENTIAL
                        or get_effective_source_classification(session, source_id=current.id)
                        != C.CONFIDENTIAL
                    ):
                        raise ValueError("reply dependency changed before acknowledgement")
                consent_source = session.get(Source, reply.claim.consent_reference.source_id)
                if consent_source is None:
                    raise ValueError("reply original consent missing")
                consent = FollowupConsent.model_validate_json(
                    _bytes(session, self._capture._artifacts, consent_source)
                )
                final = self._capture._now()
                if (
                    not consent.approved_at <= final < consent.expires_at
                    or _find(
                        session,
                        f"packet-followup-revocation/{consent_source.id}",
                        SourceSystem.USER_INSTRUCTION,
                    )
                    is not None
                ):
                    raise ValueError("reply claim expired or revoked before acknowledgement")
            final = self._capture._now()
            if not consent.approved_at <= final < consent.expires_at:
                raise ValueError("reply deadline crossed after ledger read")
            self._capture._principal(principal, final)
            if final < start or final < receipt.verified_at or final < reply.recorded_at:
                raise ValueError("reply release clock moved backward")
            result = SavedTextReply(source_id, digest, reply, receipt)
        except Exception:  # noqa: BLE001,S110 - private callback/record diagnostics
            pass
        if result is None:
            raise TextReplyCaptureError("reply unavailable or held")
        return result
