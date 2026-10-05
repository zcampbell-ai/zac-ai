"""Canonical follow-up consent/consumed-claim historical durability recovery.

Receipts prove recovery of committed canonical rows, not active processing
authority. Expiry/revocation is rechecked separately by the trusted ledger.
Existing BRAINSTORM backup/restore mechanics remain authoritative.

Construction performs no I/O. Host must explicitly approve/configure live use,
actual independent object clients and an exclusive cooperating recovery window.
No credentials, service mounting, approval, model or source-system action exists.
Local/mock clients demonstrate mechanics, never actual off-device availability.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy import text

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.brainstorm_identity_recovery import verify_brainstorm_recovered_identity
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.followup_authorization import (
    ClaimedFollowup,
    FollowupClaim,
    FollowupConsent,
    FollowupHostSnapshot,
    FollowupRunScope,
    _owner_digest,
    _raw,
    followup_scope_digest,
    scope_from_snapshot,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.text_turn_capture import decode_text_turn
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class FollowupAuthorityRecoveryError(ValueError):
    """Fixed diagnostics; host must disable traceback-local capture."""


def followup_authority_receipt_key(source_id: UUID, digest: str) -> str:
    if (
        type(source_id) is not UUID
        or type(digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise FollowupAuthorityRecoveryError("authority checkpoint identity unavailable")
    return f"BRAINSTORM/state/followup-authority-{source_id}/receipt-{digest}.age"


class FollowupAuthoritySubject(Contract):
    """Exact historical subject metadata, never authority or authentication."""

    kind: Literal["consent", "consumed_claim"]
    reference: EvidenceReference
    consent_reference: EvidenceReference
    scope_digest: Digest
    captured_at: AwareDatetime
    original_request_digest: Digest | None = None
    original_observed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def bindings(self) -> Self:
        for ref in (self.reference, self.consent_reference):
            if ref.trust_boundary != B.BRAINSTORM or ref.effective_classification != C.CONFIDENTIAL:
                raise ValueError("authority subject boundary invalid")
        if self.kind == "consent":
            if (
                self.reference != self.consent_reference
                or self.original_request_digest is not None
                or self.original_observed_at is not None
            ):
                raise ValueError("consent subject binding invalid")
        elif (
            self.reference.source_id == self.consent_reference.source_id
            or self.original_request_digest is None
            or self.original_observed_at is None
            or self.original_observed_at > self.captured_at
        ):
            raise ValueError("claim subject binding invalid")
        return self


def consent_subject(
    consent: FollowupConsent, reference: EvidenceReference
) -> FollowupAuthoritySubject:
    consent = FollowupConsent.model_validate(consent)
    if reference.content_hash != content_hash_of(_raw(consent)):
        raise FollowupAuthorityRecoveryError("authority subject unavailable")
    return FollowupAuthoritySubject(
        kind="consent",
        reference=reference,
        consent_reference=reference,
        scope_digest=followup_scope_digest(consent.scope),
        captured_at=consent.approved_at,
    )


def claim_subject(claimed: ClaimedFollowup, request: FollowupRequest) -> FollowupAuthoritySubject:
    if (
        type(claimed) is not ClaimedFollowup
        or type(request) is not FollowupRequest
        or request != prepare_followup_request(request.context)
        or claimed.claim.request_digest != request.digest
        or claimed.reference.content_hash != content_hash_of(_raw(claimed.claim))
        or not request.context.task.event.occurred_at
        <= request.context.task.event.observed_at
        <= claimed.claim.claimed_at
    ):
        raise FollowupAuthorityRecoveryError("authority subject unavailable")
    return FollowupAuthoritySubject(
        kind="consumed_claim",
        reference=claimed.reference,
        consent_reference=claimed.claim.consent_reference,
        scope_digest=followup_scope_digest(claimed.claim.run_scope),
        captured_at=claimed.claim.claimed_at,
        original_request_digest=request.digest,
        original_observed_at=request.context.task.event.observed_at,
    )


class FollowupAuthorityRecoveryReceipt(Contract):
    format: Literal["zac-followup-authority-recovery-v1"] = "zac-followup-authority-recovery-v1"
    subject: FollowupAuthoritySubject = Field(repr=False)
    inventory_digest: Digest
    key_proof_digest: Digest
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    artifact_ciphertext_hash: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def chronology(self) -> Self:
        if self.verified_at < self.subject.captured_at:
            raise ValueError("authority recovery chronology invalid")
        return self

    @property
    def receipt_object(self) -> str:
        return followup_authority_receipt_key(
            self.subject.reference.source_id, self.subject.reference.content_hash
        )

    @property
    def artifact_object(self) -> str:
        return backup_object_key_for(B.BRAINSTORM, self.subject.reference.content_hash)

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/followup-authority-{self.subject.reference.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/followup-authority-{self.subject.reference.source_id}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


def _inventory_digest(hashes: dict[UUID, str]) -> str:
    return content_hash_of(
        canonical_bytes(
            {
                str(key): value
                for key, value in sorted(hashes.items(), key=lambda pair: str(pair[0]))
            }
        )
    )


def _receipt_bytes(receipt: FollowupAuthorityRecoveryReceipt) -> bytes:
    return canonical_bytes(
        FollowupAuthorityRecoveryReceipt.model_validate(receipt).model_dump(mode="json")
    )


class BrainstormFollowupAuthorityRecovery:
    """Dedicated concrete protector, not an agent-provided backup dependency.

    Serializes with existing contextual operators plus backup's shared throwaway
    target lease. Non-cooperating administrators still require an exclusive host
    recovery window. Existing receipts are never overwritten, including corrupt
    ones. Historical full snapshots remain recoverable as unrelated work grows;
    The selected inventory covers the authority subject, consent, user and explicit direct parents,
    packet and original context; ancestor bodies are not traversed.
    Selected provenance or current ACL/context changes can hold release. The
    host must reconcile that hold rather than silently replacing its receipt.
    """

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        clock: HostObservedClock,
        refresh: Callable[[], FollowupHostSnapshot],
        owner: Callable[[], OwnerGrant],
        recovered_key_receipt: Path,
        expected_key_proof_digest: str,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
            or type(clock) is not HostObservedClock
            or re.fullmatch(r"[0-9a-f]{64}", expected_key_proof_digest) is None
        ):
            raise FollowupAuthorityRecoveryError("authority recovery configuration rejected")
        self._protector, self._clock = protector, clock
        self._refresh, self._owner = refresh, owner
        self._key_receipt, self._key_proof_digest = recovered_key_receipt, expected_key_proof_digest
        self._lock = RLock()
        self._last_observed: datetime | None = None

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def _key_check(self) -> None:
        p = self._protector
        verify_brainstorm_recovered_identity(
            verification_objects=p._reader,
            recipient=p._recipient,
            identity_path=p._identity,
            recovered_key_receipt=self._key_receipt,
            expected_receipt_hash=self._key_proof_digest,
        )

    def _fresh(self, declared: FollowupRunScope, subject: FollowupAuthoritySubject) -> None:
        snapshot = self._refresh()
        if (
            scope_from_snapshot(snapshot, run_id=declared.run_id, builder_id=declared.builder_id)
            != declared
            or _owner_digest(self._owner()) != declared.owner_grant_digest
        ):
            raise ValueError("authority current owner/context changed")
        if subject.kind == "consumed_claim":
            event = snapshot.assembled.context.task.event.model_copy(
                update={"observed_at": subject.original_observed_at}
            )
            context = replace(
                snapshot.assembled.context,
                task=snapshot.assembled.context.task.model_copy(update={"event": event}),
            )
            request = prepare_followup_request(context)
            if (
                request.digest != subject.original_request_digest
                or not event.occurred_at <= event.observed_at <= subject.captured_at
            ):
                raise ValueError("authority original request changed")

    def _fresh_subject(self, subject: FollowupAuthoritySubject) -> None:
        """Canonical recovery refresh runs outside our SQL and restore leases."""
        p = self._protector
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("authority refresh session mismatch")
            source = session.get(Source, subject.consent_reference.source_id)
            if (
                source is None
                or source.system != SourceSystem.USER_INSTRUCTION
                or source.trust_boundary != B.BRAINSTORM
                or source.data_classification != C.CONFIDENTIAL
                or get_effective_source_classification(session, source_id=source.id)
                != C.CONFIDENTIAL
                or source.content_hash != subject.consent_reference.content_hash
            ):
                raise ValueError("authority refresh consent denied")
            raw = _bytes(session, p._artifacts, source)
            consent = FollowupConsent.model_validate_json(raw)
            if (
                raw != _raw(consent)
                or source.external_ref != f"packet-followup-consent/{consent.id}"
                or source.captured_at != consent.approved_at
                or followup_scope_digest(consent.scope) != subject.scope_digest
            ):
                raise ValueError("authority refresh consent mismatch")
        self._fresh(consent.scope, subject)

    def preflight(self, consent: FollowupConsent) -> None:
        """Pre-commit prerequisites; never claims a nonexistent Source is backed up.

        Fresh host assembly must perform canonical input recovery. Actual newly
        committed authority recovery is exclusively the post-commit methods.
        """
        succeeded = False
        try:
            consent = FollowupConsent.model_validate(consent)
            started = self._now()
            self._key_check()
            snapshot = self._refresh()
            if (
                scope_from_snapshot(
                    snapshot, run_id=consent.scope.run_id, builder_id=consent.scope.builder_id
                )
                != consent.scope
                or _owner_digest(self._owner()) != consent.scope.owner_grant_digest
                or self._now() < started
            ):
                raise ValueError("authority pre-commit prerequisites changed")
            succeeded = True
        except Exception:  # noqa: BLE001,S110 - fixed private-safe diagnostic
            pass
        if not succeeded:
            raise FollowupAuthorityRecoveryError("authority preflight unavailable")

    def protect_consent(self, *, consent: FollowupConsent, reference: EvidenceReference) -> None:
        """Durability only; the calling ledger separately checks active permission."""
        succeeded = False
        try:
            subject = consent_subject(consent, reference)
            receipt = self.protect(subject)
            if (
                type(receipt) is not FollowupAuthorityRecoveryReceipt
                or receipt.subject != subject
                or receipt.key_proof_digest != self._key_proof_digest
            ):
                raise ValueError("authority recovery result differs")
            succeeded = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not succeeded:
            raise FollowupAuthorityRecoveryError("authority consent recovery unavailable")

    def protect_claim(self, *, claimed: ClaimedFollowup, request: FollowupRequest) -> None:
        """Consumed-attempt durability, never renewal or runtime dispatch."""
        succeeded = False
        try:
            subject = claim_subject(claimed, request)
            receipt = self.protect(subject)
            if (
                type(receipt) is not FollowupAuthorityRecoveryReceipt
                or receipt.subject != subject
                or receipt.key_proof_digest != self._key_proof_digest
            ):
                raise ValueError("authority recovery result differs")
            succeeded = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not succeeded:
            raise FollowupAuthorityRecoveryError("authority claim recovery unavailable")

    def _now(self) -> datetime:
        """Validate every observed host clock value, including inventory reads.

        Equal observations are valid. This process-local watermark is not a
        persistent/global clock service or standalone inventory transaction gate.
        """
        with self._lock:
            now = self._clock()
            if (
                type(now) is not datetime
                or now.utcoffset() is None
                or (self._last_observed is not None and now < self._last_observed)
            ):
                raise ValueError("host clock observation moved backward or is invalid")
            self._last_observed = now
            return now

    @contextmanager
    def _lease(self) -> Iterator[Callable[[], None]]:
        with checkpoint_lease(self._protector, self._lock) as require:
            yield require

    def _hashes(self, scope: FollowupAuthoritySubject) -> dict[UUID, str]:
        """Caller holds the shared lease; each selected row is currently ACL-gated.

        Current owner is checked by _fresh_subject before/after the lease; no
        arbitrary host callback runs in this inventory transaction. Historical
        durability does not require an active processing TTL or dispatch; the
        ledger owns those fresh gates.
        """
        scope = FollowupAuthoritySubject.model_validate(scope)
        p = self._protector
        now = self._now()
        if scope.captured_at > now:
            raise ValueError("authority subject is future dated")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("authority session target mismatch")
            hashes: dict[UUID, str] = {}

            def add(
                ref: EvidenceReference, system: SourceSystem, *, read: bool = True
            ) -> tuple[Source, bytes]:
                if ref.source_id in hashes:
                    raise ValueError("duplicate authority dependency Source")
                selected = session.get(Source, ref.source_id)
                if (
                    selected is None
                    or selected.system != system
                    or selected.trust_boundary != B.BRAINSTORM
                    or selected.data_classification != C.CONFIDENTIAL
                    or ref.trust_boundary != B.BRAINSTORM
                    or ref.effective_classification != C.CONFIDENTIAL
                    or get_effective_source_classification(session, source_id=selected.id)
                    != C.CONFIDENTIAL
                    or selected.content_hash != ref.content_hash
                    or selected.captured_at > now
                ):
                    raise ValueError("authority dependency Source denied")
                raw = _bytes(session, p._artifacts, selected) if read else b""
                hashes[selected.id] = ref.content_hash
                return selected, raw

            if scope.kind == "consumed_claim":
                claim_source, claim_raw = add(scope.reference, SourceSystem.MANUAL)
                claim = FollowupClaim.model_validate_json(claim_raw)
                if (
                    claim_raw != _raw(claim)
                    or claim_source.external_ref
                    != f"packet-followup-claim/{scope.consent_reference.source_id}"
                    or claim_source.captured_at != scope.captured_at
                    or claim.claimed_at != scope.captured_at
                    or claim.consent_reference != scope.consent_reference
                    or claim.request_digest != scope.original_request_digest
                ):
                    raise ValueError("authority canonical claim mismatch")
                declared = claim.run_scope
            consent_source, consent_raw = add(
                scope.consent_reference, SourceSystem.USER_INSTRUCTION
            )
            consent = FollowupConsent.model_validate_json(consent_raw)
            if (
                consent_raw != _raw(consent)
                or consent_source.external_ref != f"packet-followup-consent/{consent.id}"
                or consent_source.captured_at != consent.approved_at
                or followup_scope_digest(consent.scope) != scope.scope_digest
                or consent.approved_at > now
            ):
                raise ValueError("authority canonical consent mismatch")
            if scope.kind == "consent":
                if scope.captured_at != consent.approved_at:
                    raise ValueError("authority consent capture mismatch")
                declared = consent.scope
            elif (
                declared != consent.scope
                or not consent.approved_at <= scope.captured_at < consent.expires_at
            ):
                raise ValueError("authority claim original window mismatch")
            user_source, user_raw = add(declared.user_reference, SourceSystem.USER_INSTRUCTION)
            user = decode_text_turn(user_raw)
            if (
                user_source.external_ref != f"text-turn/{user.request_id}"
                or user_source.captured_at != user.recorded_at
                or user.issuer != declared.actor_issuer
                or user.subject != declared.actor_subject
                or user.conversation_id != declared.conversation_id
                or user.packet_reference != declared.packet_reference
                or user.parent_references != declared.parent_references
                or user.packet_receipt_digest != declared.packet_receipt_digest
                or user.recorded_at > consent.approved_at
            ):
                raise ValueError("authority user context mismatch")
            if scope.kind == "consumed_claim" and (
                scope.original_observed_at is None
                or not user.recorded_at <= scope.original_observed_at <= scope.captured_at
            ):
                raise ValueError("authority user observation mismatch")
            for ref in declared.parent_references:
                parent_source, parent_raw = add(ref, SourceSystem.USER_INSTRUCTION)
                parent = decode_text_turn(parent_raw)
                if (
                    parent_source.external_ref != f"text-turn/{parent.request_id}"
                    or parent_source.captured_at != parent.recorded_at
                    or parent.issuer != user.issuer
                    or parent.subject != user.subject
                    or parent.conversation_id != user.conversation_id
                    or parent.packet_reference != user.packet_reference
                    or parent.packet_receipt_digest != user.packet_receipt_digest
                    or parent.recorded_at > user.recorded_at
                    or parent.request_id == user.request_id
                ):
                    raise ValueError("authority direct parent mismatch")
            add(declared.packet_reference, SourceSystem.MANUAL)
            packet = load_contextual_packet(
                session,
                artifacts=p._artifacts,
                source_id=declared.packet_reference.source_id,
                expected_digest=declared.packet_reference.content_hash,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
            if (
                packet_fingerprint(packet) != declared.packet_reference.content_hash
                or packet.created_at > user.recorded_at
                or declared.context_references
                != (
                    declared.user_reference,
                    *(item.reference for item in packet.task.context),
                    *declared.parent_references,
                )
            ):
                raise ValueError("authority original context mismatch")
            for item in packet.task.context:
                selected = session.get(Source, item.reference.source_id)
                if selected is None:
                    raise ValueError("authority original evidence missing")
                add(item.reference, selected.system, read=False)
            return hashes

    def _load_receipt(self, key: str) -> FollowupAuthorityRecoveryReceipt:
        p = self._protector
        raw = age_decrypt(p._read(key, 64_000), p._identity)
        receipt = FollowupAuthorityRecoveryReceipt.model_validate_json(raw)
        if raw != _receipt_bytes(receipt) or receipt.receipt_object != key:
            raise ValueError("noncanonical recovery receipt")
        return receipt

    def _verify(
        self, scope: FollowupAuthoritySubject, receipt: FollowupAuthorityRecoveryReceipt
    ) -> datetime:
        p = self._protector
        started = self._now()
        hashes = self._hashes(scope)
        if (
            started.utcoffset() is None
            or receipt.subject != scope
            or receipt.inventory_digest != _inventory_digest(hashes)
            or receipt.key_proof_digest != self._key_proof_digest
            or receipt.verified_at > started
        ):
            raise ValueError("authority receipt mismatch")
        # Artifact keys bind plaintext, and backup repair may re-encrypt them.
        # Historical observed ciphertext remains in the immutable receipt, but
        # current recoverability requires decryption and exact plaintext hash.
        for digest in hashes.values():
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("authority/dependency artifact mismatch")
        state = p._read(receipt.state_object, 65_000_000)
        journal = p._read(receipt.journal_object, 4_100_000)
        if (
            content_hash_of(state) != receipt.state_ciphertext_hash
            or content_hash_of(journal) != receipt.journal_ciphertext_hash
        ):
            raise ValueError("checkpoint ciphertext mismatch")
        plain = age_decrypt(state, p._identity)
        plain_journal = age_decrypt(journal, p._identity)
        if (
            content_hash_of(plain) != receipt.state_plaintext_hash
            or content_hash_of(plain_journal) != receipt.journal_plaintext_hash
        ):
            raise ValueError("checkpoint plaintext mismatch")
        backup._csv_columns("artifact_backup_run", plain_journal)
        runs = list(csv.DictReader(io.StringIO(plain_journal.decode("utf-8"))))
        matched = [row for row in runs if row.get("id") == str(receipt.artifact_backup_run_id)]
        if (
            len(matched) != 1
            or matched[0].get("trust_boundary") != B.BRAINSTORM.value
            or matched[0].get("status") != "SUCCEEDED"
        ):
            raise ValueError("artifact backup journal binding mismatch")
        run_started = datetime.fromisoformat(matched[0]["started_at"])
        run_finished = datetime.fromisoformat(matched[0]["finished_at"])
        if (
            run_started.utcoffset() is None
            or run_finished.utcoffset() is None
            or not scope.captured_at <= run_started <= run_finished <= receipt.verified_at
        ):
            raise ValueError("artifact backup run chronology mismatch")
        p._restoration.verify(
            plain, hashes, current_selected_sources=p._engine, operational_journal=plain_journal
        )
        if self._hashes(scope) != hashes:
            raise ValueError("authority inventory changed during restore")
        final = self._now()
        if final.utcoffset() is None or final < started or final < receipt.verified_at:
            raise ValueError("host clock moved backward")
        return final

    def protect(self, scope: FollowupAuthoritySubject) -> FollowupAuthorityRecoveryReceipt:
        result: FollowupAuthorityRecoveryReceipt | None = None
        try:
            scope = FollowupAuthoritySubject.model_validate(scope)
            operation_started = self._now()
            self._key_check()
            self._fresh_subject(scope)
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            with self._lease() as require:
                hashes = self._hashes(scope)
                key = followup_authority_receipt_key(
                    scope.reference.source_id, scope.reference.content_hash
                )
                p = self._protector
                if p._reader.exists(key):
                    receipt = self._load_receipt(key)
                    completed = self._verify(scope, receipt)
                else:
                    protected = p._protect_state(
                        hashes, f"BRAINSTORM/state/followup-authority-{scope.reference.source_id}"
                    )
                    artifact = p._read(
                        backup_object_key_for(B.BRAINSTORM, scope.reference.content_hash), 8_500_000
                    )
                    receipt = FollowupAuthorityRecoveryReceipt(
                        subject=scope,
                        inventory_digest=_inventory_digest(hashes),
                        key_proof_digest=self._key_proof_digest,
                        verified_at=self._now(),
                        artifact_backup_run_id=protected.artifact_backup_run_id,
                        artifact_ciphertext_hash=content_hash_of(artifact),
                        state_ciphertext_hash=protected.state_ciphertext_hash,
                        state_plaintext_hash=protected.state_plaintext_hash,
                        journal_ciphertext_hash=protected.journal_ciphertext_hash,
                        journal_plaintext_hash=protected.journal_plaintext_hash,
                    )
                    if (
                        protected.state_object != receipt.state_object
                        or protected.journal_object != receipt.journal_object
                    ):
                        raise ValueError("checkpoint namespace mismatch")
                    completed = self._verify(scope, receipt)
                    if completed < operation_started:
                        raise ValueError("host clock moved backward during recovery")
                    receipt = FollowupAuthorityRecoveryReceipt.model_validate(
                        receipt.model_copy(update={"verified_at": completed})
                    )
                    raw = _receipt_bytes(receipt)
                    encrypted = age_encrypt(raw, p._recipient)
                    require()
                    if p._reader.exists(key):
                        raise ValueError("receipt already present; explicit retry required")
                    p._put(key, encrypted)
                    if p._read(key, 64_000) != encrypted or self._load_receipt(key) != receipt:
                        raise ValueError("receipt readback mismatch")
                    if self._hashes(scope) != hashes:
                        raise ValueError("authority changed before receipt release")
                final = self._now()
                if (
                    type(final) is not datetime
                    or final.utcoffset() is None
                    or final < operation_started
                    or final < completed
                    or final < receipt.verified_at
                ):
                    raise ValueError("host clock moved backward before receipt release")
                require()
            self._key_check()
            self._fresh_subject(scope)
            if self._hashes(scope) != hashes:
                raise ValueError("authority inventory changed after lease release")
            released = self._now()
            if type(released) is not datetime or released.utcoffset() is None or released < final:
                raise ValueError("host clock moved backward after lease release")
            result = receipt
        except Exception:  # noqa: BLE001,S110 - no source/configuration diagnostics
            pass
        if result is None:
            raise FollowupAuthorityRecoveryError(
                "authority recovery unavailable; no acknowledgement"
            )
        return result

    def recheck(
        self, scope: FollowupAuthoritySubject, receipt: FollowupAuthorityRecoveryReceipt
    ) -> None:
        succeeded = False
        try:
            scope = FollowupAuthoritySubject.model_validate(scope)
            operation_started = self._now()
            self._key_check()
            self._fresh_subject(scope)
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            receipt = FollowupAuthorityRecoveryReceipt.model_validate(receipt)
            with self._lease() as require:
                hashes = self._hashes(scope)  # Current source ACL/identity before object reads.
                if (
                    receipt.subject != scope
                    or receipt.inventory_digest != _inventory_digest(hashes)
                    or receipt.key_proof_digest != self._key_proof_digest
                ):
                    raise ValueError("retained receipt subject/inventory/proof differs")
                loaded = self._load_receipt(receipt.receipt_object)
                if loaded != receipt:
                    raise ValueError("retained receipt differs")
                completed = self._verify(scope, loaded)
                require()
            self._key_check()
            self._fresh_subject(scope)
            if self._hashes(scope) != hashes:
                raise ValueError("authority inventory changed after lease release")
            final = self._now()
            if (
                type(final) is not datetime
                or final.utcoffset() is None
                or final < operation_started
                or final < completed
                or final < receipt.verified_at
            ):
                raise ValueError("host clock moved backward before recovery acknowledgement")
            succeeded = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not succeeded:
            raise FollowupAuthorityRecoveryError(
                "authority recovery recheck unavailable; no acknowledgement"
            )
