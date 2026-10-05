"""Concrete generated-reply recovery using existing BRAINSTORM backup/restore mechanics.

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
from datetime import datetime
from threading import RLock
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.followup_authorization import (
    FollowupConsentV2,
    NamedFollowupConsentBinding,
    checked_named_consent_inventory,
    decode_followup_consent,
    encode_followup_consent,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.text_reply_capture import (
    TextReply,
    TextReplyCheckpointScope,
    TextReplyRecoveryReceipt,
    decode_text_reply,
    text_reply_receipt_key,
)
from zacai.interfaces.text_turn_capture import decode_text_turn
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class TextReplyProtectionError(ValueError):
    """Fixed diagnostics; host must disable traceback-local capture."""


def _receipt_bytes(receipt: TextReplyRecoveryReceipt) -> bytes:
    return canonical_bytes(TextReplyRecoveryReceipt.model_validate(receipt).model_dump(mode="json"))


class BrainstormTextReplyProtection:
    """Dedicated concrete protector, not an agent-provided backup dependency.

    Serializes with existing contextual operators plus backup's shared throwaway
    target lease. Non-cooperating administrators still require an exclusive host
    recovery window. Existing receipts are never overwritten, including corrupt
    ones. Historical full snapshots remain recoverable as unrelated work grows;
    The selected inventory covers the generated reply, canonical claim/consent, user and explicit direct parents,
    packet and original context; ancestor bodies are not traversed.
    Selected provenance or current ACL/context changes can hold release. The
    host must reconcile that hold rather than silently replacing its receipt.
    """

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        clock: Callable[[], datetime],
        named_binding: NamedFollowupConsentBinding | None = None,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
        ):
            raise TextReplyProtectionError("reply protection configuration rejected")
        self._protector, self._clock = protector, clock
        if named_binding is not None:
            valid = False
            try:
                valid = type(clock) is HostObservedClock and named_binding.host_clock is clock
            except Exception:  # noqa: BLE001,S110 - fixed dependency diagnostics
                pass
            if not valid:
                raise TextReplyProtectionError("shared named binding clock required")
        self._named_binding = named_binding
        self._named_clock = clock if type(clock) is HostObservedClock else None
        self._lock = RLock()
        self._last_observed: datetime | None = None

    @property
    def host_clock(self) -> HostObservedClock:
        if type(self._clock) is not HostObservedClock:
            raise TextReplyProtectionError("shared reply host clock unavailable")
        return self._clock

    @property
    def named_binding(self) -> NamedFollowupConsentBinding | None:
        return self._named_binding

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

    def _read_reply(self, session: Session, source: Source) -> TextReply:
        if (
            source.system != SourceSystem.MANUAL
            or source.trust_boundary != B.BRAINSTORM
            or source.data_classification != C.CONFIDENTIAL
            or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
        ):
            raise ValueError("reply Source denied")
        turn = decode_text_reply(_bytes(session, self._protector._artifacts, source))
        if (
            source.external_ref != f"text-reply/{turn.request_id}"
            or source.captured_at != turn.recorded_at
        ):
            raise ValueError("reply Source provenance mismatch")
        return turn

    def _hashes(self, scope: TextReplyCheckpointScope) -> dict[UUID, str]:
        # Production callers hold _lease across inventory/recovery/recheck.
        # _now serializes only clock observations, not this SQL transaction.
        p = self._protector
        now = self._now()
        if (
            type(scope) is not TextReplyCheckpointScope
            or type(scope.source_id) is not UUID
            or type(scope.reply_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", scope.reply_digest) is None
            or type(now) is not datetime
            or now.utcoffset() is None
            or scope.boundary != B.BRAINSTORM
            or scope.classification != C.CONFIDENTIAL
            or type(scope.captured_at) is not datetime
            or scope.captured_at.utcoffset() is None
            or scope.captured_at > now
        ):
            raise ValueError("reply scope/time mismatch")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("reply session target mismatch")
            source = session.get(Source, scope.source_id)
            if (
                source is None
                or source.content_hash != scope.reply_digest
                or source.captured_at != scope.captured_at
            ):
                raise ValueError("reply Source missing/mismatched")
            reply = self._read_reply(session, source)
            declared = reply.claim.run_scope
            hashes = {scope.source_id: scope.reply_digest}

            def add(
                ref: EvidenceReference, system: SourceSystem, *, read: bool = True
            ) -> tuple[Source, bytes]:
                if ref.source_id in hashes:
                    raise ValueError("duplicate reply dependency Source")
                selected = session.get(Source, ref.source_id)
                if (
                    selected is None
                    or selected.system != system
                    or selected.trust_boundary != B.BRAINSTORM
                    or selected.data_classification != C.CONFIDENTIAL
                    or get_effective_source_classification(session, source_id=selected.id)
                    != C.CONFIDENTIAL
                    or selected.content_hash != ref.content_hash
                ):
                    raise ValueError("reply dependency Source denied")
                raw = _bytes(session, p._artifacts, selected) if read else b""
                hashes[selected.id] = ref.content_hash
                return selected, raw

            claim_source, claim_raw = add(reply.claim_reference, SourceSystem.MANUAL)
            if (
                claim_raw != canonical_bytes(reply.claim.model_dump(mode="json"))
                or claim_source.external_ref
                != f"packet-followup-claim/{reply.claim.consent_reference.source_id}"
                or claim_source.captured_at != reply.claim.claimed_at
            ):
                raise ValueError("reply canonical claim binding mismatch")
            consent_source, consent_raw = add(
                reply.claim.consent_reference, SourceSystem.USER_INSTRUCTION
            )
            consent = decode_followup_consent(consent_raw)
            if (
                consent_raw != encode_followup_consent(consent)
                or consent_source.external_ref != f"packet-followup-consent/{consent.id}"
                or consent_source.captured_at != consent.approved_at
                or consent.scope != declared
                or not consent.approved_at <= reply.claim.claimed_at < consent.expires_at
                or not reply.recorded_at < consent.expires_at
                or not reply.original_observed_at
                <= reply.claim.claimed_at
                <= reply.recorded_at
                <= now
            ):
                raise ValueError("reply original consent binding mismatch")
            named = None
            if type(consent) is FollowupConsentV2:
                binding = self._named_binding
                if binding is None or self._named_clock is None:
                    raise ValueError("named reply row binding unavailable")
                named = checked_named_consent_inventory(
                    session,
                    artifacts=p._artifacts,
                    consent=consent,
                    binding=binding,
                    clock=self._named_clock,
                    as_of=now,
                )
                add(consent.decision_reference, SourceSystem.USER_INSTRUCTION)
                if (
                    reply.original_observed_at != named.decision.original_observed_at
                    or reply.claim.request_digest != named.decision.prepared_request_digest
                    or not named.decision.bound_at <= reply.claim.claimed_at < consent.expires_at
                ):
                    raise ValueError("named reply original processing binding differs")
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
                or not user.recorded_at
                <= reply.original_observed_at
                <= reply.claim.claimed_at
                <= reply.recorded_at
            ):
                raise ValueError("reply user/context/time mismatch")
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
                    raise ValueError("reply direct parent binding mismatch")
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
                raise ValueError("reply original packet/context mismatch")
            for item in packet.task.context:
                selected = session.get(Source, item.reference.source_id)
                if selected is None:
                    raise ValueError("reply original evidence missing")
                add(item.reference, selected.system, read=False)
            if named is not None:
                for source_id, digest in named.hashes:
                    if hashes.get(source_id) != digest:
                        raise ValueError("named reply dependency inventory differs")
            return hashes

    def _fresh_named(self, scope: TextReplyCheckpointScope) -> None:
        # Legacy-only compositions do not acquire new callbacks. V2 is still
        # denied by _hashes before object reads when this dependency is absent.
        if self._named_binding is None:
            return
        p = self._protector
        if p._lease_guard is not None:
            raise ValueError("named fresh gate inside recovery lease")
        with p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != p._engine.url.database:
                raise ValueError("named reply session target mismatch")
            source = session.get(Source, scope.source_id)
            if (
                source is None
                or source.content_hash != scope.reply_digest
                or source.captured_at != scope.captured_at
            ):
                raise ValueError("named reply Source unavailable")
            reply = self._read_reply(session, source)
            consent_source = session.get(Source, reply.claim.consent_reference.source_id)
            if (
                consent_source is None
                or consent_source.content_hash != reply.claim.consent_reference.content_hash
                or consent_source.system != SourceSystem.USER_INSTRUCTION
                or consent_source.trust_boundary != B.BRAINSTORM
                or consent_source.data_classification != C.CONFIDENTIAL
                or get_effective_source_classification(session, source_id=consent_source.id)
                != C.CONFIDENTIAL
            ):
                raise ValueError("named reply consent missing")
            consent = decode_followup_consent(_bytes(session, p._artifacts, consent_source))
        if (
            type(consent) is FollowupConsentV2
            and self._named_binding.verify_fresh(consent, self._now()) is not None
        ):
            raise ValueError("named reply protected binding unavailable")

    def _load_receipt(self, key: str) -> TextReplyRecoveryReceipt:
        p = self._protector
        raw = age_decrypt(p._read(key, 64_000), p._identity)
        receipt = TextReplyRecoveryReceipt.model_validate_json(raw)
        if raw != _receipt_bytes(receipt) or receipt.receipt_object != key:
            raise ValueError("noncanonical recovery receipt")
        return receipt

    def _verify(
        self, scope: TextReplyCheckpointScope, receipt: TextReplyRecoveryReceipt
    ) -> datetime:
        p = self._protector
        started = self._now()
        if (
            started.utcoffset() is None
            or receipt.source_id != scope.source_id
            or receipt.reply_digest != scope.reply_digest
            or receipt.captured_at != scope.captured_at
            or receipt.verified_at > started
        ):
            raise ValueError("reply receipt mismatch")
        hashes = self._hashes(scope)
        # Artifact keys bind plaintext, and backup repair may re-encrypt them.
        # Historical observed ciphertext remains in the immutable receipt, but
        # current recoverability requires decryption and exact plaintext hash.
        for digest in hashes.values():
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("reply/dependency artifact mismatch")
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
            raise ValueError("reply inventory changed during restore")
        final = self._now()
        if final.utcoffset() is None or final < started or final < receipt.verified_at:
            raise ValueError("host clock moved backward")
        return final

    def protect(self, scope: TextReplyCheckpointScope) -> TextReplyRecoveryReceipt:
        result: TextReplyRecoveryReceipt | None = None
        try:
            operation_started = self._now()
            self._fresh_named(scope)
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            with self._lease() as require:
                hashes = self._hashes(scope)
                key = text_reply_receipt_key(scope.source_id, scope.reply_digest)
                p = self._protector
                if p._reader.exists(key):
                    receipt = self._load_receipt(key)
                    completed = self._verify(scope, receipt)
                else:
                    protected = p._protect_state(
                        hashes, f"BRAINSTORM/state/text-reply-{scope.source_id}"
                    )
                    artifact = p._read(
                        backup_object_key_for(B.BRAINSTORM, scope.reply_digest), 8_500_000
                    )
                    receipt = TextReplyRecoveryReceipt(
                        source_id=scope.source_id,
                        reply_digest=scope.reply_digest,
                        captured_at=scope.captured_at,
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
                    receipt = TextReplyRecoveryReceipt.model_validate(
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
                        raise ValueError("reply changed before receipt release")
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
            self._fresh_named(scope)
            if self._named_binding is not None and self._hashes(scope) != hashes:
                raise ValueError("named reply inventory changed after final host callback")
            released = self._now()
            if type(released) is not datetime or released.utcoffset() is None or released < final:
                raise ValueError("host clock moved backward after lease release")
            result = receipt
        except Exception:  # noqa: BLE001,S110 - no source/configuration diagnostics
            pass
        if result is None:
            raise TextReplyProtectionError("reply recovery unavailable; no acknowledgement")
        return result

    def recheck(self, scope: TextReplyCheckpointScope, receipt: TextReplyRecoveryReceipt) -> None:
        succeeded = False
        try:
            operation_started = self._now()
            self._fresh_named(scope)
            if type(operation_started) is not datetime or operation_started.utcoffset() is None:
                raise ValueError("aware operation clock required")
            receipt = TextReplyRecoveryReceipt.model_validate(receipt)
            with self._lease() as require:
                hashes = self._hashes(scope)  # Current source ACL/identity before object reads.
                loaded = self._load_receipt(receipt.receipt_object)
                if loaded != receipt:
                    raise ValueError("retained receipt differs")
                completed = self._verify(scope, loaded)
                require()
            self._fresh_named(scope)
            if self._named_binding is not None and self._hashes(scope) != hashes:
                raise ValueError("named reply inventory changed after final host callback")
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
            raise TextReplyProtectionError("reply recovery recheck unavailable; no acknowledgement")
