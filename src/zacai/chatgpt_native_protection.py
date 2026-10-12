"""PERSONAL native-pair whole-inventory recovery, never task/processing authority.

Reuses the existing concrete PERSONAL backup/cold-restore machinery. BRAINSTORM
has no compatible native subject API here and is explicitly held, never aliased.
"""

from __future__ import annotations

import json
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.chatgpt_native_custody import _bound_factory, _host, _standard_factory
from zacai.chatgpt_native_source import load_chatgpt_native_view_pair
from zacai.chatgpt_native_view import ChatGPTNativeViewCompanion
from zacai.claude_local_custody import _SCOPE
from zacai.contextual_protection import (
    ContextualProtectionError,
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.interfaces.named_session_binding import VerifiedNamedSession
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class _PersonalNativeSubject(Contract):
    capture_id: UUID
    original_reference: EvidenceReference = Field(repr=False)
    companion_reference: EvidenceReference = Field(repr=False)
    companion_digest: Digest
    selected_pointer: str = Field(min_length=1, max_length=255)
    selected_text_hash: Digest
    reported_role: Literal["USER", "ASSISTANT"]
    projection_observed_at: AwareDatetime
    source_captured_at: tuple[AwareDatetime, AwareDatetime]
    actor_issuer: str = Field(min_length=1, max_length=255)
    actor_subject: str = Field(min_length=1, max_length=255, repr=False)
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime

    @model_validator(mode="after")
    def assigned_pair(self) -> Self:
        refs = (self.original_reference, self.companion_reference)
        if (
            self.capture_id.int == 0
            or any(r.source_id.int == 0 for r in refs)
            or refs[0].source_id == refs[1].source_id
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or self.companion_digest != refs[1].content_hash
            or not self.selected_pointer.startswith("/turns/")
            or self.source_captured_at[0] > self.source_captured_at[1]
            or self.projection_observed_at > self.source_captured_at[1]
            or self.original_session_issued_at >= self.original_session_expires_at
        ):
            raise ValueError("explicit PERSONAL HR native subject required")
        return self

    @property
    def subject_digest(self) -> str:
        return content_hash_of(
            canonical_bytes(
                _PersonalNativeSubject.model_validate(
                    {n: getattr(self, n) for n in _PersonalNativeSubject.model_fields}
                ).model_dump(mode="json")
            )
        )


class PersonalNativePairRecoveryReceiptV1(_PersonalNativeSubject):
    format: Literal["zac-personal-chatgpt-native-pair-recovery-v1"] = (
        "zac-personal-chatgpt-native-pair-recovery-v1"
    )
    full_plan_digest: Digest
    full_boundary_source_hashes: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    full_boundary_source_fingerprints: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    live_journal_digest: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def complete_inventory(self) -> Self:
        hashes = dict(self.full_boundary_source_hashes)
        if (
            self.artifact_backup_run_id.int == 0
            or not 1 <= len(hashes) == len(self.full_boundary_source_hashes) <= 4096
            or any(s.int == 0 for s in hashes)
            or tuple(sorted(self.full_boundary_source_hashes, key=lambda p: str(p[0])))
            != self.full_boundary_source_hashes
            or tuple(s for s, _ in self.full_boundary_source_hashes)
            != tuple(s for s, _ in self.full_boundary_source_fingerprints)
            or hashes.get(self.original_reference.source_id) != self.original_reference.content_hash
            or hashes.get(self.companion_reference.source_id)
            != self.companion_reference.content_hash
            or not self.original_session_issued_at
            <= self.verified_at
            < self.original_session_expires_at
            or self.source_captured_at[1] > self.verified_at
        ):
            raise ValueError("complete native inventory checkpoint required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/chatgpt-native-{self.capture_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.subject_digest}.age"

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def current_facts_verified(self) -> Literal[False]:
        return False

    @property
    def source_authorship_verified(self) -> Literal[False]:
        return False


def encode_native_pair_recovery_receipt(value: PersonalNativePairRecoveryReceiptV1) -> bytes:
    if type(value) is not PersonalNativePairRecoveryReceiptV1:
        raise TypeError("exact native receipt required")
    raw = canonical_bytes(
        PersonalNativePairRecoveryReceiptV1.model_validate(
            value.model_dump(mode="json")
        ).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded native receipt required")
    return raw


def decode_native_pair_recovery_receipt(raw: bytes) -> PersonalNativePairRecoveryReceiptV1:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded native receipt required")
    result = PersonalNativePairRecoveryReceiptV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_native_pair_recovery_receipt(result) != raw:
        raise ValueError("canonical native receipt required")
    return result


def _native_access(
    protector: PersonalHistoryFragmentProtector,
    inputs: NamedOwnerHostInputs,
    prior: VerifiedNamedSession | None = None,
) -> VerifiedNamedSession:
    # Existing configuration/private-identity metadata checks first; actual
    # original signed owner is LAST after all host-clock/config callbacks.
    observed = protector._access(prior)
    protector._configuration()
    _host(inputs, protector._operation)
    inputs.clock()
    actual = protector._operation.recheck(observed.binding_digest)
    with inputs.clock._lock:
        now = inputs.clock._last
    if (
        actual != observed
        or (prior is not None and actual != prior)
        or actual.principal.scopes != _SCOPE
        or now is None
        or not actual.issued_at <= now < actual.effective_expires_at
    ):
        raise ValueError("current original PERSONAL owner required")
    return actual


def protect_personal_chatgpt_native_pair(
    protector: PersonalHistoryFragmentProtector,
    *,
    inputs: NamedOwnerHostInputs,
    capture_id: UUID,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    expected_companion: ChatGPTNativeViewCompanion,
    read_existing: bool = False,
) -> PersonalNativePairRecoveryReceiptV1:
    """Reopen exact pair, full backup/cold State+journal restore, no approval.

    Actual separately approved whole-inventory/key/independent-read setup remains
    required outside this dormant primitive. Per-instance lock plus exclusive
    cooperating operator window, no cross-process no-clobber guarantee. Existing
    receipt is reobserved only under the same original current operation/plan;
    no repair, processing expiry renewal or grant is inferred from receipt bytes.
    """
    from zacai.backup_artifacts import run_artifact_backup
    from zacai.claude_local_protection import _crypt, _read, _recover
    from zacai.review_protection import ReviewProtectionCleanupUncertain
    from zacai.state import ArtifactBackupRunStatus

    result = None
    uncertain = False
    interruption: type[KeyboardInterrupt | SystemExit] | None = None
    try:
        if (
            type(protector) is not PersonalHistoryFragmentProtector
            or type(inputs) is not NamedOwnerHostInputs
            or type(read_existing) is not bool
            or type(capture_id) is not UUID
            or capture_id.int == 0
        ):
            raise ValueError("concrete native PERSONAL recovery graph required")
        refs = tuple(
            EvidenceReference.model_validate(r.model_dump(mode="json"))
            for r in (original_reference, companion_reference)
        )
        if refs[0].source_id == refs[1].source_id or any(
            r.trust_boundary is not B.PERSONAL
            or r.effective_classification is not C.HIGHLY_RESTRICTED
            for r in refs
        ):
            raise ValueError("BRAINSTORM/mixed/weaker native subject unavailable")
        companion = ChatGPTNativeViewCompanion.model_validate(
            expected_companion.model_dump(mode="json")
        )
        _standard_factory(protector._factory)
        factory_class, factory_options = protector._factory.class_, dict(protector._factory.kw)
        with protector._lock:
            access = _native_access(protector, inputs)
            _bound_factory(protector._factory, factory_class, factory_options)
            plan = protector._plan()
            rows = json.loads(plan.rows)
            expected = {UUID(row["id"]): row["content_hash"] for row in rows}
            if any(expected.get(ref.source_id) != ref.content_hash for ref in refs):
                raise ValueError("full inventory excludes native pair")
            with protector._factory() as session:
                session.begin()
                entry = _physical(session)
                loaded = load_chatgpt_native_view_pair(
                    session,
                    artifacts=protector._artifacts,
                    capture_id=capture_id,
                    original_reference=refs[0],
                    companion_reference=refs[1],
                    expected_companion=companion,
                    authorized_boundaries=frozenset({B.PERSONAL}),
                    allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
                )
                _same(session, entry)
            _native_access(protector, inputs, access)
            _bound_factory(protector._factory, factory_class, factory_options)
            if protector._plan() != plan:
                raise ValueError("plan changed during native pair read")
            subject = _PersonalNativeSubject(
                capture_id=capture_id,
                original_reference=refs[0],
                companion_reference=refs[1],
                companion_digest=content_hash_of(
                    canonical_bytes(companion.model_dump(mode="json"))
                ),
                selected_pointer=companion.selected_field.pointer,
                selected_text_hash=companion.selected_text_hash,
                reported_role=companion.selected_field.reported_role,
                projection_observed_at=companion.projection_observed_at,
                source_captured_at=loaded.source_captured_at,
                actor_issuer=access.principal.identity.issuer,
                actor_subject=access.principal.identity.subject,
                original_session_binding=access.binding_digest,
                original_session_issued_at=access.issued_at,
                original_session_expires_at=access.effective_expires_at,
            )
            if (subject.actor_issuer, subject.actor_subject) != (
                access.principal.identity.issuer,
                access.principal.identity.subject,
            ):
                raise ValueError("exact current signed actor metadata required")
            binding = {n: getattr(subject, n) for n in _PersonalNativeSubject.model_fields}
            complete = dict(
                **binding,
                full_plan_digest=content_hash_of(plan.rows),
                full_boundary_source_hashes=tuple(
                    sorted(expected.items(), key=lambda p: str(p[0]))
                ),
                full_boundary_source_fingerprints=tuple(
                    sorted(
                        ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                        key=lambda p: str(p[0]),
                    )
                ),
            )
            prefix = f"PERSONAL/state/chatgpt-native-{capture_id}"
            key = f"{prefix}/receipt-{subject.subject_digest}.age"
            if read_existing:
                cipher = _read(protector._reader, key, 2_100_000)
                _native_access(protector, inputs, access)
                raw = _recover(cipher, protector._identity, 2_000_000)
                _native_access(protector, inputs, access)
                receipt = decode_native_pair_recovery_receipt(raw)
                receipt_cipher_digest = content_hash_of(cipher)
            else:
                if protector._reader.exists(key) is not False:
                    raise ValueError("existing native receipt cannot be overwritten or repaired")
                _native_access(protector, inputs, access)
                completed = run_artifact_backup(
                    protector._factory,
                    trust_boundary=B.PERSONAL,
                    artifact_store=protector._artifacts,
                    backup_store=protector._writer,
                    recipient=protector._recipient,
                    local_manifest_cache_path=protector._cache,
                    personal_plan=plan,
                )
                _native_access(protector, inputs, access)
                _bound_factory(protector._factory, factory_class, factory_options)
                if (
                    completed.status is not ArtifactBackupRunStatus.SUCCEEDED
                    or protector._plan() != plan
                ):
                    raise ValueError("full native inventory backup required")
                snapshot, journal = protector._snapshot(expected, completed.id)
                _native_access(protector, inputs, access)
                objects = []
                for name, plain, maximum in (
                    ("state", snapshot, 64_000_000),
                    ("journal", journal, 4_000_000),
                ):
                    encrypted = _crypt(plain, protector._recipient, maximum)
                    _native_access(protector, inputs, access)
                    digest = content_hash_of(encrypted)
                    protector._writer.put_object(f"{prefix}/{name}-{digest}.age", encrypted)
                    _native_access(protector, inputs, access)
                    objects.append((digest, content_hash_of(plain)))
                receipt = PersonalNativePairRecoveryReceiptV1.model_validate(
                    dict(
                        **complete,
                        verified_at=protector._clock(),
                        artifact_backup_run_id=completed.id,
                        live_journal_digest=content_hash_of(protector._run_row(completed.id)),
                        state_ciphertext_hash=objects[0][0],
                        state_plaintext_hash=objects[0][1],
                        journal_ciphertext_hash=objects[1][0],
                        journal_plaintext_hash=objects[1][1],
                    )
                )
            _native_access(protector, inputs, access)
            if any(getattr(receipt, n) != v for n, v in complete.items()):
                raise ValueError("exact native subject/full checkpoint binding required")
            observations = list(protector._artifacts_recover(plan, access))
            _native_access(protector, inputs, access)
            recovered = []
            for object_key, digest, plainhash, maximum in (
                (
                    receipt.state_object,
                    receipt.state_ciphertext_hash,
                    receipt.state_plaintext_hash,
                    64_000_000,
                ),
                (
                    receipt.journal_object,
                    receipt.journal_ciphertext_hash,
                    receipt.journal_plaintext_hash,
                    4_000_000,
                ),
            ):
                cipher = _read(protector._reader, object_key, maximum + 1_000_000)
                _native_access(protector, inputs, access)
                if content_hash_of(cipher) != digest:
                    raise ValueError("native snapshot ciphertext changed")
                plain = _recover(cipher, protector._identity, maximum)
                _native_access(protector, inputs, access)
                if content_hash_of(plain) != plainhash:
                    raise ValueError("native snapshot plaintext changed")
                recovered.append(plain)
                observations.append((object_key, digest, maximum + 1_000_000))
            protector._restoration.verify_personal(
                recovered[0],
                expected,
                current_selected_sources=protector._engine,
                operational_journal=recovered[1],
            )
            _native_access(protector, inputs, access)
            if not read_existing:
                receipt = PersonalNativePairRecoveryReceiptV1.model_validate(
                    {**receipt.model_dump(), "verified_at": protector._clock()}
                )
                cipher = _crypt(
                    encode_native_pair_recovery_receipt(receipt), protector._recipient, 2_000_000
                )
                _native_access(protector, inputs, access)
                if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                    raise ValueError("bounded native receipt ciphertext required")
                # Bounded inherited re-observation AFTER proof/crypto callbacks,
                # BEFORE first immutable receipt publication. No repair on HOLD.
                protector._reobserve_objects(tuple(observations), access)
                _native_access(protector, inputs, access)
                protector._writer.put_object(key, cipher)
                _native_access(protector, inputs, access)
                returned = _read(protector._reader, key, 2_100_000)
                _native_access(protector, inputs, access)
                raw = _recover(returned, protector._identity, 2_000_000)
                _native_access(protector, inputs, access)
                if returned != cipher or decode_native_pair_recovery_receipt(raw) != receipt:
                    raise ValueError("native receipt readback differs")
                receipt_cipher_digest = content_hash_of(returned)
            protector._reobserve_objects(
                (*observations, (key, receipt_cipher_digest, 2_100_000)), access
            )
            _native_access(protector, inputs, access)
            with protector._clock._lock:
                terminal = protector._clock._last
            if terminal is None or receipt.verified_at > terminal:
                raise ValueError("actual native verification time required")
            _bound_factory(protector._factory, factory_class, factory_options)
            # Finite owner watermark only: callback-free terminal Source/journal
            # reads follow it. No promise of owner currency/expiry at return or
            # detection of later external changes; future consumers recheck.
            if (
                protector._plan() != plan
                or content_hash_of(protector._run_row(receipt.artifact_backup_run_id))
                != receipt.live_journal_digest
            ):
                raise ValueError("terminal native inventory/journal changed")
            result = receipt
    except (ReviewProtectionCleanupUncertain, PersonalFragmentCleanupUncertain):
        uncertain = True
    except KeyboardInterrupt:
        interruption = KeyboardInterrupt
    except SystemExit:
        interruption = SystemExit
    except Exception:  # noqa: BLE001 - fixed private-safe HOLD, never retry.
        result = None
    if uncertain:
        raise PersonalFragmentCleanupUncertain(
            "PERSONAL native cleanup uncertain; operator review required"
        )
    if interruption is not None:
        raise interruption("PERSONAL native checkpoint interrupted; stop and reconcile")
    if result is None:
        raise ContextualProtectionError(
            "PERSONAL native checkpoint unavailable; stop and reconcile"
        )
    return result
