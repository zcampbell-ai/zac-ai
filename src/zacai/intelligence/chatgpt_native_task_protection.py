"""Native retained-task whole PERSONAL recovery; never processing authority.

Distinct subject/key, unchanged pair receipt. Reuses concrete full inventory
backup/State/journal/cold restore mechanics; no Claude semantic cast or store.
"""

from __future__ import annotations

import json
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.chatgpt_native_custody import _bound_factory, _standard_factory
from zacai.chatgpt_native_protection import _native_access, _PersonalNativeSubject
from zacai.contextual_protection import (
    ContextualProtectionError,
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import chatgpt_native_retention as retained
from zacai.intelligence.chatgpt_native_task import ChatGPTNativeTaskDeclarationV1
from zacai.intelligence.contracts import Digest, EvidenceReference
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.interfaces.named_session_binding import VerifiedNamedSession
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class _PersonalNativeTaskSubject(_PersonalNativeSubject):
    declaration_id: UUID
    declaration_reference: EvidenceReference
    association_reference: EvidenceReference
    request_digest: Digest
    wire_digest: Digest
    counter_digest: Digest
    original_task_id: UUID
    derived_task_id: UUID
    selected_references: tuple[EvidenceReference, ...] = Field(
        min_length=3, max_length=96, repr=False
    )
    retained_captured_at: AwareDatetime
    declaration_prepared_at: AwareDatetime
    declaration_expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_task(self) -> Self:
        refs = self.selected_references
        if (
            any(
                v.int == 0
                for v in (self.declaration_id, self.original_task_id, self.derived_task_id)
            )
            or len({r.source_id for r in refs}) != len(refs)
            or tuple(sorted(refs, key=lambda r: str(r.source_id))) != refs
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or any(
                r not in refs
                for r in (
                    self.original_reference,
                    self.companion_reference,
                    self.declaration_reference,
                    self.association_reference,
                )
            )
            or len(
                {
                    r.source_id
                    for r in (
                        self.original_reference,
                        self.companion_reference,
                        self.declaration_reference,
                        self.association_reference,
                    )
                }
            )
            != 4
            or not self.original_session_issued_at
            <= self.declaration_prepared_at
            <= self.retained_captured_at
            < self.declaration_expires_at
            <= self.original_session_expires_at
        ):
            raise ValueError("exact distinct native retained task subject required")
        return self

    @property
    def subject_digest(self) -> str:
        return content_hash_of(
            canonical_bytes(
                _PersonalNativeTaskSubject.model_validate(
                    {n: getattr(self, n) for n in _PersonalNativeTaskSubject.model_fields}
                ).model_dump(mode="json")
            )
        )


class PersonalNativeTaskRecoveryReceiptV1(_PersonalNativeTaskSubject):
    format: Literal["zac-personal-chatgpt-native-task-recovery-v1"] = (
        "zac-personal-chatgpt-native-task-recovery-v1"
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
            or not self.retained_captured_at <= self.verified_at < self.declaration_expires_at
            or any(hashes.get(r.source_id) != r.content_hash for r in self.selected_references)
        ):
            raise ValueError("complete native inventory checkpoint required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/chatgpt-native-task-{self.declaration_id}"

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

    @property
    def runtime_ready(self) -> Literal[False]:
        return False

    @property
    def reviewer_ready(self) -> Literal[False]:
        return False


def encode_native_task_recovery_receipt(value: PersonalNativeTaskRecoveryReceiptV1) -> bytes:
    if type(value) is not PersonalNativeTaskRecoveryReceiptV1:
        raise TypeError("exact native receipt required")
    raw = canonical_bytes(
        PersonalNativeTaskRecoveryReceiptV1.model_validate(
            value.model_dump(mode="json")
        ).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded native receipt required")
    return raw


def decode_native_task_recovery_receipt(raw: bytes) -> PersonalNativeTaskRecoveryReceiptV1:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded native receipt required")
    result = PersonalNativeTaskRecoveryReceiptV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_native_task_recovery_receipt(result) != raw:
        raise ValueError("canonical native receipt required")
    return result


def _task_access(
    protector: PersonalHistoryFragmentProtector,
    inputs: NamedOwnerHostInputs,
    declaration: ChatGPTNativeTaskDeclarationV1,
    prior: VerifiedNamedSession | None = None,
) -> VerifiedNamedSession:
    observed = _native_access(protector, inputs, prior)
    # Final original signed owner/window check follows every config/clock callback.
    retained._owner(inputs, protector._operation, declaration)
    if (
        observed.binding_digest != declaration.original_session_binding
        or observed.issued_at != declaration.original_session_issued_at
        or observed.effective_expires_at != declaration.original_session_expires_at
        or (observed.principal.identity.issuer, observed.principal.identity.subject)
        != (declaration.actor_issuer, declaration.actor_subject)
    ):
        raise ValueError("exact original native task owner/session required")
    return observed


def protect_personal_chatgpt_native_task(
    protector: PersonalHistoryFragmentProtector,
    *,
    inputs: NamedOwnerHostInputs,
    declaration_reference: EvidenceReference,
    association_reference: EvidenceReference,
    expected_declaration: ChatGPTNativeTaskDeclarationV1,
    read_existing: bool = False,
) -> PersonalNativeTaskRecoveryReceiptV1:
    """Reopen retained task and exact whole PERSONAL inventory, never approval.

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
        ):
            raise ValueError("concrete native PERSONAL recovery graph required")
        _, declaration, request, dependencies = retained._parts(expected_declaration)
        checked_refs = tuple(
            EvidenceReference.model_validate(r.model_dump(mode="json"))
            for r in (declaration_reference, association_reference)
        )
        refs = (checked_refs[0], checked_refs[1])
        selected = tuple(sorted((*dependencies, *refs), key=lambda r: str(r.source_id)))
        if (
            len({r.source_id for r in selected}) != len(selected)
            or not 3 <= len(selected) <= 96
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in selected
            )
            or protector._clock is not inputs.clock
        ):
            raise ValueError("exact distinct PERSONAL HR task subject required")
        companion = request.profile.companion
        _standard_factory(protector._factory)
        factory_class, factory_options = protector._factory.class_, dict(protector._factory.kw)
        with protector._lock:
            access = _task_access(protector, inputs, declaration)
            _bound_factory(protector._factory, factory_class, factory_options)
            plan = protector._plan()
            rows = json.loads(plan.rows)
            expected = {UUID(row["id"]): row["content_hash"] for row in rows}
            if any(expected.get(ref.source_id) != ref.content_hash for ref in selected):
                raise ValueError("full inventory excludes native pair")
            with protector._factory() as session:
                session.begin()
                entry = _physical(session)
                loaded = retained.load_retained_chatgpt_native_task(
                    session,
                    artifacts=protector._artifacts,
                    declaration_reference=refs[0],
                    association_reference=refs[1],
                    expected_declaration=declaration,
                    authorized_boundaries=retained.BOUNDS,
                    allowed_classifications=retained.LABELS,
                )
                initial_rows = retained._snapshot(session, declaration, refs, selected)[0]
                _same(session, entry)
            _task_access(protector, inputs, declaration, access)
            _bound_factory(protector._factory, factory_class, factory_options)
            if protector._plan() != plan:
                raise ValueError("plan changed during native pair read")
            subject = _PersonalNativeTaskSubject(
                capture_id=request.profile.capture_id,
                original_reference=request.profile.current_original_reference,
                companion_reference=request.profile.current_companion_reference,
                companion_digest=content_hash_of(
                    canonical_bytes(companion.model_dump(mode="json"))
                ),
                selected_pointer=companion.selected_field.pointer,
                selected_text_hash=companion.selected_text_hash,
                reported_role=companion.selected_field.reported_role,
                projection_observed_at=companion.projection_observed_at,
                source_captured_at=request.profile.source_captured_at,
                actor_issuer=access.principal.identity.issuer,
                actor_subject=access.principal.identity.subject,
                original_session_binding=access.binding_digest,
                original_session_issued_at=access.issued_at,
                original_session_expires_at=access.effective_expires_at,
                declaration_id=declaration.id,
                declaration_reference=refs[0],
                association_reference=refs[1],
                request_digest=declaration.request_digest,
                wire_digest=declaration.wire_digest,
                counter_digest=content_hash_of(
                    canonical_bytes(declaration.counter.model_dump(mode="json"))
                ),
                original_task_id=loaded.association.original_task_id,
                derived_task_id=loaded.association.derived_task_id,
                selected_references=selected,
                retained_captured_at=loaded.captured_at,
                declaration_prepared_at=declaration.prepared_at,
                declaration_expires_at=declaration.expires_at,
            )
            if (subject.actor_issuer, subject.actor_subject) != (
                access.principal.identity.issuer,
                access.principal.identity.subject,
            ):
                raise ValueError("exact current signed actor metadata required")
            binding = {n: getattr(subject, n) for n in _PersonalNativeTaskSubject.model_fields}
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
            prefix = f"PERSONAL/state/chatgpt-native-task-{declaration.id}"
            key = f"{prefix}/receipt-{subject.subject_digest}.age"
            if read_existing:
                cipher = _read(protector._reader, key, 2_100_000)
                _task_access(protector, inputs, declaration, access)
                raw = _recover(cipher, protector._identity, 2_000_000)
                _task_access(protector, inputs, declaration, access)
                receipt = decode_native_task_recovery_receipt(raw)
                receipt_cipher_digest = content_hash_of(cipher)
            else:
                if protector._reader.exists(key) is not False:
                    raise ValueError("existing native receipt cannot be overwritten or repaired")
                _task_access(protector, inputs, declaration, access)
                completed = run_artifact_backup(
                    protector._factory,
                    trust_boundary=B.PERSONAL,
                    artifact_store=protector._artifacts,
                    backup_store=protector._writer,
                    recipient=protector._recipient,
                    local_manifest_cache_path=protector._cache,
                    personal_plan=plan,
                )
                _task_access(protector, inputs, declaration, access)
                _bound_factory(protector._factory, factory_class, factory_options)
                if (
                    completed.status is not ArtifactBackupRunStatus.SUCCEEDED
                    or protector._plan() != plan
                ):
                    raise ValueError("full native inventory backup required")
                snapshot, journal = protector._snapshot(expected, completed.id)
                _task_access(protector, inputs, declaration, access)
                objects = []
                for name, plain, maximum in (
                    ("state", snapshot, 64_000_000),
                    ("journal", journal, 4_000_000),
                ):
                    encrypted = _crypt(plain, protector._recipient, maximum)
                    _task_access(protector, inputs, declaration, access)
                    digest = content_hash_of(encrypted)
                    protector._writer.put_object(f"{prefix}/{name}-{digest}.age", encrypted)
                    _task_access(protector, inputs, declaration, access)
                    objects.append((digest, content_hash_of(plain)))
                receipt = PersonalNativeTaskRecoveryReceiptV1.model_validate(
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
            _task_access(protector, inputs, declaration, access)
            if any(getattr(receipt, n) != v for n, v in complete.items()):
                raise ValueError("exact native subject/full checkpoint binding required")
            observations = list(protector._artifacts_recover(plan, access))
            _task_access(protector, inputs, declaration, access)
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
                _task_access(protector, inputs, declaration, access)
                if content_hash_of(cipher) != digest:
                    raise ValueError("native snapshot ciphertext changed")
                plain = _recover(cipher, protector._identity, maximum)
                _task_access(protector, inputs, declaration, access)
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
            _task_access(protector, inputs, declaration, access)
            with protector._factory() as session:
                session.begin()
                entry = _physical(session)
                cold_loaded = retained.load_retained_chatgpt_native_task(
                    session,
                    artifacts=protector._cold,
                    declaration_reference=refs[0],
                    association_reference=refs[1],
                    expected_declaration=declaration,
                    authorized_boundaries=retained.BOUNDS,
                    allowed_classifications=retained.LABELS,
                )
                _same(session, entry)
            _task_access(protector, inputs, declaration, access)
            if cold_loaded != loaded:
                raise ValueError("cold retained task reconstruction differs")
            if not read_existing:
                receipt = PersonalNativeTaskRecoveryReceiptV1.model_validate(
                    {**receipt.model_dump(), "verified_at": protector._clock()}
                )
                cipher = _crypt(
                    encode_native_task_recovery_receipt(receipt), protector._recipient, 2_000_000
                )
                _task_access(protector, inputs, declaration, access)
                if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                    raise ValueError("bounded native receipt ciphertext required")
                # Bounded inherited re-observation AFTER proof/crypto callbacks,
                # BEFORE first immutable receipt publication. No repair on HOLD.
                protector._reobserve_objects(tuple(observations), access)
                _task_access(protector, inputs, declaration, access)
                _bound_factory(protector._factory, factory_class, factory_options)
                if (
                    protector._plan() != plan
                    or content_hash_of(protector._run_row(receipt.artifact_backup_run_id))
                    != receipt.live_journal_digest
                ):
                    raise ValueError("prepublication native inventory/journal changed")
                with protector._factory() as session:
                    session.begin()
                    entry = _physical(session)
                    if retained._snapshot(session, declaration, refs, selected)[0] != initial_rows:
                        raise ValueError("prepublication retained task union changed")
                    _same(session, entry)
                protector._writer.put_object(key, cipher)
                _task_access(protector, inputs, declaration, access)
                returned = _read(protector._reader, key, 2_100_000)
                _task_access(protector, inputs, declaration, access)
                raw = _recover(returned, protector._identity, 2_000_000)
                _task_access(protector, inputs, declaration, access)
                if returned != cipher or decode_native_task_recovery_receipt(raw) != receipt:
                    raise ValueError("native receipt readback differs")
                receipt_cipher_digest = content_hash_of(returned)
            protector._reobserve_objects(
                (*observations, (key, receipt_cipher_digest, 2_100_000)), access
            )
            _task_access(protector, inputs, declaration, access)
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
            with protector._factory() as session:
                session.begin()
                entry = _physical(session)
                if retained._snapshot(session, declaration, refs, selected)[0] != initial_rows:
                    raise ValueError("terminal retained task union changed")
                _same(session, entry)
            result = receipt
    except (ReviewProtectionCleanupUncertain, PersonalFragmentCleanupUncertain):
        uncertain = True
    except KeyboardInterrupt:
        interruption = KeyboardInterrupt
    except SystemExit:
        interruption = SystemExit
    except BaseException:  # noqa: BLE001 - fixed private-safe HOLD, never retry.
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
