"""Explicit complete declaration recovery using existing whole-inventory machinery.

Closed family metadata only; no approval or authenticated reviewer is created.
"""

from __future__ import annotations

import json
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.history_generation_review_declaration import (
    HistoryConsentV1,
    HistoryGenerationReviewDeclarationV1,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_review_retention import (
    HistoryDeclarationContext,
    _parts,
    history_declaration_owner,
    load_history_review_declaration,
)
from zacai.interfaces.named_session_binding import VerifiedNamedSession
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class PersonalHistoryDeclarationReceiptV1(Contract):
    """Closed full-purpose bytes recovery observation; no human/claim authority."""

    format: Literal["zac-personal-history-complete-declaration-recovery-v1"] = (
        "zac-personal-history-complete-declaration-recovery-v1"
    )
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    request_digest: Digest
    generation_wire_digest: Digest
    review_profile_digest: Digest
    selected_references: tuple[EvidenceReference, ...] = Field(repr=False)
    full_plan_digest: Digest
    full_boundary_source_hashes: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    full_boundary_source_fingerprints: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    task_id: UUID
    builder_id: UUID
    original_observed_at: AwareDatetime
    declared_window_started_at: AwareDatetime
    expires_at: AwareDatetime
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    live_journal_digest: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def closed_publication(self) -> Self:
        hashes = dict(self.full_boundary_source_hashes)
        if (
            any(
                v.int == 0
                for v in (
                    self.task_id,
                    self.builder_id,
                    self.publication_reference.source_id,
                    self.artifact_backup_run_id,
                )
            )
            or not 1 <= len(self.selected_references) <= 95
            or tuple(sorted(self.selected_references, key=lambda r: str(r.source_id)))
            != self.selected_references
            or len({r.source_id for r in self.selected_references}) != len(self.selected_references)
            or self.publication_reference not in self.selected_references
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in self.selected_references
            )
            or not 1 <= len(hashes) == len(self.full_boundary_source_hashes) <= 4096
            or tuple(sorted(self.full_boundary_source_hashes, key=lambda r: str(r[0])))
            != self.full_boundary_source_hashes
            or tuple(sid for sid, _ in self.full_boundary_source_hashes)
            != tuple(sid for sid, _ in self.full_boundary_source_fingerprints)
            or any(hashes.get(r.source_id) != r.content_hash for r in self.selected_references)
            or not self.original_session_issued_at
            <= self.declared_window_started_at
            <= self.verified_at
            < self.expires_at
            <= self.original_session_expires_at
            or self.original_observed_at > self.declared_window_started_at
        ):
            raise ValueError("closed full publication recovery observation required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-complete-declaration-{self.publication_reference.source_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.publication_digest}.age"

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False


def encode_history_declaration_receipt(value: PersonalHistoryDeclarationReceiptV1) -> bytes:
    if type(value) is not PersonalHistoryDeclarationReceiptV1:
        raise ValueError("exact declaration receipt required")
    raw = canonical_bytes(
        PersonalHistoryDeclarationReceiptV1.model_validate(value).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded declaration receipt required")
    return raw


def decode_history_declaration_receipt(raw: bytes) -> PersonalHistoryDeclarationReceiptV1:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded declaration receipt required")
    result = PersonalHistoryDeclarationReceiptV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_history_declaration_receipt(result) != raw:
        raise ValueError("canonical declaration receipt required")
    return result


def _access(
    protector: PersonalHistoryFragmentProtector,
    generation: HistoryConsentV1,
    prior: VerifiedNamedSession | None = None,
) -> VerifiedNamedSession:
    # Reuse concrete graph/root/key metadata checks, then finish with actual
    # signed owner AFTER all host clock callbacks, never a boolean callback.
    observed = protector._access(prior)
    protector._configuration()
    actual = history_declaration_owner(protector._operation, protector._clock, generation)
    if actual != observed or (prior is not None and actual != prior):
        raise ValueError("original whole-inventory owner changed")
    return actual


def protect_history_declaration(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    context: HistoryDeclarationContext,
    read_existing: bool = False,
) -> PersonalHistoryDeclarationReceiptV1:
    """Actual full checkpoint/read-existing; no repair, admission or dispatch.

    The old fragment methods and receipt format are deliberately unchanged.
    Cleanup uncertainty preserves the existing operator quarantine exception.
    """
    from zacai.backup_artifacts import run_artifact_backup
    from zacai.claude_local_protection import _crypt, _read, _recover
    from zacai.review_protection import ReviewProtectionCleanupUncertain
    from zacai.state import ArtifactBackupRunStatus

    result = None
    uncertain = False
    try:
        if (
            type(protector) is not PersonalHistoryFragmentProtector
            or type(read_existing) is not bool
        ):
            raise ValueError("exact existing inventory protector and mode required")
        raw, generation, request = _parts(expected_declaration)
        if (
            type(reference) is not EvidenceReference
            or reference.content_hash != content_hash_of(raw)
            or reference.source_id.int == 0
            or reference.trust_boundary is not B.PERSONAL
            or reference.effective_classification is not C.HIGHLY_RESTRICTED
        ):
            raise ValueError("actual canonical complete subject required")
        selected = tuple(
            sorted((*generation.provenance, reference), key=lambda r: str(r.source_id))
        )
        if len(selected) > 95 or len({r.source_id for r in selected}) != len(selected):
            raise ValueError("bounded distinct complete subject required")
        binding = dict(  # noqa: C408
            publication_reference=reference,
            publication_digest=history_generation_review_declaration_digest(expected_declaration),
            request_digest=generation.request_digest,
            generation_wire_digest=generation.generation_wire_digest,
            review_profile_digest=expected_declaration.review_profile_digest,
            selected_references=selected,
            task_id=generation.task_id,
            builder_id=generation.builder_id,
            original_observed_at=request.sidecar.entries[0].projection_observed_at,
            declared_window_started_at=generation.approved_at,
            expires_at=generation.expires_at,
            original_session_binding=generation.original_session_binding,
            original_session_issued_at=generation.original_session_issued_at,
            original_session_expires_at=generation.original_session_expires_at,
        )
        with protector._lock:
            access = _access(protector, generation)
            plan = protector._plan()
            rows = json.loads(plan.rows)
            expected = {UUID(row["id"]): row["content_hash"] for row in rows}
            hashes = tuple(sorted(expected.items(), key=lambda pair: str(pair[0])))
            fingerprints = tuple(
                sorted(
                    ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                    key=lambda pair: str(pair[0]),
                )
            )
            if any(expected.get(ref.source_id) != ref.content_hash for ref in selected):
                raise ValueError("full inventory excludes complete subject")
            with protector._factory() as session:
                session.begin()
                load_history_review_declaration(
                    session,
                    artifacts=protector._artifacts,
                    context=context,
                    reference=reference,
                    expected_declaration=expected_declaration,
                )
            _access(protector, generation, access)
            if protector._plan() != plan:
                raise ValueError("plan changed during actual complete load")
            complete = dict(
                **binding,
                full_plan_digest=content_hash_of(plan.rows),
                full_boundary_source_hashes=hashes,
                full_boundary_source_fingerprints=fingerprints,
            )
            prefix = f"PERSONAL/state/history-complete-declaration-{reference.source_id}"
            key = f"{prefix}/receipt-{binding['publication_digest']}.age"
            if read_existing:
                cipher = _read(protector._reader, key, 2_100_000)
                _access(protector, generation, access)
                raw = _recover(cipher, protector._identity, 2_000_000)
                _access(protector, generation, access)
                receipt = decode_history_declaration_receipt(raw)
                receipt_cipher_digest = content_hash_of(cipher)
            else:
                if protector._reader.exists(key) is not False:
                    raise ValueError("existing receipt never overwritten or repaired")
                _access(protector, generation, access)
                completed = run_artifact_backup(
                    protector._factory,
                    trust_boundary=B.PERSONAL,
                    artifact_store=protector._artifacts,
                    backup_store=protector._writer,
                    recipient=protector._recipient,
                    local_manifest_cache_path=protector._cache,
                    personal_plan=plan,
                )
                _access(protector, generation, access)
                if (
                    completed.status is not ArtifactBackupRunStatus.SUCCEEDED
                    or protector._plan() != plan
                ):
                    raise ValueError("actual complete inventory backup required")
                snapshot, journal = protector._snapshot(expected, completed.id)
                _access(protector, generation, access)
                objects = []
                for name, plain, maximum in (
                    ("state", snapshot, 64_000_000),
                    ("journal", journal, 4_000_000),
                ):
                    encrypted = _crypt(plain, protector._recipient, maximum)
                    _access(protector, generation, access)
                    digest = content_hash_of(encrypted)
                    protector._writer.put_object(f"{prefix}/{name}-{digest}.age", encrypted)
                    _access(protector, generation, access)
                    objects.append((digest, content_hash_of(plain)))
                receipt = PersonalHistoryDeclarationReceiptV1.model_validate(
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
            _access(protector, generation, access)
            if (
                any(getattr(receipt, name) != value for name, value in complete.items())
                or not generation.approved_at <= receipt.verified_at < generation.expires_at
            ):
                raise ValueError("exact complete checkpoint binding required")
            # Existing whole-original recovery uses canonical cipher locators,
            # native bounded decryption and actual disjoint cold artifact hashes.
            observations = list(protector._artifacts_recover(plan, access))
            _access(protector, generation, access)
            recovered = []
            for object_key, digest, plaintext_hash, maximum in (
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
                _access(protector, generation, access)
                returned = _read(protector._reader, object_key, maximum + 1_000_000)
                _access(protector, generation, access)
                if content_hash_of(returned) != digest:
                    raise ValueError("complete snapshot ciphertext changed")
                restored = _recover(returned, protector._identity, maximum)
                _access(protector, generation, access)
                if content_hash_of(restored) != plaintext_hash:
                    raise ValueError("complete snapshot plaintext changed")
                recovered.append(restored)
                observations.append((object_key, digest, maximum + 1_000_000))
            protector._restoration.verify_personal(
                recovered[0],
                expected,
                current_selected_sources=protector._engine,
                operational_journal=recovered[1],
            )
            _access(protector, generation, access)
            if not read_existing:
                receipt = PersonalHistoryDeclarationReceiptV1.model_validate(
                    {**receipt.model_dump(), "verified_at": protector._clock()}
                )
                cipher = _crypt(
                    encode_history_declaration_receipt(receipt), protector._recipient, 2_000_000
                )
                _access(protector, generation, access)
                if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                    raise ValueError("bounded complete receipt ciphertext required")
                protector._writer.put_object(key, cipher)
                _access(protector, generation, access)
                returned = _read(protector._reader, key, 2_100_000)
                _access(protector, generation, access)
                plain = _recover(returned, protector._identity, 2_000_000)
                _access(protector, generation, access)
                if returned != cipher or decode_history_declaration_receipt(plain) != receipt:
                    raise ValueError("complete receipt readback differs")
                receipt_cipher_digest = content_hash_of(returned)
            for object_key, digest, maximum in (
                *observations,
                (key, receipt_cipher_digest, 2_100_000),
            ):
                _access(protector, generation, access)
                returned = _read(protector._reader, object_key, maximum)
                _access(protector, generation, access)
                if content_hash_of(returned) != digest:
                    raise ValueError("terminal recovered object changed")
            _access(protector, generation, access)
            with protector._clock._lock:
                terminal_now = protector._clock._last
            if terminal_now is None or receipt.verified_at > terminal_now:
                raise ValueError("checkpoint date is not actual prior observation")
            # Callback-free final actual Source+journal scalars. No arbitrary
            # owner, clock, body or protection callback follows this result.
            if (
                protector._plan() != plan
                or content_hash_of(protector._run_row(receipt.artifact_backup_run_id))
                != receipt.live_journal_digest
            ):
                raise ValueError("terminal complete inventory/journal changed")
            result = receipt
    except (ReviewProtectionCleanupUncertain, PersonalFragmentCleanupUncertain):
        uncertain = True
    except Exception:  # noqa: BLE001
        result = None
    if uncertain:
        raise PersonalFragmentCleanupUncertain(
            "PERSONAL complete declaration cleanup uncertain; operator review required"
        )
    if result is None:
        raise ValueError("PERSONAL complete declaration checkpoint unavailable or mismatched")
    return result
