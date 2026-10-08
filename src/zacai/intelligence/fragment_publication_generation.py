"""Dormant concrete publication generation/retained-output joins.

Exact full-purpose observed admission is mandatory. No activation, human identity,
semantic assessment or delivery is inferred from constructing these contracts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker

from zacai import contextual_authorization as auth
from zacai.backup_artifacts import (
    PersonalFullOriginalBackupPlan,
    prepare_personal_encrypted_custody_backup_plan,
    run_artifact_backup,
)
from zacai.contextual_protection import (
    ContextualProtectionError,
    PersonalFragmentCleanupUncertain,
    PersonalFragmentRecoveryReceipt,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_generation import ContextualDraft
from zacai.intelligence.contextual_storage import (
    _fragment_profile_lineage,
    _fragment_rows,
    _fragment_same_transaction,
    _fragment_transaction,
    capture_history_fragment_contextual_packet,
    load_history_fragment_contextual_packet,
)
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, UsageObservation
from zacai.intelligence.fragment_publication_admission import (
    FragmentPublicationAdmissionV1,
    PersonalFragmentPublicationAdmissionReceiptV1,
    _binding,
    _ids,
    _prefix,
    encode_fragment_publication_admission,
    load_fragment_publication_admission,
)
from zacai.intelligence.fragment_review_declaration import (
    FragmentGenerationReviewDeclarationV2,
    fragment_generation_review_declaration_digest,
)
from zacai.intelligence.fragment_review_retention import _parts, _physical, _same
from zacai.intelligence.fragment_review_withdrawal import assert_fragment_publication_not_withdrawn
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualPacketV1,
    HistoryFragmentContextualRequestV1,
    encode_history_fragment_contextual_packet,
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.local_contextual_runtime import (
    FragmentContextualDispatchDescriptor,
    FragmentLocalContextualRuntime,
)
from zacai.intelligence.personal_fragment_output import PersonalFragmentRetainedOutput
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.state import ArtifactBackupRunStatus, SourceSystem

MAX_PUBLICATION_CLAIM_BYTES = 16000
_BOUNDARIES = auth._FRAGMENT_BOUNDARIES
_LABELS = auth._FRAGMENT_LABELS


class FragmentPublicationGenerationError(RuntimeError):
    """Fixed hold; traceback-local capture must remain disabled."""


class FragmentPublicationClaimV1(Contract):
    format: Literal["zac-personal-fragment-publication-claim-v1"] = (
        "zac-personal-fragment-publication-claim-v1"
    )
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    admission_reference: EvidenceReference = Field(repr=False)
    admission_digest: Digest
    review_profile_digest: Digest
    generation_id: UUID
    request_digest: Digest
    attempt_id: UUID
    task_id: UUID
    builder_id: UUID
    original_session_binding: Digest = Field(repr=False)
    original_approved_at: AwareDatetime
    expires_at: AwareDatetime
    body_digest: Digest
    route_digest: Digest
    model_digest: Digest
    tokenizer_digest: Digest
    runtime_digest: Digest
    template_digest: Digest
    renderer_digest: Digest
    prompt_tokens: int = Field(gt=0, strict=True)
    max_output_tokens: int = Field(gt=0, strict=True)
    consumed_at: AwareDatetime

    @model_validator(mode="after")
    def closed_claim(self) -> Self:
        refs = (self.publication_reference, self.admission_reference)
        if (
            any(
                v.int == 0
                for v in (self.generation_id, self.attempt_id, self.task_id, self.builder_id)
            )
            or refs[0].source_id == refs[1].source_id
            or any(
                r.source_id.int == 0
                or r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or refs[1].content_hash != self.admission_digest
            or not self.original_approved_at <= self.consumed_at < self.expires_at
        ):
            raise ValueError("closed publication claim required")
        return self


def encode_fragment_publication_claim(value: FragmentPublicationClaimV1) -> bytes:
    raw = None
    try:
        if type(value) is not FragmentPublicationClaimV1:
            raise ValueError("exact claim type")
        checked = FragmentPublicationClaimV1.model_validate(value.model_dump(mode="json"))
        candidate = canonical_bytes(checked.model_dump(mode="json"))
        if len(candidate) > MAX_PUBLICATION_CLAIM_BYTES:
            raise ValueError("claim bound")
        raw = candidate
    except Exception:  # noqa: BLE001,S110
        pass
    if raw is None:
        raise FragmentPublicationGenerationError("publication claim unavailable")
    return raw


def decode_fragment_publication_claim(raw: bytes) -> FragmentPublicationClaimV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PUBLICATION_CLAIM_BYTES:
            raise ValueError("claim bound")
        result = FragmentPublicationClaimV1.model_validate_json(raw)
        if encode_fragment_publication_claim(result) != raw:
            result = None
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationGenerationError("publication claim unavailable")
    return result


def _claim_prefix(generation_id: UUID) -> str:
    return f"personal-history-fragment-claim/{generation_id}/"


def _claim_namespace(claim: FragmentPublicationClaimV1) -> str:
    return _claim_prefix(claim.generation_id) + "publication-v1/" + claim.admission_digest


def _claim_binding(
    claim: FragmentPublicationClaimV1,
    admission_reference: EvidenceReference,
    admission: FragmentPublicationAdmissionV1,
    publication: FragmentGenerationReviewDeclarationV2,
) -> None:
    _binding(admission, publication)
    _, g, request = _parts(publication)
    if type(claim) is not FragmentPublicationClaimV1 or publication.review_profile_digest is None:
        raise ValueError("full review purpose claim required")
    fields = {
        "publication_reference": admission.publication_reference,
        "publication_digest": fragment_generation_review_declaration_digest(publication),
        "admission_reference": admission_reference,
        "admission_digest": content_hash_of(encode_fragment_publication_admission(admission)),
        "review_profile_digest": publication.review_profile_digest,
        "generation_id": g.id,
        "request_digest": g.request_digest,
        "task_id": g.task_id,
        "builder_id": g.builder_id,
        "original_session_binding": g.original_session_binding,
        "original_approved_at": g.approved_at,
        "expires_at": g.expires_at,
        "body_digest": g.body_digest,
        "route_digest": content_hash_of(
            canonical_bytes(
                {**g.route.model_dump(mode="json"), "capabilities": sorted(g.route.capabilities)}
            )
        ),
        "model_digest": g.model_digest,
        "tokenizer_digest": g.tokenizer_digest,
        "runtime_digest": g.runtime_digest,
        "template_digest": g.template_digest,
        "renderer_digest": g.renderer_digest,
        "prompt_tokens": g.prompt_tokens,
        "max_output_tokens": g.max_output_tokens,
    }
    if claim.consumed_at < admission.observed_action_at or any(
        getattr(claim, k) != v for k, v in fields.items()
    ):
        raise ValueError("exact publication claim relation required")
    if g.body_digest != content_hash_of(request.prompt_body.encode()):
        raise ValueError("exact original request required")


def _union(
    admission: FragmentPublicationAdmissionV1,
    admission_reference: EvidenceReference,
    publication: FragmentGenerationReviewDeclarationV2,
    claim_reference: EvidenceReference | None = None,
) -> tuple[EvidenceReference, ...]:
    _binding(admission, publication)
    _, g, _ = _parts(publication)
    refs = tuple(
        sorted(
            (
                *g.provenance,
                admission.publication_reference,
                admission_reference,
                *((claim_reference,) if claim_reference is not None else ()),
            ),
            key=lambda r: str(r.source_id),
        )
    )
    if len({r.source_id for r in refs}) != len(refs) or len(refs) > 96:
        raise ValueError("distinct bounded complete publication union required")
    return refs


def _current(
    session: Session,
    admission_reference: EvidenceReference,
    admission: FragmentPublicationAdmissionV1,
    publication: FragmentGenerationReviewDeclarationV2,
    claim_reference: EvidenceReference | None = None,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    _, g, request = _parts(publication)
    rows = _fragment_rows(
        session,
        _union(admission, admission_reference, publication, claim_reference),
        auth._FRAGMENT_BOUNDARIES,
        auth._FRAGMENT_LABELS,
    )
    _fragment_profile_lineage(request, rows)
    assert_fragment_publication_not_withdrawn(session, generation_id=g.id)
    if _ids(
        session, f"personal-history-fragment-declaration-v2/{g.id}/", system=SourceSystem.MANUAL
    ) != (admission.publication_reference.source_id,) or _ids(session, _prefix(admission)) != (
        admission_reference.source_id,
    ):
        raise ValueError("exact publication/admission namespace required")
    expected = () if claim_reference is None else (claim_reference.source_id,)
    if _ids(session, _claim_prefix(g.id), system=SourceSystem.MANUAL) != expected:
        raise ValueError("original generation consumed or changed")
    return rows


def load_fragment_publication_claim(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    expected_claim: FragmentPublicationClaimV1,
    admission_reference: EvidenceReference,
    expected_admission: FragmentPublicationAdmissionV1,
    expected_publication: FragmentGenerationReviewDeclarationV2,
) -> FragmentPublicationClaimV1:
    result = None
    try:
        _claim_binding(
            expected_claim, admission_reference, expected_admission, expected_publication
        )
        raw = encode_fragment_publication_claim(expected_claim)
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(reference) is not EvidenceReference
            or reference.content_hash != content_hash_of(raw)
        ):
            raise ValueError("exact claim storage required")
        entry = _physical(session)
        rows = _current(
            session, admission_reference, expected_admission, expected_publication, reference
        )
        row = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
        if (
            row["system"] is not SourceSystem.MANUAL
            or row["external_ref"] != _claim_namespace(expected_claim)
            or row["supersedes_source_id"] is not None
            or row["captured_at"] != expected_claim.consumed_at
        ):
            raise ValueError("canonical first claim required")
        load_fragment_publication_admission(
            session,
            artifacts=artifacts,
            reference=admission_reference,
            expected_admission=expected_admission,
            expected_publication=expected_publication,
        )
        _same(session, entry)
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("exact claim location")
        returned = artifacts.get_bounded(
            B.PERSONAL, location, max_bytes=MAX_PUBLICATION_CLAIM_BYTES
        )
        _same(session, entry)
        if returned != raw or decode_fragment_publication_claim(returned) != expected_claim:
            raise ValueError("exact claim bytes required")
        if (
            _current(
                session, admission_reference, expected_admission, expected_publication, reference
            )
            != rows
        ):
            raise ValueError("claim union changed")
        _same(session, entry)
        result = expected_claim
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationGenerationError("publication claim unavailable")
    return result


class PersonalFragmentPublicationClaimReceiptV1(Contract):
    """Closed full-purpose bytes recovery observation; no human/claim authority."""

    format: Literal["zac-personal-fragment-publication-claim-recovery-v1"] = (
        "zac-personal-fragment-publication-claim-recovery-v1"
    )
    claim_reference: EvidenceReference = Field(repr=False)
    claim_digest: Digest
    attempt_id: UUID
    consumed_at: AwareDatetime
    admission_reference: EvidenceReference = Field(repr=False)
    admission_digest: Digest
    observed_action_at: AwareDatetime
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    request_digest: Digest
    review_profile_digest: Digest | None
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
            or not 1 <= len(self.selected_references) <= 96
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
        if (
            self.admission_reference not in self.selected_references
            or self.admission_reference.content_hash != self.admission_digest
            or self.admission_reference.source_id == self.publication_reference.source_id
            or not self.declared_window_started_at
            <= self.observed_action_at
            <= self.verified_at
            < self.expires_at
        ):
            raise ValueError("exact observed action receipt required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-fragment-publication-claim-{self.claim_reference.source_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.claim_digest}.age"

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

    @model_validator(mode="after")
    def claim_subject(self) -> Self:
        if (
            self.claim_reference.source_id.int == 0
            or self.claim_reference not in self.selected_references
            or self.claim_reference.content_hash != self.claim_digest
            or self.claim_reference.source_id
            in (self.admission_reference.source_id, self.publication_reference.source_id)
            or self.attempt_id.int == 0
            or self.review_profile_digest is None
            or not self.observed_action_at <= self.consumed_at <= self.verified_at < self.expires_at
        ):
            raise ValueError("exact publication claim checkpoint required")
        return self


def encode_publication_claim_receipt(value: PersonalFragmentPublicationClaimReceiptV1) -> bytes:
    result = None
    try:
        if type(value) is not PersonalFragmentPublicationClaimReceiptV1:
            raise ValueError("exact receipt family")
        checked = PersonalFragmentPublicationClaimReceiptV1.model_validate(
            value.model_dump(mode="json")
        )
        candidate = canonical_bytes(checked.model_dump(mode="json"))
        if len(candidate) <= 2_000_000:
            result = candidate
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationGenerationError("publication claim checkpoint unavailable")
    return result


def decode_publication_claim_receipt(raw: bytes) -> PersonalFragmentPublicationClaimReceiptV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
            raise ValueError("bounded receipt")
        checked = PersonalFragmentPublicationClaimReceiptV1.model_validate_json(raw)
        if encode_publication_claim_receipt(checked) == raw:
            result = checked
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationGenerationError("publication claim checkpoint unavailable")
    return result


def protect_publication_claim(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_claim: FragmentPublicationClaimV1,
    admission_reference: EvidenceReference,
    expected_admission: FragmentPublicationAdmissionV1,
    expected_publication: FragmentGenerationReviewDeclarationV2,
) -> PersonalFragmentPublicationClaimReceiptV1:
    return _publication_claim_checkpoint(
        protector,
        reference,
        expected_claim,
        admission_reference,
        expected_admission,
        expected_publication,
        False,
    )


def recheck_publication_claim(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_claim: FragmentPublicationClaimV1,
    admission_reference: EvidenceReference,
    expected_admission: FragmentPublicationAdmissionV1,
    expected_publication: FragmentGenerationReviewDeclarationV2,
) -> PersonalFragmentPublicationClaimReceiptV1:
    return _publication_claim_checkpoint(
        protector,
        reference,
        expected_claim,
        admission_reference,
        expected_admission,
        expected_publication,
        True,
    )


def _publication_claim_checkpoint(
    self: PersonalHistoryFragmentProtector,
    reference: EvidenceReference,
    claim: FragmentPublicationClaimV1,
    admission_reference: EvidenceReference,
    admission: FragmentPublicationAdmissionV1,
    declaration: FragmentGenerationReviewDeclarationV2,
    read_existing: bool,
) -> PersonalFragmentPublicationClaimReceiptV1:

    from zacai.claude_local_protection import _crypt, _read, _recover
    from zacai.review_protection import ReviewProtectionCleanupUncertain

    result = None
    failure: type[ContextualProtectionError] = ContextualProtectionError
    try:
        if type(self) is not PersonalHistoryFragmentProtector:
            raise ValueError("concrete protector required")
        _claim_binding(claim, admission_reference, admission, declaration)
        if (
            type(reference) is not EvidenceReference
            or reference.source_id.int == 0
            or reference.trust_boundary is not B.PERSONAL
            or reference.effective_classification is not C.HIGHLY_RESTRICTED
            or type(declaration) is not FragmentGenerationReviewDeclarationV2
        ):
            raise ValueError("exact PERSONAL full declaration required")
        _, consent, request = _parts(declaration)
        _binding(admission, declaration)
        raw = encode_fragment_publication_claim(claim)
        if reference.content_hash != content_hash_of(raw):
            raise ValueError("own canonical full declaration digest required")
        selected = _union(admission, admission_reference, declaration, reference)
        binding = {
            "admission_reference": admission_reference,
            "admission_digest": admission_reference.content_hash,
            "claim_reference": reference,
            "claim_digest": content_hash_of(raw),
            "attempt_id": claim.attempt_id,
            "consumed_at": claim.consumed_at,
            "observed_action_at": admission.observed_action_at,
            "publication_reference": admission.publication_reference,
            "publication_digest": fragment_generation_review_declaration_digest(declaration),
            "request_digest": consent.request_digest,
            "review_profile_digest": declaration.review_profile_digest,
            "selected_references": selected,
            "task_id": consent.task_id,
            "builder_id": consent.builder_id,
            "original_observed_at": request.observed_at,
            "declared_window_started_at": declaration.approved_at,
            "expires_at": declaration.expires_at,
            "original_session_binding": consent.original_session_binding,
            "original_session_issued_at": consent.original_session_issued_at,
            "original_session_expires_at": consent.original_session_expires_at,
        }
        key = (
            f"PERSONAL/state/history-fragment-publication-claim-{reference.source_id}/"
            f"receipt-{binding['claim_digest']}.age"
        )
        with self._lock:
            access = self._authority_access(consent)  # before key/private reads
            plan = self._plan()
            rows = json.loads(plan.rows)
            expected = {UUID(row["id"]): row["content_hash"] for row in rows}
            hashes = tuple(sorted(expected.items(), key=lambda p: str(p[0])))
            fingerprints = tuple(
                sorted(
                    ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                    key=lambda p: str(p[0]),
                )
            )
            if any(expected.get(r.source_id) != r.content_hash for r in selected):
                raise ValueError("whole boundary missing authority union")
            with self._factory() as session:
                session.begin()
                load_fragment_publication_claim(
                    session,
                    artifacts=self._artifacts,
                    reference=reference,
                    expected_claim=claim,
                    admission_reference=admission_reference,
                    expected_admission=admission,
                    expected_publication=declaration,
                )
            self._authority_access(consent, access)
            if self._plan() != plan:
                raise ValueError("authority plan changed during canonical load")
            complete = dict(
                **binding,
                full_plan_digest=content_hash_of(plan.rows),
                full_boundary_source_hashes=hashes,
                full_boundary_source_fingerprints=fingerprints,
            )
            if read_existing:
                cipher = _read(self._reader, key, 2_100_000)
                self._authority_access(consent, access)
                raw = _recover(cipher, self._identity, 2_000_000)
                self._authority_access(consent, access)
                receipt = decode_publication_claim_receipt(raw)
                receipt_cipher_digest = content_hash_of(cipher)
            else:
                if self._reader.exists(key) is not False:
                    raise ValueError("existing authority receipt never overwritten")
                self._authority_access(consent, access)
                completed = run_artifact_backup(
                    self._factory,
                    trust_boundary=B.PERSONAL,
                    artifact_store=self._artifacts,
                    backup_store=self._writer,
                    recipient=self._recipient,
                    local_manifest_cache_path=self._cache,
                    personal_plan=plan,
                )
                self._authority_access(consent, access)
                if (
                    completed.status is not ArtifactBackupRunStatus.SUCCEEDED
                    or self._plan() != plan
                ):
                    raise ValueError("authority artifact backup incomplete")
                snapshot, journal = self._snapshot(expected, completed.id)
                self._authority_access(consent, access)
                objects = []
                prefix = key.rsplit("/", 1)[0]
                for name, raw, maximum in (
                    ("state", snapshot, 64_000_000),
                    ("journal", journal, 4_000_000),
                ):
                    cipher = _crypt(raw, self._recipient, maximum)
                    self._authority_access(consent, access)
                    cipher_digest = content_hash_of(cipher)
                    self._writer.put_object(f"{prefix}/{name}-{cipher_digest}.age", cipher)
                    self._authority_access(consent, access)
                    objects.append((cipher_digest, content_hash_of(raw)))
                receipt = PersonalFragmentPublicationClaimReceiptV1.model_validate(
                    dict(
                        **complete,
                        verified_at=self._clock(),
                        artifact_backup_run_id=completed.id,
                        live_journal_digest=content_hash_of(self._run_row(completed.id)),
                        state_ciphertext_hash=objects[0][0],
                        state_plaintext_hash=objects[0][1],
                        journal_ciphertext_hash=objects[1][0],
                        journal_plaintext_hash=objects[1][1],
                    )
                )
            if (
                any(getattr(receipt, n) != v for n, v in complete.items())
                or not consent.approved_at <= receipt.verified_at < consent.expires_at
                or receipt.verified_at > self._clock()
            ):
                raise ValueError("exact current authority checkpoint required")
            observations = _verify_publication_claim(self, receipt, consent, plan, access, expected)
            self._reobserve_objects(observations, access)
            self._authority_access(consent, access)
            if not read_existing:
                receipt = PersonalFragmentPublicationClaimReceiptV1.model_validate(
                    {**receipt.model_dump(), "verified_at": self._clock()}
                )
                cipher = _crypt(encode_publication_claim_receipt(receipt), self._recipient, 2_000_000)
                self._authority_access(consent, access)
                if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                    raise ValueError("bounded complete receipt ciphertext required")
                self._writer.put_object(key, cipher)
                self._authority_access(consent, access)
                returned = _read(self._reader, key, 2_100_000)
                self._authority_access(consent, access)
                plain = _recover(returned, self._identity, 2_000_000)
                self._authority_access(consent, access)
                if returned != cipher or decode_publication_claim_receipt(plain) != receipt:
                    raise ValueError("authority encrypted receipt readback differs")
                receipt_cipher_digest = content_hash_of(returned)
            self._reobserve_objects((*observations, (key, receipt_cipher_digest, 2_100_000)), access)
            self._authority_access(consent, access)
            # No arbitrary callbacks after this full Source/journal comparison.
            if (
                self._plan() != plan
                or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
                != receipt.live_journal_digest
            ):
                raise ValueError("terminal authority plan/journal changed")
            with self._factory() as session:
                session.begin()
                entry = _physical(session)
                _current(session, admission_reference, admission, declaration, reference)
                _same(session, entry)
            result = receipt
    except ReviewProtectionCleanupUncertain:
        failure = PersonalFragmentCleanupUncertain
    except Exception:  # noqa: BLE001,S110 - private-safe fixed failure
        pass
    if result is None:
        if failure is PersonalFragmentCleanupUncertain:
            raise failure("PERSONAL publication claim cleanup uncertain; operator review required")
        raise failure("PERSONAL publication claim checkpoint unavailable or mismatched")
    return result


class CanonicalPersonalFragmentPublicationAuthorization:
    """Exact full-publication consumer; no optional inner-consent admission.

    A committed withdrawal before each locked dispatch boundary denies. After
    that boundary the local request can already be in flight; RELEASE denies
    subsequent withdrawal. No atomic socket cancellation or delivery promise.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        artifacts: LocalFilesystemArtifactStore,
        publication: FragmentGenerationReviewDeclarationV2,
        admission_reference: EvidenceReference,
        admission: FragmentPublicationAdmissionV1,
        request: HistoryFragmentContextualRequestV1,
        protector: PersonalHistoryFragmentProtector,
        operation: NamedSessionOperation,
        clock: HostObservedClock,
    ) -> None:
        failed = False
        try:
            if (
                type(factory) is not sessionmaker
                or type(artifacts) is not LocalFilesystemArtifactStore
                or type(publication) is not FragmentGenerationReviewDeclarationV2
                or type(admission) is not FragmentPublicationAdmissionV1
                or type(admission_reference) is not EvidenceReference
                or type(protector) is not PersonalHistoryFragmentProtector
                or type(operation) is not NamedSessionOperation
                or type(clock) is not HostObservedClock
                or operation.host_clock is not clock
                or protector._factory is not factory
                or protector._artifacts is not artifacts
                or protector._operation is not operation
                or protector._clock is not clock
                or factory.kw.get("bind") is not protector._engine
                or factory.kw.get("binds")
            ):
                raise ValueError("exact full publication graph required")
            _binding(admission, publication)
            raw, consent, actual_request = _parts(publication)
            if (
                publication.review_profile_digest is None
                or type(request) is not HistoryFragmentContextualRequestV1
                or encode_history_fragment_contextual_request(request)
                != encode_history_fragment_contextual_request(actual_request)
                or admission_reference.content_hash
                != content_hash_of(encode_fragment_publication_admission(admission))
                or admission_reference.trust_boundary is not B.PERSONAL
                or admission_reference.effective_classification is not C.HIGHLY_RESTRICTED
            ):
                raise ValueError("exact full purpose request/admission required")
            self._factory, self._artifacts = factory, artifacts
            self._publication, self._admission, self._admission_reference = (
                publication,
                admission,
                admission_reference,
            )
            self._consent, self._request = consent, request
            self._protector, self._operation, self._clock = protector, operation, clock
            self._raw, self._admission_raw = raw, encode_fragment_publication_admission(admission)
            self._graph = (
                factory,
                artifacts,
                publication,
                admission_reference,
                admission,
                request,
                protector,
                operation,
                clock,
                protector._engine,
            )
            self._configuration = (
                consent.model_digest,
                consent.tokenizer_digest,
                consent.runtime_digest,
                consent.template_digest,
                consent.renderer_digest,
                canonical_bytes(
                    {
                        **consent.route.model_dump(mode="json"),
                        "capabilities": sorted(consent.route.capabilities),
                    }
                ).decode(),
            )
            self._runtime: FragmentLocalContextualRuntime | None = None
            self._claim: FragmentPublicationClaimV1 | None = None
            self._claim_reference: EvidenceReference | None = None
            self._receipt: PersonalFragmentPublicationClaimReceiptV1 | None = None
            self._released: FragmentContextualDispatchDescriptor | None = None
            self._associated_result: PersonalFragmentAssociatedOutput | None = None
            self._phase = "UNUSED"
            self._lock = RLock()
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise FragmentPublicationGenerationError("invalid full publication authorization graph")

    def _graph_check(self) -> None:
        current = (
            self._factory,
            self._artifacts,
            self._publication,
            self._admission_reference,
            self._admission,
            self._request,
            self._protector,
            self._operation,
            self._clock,
            self._protector._engine,
        )
        if (
            any(a is not b for a, b in zip(current, self._graph, strict=True))
            or self._protector._factory is not self._factory
            or self._protector._artifacts is not self._artifacts
            or self._protector._operation is not self._operation
            or self._protector._clock is not self._clock
            or self._operation.host_clock is not self._clock
            or self._factory.kw.get("bind") is not self._graph[-1]
            or self._factory.kw.get("binds")
            or _parts(self._publication)[0] != self._raw
            or self._consent != _parts(self._publication)[1]
            or self._configuration
            != (
                self._consent.model_digest,
                self._consent.tokenizer_digest,
                self._consent.runtime_digest,
                self._consent.template_digest,
                self._consent.renderer_digest,
                canonical_bytes(
                    {
                        **self._consent.route.model_dump(mode="json"),
                        "capabilities": sorted(self._consent.route.capabilities),
                    }
                ).decode(),
            )
            or encode_fragment_publication_admission(self._admission) != self._admission_raw
            or encode_history_fragment_contextual_request(self._request)
            != encode_history_fragment_contextual_request(_parts(self._publication)[2])
        ):
            raise ValueError("full publication graph changed")
        _binding(self._admission, self._publication)

    def _receipt_plan(
        self,
        session: Session,
        receipt: PersonalFragmentPublicationAdmissionReceiptV1
        | PersonalFragmentPublicationClaimReceiptV1,
        claim_reference: EvidenceReference | None = None,
    ) -> None:
        from zacai.backup_artifacts import prepare_personal_encrypted_custody_backup_plan

        expected_type = (
            PersonalFragmentPublicationAdmissionReceiptV1
            if claim_reference is None
            else PersonalFragmentPublicationClaimReceiptV1
        )
        if type(receipt) is not expected_type:
            raise ValueError("exact own checkpoint family required")
        checked = expected_type.model_validate(receipt.model_dump(mode="json"))
        fields = {
            "admission_reference": self._admission_reference,
            "admission_digest": self._admission_reference.content_hash,
            "observed_action_at": self._admission.observed_action_at,
            "publication_reference": self._admission.publication_reference,
            "publication_digest": fragment_generation_review_declaration_digest(self._publication),
            "request_digest": self._consent.request_digest,
            "review_profile_digest": self._publication.review_profile_digest,
            "selected_references": _union(
                self._admission, self._admission_reference, self._publication, claim_reference
            ),
            "task_id": self._consent.task_id,
            "builder_id": self._consent.builder_id,
            "original_observed_at": self._request.observed_at,
            "declared_window_started_at": self._publication.approved_at,
            "expires_at": self._publication.expires_at,
            "original_session_binding": self._consent.original_session_binding,
            "original_session_issued_at": self._consent.original_session_issued_at,
            "original_session_expires_at": self._consent.original_session_expires_at,
        }
        if any(getattr(checked, k) != v for k, v in fields.items()):
            raise ValueError("exact admission/checkpoint relation required")
        if claim_reference is not None and (
            type(receipt) is not PersonalFragmentPublicationClaimReceiptV1
            or self._claim is None
            or receipt.claim_reference != claim_reference
            or receipt.claim_digest != claim_reference.content_hash
            or receipt.attempt_id != self._claim.attempt_id
            or receipt.consumed_at != self._claim.consumed_at
        ):
            raise ValueError("exact consumed publication checkpoint required")
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        rows = json.loads(plan.rows)
        hashes = tuple(
            sorted(((UUID(v["id"]), v["content_hash"]) for v in rows), key=lambda v: str(v[0]))
        )
        fingerprints = tuple(
            sorted(
                ((UUID(v["id"]), content_hash_of(canonical_bytes(v))) for v in rows),
                key=lambda v: str(v[0]),
            )
        )
        if (
            content_hash_of(plan.rows) != receipt.full_plan_digest
            or hashes != receipt.full_boundary_source_hashes
            or fingerprints != receipt.full_boundary_source_fingerprints
        ):
            raise ValueError("complete current publication checkpoint changed")

    def _burn(
        self,
        descriptor: FragmentContextualDispatchDescriptor,
        receipt: PersonalFragmentPublicationAdmissionReceiptV1,
    ) -> tuple[FragmentPublicationClaimV1, EvidenceReference]:
        from zacai.review_authorization import _lock
        from zacai.state_repository import record_source

        with self._factory() as session:
            session.begin()
            _lock(session, self._consent.id)
            entry = self._physical_transaction(session)
            from zacai.backup_artifacts import _assert_personal_custody_append_capacity

            _assert_publication_review_provenance(self._publication)
            _assert_personal_custody_append_capacity(session, 6)
            self._receipt_plan(session, receipt)
            load_fragment_publication_admission(
                session,
                artifacts=self._artifacts,
                reference=self._admission_reference,
                expected_admission=self._admission,
                expected_publication=self._publication,
            )
            before = _current(
                session, self._admission_reference, self._admission, self._publication
            )
            consumed = self._clock()
            if not self._consent.approved_at <= consumed < self._consent.expires_at:
                raise ValueError("original processing deadline exhausted")
            c = self._consent
            claim = FragmentPublicationClaimV1(
                publication_reference=self._admission.publication_reference,
                publication_digest=fragment_generation_review_declaration_digest(self._publication),
                admission_reference=self._admission_reference,
                admission_digest=self._admission_reference.content_hash,
                review_profile_digest=self._admission.review_profile_digest,
                generation_id=c.id,
                request_digest=c.request_digest,
                attempt_id=descriptor.attempt_id,
                task_id=c.task_id,
                builder_id=c.builder_id,
                original_session_binding=c.original_session_binding,
                original_approved_at=c.approved_at,
                expires_at=c.expires_at,
                body_digest=c.body_digest,
                route_digest=content_hash_of(self._configuration[5].encode()),
                model_digest=c.model_digest,
                tokenizer_digest=c.tokenizer_digest,
                runtime_digest=c.runtime_digest,
                template_digest=c.template_digest,
                renderer_digest=c.renderer_digest,
                prompt_tokens=c.prompt_tokens,
                max_output_tokens=c.max_output_tokens,
                consumed_at=consumed,
            )
            _claim_binding(claim, self._admission_reference, self._admission, self._publication)
            raw = encode_fragment_publication_claim(claim)
            location = self._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            self._same_physical_transaction(session, entry)
            returned = self._artifacts.get_bounded(
                B.PERSONAL, location, max_bytes=MAX_PUBLICATION_CLAIM_BYTES
            )
            self._same_physical_transaction(session, entry)
            self._graph_check()
            self._descriptor(self._request, descriptor)
            self._receipt_plan(session, receipt)
            if returned != raw or not consumed <= self._clock() < c.expires_at:
                raise ValueError("original claim changed/expired")
            if (
                _current(session, self._admission_reference, self._admission, self._publication)
                != before
            ):
                raise ValueError("full current generation union changed")
            self._same_physical_transaction(session, entry)
            self._require_phase("ENTERED")
            source, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=_claim_namespace(claim),
                content_hash=content_hash_of(raw),
                content_location=location,
                captured_at=consumed,
            )
            if not new or source.supersedes_source_id is not None:
                raise ValueError("original generation already burned")
            reference = EvidenceReference(
                source_id=source.id,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            if not consumed <= self._clock() < c.expires_at:
                raise ValueError("original deadline before commit")
            _current(
                session, self._admission_reference, self._admission, self._publication, reference
            )
            self._same_physical_transaction(session, entry)
            self._require_phase("ENTERED")
            session.commit()
        return claim, reference

    def _reopen_claim(self) -> None:
        if self._claim is None or self._claim_reference is None:
            raise ValueError("committed publication claim required")
        with self._factory() as session:
            session.begin()
            load_fragment_publication_claim(
                session,
                artifacts=self._artifacts,
                reference=self._claim_reference,
                expected_claim=self._claim,
                admission_reference=self._admission_reference,
                expected_admission=self._admission,
                expected_publication=self._publication,
            )
        self._owner()

    def _final_claim(self, receipt: PersonalFragmentPublicationClaimReceiptV1) -> None:
        from zacai.review_authorization import _lock

        if self._claim is None or self._claim_reference is None:
            raise ValueError("committed original publication claim required")
        if (
            content_hash_of(self._protector._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest
        ):
            raise ValueError("live publication journal changed")
        self._graph_check()
        from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

        started = _AUTHENTICATED_MONOTONIC()
        if not self._consent.approved_at <= self._clock() < self._consent.expires_at:
            raise ValueError("original publication processing expired")
        bound = _publication_terminal_deadline(self, started)
        self._owner()  # Outside SQL, after the final caller clock callback.
        with self._factory() as session:
            session.begin()
            _lock(session, self._consent.id)
            entry = self._physical_transaction(session)
            self._receipt_plan(session, receipt, self._claim_reference)
            _current(
                session,
                self._admission_reference,
                self._admission,
                self._publication,
                self._claim_reference,
            )
            self._same_physical_transaction(session, entry)
        _publication_terminal_time(self, bound)

    def _require_phase(self, expected: str) -> None:
        """A nested failure permanently poisons the outer operation too."""
        if self._phase != expected:
            raise ValueError("original operation phase changed")

    def recheck(
        self,
        request: HistoryFragmentContextualRequestV1,
        descriptor: FragmentContextualDispatchDescriptor,
    ) -> None:
        with self._lock:
            if self._phase in {"ENTERED", "RELEASING", "OUTPUT_ENTERED"}:
                self._phase = "HELD"
                raise FragmentPublicationGenerationError(
                    "full publication attempt unavailable or consumed"
                )
            succeeded = False
            cleanup_uncertain = False
            try:
                self._descriptor(request, descriptor)
                if descriptor.phase == "PRE_DISPATCH":
                    if self._phase != "UNUSED":
                        raise ValueError("one original publication PRE only")
                    self._phase = "ENTERED"
                    self._owner()
                    prior = self._protector.recheck_publication_admission(
                        reference=self._admission_reference,
                        expected_admission=self._admission,
                        expected_publication=self._publication,
                    )
                    self._owner()
                    self._descriptor(request, descriptor)
                    self._require_phase("ENTERED")
                    self._claim, self._claim_reference = self._burn(descriptor, prior)
                    self._owner()
                    self._reopen_claim()
                    self._receipt = protect_publication_claim(
                        self._protector,
                        reference=self._claim_reference,
                        expected_claim=self._claim,
                        admission_reference=self._admission_reference,
                        expected_admission=self._admission,
                        expected_publication=self._publication,
                    )
                    self._final_claim(self._receipt)
                    self._descriptor(request, descriptor)
                    self._require_phase("ENTERED")
                    self._phase = "DISPATCHED"
                else:
                    if (
                        self._phase != "DISPATCHED"
                        or self._claim is None
                        or self._claim_reference is None
                    ):
                        raise ValueError("original consumed publication PRE required")
                    self._phase = "RELEASING"
                    self._owner()
                    existing = recheck_publication_claim(
                        self._protector,
                        reference=self._claim_reference,
                        expected_claim=self._claim,
                        admission_reference=self._admission_reference,
                        expected_admission=self._admission,
                        expected_publication=self._publication,
                    )
                    if existing != self._receipt:
                        raise ValueError("original publication claim checkpoint changed")
                    self._final_claim(existing)
                    self._descriptor(request, descriptor)
                    self._require_phase("RELEASING")
                    self._released = descriptor
                    self._phase = "RELEASED"
                succeeded = True
            except PersonalFragmentCleanupUncertain:
                cleanup_uncertain = True
            except Exception:  # noqa: BLE001,S110
                pass
            finally:
                if not succeeded and self._phase != "UNUSED":
                    self._phase = "HELD"
            if not succeeded:
                if cleanup_uncertain:
                    raise PersonalFragmentCleanupUncertain(
                        "PERSONAL recovery cleanup uncertain; operator review required"
                    )
                raise FragmentPublicationGenerationError(
                    "full publication attempt unavailable or consumed"
                )

    def bind_runtime(self, runtime: FragmentLocalContextualRuntime) -> None:
        """Bind the actual existing runtime and its bound gate, before preflight.

        No arbitrary protocol or callback returning success can replace this
        concrete graph. This establishes wiring only, not human approval.
        """
        from zacai.intelligence.local_contextual_runtime import FragmentLocalContextualRuntime

        with self._lock:
            failed = False
            try:
                from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

                started = _AUTHENTICATED_MONOTONIC()
                self._graph_check()
                self._owner()
                bound = _publication_terminal_deadline(self, started)
                if (
                    self._runtime is not None
                    or self._phase != "UNUSED"
                    or type(runtime) is not FragmentLocalContextualRuntime
                    or getattr(runtime._recheck, "__self__", None) is not self
                    or getattr(runtime._recheck, "__func__", None) is not type(self).recheck
                    or runtime._configuration != self._configuration
                    or runtime.route != self._consent.route
                    or runtime._attempted
                    or runtime._prepared is not None
                ):
                    raise ValueError("exact unused fragment runtime required")
                window: tuple[object, float] = (self, bound)
                self._generation_window = window
                runtime._publication_window = window
                self._runtime = runtime
            except Exception:  # noqa: BLE001
                failed = True
            if failed:
                raise FragmentPublicationGenerationError(
                    "PERSONAL fragment runtime binding unavailable"
                )

    def _descriptor(
        self,
        request: HistoryFragmentContextualRequestV1,
        descriptor: FragmentContextualDispatchDescriptor,
    ) -> None:
        from zacai.intelligence.local_contextual_runtime import (
            FragmentContextualDispatchDescriptor,
            FragmentLocalContextualRuntime,
        )

        self._graph_check()
        r = self._runtime
        c = self._consent
        if (
            request is not self._request
            or type(descriptor) is not FragmentContextualDispatchDescriptor
            or type(r) is not FragmentLocalContextualRuntime
            or getattr(r._recheck, "__self__", None) is not self
            or getattr(r._recheck, "__func__", None) is not type(self).recheck
            or r._configuration != self._configuration
            or r.route != c.route
            or type(descriptor.attempt_id) is not UUID
            or descriptor.attempt_id.int == 0
            or descriptor.phase not in ("PRE_DISPATCH", "RELEASE")
            or descriptor.retained_request_digest != c.request_digest
            or descriptor.body_digest != c.body_digest
            or type(descriptor.prompt_tokens) is not int
            or descriptor.prompt_tokens != c.prompt_tokens
            or (
                descriptor.model_digest,
                descriptor.tokenizer_digest,
                descriptor.runtime_digest,
                descriptor.template_digest,
                descriptor.renderer_digest,
                descriptor.route_json,
            )
            != self._configuration
            or c.body_digest != content_hash_of(request.prompt_body.encode())
            or c.max_output_tokens != request.task.max_output_tokens
        ):
            raise ValueError("exact original dispatch descriptor required")
        observations = (descriptor.output_digest, descriptor.usage_digest)
        if descriptor.phase == "PRE_DISPATCH":
            if observations != (None, None):
                raise ValueError("no output before dispatch")
        elif any(
            type(v) is not str or len(v) != 64 or any(ch not in "0123456789abcdef" for ch in v)
            for v in observations
        ):
            raise ValueError("exact release observations required")
        if descriptor.phase == "RELEASE" and (
            self._claim is None or self._claim.attempt_id != descriptor.attempt_id
        ):
            raise ValueError("same consumed runtime attempt required")

    def _owner(self) -> None:
        from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
        from zacai.policy import AccessRequest

        self._graph_check()
        owner = _publication_decision_owner(self._operation, self._clock, self._consent)
        gate = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.SUMMARIZE_CONTENT,
                access=AccessRequest(
                    data_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    requestor_boundaries=frozenset(s.boundary for s in owner.principal.scopes),
                    destination=Destination.LOCAL,
                ),
                description="bounded approved historical fragment draft",
            )
        )
        if gate.outcome is not GatewayOutcome.ALLOW:
            raise ValueError("original owner gateway denied")
        self._graph_check()

    def _physical_transaction(
        self, session: Session
    ) -> tuple[SessionTransaction, SessionTransaction | None, object, object]:
        """Require the real psycopg transaction holding the existing UUID lock.

        A Session logical transaction and SHOW read committed do not exclude
        DBAPI AUTOCOMMIT. IDLE statements would release an xact advisory lock
        immediately. No legacy helper or other family is widened here.
        """
        from psycopg import Connection as PsycopgConnection
        from psycopg.pq import TransactionStatus

        outer, nested = _fragment_transaction(session)
        connection = session.connection()
        driver = connection.connection.driver_connection
        if (
            not isinstance(driver, PsycopgConnection)
            or driver.autocommit is not False
            or driver.closed
            or driver.broken
            or driver.info.transaction_status is not TransactionStatus.INTRANS
            or not connection.in_transaction()
        ):
            raise ValueError("live physical psycopg transaction required")
        return outer, nested, connection, driver

    def _same_physical_transaction(
        self,
        session: Session,
        entry: tuple[SessionTransaction, SessionTransaction | None, object, object],
    ) -> None:
        _fragment_same_transaction(session, (entry[0], entry[1]))
        current = self._physical_transaction(session)
        if any(a is not b for a, b in zip(current, entry, strict=True)):
            raise ValueError("original physical claim transaction changed")


class FragmentPublicationOutputAssociationV1(Contract):
    """Immutable output lineage, never processing or reviewer authority."""

    format: Literal["zac-personal-fragment-publication-output-association-v1"] = (
        "zac-personal-fragment-publication-output-association-v1"
    )
    packet_reference: EvidenceReference
    publication_reference: EvidenceReference
    publication_digest: Digest
    admission_reference: EvidenceReference
    admission_digest: Digest
    claim_reference: EvidenceReference
    claim_digest: Digest
    generation_id: UUID
    attempt_id: UUID
    request_digest: Digest
    output_digest: Digest
    usage_digest: Digest
    packet_created_at: AwareDatetime

    @model_validator(mode="after")
    def literal_binding(self) -> Self:
        refs = (
            self.packet_reference,
            self.publication_reference,
            self.admission_reference,
            self.claim_reference,
        )
        if (
            len({r.source_id for r in refs}) != 4
            or any(
                r.source_id.int == 0
                or r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or self.generation_id.int == 0
            or self.attempt_id.int == 0
            or self.admission_digest != self.admission_reference.content_hash
            or self.claim_digest != self.claim_reference.content_hash
        ):
            raise ValueError("exact output lineage required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def encode_fragment_publication_output_association(
    value: FragmentPublicationOutputAssociationV1,
) -> bytes:
    raw = None
    try:
        if type(value) is not FragmentPublicationOutputAssociationV1:
            raise ValueError("exact association required")
        checked = FragmentPublicationOutputAssociationV1.model_validate(value.model_dump())
        candidate = canonical_bytes(checked.model_dump(mode="json"))
        if len(candidate) > MAX_PUBLICATION_CLAIM_BYTES:
            raise ValueError("bounded association required")
        raw = candidate
    except Exception:  # noqa: BLE001,S110
        pass
    if raw is None:
        raise FragmentPublicationGenerationError("output association unavailable")
    return raw


def decode_fragment_publication_output_association(
    raw: bytes,
) -> FragmentPublicationOutputAssociationV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PUBLICATION_CLAIM_BYTES:
            raise ValueError("bounded association required")
        value = FragmentPublicationOutputAssociationV1.model_validate_json(raw)
        if encode_fragment_publication_output_association(value) != raw:
            raise ValueError("canonical association required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationGenerationError("output association unavailable")
    return result


def _association_prefix(generation_id: UUID) -> str:
    return f"personal-history-fragment-publication-output/{generation_id}/"


def _association_namespace(value: FragmentPublicationOutputAssociationV1) -> str:
    return _association_prefix(value.generation_id) + str(value.attempt_id)


def _associated_output(
    gate: CanonicalPersonalFragmentPublicationAuthorization,
    packet_reference: EvidenceReference,
    created_at: datetime,
) -> FragmentPublicationOutputAssociationV1:
    claim, reference, released = gate._claim, gate._claim_reference, gate._released
    if claim is None or reference is None or released is None or released.phase != "RELEASE":
        raise ValueError("actual RELEASE lineage required")
    return FragmentPublicationOutputAssociationV1(
        packet_reference=packet_reference,
        publication_reference=gate._admission.publication_reference,
        publication_digest=fragment_generation_review_declaration_digest(gate._publication),
        admission_reference=gate._admission_reference,
        admission_digest=gate._admission_reference.content_hash,
        claim_reference=reference,
        claim_digest=reference.content_hash,
        generation_id=claim.generation_id,
        attempt_id=claim.attempt_id,
        request_digest=claim.request_digest,
        output_digest=released.output_digest,
        usage_digest=released.usage_digest,
        packet_created_at=created_at,
    )


def _association_rows(
    session: Session,
    gate: CanonicalPersonalFragmentPublicationAuthorization,
    reference: EvidenceReference,
    expected: FragmentPublicationOutputAssociationV1,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    if expected != _associated_output(gate, expected.packet_reference, expected.packet_created_at):
        raise ValueError("exact original RELEASE association required")
    if reference.content_hash != content_hash_of(
        encode_fragment_publication_output_association(expected)
    ):
        raise ValueError("exact association reference required")
    _current(
        session,
        gate._admission_reference,
        gate._admission,
        gate._publication,
        gate._claim_reference,
    )
    refs = (
        *_union(
            gate._admission, gate._admission_reference, gate._publication, gate._claim_reference
        ),
        expected.packet_reference,
        reference,
    )
    rows = _fragment_rows(session, refs, _BOUNDARIES, _LABELS)
    _fragment_profile_lineage(gate._request, rows)
    own = [dict(v) for v in rows if dict(v)["id"] == reference.source_id]
    if len(own) != 1 or _ids(
        session, _association_prefix(expected.generation_id), system=SourceSystem.MANUAL
    ) != (reference.source_id,):
        raise ValueError("one generation association required")
    row = own[0]
    if (
        row["system"] is not SourceSystem.MANUAL
        or row["trust_boundary"] is not B.PERSONAL
        or row["data_classification"] is not C.HIGHLY_RESTRICTED
        or row["external_ref"] != _association_namespace(expected)
        or row["captured_at"] != expected.packet_created_at
        or row["supersedes_source_id"] is not None
        or row["lineage_id"] != reference.source_id
    ):
        raise ValueError("immutable canonical association required")
    packet = next(dict(v) for v in rows if dict(v)["id"] == expected.packet_reference.source_id)
    if packet["captured_at"] != expected.packet_created_at:
        raise ValueError("packet capture time differs")
    return rows


def load_fragment_publication_output_association(
    session: Session,
    *,
    authorization: CanonicalPersonalFragmentPublicationAuthorization,
    reference: EvidenceReference,
    expected: FragmentPublicationOutputAssociationV1,
) -> tuple[HistoryFragmentContextualPacketV1, FragmentPublicationOutputAssociationV1]:
    result = None
    try:
        gate = authorization
        if type(gate) is not CanonicalPersonalFragmentPublicationAuthorization:
            raise ValueError("exact original issuer required")
        entry = gate._physical_transaction(session)
        rows = _association_rows(session, gate, reference, expected)
        row = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("canonical association location required")
        packet = load_history_fragment_contextual_packet(
            session,
            artifacts=gate._artifacts,
            source_id=expected.packet_reference.source_id,
            expected_digest=expected.packet_reference.content_hash,
            expected_request=gate._request,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
        )
        gate._same_physical_transaction(session, entry)
        if (
            packet.builder_id != gate._consent.builder_id
            or packet.created_at != expected.packet_created_at
            or encode_history_fragment_contextual_request(packet.request())
            != encode_history_fragment_contextual_request(gate._request)
            or _association_rows(session, gate, reference, expected) != rows
        ):
            raise ValueError("paired canonical packet differs")
        raw = gate._artifacts.get_bounded(
            B.PERSONAL, location, max_bytes=MAX_PUBLICATION_CLAIM_BYTES
        )
        gate._same_physical_transaction(session, entry)
        if (
            raw != encode_fragment_publication_output_association(expected)
            or decode_fragment_publication_output_association(raw) != expected
            or _association_rows(session, gate, reference, expected) != rows
        ):
            raise ValueError("output association changed")
        gate._same_physical_transaction(session, entry)
        result = (packet, expected)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationGenerationError("output association unavailable")
    return result


@dataclass(frozen=True, slots=True, repr=False)
class PersonalFragmentAssociatedOutput:
    retained: PersonalFragmentRetainedOutput
    association_reference: EvidenceReference
    association: FragmentPublicationOutputAssociationV1


def _publication_output_origin(
    gate: CanonicalPersonalFragmentPublicationAuthorization,
    runtime: FragmentLocalContextualRuntime,
    request: HistoryFragmentContextualRequestV1,
    draft: ContextualDraft,
) -> UsageObservation:
    if (
        gate._phase != "OUTPUT_ENTERED"
        or gate._released is None
        or gate._runtime is not runtime
        or gate._request is not request
        or type(runtime) is not FragmentLocalContextualRuntime
        or type(request) is not HistoryFragmentContextualRequestV1
        or type(draft) is not ContextualDraft
        or not runtime.did_transport_attempt
        or not runtime._attempted
        or runtime._prepared is not None
        or runtime.usage is None
    ):
        raise ValueError("exact completed origin required")
    gate._descriptor(request, gate._released)
    usage = UsageObservation.model_validate(runtime.usage)
    checked = ContextualDraft.model_validate(draft)
    if (
        content_hash_of(canonical_bytes(checked.model_dump(mode="json")))
        != gate._released.output_digest
        or content_hash_of(canonical_bytes(usage.model_dump(mode="json")))
        != gate._released.usage_digest
    ):
        raise ValueError("exact released output observations required")
    return usage


def _publication_owner_time(gate: CanonicalPersonalFragmentPublicationAuthorization) -> datetime:
    now = gate._clock()
    gate._owner()  # Last actual owner recheck follows ALL caller clock reads.
    if not gate._consent.approved_at <= now < gate._consent.expires_at:
        raise ValueError("original consent expired")
    return now


def _reopen_publication_output(
    gate: CanonicalPersonalFragmentPublicationAuthorization,
    sid: UUID,
    digest: str,
    association_reference: EvidenceReference,
    association: FragmentPublicationOutputAssociationV1,
) -> tuple[HistoryFragmentContextualPacketV1, PersonalFullOriginalBackupPlan]:
    if gate._claim is None or gate._claim_reference is None:
        raise ValueError("original canonical claim required")
    with gate._factory() as session:
        session.begin()
        entry = gate._physical_transaction(session)
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        gate._same_physical_transaction(session, entry)
        expected = {UUID(row["id"]): row["content_hash"] for row in json.loads(plan.rows)}
        if (
            plan.engine is not gate._protector._engine
            or expected.get(sid) != digest
            or expected.get(gate._admission_reference.source_id)
            != gate._admission_reference.content_hash
            or expected.get(gate._admission.publication_reference.source_id)
            != gate._admission.publication_reference.content_hash
            or expected.get(gate._claim_reference.source_id) != gate._claim_reference.content_hash
        ):
            raise ValueError("new full checkpoint must contain original authorities")
        packet = load_history_fragment_contextual_packet(
            session,
            artifacts=gate._artifacts,
            source_id=sid,
            expected_digest=digest,
            expected_request=gate._request,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
        )
        gate._same_physical_transaction(session, entry)
        claim = load_fragment_publication_claim(
            session,
            artifacts=gate._artifacts,
            reference=gate._claim_reference,
            expected_claim=gate._claim,
            admission_reference=gate._admission_reference,
            expected_admission=gate._admission,
            expected_publication=gate._publication,
        )
        gate._same_physical_transaction(session, entry)
        if claim != gate._claim:
            raise ValueError("original canonical publication claim differs")
        load_fragment_publication_output_association(
            session, authorization=gate, reference=association_reference, expected=association
        )
        if (
            expected.get(association_reference.source_id) != association_reference.content_hash
            or prepare_personal_encrypted_custody_backup_plan(session) != plan
        ):
            raise ValueError("typed authority full snapshot changed")
        gate._same_physical_transaction(session, entry)
    return packet, plan


def _terminal_publication_output(
    gate: CanonicalPersonalFragmentPublicationAuthorization,
    receipt: PersonalFragmentRecoveryReceipt,
    packet: HistoryFragmentContextualPacketV1,
    sid: UUID,
    digest: str,
    expected_plan: PersonalFullOriginalBackupPlan,
    association_reference: EvidenceReference,
    association: FragmentPublicationOutputAssociationV1,
) -> None:
    """Only actual scalar SQL/journal and trusted clock after terminal recovery."""
    if gate._claim_reference is None:
        raise ValueError("original claim missing")
    receipt = PersonalFragmentRecoveryReceipt.model_validate(receipt)
    if (
        receipt.packet_reference.source_id != sid
        or receipt.packet_reference.content_hash != digest
        or receipt.packet_reference.trust_boundary is not B.PERSONAL
        or receipt.packet_reference.effective_classification is not C.HIGHLY_RESTRICTED
        or receipt.task_id != gate._request.task.task_id
        or receipt.builder_id != gate._consent.builder_id
        or receipt.packet_created_at != packet.created_at
        or receipt.original_observed_at != gate._request.observed_at
        or receipt.request_digest
        != content_hash_of(encode_history_fragment_contextual_request(gate._request))
    ):
        raise ValueError("exact output receipt binding required")
    if (
        content_hash_of(gate._protector._run_row(receipt.artifact_backup_run_id))
        != receipt.live_journal_digest
    ):
        raise ValueError("output journal changed")
    gate._graph_check()
    from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

    started = _AUTHENTICATED_MONOTONIC()
    if not gate._consent.approved_at <= gate._clock() < gate._consent.expires_at:
        raise ValueError("original publication processing expired")
    bound = _publication_terminal_deadline(gate, started)
    gate._owner()  # Last actual owner read after final clock; no later callback.
    with gate._factory() as session:
        session.begin()
        from zacai.review_authorization import _lock

        _lock(session, gate._consent.id)
        entry = gate._physical_transaction(session)
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        gate._same_physical_transaction(session, entry)
        rows = json.loads(plan.rows)
        hashes = tuple(
            sorted(
                ((UUID(row["id"]), row["content_hash"]) for row in rows), key=lambda p: str(p[0])
            )
        )
        fingerprints = tuple(
            sorted(
                ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                key=lambda p: str(p[0]),
            )
        )
        if (
            plan.engine is not gate._protector._engine
            or plan != expected_plan
            or content_hash_of(plan.rows) != receipt.full_plan_digest
            or hashes != receipt.full_boundary_source_hashes
            or fingerprints != receipt.full_boundary_source_fingerprints
            or dict(hashes).get(gate._admission_reference.source_id)
            != gate._admission_reference.content_hash
            or dict(hashes).get(gate._admission.publication_reference.source_id)
            != gate._admission.publication_reference.content_hash
            or dict(hashes).get(gate._claim_reference.source_id)
            != gate._claim_reference.content_hash
            or dict(hashes).get(sid) != digest
            or dict(hashes).get(association_reference.source_id)
            != association_reference.content_hash
        ):
            raise ValueError("complete output checkpoint changed")
        gate._same_physical_transaction(session, entry)
        _association_rows(session, gate, association_reference, association)
        _current(
            session,
            gate._admission_reference,
            gate._admission,
            gate._publication,
            gate._claim_reference,
        )
        gate._same_physical_transaction(session, entry)
    _publication_terminal_time(gate, bound)


def _same_output_commit_transaction(
    session: Session,
    entry: tuple[SessionTransaction, SessionTransaction | None, object, object],
) -> None:
    """Scalar-only observation of the already verified physical transaction.

    The usual full physical helper issues SHOW. Its SQL must precede the last
    host-clock observation; this narrow check cannot reconnect or issue SQL.
    """
    from psycopg import Connection as PsycopgConnection
    from psycopg.pq import TransactionStatus
    from sqlalchemy.engine import Connection

    _fragment_same_transaction(session, (entry[0], entry[1]))
    connection, driver = entry[2], entry[3]
    if (
        not isinstance(connection, Connection)
        or not isinstance(driver, PsycopgConnection)
        or connection.closed
        or connection.invalidated
        or not connection.in_transaction()
        or driver.closed
        or driver.broken
        or driver.autocommit is not False
        or driver.info.transaction_status is not TransactionStatus.INTRANS
        or connection.connection.driver_connection is not driver
    ):
        raise ValueError("original output commit transaction changed")


def retain_personal_fragment_publication_output(
    authorization: CanonicalPersonalFragmentPublicationAuthorization,
    *,
    runtime: FragmentLocalContextualRuntime,
    request: HistoryFragmentContextualRequestV1,
    draft: ContextualDraft,
) -> PersonalFragmentAssociatedOutput:
    """Consume the actual issuer RELEASED once; return retained NEEDS_REVIEW only.

    No model call or repeated RELEASE occurs. Every entered failure/interruption
    permanently holds this instance; durable packet/orphan evidence may remain for
    manual reconciliation. No repair/retry/delete. Authenticated whole
    answer review remains an activation gate. Cancellation propagates after burning.
    """
    result = None
    cleanup_uncertain = False
    try:
        if type(authorization) is not CanonicalPersonalFragmentPublicationAuthorization:
            raise TypeError("actual original issuer required")
        gate = authorization
        with gate._lock:
            if gate._phase != "RELEASED":
                if gate._phase == "OUTPUT_ENTERED":
                    gate._phase = "OUTPUT_HELD"
                raise ValueError("one original released output required")
            gate._phase = "OUTPUT_ENTERED"
            try:
                released = gate._released
                usage = _publication_output_origin(gate, runtime, request, draft)
                claim, claim_reference = gate._claim, gate._claim_reference
                if claim is None or claim_reference is None:
                    raise ValueError("original claim required")
                claim_bytes = encode_fragment_publication_claim(claim)
                if content_hash_of(claim_bytes) != claim_reference.content_hash:
                    raise ValueError("original claim binding changed")
                review = runtime.resolve_fragment(draft, request)
                _publication_output_origin(gate, runtime, request, draft)
                created_at = _publication_owner_time(gate)
                payload = encode_history_fragment_contextual_packet(
                    review,
                    request,
                    builder_id=gate._consent.builder_id,
                    created_at=created_at,
                )
                digest = content_hash_of(payload)
                with gate._factory() as session:
                    session.begin()
                    from zacai.review_authorization import _lock

                    _lock(session, gate._consent.id)
                    entry = gate._physical_transaction(session)
                    _current(
                        session,
                        gate._admission_reference,
                        gate._admission,
                        gate._publication,
                        claim_reference,
                    )
                    if _ids(
                        session, _association_prefix(gate._consent.id), system=SourceSystem.MANUAL
                    ):
                        raise ValueError("generation output already associated")
                    gate._require_phase("OUTPUT_ENTERED")
                    from zacai.backup_artifacts import _assert_personal_custody_append_capacity

                    _assert_personal_custody_append_capacity(session, 5)
                    sid = capture_history_fragment_contextual_packet(
                        session,
                        artifacts=gate._artifacts,
                        payload=payload,
                        authorized_boundaries=_BOUNDARIES,
                        allowed_classifications=_LABELS,
                    )
                    gate._same_physical_transaction(session, entry)
                    _current(
                        session,
                        gate._admission_reference,
                        gate._admission,
                        gate._publication,
                        claim_reference,
                    )
                    packet_reference = EvidenceReference(
                        source_id=sid,
                        content_hash=digest,
                        trust_boundary=B.PERSONAL,
                        effective_classification=C.HIGHLY_RESTRICTED,
                    )
                    association = _associated_output(gate, packet_reference, created_at)
                    association_raw = encode_fragment_publication_output_association(association)
                    association_hash = content_hash_of(association_raw)
                    _assert_personal_custody_append_capacity(session, 4)
                    location = gate._artifacts.put(B.PERSONAL, association_hash, association_raw)
                    gate._same_physical_transaction(session, entry)
                    gate._require_phase("OUTPUT_ENTERED")
                    returned = gate._artifacts.get_bounded(
                        B.PERSONAL, location, max_bytes=MAX_PUBLICATION_CLAIM_BYTES
                    )
                    gate._same_physical_transaction(session, entry)
                    gate._require_phase("OUTPUT_ENTERED")
                    if returned != association_raw or _ids(
                        session, _association_prefix(gate._consent.id), system=SourceSystem.MANUAL
                    ):
                        raise ValueError("generation association changed before capture")
                    from zacai.state_repository import record_source

                    _assert_personal_custody_append_capacity(session, 4)
                    source, new = record_source(
                        session,
                        trust_boundary=B.PERSONAL,
                        data_classification=C.HIGHLY_RESTRICTED,
                        system=SourceSystem.MANUAL,
                        external_ref=_association_namespace(association),
                        content_hash=association_hash,
                        content_location=location,
                        captured_at=created_at,
                    )
                    if not new or source.supersedes_source_id is not None:
                        raise ValueError("immutable first output association required")
                    association_reference = EvidenceReference(
                        source_id=source.id,
                        content_hash=association_hash,
                        trust_boundary=B.PERSONAL,
                        effective_classification=C.HIGHLY_RESTRICTED,
                    )
                    _association_rows(session, gate, association_reference, association)
                    _assert_personal_custody_append_capacity(session, 3)
                    gate._same_physical_transaction(session, entry)
                    # All body callbacks and blocking SQL (including SHOW in
                    # the full physical check) precede this original clock.
                    if not created_at <= gate._clock() < gate._consent.expires_at:
                        raise ValueError("original output commit window expired")
                    _same_output_commit_transaction(session, entry)
                    gate._require_phase("OUTPUT_ENTERED")
                    session.commit()
                _publication_owner_time(gate)
                packet, expected_plan = _reopen_publication_output(
                    gate, sid, digest, association_reference, association
                )
                if (
                    packet.builder_id != gate._consent.builder_id
                    or packet.created_at != created_at
                    or packet.review != review
                    or encode_history_fragment_contextual_request(packet.request())
                    != encode_history_fragment_contextual_request(request)
                ):
                    raise ValueError("captured output differs")
                _publication_owner_time(gate)
                _publication_output_origin(gate, runtime, request, draft)
                receipt = gate._protector.protect(
                    source_id=sid,
                    expected_digest=digest,
                    expected_request=request,
                )
                _terminal_publication_output(
                    gate,
                    receipt,
                    packet,
                    sid,
                    digest,
                    expected_plan,
                    association_reference,
                    association,
                )
                # No arbitrary owner/body callbacks after final recovery proof.
                if (
                    gate._released is not released
                    or gate._claim is not claim
                    or gate._claim_reference is not claim_reference
                    or encode_fragment_publication_claim(claim) != claim_bytes
                    or _publication_output_origin(gate, runtime, request, draft) != usage
                ):
                    raise ValueError("released origin changed")
                gate._require_phase("OUTPUT_ENTERED")
                result = PersonalFragmentAssociatedOutput(
                    PersonalFragmentRetainedOutput(sid, digest, packet, usage, receipt),
                    association_reference,
                    association,
                )
                gate._associated_result = result
                gate._phase = "OUTPUT_RETAINED"
            finally:
                if result is None:
                    gate._phase = "OUTPUT_HELD"
    except PersonalFragmentCleanupUncertain:
        cleanup_uncertain = True
    except Exception:  # noqa: BLE001,S110 - fixed error outside private exception context
        pass
    if result is None:
        if cleanup_uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL recovery cleanup uncertain; operator review required"
            )
        raise FragmentPublicationGenerationError("PERSONAL fragment output unavailable or consumed")
    return result


def _verify_publication_claim(
    self: PersonalHistoryFragmentProtector,
    receipt: PersonalFragmentPublicationClaimReceiptV1,
    consent: auth.HistoryFragmentConsentV1,
    plan: PersonalFullOriginalBackupPlan,
    access: VerifiedNamedSession,
    expected: dict[UUID, str],
) -> tuple[tuple[str, str, int], ...]:
    from zacai.claude_local_protection import _read, _recover

    self._authority_access(consent, access)
    observations = list(self._artifacts_recover(plan, access))
    self._authority_access(consent, access)
    recovered = []
    for key, digest, plain, maximum in (
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
        self._authority_access(consent, access)
        raw = _read(self._reader, key, maximum + 1_000_000)
        self._authority_access(consent, access)
        if content_hash_of(raw) != digest:
            raise ValueError("authority snapshot ciphertext differs")
        observations.append((key, digest, maximum + 1_000_000))
        restored = _recover(raw, self._identity, maximum)
        self._authority_access(consent, access)
        if content_hash_of(restored) != plain:
            raise ValueError("authority snapshot plaintext differs")
        recovered.append(restored)
    self._restoration.verify_personal(
        recovered[0],
        expected,
        current_selected_sources=self._engine,
        operational_journal=recovered[1],
    )
    # Actual restoration/admin lease has closed before owner callbacks.
    self._authority_access(consent, access)
    if (
        self._plan() != plan
        or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
        != receipt.live_journal_digest
    ):
        raise ValueError("authority complete plan/journal differs")
    return tuple(observations)


def _publication_decision_owner(
    operation: NamedSessionOperation,
    clock: HostObservedClock,
    consent: auth.HistoryFragmentConsentV1,
) -> VerifiedNamedSession:
    if type(operation) is not NamedSessionOperation or type(clock) is not HostObservedClock:
        raise ValueError("exact original owner/session required")
    if operation.host_clock is not clock:
        raise ValueError("same actual clock required")
    before = clock()
    owner = operation.recheck(consent.original_session_binding)
    # The concrete operation may observe the SAME clock internally. Read its
    # existing watermark without another callback after the final owner read.
    with clock._lock:
        now = clock._last
    if (
        type(now) is not datetime
        or now.utcoffset() is None
        or now < before
        or owner.principal.identity.issuer != consent.owner_issuer
        or owner.principal.identity.subject != consent.owner_subject
        or owner.principal.scopes != auth._FRAGMENT_OWNER_SCOPE
        or owner.issued_at != consent.original_session_issued_at
        or owner.effective_expires_at != consent.original_session_expires_at
        or not consent.approved_at <= now < consent.expires_at
    ):
        raise ValueError("original full publication owner inactive")
    return owner


def _assert_publication_review_provenance(publication: FragmentGenerationReviewDeclarationV2) -> None:
    # Full review retains seven purpose-specific Sources in addition to original
    # provenance. Preserve the existing 96-reference canonical loader limit.
    _, consent, _ = _parts(publication)
    if len(consent.provenance) > 89:
        raise ValueError("full publication review provenance capacity exceeded")
    from zacai.intelligence.fragment_publication_review import _assert_publication_review_record_fit

    _assert_publication_review_record_fit(publication)


def _publication_terminal_deadline(
    gate: CanonicalPersonalFragmentPublicationAuthorization, started: float,
) -> float:
    with gate._clock._lock:
        observed = gate._clock._last
    if observed is None or not gate._consent.approved_at <= observed < gate._consent.expires_at:
        raise ValueError("original publication processing expired")
    return started + (gate._consent.expires_at - observed).total_seconds()


def _publication_terminal_time(
    gate: CanonicalPersonalFragmentPublicationAuthorization, bound: float,
) -> None:
    from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

    with gate._clock._lock:
        observed = gate._clock._last
    if (observed is None or observed >= gate._consent.expires_at
        or _AUTHENTICATED_MONOTONIC() >= bound):
        raise ValueError("original publication processing expired")
