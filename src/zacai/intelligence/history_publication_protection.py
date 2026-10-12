"""Closed complete admission recovery using existing whole-inventory machinery.

Closed family metadata only; no approval or authenticated reviewer is created.
"""

from __future__ import annotations

import json
from time import monotonic as _NATIVE_MONOTONIC
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.orm import Session

from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_contextual_codec import HistoryContextualPacketV1
from zacai.intelligence.history_generation_review_declaration import (
    HistoryClaimV1,
    HistoryConsentV1,
    HistoryGenerationReviewDeclarationV1,
    encode_history_claim,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_publication_admission import (
    HistoryPublicationAdmissionV1,
    RetainedHistoryPublicationAdmission,
    _binding,
    _history_admission_current,
    encode_history_publication_admission,
    load_history_publication_admission,
)
from zacai.intelligence.history_publication_generation import HistoryPublicationOutputAssociationV1
from zacai.intelligence.history_review_retention import (
    HistoryDeclarationContext,
    _parts,
    history_declaration_owner,
)
from zacai.interfaces.named_session_binding import VerifiedNamedSession
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

if TYPE_CHECKING:
    from zacai.intelligence.history_publication_review import (
        CanonicalPersonalHistoryReviewAuthorization,
    )


class _HistoryRecoveryFields(Contract):
    """Closed full-purpose bytes recovery observation; no human/claim authority."""

    admission_reference: EvidenceReference = Field(repr=False)
    admission_digest: Digest
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    request_digest: Digest
    generation_wire_digest: Digest
    review_profile_digest: Digest
    selected_references: tuple[EvidenceReference, ...] = Field(repr=False)
    full_plan_digest: Digest
    full_boundary_source_hashes: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    full_boundary_source_fingerprints: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    generation_id: UUID
    observed_action_at: AwareDatetime
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
                    self.generation_id,
                    self.admission_reference.source_id,
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
            or self.admission_reference.source_id == self.publication_reference.source_id
            or self.admission_reference.content_hash != self.admission_digest
            or self.admission_reference not in self.selected_references
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
            or any(sid.int == 0 for sid in hashes)
            or any(hashes.get(r.source_id) != r.content_hash for r in self.selected_references)
            or not self.original_session_issued_at
            <= self.declared_window_started_at
            <= self.observed_action_at
            <= self.verified_at
            < self.expires_at
            <= self.original_session_expires_at
            or self.original_observed_at > self.declared_window_started_at
        ):
            raise ValueError("closed full publication recovery observation required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-complete-admission-{self.admission_reference.source_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.admission_digest}.age"

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


class PersonalHistoryAdmissionReceiptV1(_HistoryRecoveryFields):
    format: Literal["zac-personal-history-complete-admission-recovery-v1"] = (
        "zac-personal-history-complete-admission-recovery-v1"
    )


class PersonalHistoryClaimReceiptV1(_HistoryRecoveryFields):
    format: Literal["zac-personal-history-complete-claim-recovery-v1"] = (
        "zac-personal-history-complete-claim-recovery-v1"
    )
    claim_reference: EvidenceReference = Field(repr=False)
    claim_digest: Digest
    attempt_id: UUID
    consumed_at: AwareDatetime

    @model_validator(mode="after")
    def exact_claim(self) -> Self:
        if (
            self.attempt_id.int == 0
            or self.claim_reference not in self.selected_references
            or self.claim_reference.source_id
            in (self.publication_reference.source_id, self.admission_reference.source_id)
            or self.claim_reference.content_hash != self.claim_digest
            or not self.observed_action_at <= self.consumed_at <= self.verified_at
        ):
            raise ValueError("exact complete claim recovery subject required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-complete-claim-{self.claim_reference.source_id}"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.claim_digest}.age"


class PersonalHistoryOutputReceiptV1(_HistoryRecoveryFields):
    format: Literal["zac-personal-history-complete-output-recovery-v1"] = (
        "zac-personal-history-complete-output-recovery-v1"
    )
    claim_reference: EvidenceReference = Field(repr=False)
    claim_digest: Digest
    packet_reference: EvidenceReference = Field(repr=False)
    association_reference: EvidenceReference = Field(repr=False)
    association_digest: Digest
    attempt_id: UUID
    packet_created_at: AwareDatetime
    output_digest: Digest
    usage_digest: Digest

    @model_validator(mode="after")
    def exact_output(self) -> Self:
        refs = (
            self.publication_reference,
            self.admission_reference,
            self.claim_reference,
            self.packet_reference,
            self.association_reference,
        )
        if (
            self.attempt_id.int == 0
            or len({r.source_id for r in refs}) != len(refs)
            or any(r not in self.selected_references for r in refs)
            or self.claim_reference.content_hash != self.claim_digest
            or self.association_reference.content_hash != self.association_digest
            or not self.observed_action_at <= self.packet_created_at <= self.verified_at
        ):
            raise ValueError("exact complete associated output recovery subject required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-complete-output-{self.association_reference.source_id}"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.association_digest}.age"


class PersonalHistoryReviewReceiptV1(_HistoryRecoveryFields):
    format: Literal["zac-personal-history-complete-review-recovery-v1"] = (
        "zac-personal-history-complete-review-recovery-v1"
    )
    subject_kind: Literal["review_claim", "assessment"]
    claim_reference: EvidenceReference = Field(repr=False)
    packet_reference: EvidenceReference = Field(repr=False)
    association_reference: EvidenceReference = Field(repr=False)
    review_claim_reference: EvidenceReference = Field(repr=False)
    review_claim_digest: Digest
    assessment_reference: EvidenceReference | None = Field(default=None, repr=False)
    assessment_digest: Digest | None = None
    reviewer_id: UUID
    run_id: UUID
    attempt_id: UUID

    @model_validator(mode="after")
    def exact_review(self) -> Self:
        refs = (
            self.publication_reference,
            self.admission_reference,
            self.claim_reference,
            self.packet_reference,
            self.association_reference,
            self.review_claim_reference,
            *((self.assessment_reference,) if self.assessment_reference is not None else ()),
        )
        if (
            self.reviewer_id.int == 0
            or self.run_id.int == 0
            or self.attempt_id.int == 0
            or self.reviewer_id == self.builder_id
            or len({r.source_id for r in refs}) != len(refs)
            or any(r not in self.selected_references for r in refs)
            or self.review_claim_reference.content_hash != self.review_claim_digest
            or (self.subject_kind == "assessment") != (self.assessment_reference is not None)
            or (self.assessment_reference is None) != (self.assessment_digest is None)
            or (
                self.assessment_reference is not None
                and self.assessment_reference.content_hash != self.assessment_digest
            )
        ):
            raise ValueError("exact complete reviewer recovery union required")
        return self

    @property
    def prefix(self) -> str:
        own = (
            self.review_claim_reference
            if self.assessment_reference is None
            else self.assessment_reference
        )
        return f"PERSONAL/state/history-complete-{self.subject_kind}-{own.source_id}"

    @property
    def receipt_object(self) -> str:
        digest = (
            self.review_claim_digest if self.assessment_digest is None else self.assessment_digest
        )
        return f"{self.prefix}/receipt-{digest}.age"


_HistoryReceipt = (
    PersonalHistoryAdmissionReceiptV1
    | PersonalHistoryClaimReceiptV1
    | PersonalHistoryOutputReceiptV1
    | PersonalHistoryReviewReceiptV1
)


_ReceiptClass = (
    type[PersonalHistoryAdmissionReceiptV1]
    | type[PersonalHistoryClaimReceiptV1]
    | type[PersonalHistoryOutputReceiptV1]
    | type[PersonalHistoryReviewReceiptV1]
)


def _encode_receipt(value: _HistoryReceipt) -> bytes:
    if type(value) not in (
        PersonalHistoryAdmissionReceiptV1,
        PersonalHistoryClaimReceiptV1,
        PersonalHistoryOutputReceiptV1,
        PersonalHistoryReviewReceiptV1,
    ):
        raise ValueError("exact closed complete subject receipt required")
    raw = canonical_bytes(
        type(value).model_validate(value.model_dump(mode="json")).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded complete subject receipt required")
    return raw


def _decode_receipt(
    raw: bytes, kind: Literal["admission", "claim", "output", "review_claim", "assessment"]
) -> _HistoryReceipt:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded complete receipt required")
    classes: dict[str, _ReceiptClass] = {
        "admission": PersonalHistoryAdmissionReceiptV1,
        "claim": PersonalHistoryClaimReceiptV1,
        "output": PersonalHistoryOutputReceiptV1,
        "review_claim": PersonalHistoryReviewReceiptV1,
        "assessment": PersonalHistoryReviewReceiptV1,
    }
    cls = classes[kind]
    result = cls.model_validate(json.loads(raw, object_pairs_hook=_unique_pairs))
    if _encode_receipt(result) != raw:
        raise ValueError("canonical complete receipt required")
    return result


def encode_history_claim_receipt(value: PersonalHistoryClaimReceiptV1) -> bytes:
    if type(value) is not PersonalHistoryClaimReceiptV1:
        raise ValueError("exact claim receipt required")
    return _encode_receipt(value)


def decode_history_claim_receipt(raw: bytes) -> PersonalHistoryClaimReceiptV1:
    result = _decode_receipt(raw, "claim")
    if type(result) is not PersonalHistoryClaimReceiptV1:
        raise ValueError("exact claim receipt required")
    return result


def encode_history_output_receipt(value: PersonalHistoryOutputReceiptV1) -> bytes:
    if type(value) is not PersonalHistoryOutputReceiptV1:
        raise ValueError("exact output receipt required")
    return _encode_receipt(value)


def decode_history_output_receipt(raw: bytes) -> PersonalHistoryOutputReceiptV1:
    result = _decode_receipt(raw, "output")
    if type(result) is not PersonalHistoryOutputReceiptV1:
        raise ValueError("exact output receipt required")
    return result


def encode_history_admission_receipt(value: PersonalHistoryAdmissionReceiptV1) -> bytes:
    if type(value) is not PersonalHistoryAdmissionReceiptV1:
        raise ValueError("exact admission receipt required")
    raw = canonical_bytes(
        PersonalHistoryAdmissionReceiptV1.model_validate(value).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded admission receipt required")
    return raw


def decode_history_admission_receipt(raw: bytes) -> PersonalHistoryAdmissionReceiptV1:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded admission receipt required")
    result = PersonalHistoryAdmissionReceiptV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_history_admission_receipt(result) != raw:
        raise ValueError("canonical admission receipt required")
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


def _protect_history_subject(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    expected_admission: HistoryPublicationAdmissionV1,
    context: HistoryDeclarationContext,
    read_existing: bool = False,
    kind: Literal["admission", "claim", "output", "review_claim", "assessment"],
    admission_reference: EvidenceReference,
    expected_claim: HistoryClaimV1 | None = None,
    claim_reference: EvidenceReference | None = None,
    expected_association: HistoryPublicationOutputAssociationV1 | None = None,
    review_gate: CanonicalPersonalHistoryReviewAuthorization | None = None,
) -> _HistoryReceipt:
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
            or type(expected_declaration) is not HistoryGenerationReviewDeclarationV1
            or type(expected_admission) is not HistoryPublicationAdmissionV1
            or type(context) is not HistoryDeclarationContext
        ):
            raise ValueError("exact existing inventory protector and mode required")
        _, generation, request = _parts(expected_declaration)
        _binding(expected_admission, expected_declaration)
        from zacai.intelligence import history_publication_generation as generation_module

        if kind == "admission":
            if (
                reference != admission_reference
                or expected_claim is not None
                or claim_reference is not None
                or expected_association is not None
            ):
                raise ValueError("closed admission-only subject required")
            raw = encode_history_publication_admission(expected_admission)
            cls: _ReceiptClass = PersonalHistoryAdmissionReceiptV1
        elif kind == "claim":
            if (
                type(expected_claim) is not HistoryClaimV1
                or claim_reference != reference
                or expected_association is not None
            ):
                raise ValueError("actual exact complete claim subject required")
            raw = encode_history_claim(expected_claim)
            generation_module._claim_binding(
                expected_declaration, admission_reference, expected_admission, expected_claim
            )
            cls = PersonalHistoryClaimReceiptV1
        elif kind == "output":
            if (
                type(expected_claim) is not HistoryClaimV1
                or type(claim_reference) is not EvidenceReference
                or type(expected_association) is not HistoryPublicationOutputAssociationV1
            ):
                raise ValueError("actual exact complete output subject required")
            raw = generation_module.encode_history_output_association(expected_association)
            generation_module._association_binding(
                expected_association,
                declaration=expected_declaration,
                admission_reference=admission_reference,
                admission=expected_admission,
                claim_reference=claim_reference,
                claim=expected_claim,
            )
            cls = PersonalHistoryOutputReceiptV1
        elif kind in ("review_claim", "assessment"):
            from zacai.intelligence import history_publication_review as reviewer

            if type(review_gate) is not reviewer.CanonicalPersonalHistoryReviewAuthorization:
                raise ValueError("actual original complete reviewer gate required")
            review_gate._graph_check()
            parent = review_gate._generation
            if (
                parent._declaration != expected_declaration
                or parent._admission_reference != admission_reference
                or parent._admission != expected_admission
                or parent._claim != expected_claim
                or parent._claim_reference != claim_reference
                or review_gate._output.association != expected_association
                or review_gate._claim is None
                or review_gate._claim_reference is None
            ):
                raise ValueError("closed complete reviewer subject parent required")
            if kind == "review_claim":
                if reference != review_gate._claim_reference or review_gate._assessment is not None:
                    raise ValueError("closed original review claim subject required")
                raw = reviewer.encode_history_publication_review_claim(review_gate._claim)
            else:
                if (
                    reference != review_gate._assessment_reference
                    or review_gate._assessment is None
                ):
                    raise ValueError("closed actual complete assessment subject required")
                raw = reviewer.encode_history_publication_assessment(review_gate._assessment)
            cls = PersonalHistoryReviewReceiptV1
        else:
            raise ValueError("closed complete recovery kind required")
        native_started = _NATIVE_MONOTONIC()
        if (
            type(reference) is not EvidenceReference
            or reference.content_hash != content_hash_of(raw)
            or reference.source_id.int == 0
            or reference.trust_boundary is not B.PERSONAL
            or reference.effective_classification is not C.HIGHLY_RESTRICTED
        ):
            raise ValueError("actual canonical complete subject required")
        selected_list = [
            *generation.provenance,
            expected_admission.publication_reference,
            admission_reference,
        ]
        if kind == "claim":
            selected_list.append(reference)
        elif kind in ("output", "review_claim", "assessment"):
            assert claim_reference is not None and expected_association is not None
            association_reference = reference
            if kind in ("review_claim", "assessment"):
                assert review_gate is not None and review_gate._claim_reference is not None
                association_reference = review_gate._output.association_reference
                selected_list.append(review_gate._claim_reference)
                if kind == "assessment":
                    selected_list.append(reference)
            selected_list.extend(
                (claim_reference, expected_association.packet_reference, association_reference)
            )
        selected = tuple(sorted(selected_list, key=lambda r: str(r.source_id)))
        if len(selected) > 95 or len({r.source_id for r in selected}) != len(selected):
            raise ValueError("bounded distinct complete subject required")
        binding = dict(  # noqa: C408
            admission_reference=admission_reference,
            admission_digest=content_hash_of(
                encode_history_publication_admission(expected_admission)
            ),
            publication_reference=expected_admission.publication_reference,
            publication_digest=history_generation_review_declaration_digest(expected_declaration),
            request_digest=generation.request_digest,
            generation_wire_digest=generation.generation_wire_digest,
            review_profile_digest=expected_declaration.review_profile_digest,
            selected_references=selected,
            generation_id=generation.id,
            observed_action_at=expected_admission.observed_action_at,
            task_id=generation.task_id,
            builder_id=generation.builder_id,
            original_observed_at=request.sidecar.entries[0].projection_observed_at,
            declared_window_started_at=generation.approved_at,
            expires_at=generation.expires_at,
            original_session_binding=generation.original_session_binding,
            original_session_issued_at=generation.original_session_issued_at,
            original_session_expires_at=generation.original_session_expires_at,
        )
        if kind == "claim":
            assert expected_claim is not None
            binding.update(
                claim_reference=reference,
                claim_digest=content_hash_of(raw),
                attempt_id=expected_claim.attempt_id,
                consumed_at=expected_claim.consumed_at,
            )
        elif kind == "output":
            assert expected_claim is not None and expected_association is not None
            binding.update(
                claim_reference=claim_reference,
                claim_digest=expected_association.claim_digest,
                packet_reference=expected_association.packet_reference,
                association_reference=reference,
                association_digest=content_hash_of(raw),
                attempt_id=expected_claim.attempt_id,
                packet_created_at=expected_association.packet_created_at,
                output_digest=expected_association.output_digest,
                usage_digest=expected_association.usage_digest,
            )

        elif kind in ("review_claim", "assessment"):
            assert review_gate is not None and review_gate._claim is not None
            assert review_gate._claim_reference is not None and expected_association is not None
            binding.update(
                subject_kind=kind,
                claim_reference=claim_reference,
                packet_reference=expected_association.packet_reference,
                association_reference=review_gate._output.association_reference,
                review_claim_reference=review_gate._claim_reference,
                review_claim_digest=review_gate._claim_reference.content_hash,
                assessment_reference=None if kind == "review_claim" else reference,
                assessment_digest=None if kind == "review_claim" else content_hash_of(raw),
                reviewer_id=review_gate._claim.reviewer_id,
                run_id=review_gate._claim.run_id,
                attempt_id=review_gate._claim.attempt_id,
            )

        def current_subject(session: Session) -> tuple[tuple[tuple[str, object], ...], ...]:
            if kind == "admission":
                return _history_admission_current(
                    session,
                    reference=reference,
                    expected_admission=expected_admission,
                    expected_declaration=expected_declaration,
                )
            if kind == "claim":
                assert expected_claim is not None
                return generation_module._claim_current(
                    session,
                    reference=reference,
                    expected_claim=expected_claim,
                    expected_declaration=expected_declaration,
                    admission_reference=admission_reference,
                    expected_admission=expected_admission,
                )
            if kind in ("review_claim", "assessment"):
                assert review_gate is not None
                return review_gate._current(
                    session,
                    assessment=None if kind == "review_claim" else review_gate._assessment,
                    reference=None if kind == "review_claim" else reference,
                )
            assert (
                expected_claim is not None
                and claim_reference is not None
                and expected_association is not None
            )
            return generation_module._output_current(
                session,
                reference=reference,
                value=expected_association,
                declaration=expected_declaration,
                admission_reference=admission_reference,
                admission=expected_admission,
                claim_reference=claim_reference,
                claim=expected_claim,
            )

        with protector._lock:
            access = _access(protector, generation)
            with protector._clock._lock:
                original_observed = protector._clock._last
            if original_observed is None:
                raise ValueError("actual original expiry observation required")
            original_deadline = (
                native_started + (generation.expires_at - original_observed).total_seconds()
            )
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
                entry = _physical(session)
                if kind == "admission":
                    loaded = load_history_publication_admission(
                        session,
                        artifacts=protector._artifacts,
                        context=context,
                        reference=reference,
                        expected_admission=expected_admission,
                        expected_declaration=expected_declaration,
                    )
                    if (
                        type(loaded) is not RetainedHistoryPublicationAdmission
                        or loaded.reference != reference
                        or loaded.admission != expected_admission
                        or loaded.captured_at != expected_admission.observed_action_at
                    ):
                        raise ValueError("actual canonical admission load required")
                elif kind == "claim":
                    assert expected_claim is not None
                    loaded_claim = generation_module.load_history_publication_claim(
                        session,
                        artifacts=protector._artifacts,
                        context=context,
                        reference=reference,
                        expected_claim=expected_claim,
                        expected_declaration=expected_declaration,
                        admission_reference=admission_reference,
                        expected_admission=expected_admission,
                    )
                    if type(loaded_claim) is not HistoryClaimV1 or loaded_claim != expected_claim:
                        raise ValueError("actual canonical claim load required")
                elif kind in ("review_claim", "assessment"):
                    from zacai.intelligence.history_publication_review import (
                        load_history_publication_review_subject,
                    )

                    assert review_gate is not None
                    parent = review_gate._generation
                    assert parent._claim is not None and parent._claim_reference is not None
                    assert (
                        review_gate._claim is not None and review_gate._claim_reference is not None
                    )
                    loaded_review = load_history_publication_review_subject(
                        session,
                        artifacts=protector._artifacts,
                        context=context,
                        declaration=expected_declaration,
                        admission=expected_admission,
                        admission_reference=admission_reference,
                        generation_claim=parent._claim,
                        generation_claim_reference=parent._claim_reference,
                        association=review_gate._output.association,
                        association_reference=review_gate._output.association_reference,
                        review_claim=review_gate._claim,
                        review_claim_reference=review_gate._claim_reference,
                        assessment=None if kind == "review_claim" else review_gate._assessment,
                        assessment_reference=None if kind == "review_claim" else reference,
                    )
                    expected_review = (
                        review_gate._claim if kind == "review_claim" else review_gate._assessment
                    )
                    if loaded_review != expected_review:
                        raise ValueError("actual canonical reviewer subject differs")
                else:
                    assert (
                        claim_reference is not None
                        and expected_claim is not None
                        and expected_association is not None
                    )
                    pair = generation_module.load_history_publication_output_association(
                        session,
                        artifacts=protector._artifacts,
                        context=context,
                        reference=reference,
                        expected_association=expected_association,
                        expected_declaration=expected_declaration,
                        admission_reference=admission_reference,
                        expected_admission=expected_admission,
                        claim_reference=claim_reference,
                        expected_claim=expected_claim,
                    )
                    if (
                        type(pair) is not tuple
                        or len(pair) != 2
                        or type(pair[0]) is not HistoryContextualPacketV1
                        or pair[1] != expected_association
                    ):
                        raise ValueError("actual paired output load required")
                current = current_subject(session)
                _same(session, entry)
            _access(protector, generation, access)
            if protector._plan() != plan:
                raise ValueError("plan changed during actual complete load")
            complete = dict(
                **binding,
                full_plan_digest=content_hash_of(plan.rows),
                full_boundary_source_hashes=hashes,
                full_boundary_source_fingerprints=fingerprints,
            )
            prefix = f"PERSONAL/state/history-complete-{kind}-{reference.source_id}"
            key = f"{prefix}/receipt-{content_hash_of(raw)}.age"
            if read_existing:
                cipher = _read(protector._reader, key, 2_100_000)
                _access(protector, generation, access)
                raw = _recover(cipher, protector._identity, 2_000_000)
                _access(protector, generation, access)
                receipt = _decode_receipt(raw, kind)
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
                receipt = cls.model_validate(
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
                receipt = cls.model_validate(
                    {**receipt.model_dump(), "verified_at": protector._clock()}
                )
                cipher = _crypt(_encode_receipt(receipt), protector._recipient, 2_000_000)
                _access(protector, generation, access)
                if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                    raise ValueError("bounded complete receipt ciphertext required")
                protector._writer.put_object(key, cipher)
                _access(protector, generation, access)
                returned = _read(protector._reader, key, 2_100_000)
                _access(protector, generation, access)
                plain = _recover(returned, protector._identity, 2_000_000)
                _access(protector, generation, access)
                if returned != cipher or _decode_receipt(plain, kind) != receipt:
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
            with protector._factory() as session:
                session.begin()
                entry = _physical(session)
                terminal = current_subject(session)
                _same(session, entry)
                if terminal != current:
                    raise ValueError("terminal canonical admission union changed")
            if _NATIVE_MONOTONIC() >= original_deadline:
                raise ValueError("original admission interval expired after terminal scalars")
            if type(receipt) not in (
                PersonalHistoryAdmissionReceiptV1,
                PersonalHistoryClaimReceiptV1,
                PersonalHistoryOutputReceiptV1,
                PersonalHistoryReviewReceiptV1,
            ):
                raise ValueError("exact complete subject receipt required")
            result = receipt
    except (ReviewProtectionCleanupUncertain, PersonalFragmentCleanupUncertain):
        uncertain = True
    except Exception:  # noqa: BLE001
        result = None
    if uncertain:
        raise PersonalFragmentCleanupUncertain(
            "PERSONAL complete admission cleanup uncertain; operator review required"
        )
    if result is None:
        raise ValueError("PERSONAL complete admission checkpoint unavailable or mismatched")
    return result


def protect_history_admission(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    expected_admission: HistoryPublicationAdmissionV1,
    context: HistoryDeclarationContext,
    read_existing: bool = False,
) -> PersonalHistoryAdmissionReceiptV1:
    value = _protect_history_subject(
        protector,
        reference=reference,
        expected_declaration=expected_declaration,
        expected_admission=expected_admission,
        context=context,
        read_existing=read_existing,
        kind="admission",
        admission_reference=reference,
    )
    if type(value) is not PersonalHistoryAdmissionReceiptV1:
        raise ValueError("exact admission receipt required")
    return value


def protect_history_claim(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    expected_admission: HistoryPublicationAdmissionV1,
    admission_reference: EvidenceReference,
    expected_claim: HistoryClaimV1,
    context: HistoryDeclarationContext,
    read_existing: bool = False,
) -> PersonalHistoryClaimReceiptV1:
    value = _protect_history_subject(
        protector,
        reference=reference,
        expected_declaration=expected_declaration,
        expected_admission=expected_admission,
        context=context,
        read_existing=read_existing,
        kind="claim",
        admission_reference=admission_reference,
        expected_claim=expected_claim,
        claim_reference=reference,
    )
    if type(value) is not PersonalHistoryClaimReceiptV1:
        raise ValueError("exact claim receipt required")
    return value


def protect_history_output(
    protector: PersonalHistoryFragmentProtector,
    *,
    reference: EvidenceReference,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    expected_admission: HistoryPublicationAdmissionV1,
    admission_reference: EvidenceReference,
    claim_reference: EvidenceReference,
    expected_claim: HistoryClaimV1,
    expected_association: HistoryPublicationOutputAssociationV1,
    context: HistoryDeclarationContext,
    read_existing: bool = False,
) -> PersonalHistoryOutputReceiptV1:
    value = _protect_history_subject(
        protector,
        reference=reference,
        expected_declaration=expected_declaration,
        expected_admission=expected_admission,
        context=context,
        read_existing=read_existing,
        kind="output",
        admission_reference=admission_reference,
        expected_claim=expected_claim,
        claim_reference=claim_reference,
        expected_association=expected_association,
    )
    if type(value) is not PersonalHistoryOutputReceiptV1:
        raise ValueError("exact output receipt required")
    return value


def _protect_review_gate(
    gate: CanonicalPersonalHistoryReviewAuthorization,
    *,
    kind: Literal["review_claim", "assessment"],
    read_existing: bool,
) -> PersonalHistoryReviewReceiptV1:
    from zacai.intelligence.history_publication_review import (
        CanonicalPersonalHistoryReviewAuthorization,
    )

    if type(gate) is not CanonicalPersonalHistoryReviewAuthorization:
        raise ValueError("actual complete reviewer gate required")
    p = gate._generation
    reference = gate._claim_reference if kind == "review_claim" else gate._assessment_reference
    if reference is None:
        raise ValueError("actual retained reviewer subject required")
    value = _protect_history_subject(
        p._protector,
        reference=reference,
        expected_declaration=p._declaration,
        expected_admission=p._admission,
        context=p._context,
        kind=kind,
        admission_reference=p._admission_reference,
        expected_claim=p._claim,
        claim_reference=p._claim_reference,
        expected_association=gate._output.association,
        review_gate=gate,
        read_existing=read_existing,
    )
    if type(value) is not PersonalHistoryReviewReceiptV1 or value.subject_kind != kind:
        raise ValueError("exact complete reviewer recovery receipt required")
    return value


def protect_history_review_claim(
    gate: CanonicalPersonalHistoryReviewAuthorization, *, read_existing: bool = False
) -> PersonalHistoryReviewReceiptV1:
    return _protect_review_gate(gate, kind="review_claim", read_existing=read_existing)


def protect_history_assessment(
    gate: CanonicalPersonalHistoryReviewAuthorization, *, read_existing: bool = False
) -> PersonalHistoryReviewReceiptV1:
    return _protect_review_gate(gate, kind="assessment", read_existing=read_existing)
