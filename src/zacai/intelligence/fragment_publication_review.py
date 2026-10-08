"""Concrete full-purpose child reviewer join, unmounted until acceptance.

The declared schema does not authenticate a reviewer. Only the exact original
producer, canonical claim, concrete runtime invocation and new whole-State
checkpoint may reach retained assessment. Failed attempts are never repaired.
Private traceback locals must not be captured.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.orm import Session

from zacai.backup_artifacts import prepare_personal_encrypted_custody_backup_plan
from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_evaluation import (
    ContextualEvaluation,
    check_history_fragment_contextual_evaluation,
)
from zacai.intelligence.contextual_storage import _fragment_profile_lineage, _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, UsageObservation
from zacai.intelligence.fragment_publication_admission import _ids
from zacai.intelligence.fragment_publication_generation import (
    CanonicalPersonalFragmentPublicationAuthorization,
    PersonalFragmentAssociatedOutput,
    _association_rows,
    _reopen_publication_output,
    _terminal_publication_output,
    load_fragment_publication_output_association,
)
from zacai.intelligence.fragment_review_declaration import (
    FragmentReviewPurposeProfileV1,
    fragment_generation_review_declaration_digest,
    fragment_review_profile_digest,
)
from zacai.intelligence.fragment_review_preparation import (
    FragmentReviewJudgments,
    PreparedFragmentReviewRequest,
    prepare_fragment_review_request,
    verify_fragment_review_request,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_packet,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

if TYPE_CHECKING:
    from zacai.intelligence.fragment_review_runtime import (
        AuthenticatedFragmentReviewDispatchDescriptor,
        FragmentReviewDispatchDescriptor,
        _LocalFragmentReviewRuntime,
        _MechanicalReviewResult,
    )

MAX_REVIEW_RECORD_BYTES = 16_000
_BOUNDARIES = frozenset({B.PERSONAL})
_LABELS = frozenset({C.HIGHLY_RESTRICTED})


class FragmentPublicationReviewError(RuntimeError):
    """Fixed public failure, not an evaluation verdict."""


def _closed_references(references: tuple[EvidenceReference, ...]) -> None:
    if (
        not 1 <= len(references) <= 96
        or len({r.source_id for r in references}) != len(references)
        or tuple(sorted(references, key=lambda r: str(r.source_id))) != references
        or any(
            r.source_id.int == 0
            or r.trust_boundary is not B.PERSONAL
            or r.effective_classification is not C.HIGHLY_RESTRICTED
            for r in references
        )
    ):
        raise ValueError("complete ordered PERSONAL input union required")


class FragmentPublicationReviewClaimV1(Contract):
    """A canonical one-attempt burn; construction is not admission."""

    format: Literal["zac-personal-fragment-publication-review-claim-v1"] = (
        "zac-personal-fragment-publication-review-claim-v1"
    )
    generation_id: UUID
    run_id: UUID
    reviewer_id: UUID
    attempt_id: UUID
    task_id: UUID
    builder_id: UUID
    association_reference: EvidenceReference
    association_digest: Digest
    packet_reference: EvidenceReference
    publication_reference: EvidenceReference
    publication_digest: Digest
    admission_reference: EvidenceReference
    admission_digest: Digest
    generation_claim_reference: EvidenceReference
    generation_claim_digest: Digest
    review_profile: FragmentReviewPurposeProfileV1 = Field(repr=False)
    review_profile_digest: Digest
    prepared_request_digest: Digest
    prepared_body_digest: Digest
    wire_body_digest: Digest
    route_digest: Digest
    runtime_profile_digest: Digest
    authorization_graph_digest: Digest
    model_metadata_digest: Digest
    mechanical_descriptor_digest: Digest
    original_deadline_monotonic: float = Field(strict=True, gt=0)
    measured_input_tokens: int = Field(strict=True, gt=0)
    requested_output_tokens: int = Field(strict=True, gt=0, le=2048)
    original_session_binding: Digest = Field(repr=False)
    original_approved_at: AwareDatetime
    expires_at: AwareDatetime
    consumed_at: AwareDatetime
    selected_references: tuple[EvidenceReference, ...] = Field(repr=False)

    @model_validator(mode="after")
    def exact_bindings(self) -> Self:
        _closed_references(self.selected_references)
        refs = (
            self.association_reference,
            self.packet_reference,
            self.publication_reference,
            self.admission_reference,
            self.generation_claim_reference,
        )
        if (
            any(
                v.int == 0
                for v in (
                    self.generation_id,
                    self.run_id,
                    self.reviewer_id,
                    self.attempt_id,
                    self.task_id,
                    self.builder_id,
                )
            )
            or self.reviewer_id == self.builder_id
            or len({r.source_id for r in refs}) != len(refs)
            or any(r not in self.selected_references for r in refs)
            or self.association_digest != self.association_reference.content_hash
            or self.admission_digest != self.admission_reference.content_hash
            or self.generation_claim_digest != self.generation_claim_reference.content_hash
            or self.review_profile_digest != fragment_review_profile_digest(self.review_profile)
            or self.review_profile.run_id != self.run_id
            or self.review_profile.reviewer_id != self.reviewer_id
            or self.requested_output_tokens != self.review_profile.max_output_tokens
            or self.measured_input_tokens + self.requested_output_tokens
            > self.review_profile.context_window_tokens
            or not self.original_approved_at <= self.consumed_at < self.expires_at
        ):
            raise ValueError("exact original review claim bindings required")
        return self


class FragmentPublicationAssessmentV1(Contract):
    """Closed retained invocation evidence, never model-authored host provenance."""

    format: Literal["zac-personal-fragment-publication-assessment-v1"] = (
        "zac-personal-fragment-publication-assessment-v1"
    )
    evaluation: ContextualEvaluation = Field(repr=False)
    review_claim_reference: EvidenceReference
    review_claim: FragmentPublicationReviewClaimV1 = Field(repr=False)
    released_judgments_digest: Digest
    released_usage_digest: Digest
    usage: UsageObservation
    captured_at: AwareDatetime

    @model_validator(mode="after")
    def exact_bindings(self) -> Self:
        claim, evaluation = self.review_claim, self.evaluation
        if (
            self.review_claim_reference.source_id.int == 0
            or self.review_claim_reference.trust_boundary is not B.PERSONAL
            or self.review_claim_reference.effective_classification is not C.HIGHLY_RESTRICTED
            or self.review_claim_reference.content_hash
            != content_hash_of(encode_fragment_publication_review_claim(claim))
            or self.review_claim_reference.source_id
            in {r.source_id for r in claim.selected_references}
            or evaluation.task_id != claim.task_id
            or evaluation.builder_id != claim.builder_id
            or evaluation.reviewer_id != claim.reviewer_id
            or evaluation.evaluation_id != claim.run_id
            or evaluation.packet_digest != claim.packet_reference.content_hash
            or evaluation.evaluated_at != self.captured_at
            or content_hash_of(
                canonical_bytes(
                    FragmentReviewJudgments(
                        format="zac-history-fragment-review-judgments-v1",
                        assessments=evaluation.assessments,
                    ).model_dump(mode="json")
                )
            )
            != self.released_judgments_digest
            or not claim.consumed_at <= self.captured_at < claim.expires_at
            or content_hash_of(canonical_bytes(self.usage.model_dump(mode="json")))
            != self.released_usage_digest
            or self.usage.input_tokens != claim.measured_input_tokens
            or not 0 < self.usage.output_tokens <= claim.requested_output_tokens
        ):
            raise ValueError("exact actual released assessment required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def encode_fragment_publication_review_claim(value: FragmentPublicationReviewClaimV1) -> bytes:
    result = None
    try:
        if type(value) is not FragmentPublicationReviewClaimV1:
            raise ValueError("exact claim required")
        checked = FragmentPublicationReviewClaimV1.model_validate(value.model_dump())
        payload = checked.model_dump(mode="json")
        payload["review_profile"]["route"]["capabilities"] = sorted(
            payload["review_profile"]["route"]["capabilities"]
        )
        raw = canonical_bytes(payload)
        if len(raw) > MAX_REVIEW_RECORD_BYTES:
            raise ValueError("bounded claim required")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL review claim unavailable")
    return result


def decode_fragment_publication_review_claim(raw: bytes) -> FragmentPublicationReviewClaimV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REVIEW_RECORD_BYTES:
            raise ValueError("bounded claim required")
        value = FragmentPublicationReviewClaimV1.model_validate_json(raw)
        if encode_fragment_publication_review_claim(value) != raw:
            raise ValueError("canonical claim required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL review claim unavailable")
    return result


def encode_fragment_publication_assessment(value: FragmentPublicationAssessmentV1) -> bytes:
    result = None
    try:
        if type(value) is not FragmentPublicationAssessmentV1:
            raise ValueError("exact assessment required")
        checked = FragmentPublicationAssessmentV1.model_validate(value.model_dump())
        payload = checked.model_dump(mode="json")
        profile = payload["review_claim"]["review_profile"]
        profile["route"]["capabilities"] = sorted(profile["route"]["capabilities"])
        raw = canonical_bytes(payload)
        if len(raw) > MAX_REVIEW_RECORD_BYTES:
            raise ValueError("bounded assessment required")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL review assessment unavailable")
    return result


def decode_fragment_publication_assessment(raw: bytes) -> FragmentPublicationAssessmentV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REVIEW_RECORD_BYTES:
            raise ValueError("bounded assessment required")
        value = FragmentPublicationAssessmentV1.model_validate_json(raw)
        if encode_fragment_publication_assessment(value) != raw:
            raise ValueError("canonical assessment required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL review assessment unavailable")
    return result


def _review_prefix(generation_id: UUID) -> str:
    return f"personal-history-fragment-publication-review-claim/{generation_id}/"


def _claim_namespace(value: FragmentPublicationReviewClaimV1) -> str:
    return _review_prefix(value.generation_id) + str(value.run_id)


def _assessment_prefix(generation_id: UUID) -> str:
    return f"personal-history-fragment-publication-assessment/{generation_id}/"


def _assessment_namespace(value: FragmentPublicationAssessmentV1) -> str:
    return _assessment_prefix(value.review_claim.generation_id) + str(
        value.evaluation.evaluation_id
    )



def _assert_publication_review_record_fit(
    publication: object, *, rubric_utf8: bytes = b"", template_utf8: bytes = b"",
) -> tuple[int, int]:
    """Conservative existing-schema record fit only, never canonical identities.

    Future Source IDs/digests below are distinct fixed-width sizing values. None
    is returned, stored, authorized or used as provenance. Actual canonical
    identities, complete prompt fit, rights and one-use checks remain mandatory.
    """
    from datetime import UTC, timedelta

    from zacai.intelligence.contextual_evaluation import ContextualAssessment, ContextualCriterion
    from zacai.intelligence.fragment_review_declaration import FragmentGenerationReviewDeclarationV2
    from zacai.intelligence.fragment_review_retention import _parts
    from zacai.intelligence.review_evaluation import ReviewJudgment

    if type(publication) is not FragmentGenerationReviewDeclarationV2:
        raise ValueError("exact prospective declaration required")
    _, consent, _ = _parts(publication)
    if len(consent.provenance) > 89:
        raise ValueError("full publication review provenance capacity exceeded")
    profile = publication.review
    if profile is None:
        return (0, 0)  # Historical comparison only, no review admission.
    occupied = {ref.source_id for ref in consent.provenance}
    def future_reference() -> EvidenceReference:
        value = 1
        while UUID(int=value) in occupied:
            value += 1
        sid = UUID(int=value)
        occupied.add(sid)
        return EvidenceReference(source_id=sid, content_hash="f" * 64,
            trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
    association, packet, declaration, admission, generation_claim = (
        future_reference() for _ in range(5)
    )
    at = (consent.approved_at + (consent.expires_at - consent.approved_at) / 2).astimezone(UTC)
    if at.microsecond == 0:
        at += timedelta(microseconds=1)
    maximum_float = 1.7976931348623157e308
    selected = tuple(sorted((*consent.provenance, association, packet, declaration,
        admission, generation_claim), key=lambda ref: str(ref.source_id)))
    claim = FragmentPublicationReviewClaimV1(
        generation_id=consent.id, run_id=profile.run_id, reviewer_id=profile.reviewer_id,
        attempt_id=UUID(int=1), task_id=consent.task_id, builder_id=consent.builder_id,
        association_reference=association, association_digest=association.content_hash,
        packet_reference=packet, publication_reference=declaration, publication_digest="f" * 64,
        admission_reference=admission, admission_digest=admission.content_hash,
        generation_claim_reference=generation_claim, generation_claim_digest=generation_claim.content_hash,
        review_profile=profile, review_profile_digest=fragment_review_profile_digest(profile),
        prepared_request_digest="f" * 64, prepared_body_digest="f" * 64, wire_body_digest="f" * 64,
        route_digest="f" * 64, runtime_profile_digest="f" * 64, authorization_graph_digest="f" * 64,
        model_metadata_digest="f" * 64, mechanical_descriptor_digest="f" * 64,
        original_deadline_monotonic=maximum_float,
        measured_input_tokens=profile.context_window_tokens - profile.max_output_tokens,
        requested_output_tokens=profile.max_output_tokens,
        original_session_binding=consent.original_session_binding,
        original_approved_at=consent.approved_at, expires_at=consent.expires_at,
        consumed_at=at, selected_references=selected,
    )
    claim_raw = encode_fragment_publication_review_claim(claim)
    judgments = tuple(ContextualAssessment(criterion=criterion, judgment=ReviewJudgment.UNREVIEWED)
        for criterion in ContextualCriterion)
    evaluation = ContextualEvaluation(format="zac-contextual-evaluation-v1",
        evaluation_id=profile.run_id, task_id=consent.task_id, reviewer_id=profile.reviewer_id,
        builder_id=consent.builder_id, evaluated_at=at, packet_digest=packet.content_hash,
        assessments=judgments)
    usage = UsageObservation(input_tokens=claim.measured_input_tokens,
        output_tokens=profile.max_output_tokens, latency_ms=maximum_float, cost_usd=maximum_float)
    own = future_reference().model_copy(update={"content_hash": content_hash_of(claim_raw)})
    assessment = FragmentPublicationAssessmentV1(evaluation=evaluation,
        review_claim_reference=own, review_claim=claim,
        released_judgments_digest=content_hash_of(canonical_bytes(FragmentReviewJudgments(
            format="zac-history-fragment-review-judgments-v1", assessments=judgments).model_dump(mode="json"))),
        released_usage_digest=content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
        usage=usage, captured_at=at)
    assessment_raw = encode_fragment_publication_assessment(assessment)
    if type(rubric_utf8) is not bytes or type(template_utf8) is not bytes:
        raise ValueError("exact optional declared review text bytes required")
    from zacai.intelligence.fragment_review_preparation import _text

    # The packet retains request_json as an exact JSON string. The actual
    # preparer includes that packet and this schema/rubric/template as distinct
    # values. This is a necessary lower bound, never a full prompt/token fit.
    minimum = len(canonical_bytes({"v": publication.generation_request_json})) - 6 + len(
        canonical_bytes(FragmentReviewJudgments.model_json_schema()))
    for raw in (rubric_utf8, template_utf8):
        if raw:
            minimum += len(canonical_bytes({"v": _text(raw)})) - 6
    if minimum > profile.max_input_bytes:
        raise ValueError("complete review known input exceeds declared byte capacity")
    # UTC future observations use six fractional digits, numeric widths are
    # maximal finite floats, and UNREVIEWED is the longest closed judgment enum.
    # Extra margin bounds JSON escapes/time formatting variation conservatively.
    if max(len(claim_raw), len(assessment_raw)) + 128 > MAX_REVIEW_RECORD_BYTES:
        raise ValueError("full publication review record byte capacity exceeded")
    return len(claim_raw) + 128, len(assessment_raw) + 128


def _selected(
    gate: CanonicalFragmentPublicationReviewAuthorization,
    *own: EvidenceReference,
) -> tuple[EvidenceReference, ...]:
    from zacai.intelligence.fragment_publication_generation import _union

    parent, output = gate._generation, gate._output
    references = (
        *_union(
            parent._admission,
            parent._admission_reference,
            parent._publication,
            parent._claim_reference,
        ),
        output.association.packet_reference,
        output.association_reference,
        *own,
    )
    mapping: dict[UUID, EvidenceReference] = {}
    for reference in references:
        if reference.source_id in mapping and mapping[reference.source_id] != reference:
            raise ValueError("conflicting exact Source references")
        mapping[reference.source_id] = reference
    result = tuple(sorted(mapping.values(), key=lambda r: str(r.source_id)))
    _closed_references(result)
    return result


def _review_current(
    session: Session,
    gate: CanonicalFragmentPublicationReviewAuthorization,
    *own: EvidenceReference,
    pending_claim_reference: EvidenceReference | None = None,
    pending_assessment_reference: EvidenceReference | None = None,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    gate._graph_check()
    parent, output = gate._generation, gate._output
    claim_reference = gate._claim_reference
    assessment_reference = gate._assessment_reference
    if pending_claim_reference is not None:
        if claim_reference is not None and claim_reference != pending_claim_reference:
            raise ValueError("one original child reviewer identity required")
        claim_reference = pending_claim_reference
    if pending_assessment_reference is not None:
        if (
            assessment_reference is not None
            and assessment_reference != pending_assessment_reference
        ):
            raise ValueError("one original assessment identity required")
        assessment_reference = pending_assessment_reference
    current_own = tuple(r for r in (claim_reference, assessment_reference) if r is not None)
    rows = _fragment_rows(session, _selected(gate, *own, *current_own), _BOUNDARIES, _LABELS)
    _fragment_profile_lineage(parent._request, rows)
    # Prefix membership is part of every fresh scalar union, not only the first
    # loader query. Referenced-row equality cannot detect an appended sibling.
    if _ids(session, _review_prefix(parent._consent.id), system=SourceSystem.MANUAL) != (
        () if claim_reference is None else (claim_reference.source_id,)
    ) or _ids(session, _assessment_prefix(parent._consent.id), system=SourceSystem.MANUAL) != (
        () if assessment_reference is None else (assessment_reference.source_id,)
    ):
        raise ValueError("exact original child/assessment namespace required")
    _association_rows(session, parent, output.association_reference, output.association)
    return rows


def _subject_row(
    rows: tuple[tuple[tuple[str, object], ...], ...],
    reference: EvidenceReference,
    namespace: str,
    captured_at: datetime,
) -> dict[str, object]:
    row = next(dict(r) for r in rows if dict(r)["id"] == reference.source_id)
    if (
        row["system"] is not SourceSystem.MANUAL
        or row["external_ref"] != namespace
        or row["trust_boundary"] is not B.PERSONAL
        or row["data_classification"] is not C.HIGHLY_RESTRICTED
        or row["captured_at"] != captured_at
        or row["supersedes_source_id"] is not None
        or row["lineage_id"] != reference.source_id
        or type(row["content_location"]) is not str
    ):
        raise ValueError("exact immutable review subject required")
    return row


def load_fragment_publication_review_claim(
    session: Session,
    *,
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    expected: FragmentPublicationReviewClaimV1,
) -> FragmentPublicationReviewClaimV1:
    result = None
    try:
        gate = authorization
        if type(gate) is not CanonicalFragmentPublicationReviewAuthorization:
            raise ValueError("exact original reviewer graph required")
        if gate._claim is None or expected != gate._claim:
            raise ValueError("actual owned child claim required")
        gate._claim_binding(expected)
        raw = encode_fragment_publication_review_claim(expected)
        if reference.content_hash != content_hash_of(raw):
            raise ValueError("exact own reviewer claim hash required")
        entry = _physical(session)
        rows = _review_current(session, gate, reference)
        if _ids(session, _review_prefix(expected.generation_id), system=SourceSystem.MANUAL) != (
            reference.source_id,
        ):
            raise ValueError("single original child reviewer claim required")
        row = _subject_row(rows, reference, _claim_namespace(expected), expected.consumed_at)
        parent, output = gate._generation, gate._output
        packet, association = load_fragment_publication_output_association(
            session,
            authorization=parent,
            reference=output.association_reference,
            expected=output.association,
        )
        _same(session, entry)
        if packet != output.retained.packet or association != output.association:
            raise ValueError("actual associated packet changed")
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("bounded location required")
        returned = parent._artifacts.get_bounded(
            B.PERSONAL, location, max_bytes=MAX_REVIEW_RECORD_BYTES
        )
        _same(session, entry)
        if (
            returned != raw
            or decode_fragment_publication_review_claim(returned) != expected
            or _review_current(session, gate, reference) != rows
        ):
            raise ValueError("whole reviewer union changed")
        _same(session, entry)
        result = expected
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL review claim unavailable")
    return result


def load_fragment_publication_assessment(
    session: Session,
    *,
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    expected: FragmentPublicationAssessmentV1,
) -> FragmentPublicationAssessmentV1:
    result = None
    try:
        gate = authorization
        if type(gate) is not CanonicalFragmentPublicationReviewAuthorization:
            raise ValueError("exact original reviewer graph required")
        if gate._assessment is None or expected != gate._assessment:
            raise ValueError("actual owned assessment required")
        gate._claim_binding(expected.review_claim)
        raw = encode_fragment_publication_assessment(expected)
        if reference.content_hash != content_hash_of(raw):
            raise ValueError("exact own assessment hash required")
        entry = _physical(session)
        rows = _review_current(session, gate, expected.review_claim_reference, reference)
        if _ids(
            session,
            _assessment_prefix(expected.review_claim.generation_id),
            system=SourceSystem.MANUAL,
        ) != (reference.source_id,):
            raise ValueError("single original assessment required")
        row = _subject_row(rows, reference, _assessment_namespace(expected), expected.captured_at)
        load_fragment_publication_review_claim(
            session,
            authorization=gate,
            reference=expected.review_claim_reference,
            expected=expected.review_claim,
        )
        _same(session, entry)
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("bounded location required")
        returned = gate._generation._artifacts.get_bounded(
            B.PERSONAL,
            location,
            max_bytes=MAX_REVIEW_RECORD_BYTES,
        )
        _same(session, entry)
        if (
            returned != raw
            or decode_fragment_publication_assessment(returned) != expected
            or _review_current(session, gate, expected.review_claim_reference, reference) != rows
        ):
            raise ValueError("assessment current union changed")
        _same(session, entry)
        result = expected
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL review assessment unavailable")
    return result


class PersonalFragmentPublicationReviewReceiptV1(Contract):
    """Closed full-purpose bytes recovery observation; no human/claim authority."""

    format: Literal["zac-personal-fragment-publication-review-recovery-v1"] = (
        "zac-personal-fragment-publication-review-recovery-v1"
    )
    kind: Literal["CLAIM", "ASSESSMENT"]
    subject_reference: EvidenceReference
    subject_digest: Digest
    association_reference: EvidenceReference
    packet_reference: EvidenceReference
    reviewer_id: UUID
    run_id: UUID
    authorization_graph_digest: Digest
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
        return (
            f"PERSONAL/state/history-fragment-publication-review-{self.subject_reference.source_id}"
        )

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

    @model_validator(mode="after")
    def exact_review_subject(self) -> Self:
        if (
            any(v.int == 0 for v in (self.reviewer_id, self.run_id))
            or self.reviewer_id == self.builder_id
            or self.subject_reference not in self.selected_references
            or self.association_reference not in self.selected_references
            or self.packet_reference not in self.selected_references
            or self.subject_reference.content_hash != self.subject_digest
            or (self.kind == "CLAIM" and self.subject_reference != self.claim_reference)
            or (self.kind == "ASSESSMENT" and self.subject_reference == self.claim_reference)
            or self.review_profile_digest is None
        ):
            raise ValueError("exact own review checkpoint required")
        return self


def encode_publication_review_receipt(value: PersonalFragmentPublicationReviewReceiptV1) -> bytes:
    result = None
    try:
        if type(value) is not PersonalFragmentPublicationReviewReceiptV1:
            raise ValueError("exact review receipt required")
        checked = PersonalFragmentPublicationReviewReceiptV1.model_validate(value.model_dump())
        raw = canonical_bytes(checked.model_dump(mode="json"))
        if len(raw) > 2_000_000:
            raise ValueError("bounded review receipt required")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return result


def decode_publication_review_receipt(raw: bytes) -> PersonalFragmentPublicationReviewReceiptV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
            raise ValueError("bounded review receipt required")
        value = PersonalFragmentPublicationReviewReceiptV1.model_validate_json(raw)
        if encode_publication_review_receipt(value) != raw:
            raise ValueError("canonical review receipt required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return result


class CanonicalFragmentPublicationReviewAuthorization:
    """Concrete child of the actual successful full-purpose output producer.

    This source-only join is not mounted into an owner/private host. Construction
    and preflight issue no capability. The canonical child claim burns before any
    protection or model POST; a failed first attempt is never retried/repaired.
    """

    def __init__(
        self,
        *,
        generation_authorization: CanonicalPersonalFragmentPublicationAuthorization,
        associated_output: PersonalFragmentAssociatedOutput,
        rubric_utf8: bytes,
        template_utf8: bytes,
    ) -> None:
        failed = False
        try:
            parent = generation_authorization
            if (
                type(parent) is not CanonicalPersonalFragmentPublicationAuthorization
                or type(associated_output) is not PersonalFragmentAssociatedOutput
                or parent._phase != "OUTPUT_RETAINED"
                or parent._associated_result is not associated_output
                or parent._publication.review is None
                or parent._publication.review_profile_digest is None
                or parent._released is None
                or parent._claim is None
                or parent._claim_reference is None
                or parent._runtime is None
                or type(rubric_utf8) is not bytes
                or type(template_utf8) is not bytes
            ):
                raise ValueError("actual full-purpose successful producer required")
            parent._graph_check()
            profile = parent._publication.review
            if (
                content_hash_of(rubric_utf8) != profile.rubric_digest
                or content_hash_of(template_utf8) != profile.template_digest
                or profile.reviewer_id == parent._consent.builder_id
                or profile.context_window_tokens != 16384
            ):
                raise ValueError("exact declared independent review purpose required")
            self._generation, self._output, self._profile = parent, associated_output, profile
            self._rubric, self._template = rubric_utf8, template_utf8
            self._original_graph = (
                parent,
                associated_output,
                profile,
                parent._runtime,
                parent._request,
                parent._operation,
                parent._clock,
                parent._protector,
                parent._factory,
                parent._artifacts,
                parent._released,
                parent._claim,
                parent._claim_reference,
            )
            self._authorization_graph_digest = fragment_publication_review_graph_digest()
            self._runtime: _LocalFragmentReviewRuntime | None = None
            self._prepared: PreparedFragmentReviewRequest | None = None
            self._packet_raw: bytes | None = None
            self._deadline_monotonic: float | None = None
            self._claim: FragmentPublicationReviewClaimV1 | None = None
            self._claim_reference: EvidenceReference | None = None
            self._receipt: PersonalFragmentPublicationReviewReceiptV1 | None = None
            self._mechanical: FragmentReviewDispatchDescriptor | None = None
            self._released: AuthenticatedFragmentReviewDispatchDescriptor | None = None
            self._observed_result: _MechanicalReviewResult | None = None
            self._assessment: FragmentPublicationAssessmentV1 | None = None
            self._assessment_reference: EvidenceReference | None = None
            self._invoked = False
            self._phase = "UNUSED"
            self._lock = RLock()
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise FragmentPublicationReviewError("PERSONAL full-purpose review graph unavailable")

    def _graph_check(self) -> None:
        parent = self._generation
        parent._graph_check()
        actual = (
            parent,
            self._output,
            self._profile,
            parent._runtime,
            parent._request,
            parent._operation,
            parent._clock,
            parent._protector,
            parent._factory,
            parent._artifacts,
            parent._released,
            parent._claim,
            parent._claim_reference,
        )
        if (
            any(a is not b for a, b in zip(actual, self._original_graph, strict=True))
            or parent._phase != "OUTPUT_RETAINED"
            or parent._associated_result is not self._output
            or parent._publication.review is not self._profile
            or fragment_review_profile_digest(self._profile)
            != parent._publication.review_profile_digest
            or content_hash_of(self._rubric) != self._profile.rubric_digest
            or content_hash_of(self._template) != self._profile.template_digest
            or fragment_publication_review_graph_digest() != self._authorization_graph_digest
        ):
            raise ValueError("actual original reviewer graph changed")

    def _require_phase(self, expected: str) -> None:
        if self._phase != expected:
            raise ValueError("original reviewer phase changed")

    def prepare_review(self) -> PreparedFragmentReviewRequest:
        """Canonical whole output and original profile, no permission from fit."""
        result = None
        cleanup_uncertain = False
        with self._lock:
            if self._phase != "UNUSED":
                if self._phase == "PREPARING":
                    self._phase = "HELD"
                raise FragmentPublicationReviewError("PERSONAL review preparation consumed")
            self._phase = "PREPARING"
            try:
                from zacai.intelligence import fragment_review_preparation as preparation
                from zacai.intelligence import fragment_review_runtime as engine
                from zacai.intelligence import fragment_review_wire as wire

                self._graph_check()
                parent, output, profile = self._generation, self._output, self._profile
                # First interval never resets, including all preparation overhead.
                started = engine._AUTHENTICATED_MONOTONIC()
                observed = parent._clock()
                self._deadline_monotonic = started + min(
                    profile.max_latency_ms / 1000,
                    (parent._consent.expires_at - observed).total_seconds(),
                )
                parent._owner()
                packet, plan = _reopen_publication_output(
                    parent,
                    output.retained.source_id,
                    output.retained.packet_digest,
                    output.association_reference,
                    output.association,
                )
                receipt = parent._protector.recheck(
                    source_id=output.retained.source_id,
                    expected_digest=output.retained.packet_digest,
                    expected_request=parent._request,
                )
                if receipt != output.retained.recovery_receipt:
                    raise ValueError("original successful output checkpoint changed")
                _terminal_publication_output(
                    parent,
                    receipt,
                    packet,
                    output.retained.source_id,
                    output.retained.packet_digest,
                    plan,
                    output.association_reference,
                    output.association,
                )
                packet_raw = encode_history_fragment_contextual_packet(
                    packet.review,
                    packet.request(),
                    builder_id=packet.builder_id,
                    created_at=packet.created_at,
                )
                if (
                    content_hash_of(packet_raw) != output.retained.packet_digest
                    or content_hash_of(Path(preparation.__file__).read_bytes())
                    != profile.body_derivation_digest
                    or content_hash_of(Path(wire.__file__).read_bytes())
                    != profile.reviewer_wire_digest
                ):
                    raise ValueError("exact declared packet/derivation required")
                prepared = prepare_fragment_review_request(
                    packet_raw,
                    expected_packet_digest=output.retained.packet_digest,
                    expected_task_id=parent._consent.task_id,
                    expected_builder_id=parent._consent.builder_id,
                    reviewer_id=profile.reviewer_id,
                    run_id=profile.run_id,
                    route=profile.route,
                    max_output_tokens=profile.max_output_tokens,
                    max_latency_ms=profile.max_latency_ms,
                    rubric_utf8=self._rubric,
                    template_utf8=self._template,
                    expected_rubric_digest=profile.rubric_digest,
                    expected_template_digest=profile.template_digest,
                    model_digest=profile.model_digest,
                    reviewer_wire_digest=profile.reviewer_wire_digest,
                )
                self._graph_check()
                if engine._AUTHENTICATED_MONOTONIC() >= self._deadline_monotonic:
                    raise ValueError("original reviewer interval exhausted")
                self._require_phase("PREPARING")
                self._packet_raw, self._prepared = packet_raw, prepared
                self._phase = "PREPARED"
                result = prepared
            except PersonalFragmentCleanupUncertain:
                cleanup_uncertain = True
            except Exception:  # noqa: BLE001,S110
                pass
            finally:
                if result is None:
                    self._phase = "HELD"
        if result is None:
            if cleanup_uncertain:
                raise PersonalFragmentCleanupUncertain(
                    "PERSONAL review cleanup uncertain; operator review required"
                )
            raise FragmentPublicationReviewError("PERSONAL review preparation unavailable")
        return result

    def bind_review_runtime(self, runtime: _LocalFragmentReviewRuntime) -> None:
        from zacai.intelligence.fragment_review_runtime import (
            _AUTHENTICATED_MONOTONIC,
            _LocalFragmentReviewRuntime,
        )

        failed = False
        with self._lock:
            try:
                self._graph_check()
                profile = self._profile
                if (
                    type(runtime) is not _LocalFragmentReviewRuntime
                    or self._runtime is not None
                    or self._phase != "PREPARED"
                    or runtime._clock is not _AUTHENTICATED_MONOTONIC
                    or runtime._attempted
                    or runtime._prepared is not None
                    or runtime.profile.implementation_digest != profile.runtime_digest
                    or runtime.profile.model_digest != profile.model_digest
                    or runtime.profile.tokenizer_digest != profile.tokenizer_digest
                    or runtime.profile.renderer_digest != profile.renderer_digest
                ):
                    raise ValueError("exact unused declared reviewer runtime required")
                # Literal instruction template hash is separately checked above.
                # Backend counter template is a different, concrete profile pin.
                self._runtime = runtime
            except Exception:  # noqa: BLE001
                failed = True
            if failed:
                self._phase = "HELD"
        if failed:
            raise FragmentPublicationReviewError("PERSONAL reviewer runtime binding unavailable")

    def _descriptor(
        self,
        prepared: PreparedFragmentReviewRequest,
        descriptor: AuthenticatedFragmentReviewDispatchDescriptor,
    ) -> None:
        from zacai.intelligence.fragment_review_runtime import (
            _AUTHENTICATED_MONOTONIC,
            AuthenticatedFragmentReviewDispatchDescriptor,
        )

        self._graph_check()
        runtime, packet_raw = self._runtime, self._packet_raw
        if (
            runtime is None
            or packet_raw is None
            or prepared is not self._prepared
            or type(descriptor) is not AuthenticatedFragmentReviewDispatchDescriptor
            or runtime._clock is not _AUTHENTICATED_MONOTONIC
            or runtime._prepared is None
            or descriptor.phase not in {"PRE_DISPATCH", "RELEASE"}
            or descriptor.run_id != self._profile.run_id
            or descriptor.attempt_id != runtime._authenticated_attempt_id
            or descriptor.authorization_graph_digest != self._authorization_graph_digest
            or descriptor.mechanical != runtime._prepared
            or descriptor.mechanical.deadline_monotonic != self._deadline_monotonic
        ):
            raise ValueError("exact original authenticated dispatch descriptor required")
        verify_fragment_review_request(
            prepared, packet_raw=packet_raw, rubric_utf8=self._rubric, template_utf8=self._template
        )
        body, mechanical = runtime._describe(
            prepared,
            packet_raw=packet_raw,
            rubric_utf8=self._rubric,
            template_utf8=self._template,
            count=descriptor.mechanical.measured_input_tokens,
            deadline=descriptor.mechanical.deadline_monotonic,
            metadata_digest=descriptor.mechanical.model_metadata_digest,
        )
        if (
            body != descriptor.body
            or mechanical != descriptor.mechanical
            or (
                descriptor.phase == "PRE_DISPATCH"
                and (descriptor.judgments_digest is not None or descriptor.usage_digest is not None)
            )
            or (
                descriptor.phase == "RELEASE"
                and (descriptor.judgments_digest is None or descriptor.usage_digest is None)
            )
        ):
            raise ValueError("exact phase/body/pins/count required")

    def _claim_binding(self, claim: FragmentPublicationReviewClaimV1) -> None:
        parent, output, profile = self._generation, self._output, self._profile
        prepared = self._prepared
        if prepared is None or parent._claim_reference is None:
            raise ValueError("exact original prepared review required")
        association = output.association
        expected = {
            "generation_id": parent._consent.id,
            "run_id": profile.run_id,
            "reviewer_id": profile.reviewer_id,
            "task_id": prepared.task_id,
            "builder_id": prepared.builder_id,
            "association_reference": output.association_reference,
            "association_digest": output.association_reference.content_hash,
            "packet_reference": association.packet_reference,
            "publication_reference": association.publication_reference,
            "publication_digest": fragment_generation_review_declaration_digest(
                parent._publication
            ),
            "admission_reference": association.admission_reference,
            "admission_digest": association.admission_digest,
            "generation_claim_reference": association.claim_reference,
            "generation_claim_digest": association.claim_digest,
            "review_profile": profile,
            "review_profile_digest": fragment_review_profile_digest(profile),
            "prepared_request_digest": prepared.request_digest,
            "prepared_body_digest": prepared.body_digest,
            "authorization_graph_digest": self._authorization_graph_digest,
            "original_session_binding": parent._consent.original_session_binding,
            "original_approved_at": parent._consent.approved_at,
            "expires_at": parent._consent.expires_at,
            "selected_references": _selected(self),
        }
        checked = FragmentPublicationReviewClaimV1.model_validate(claim.model_dump())
        if any(getattr(checked, k) != v for k, v in expected.items()):
            raise ValueError("exact original child claim relation required")
        if self._mechanical is not None and (
            checked.mechanical_descriptor_digest
            != content_hash_of(canonical_bytes(asdict(self._mechanical)))
            or checked.original_deadline_monotonic != self._deadline_monotonic
        ):
            raise ValueError("original mechanical/deadline observation changed")
        if self._claim is not None and checked != self._claim:
            raise ValueError("original burned child claim changed")

    def _burn(
        self,
        descriptor: AuthenticatedFragmentReviewDispatchDescriptor,
    ) -> tuple[FragmentPublicationReviewClaimV1, EvidenceReference]:
        from zacai.review_authorization import _lock
        from zacai.state_repository import record_source

        parent, output = self._generation, self._output
        prepared = self._prepared
        if prepared is None:
            raise ValueError("original prepared review required")
        with parent._factory() as session:
            session.begin()
            _lock(session, parent._consent.id)
            entry = _physical(session)
            if _ids(session, _review_prefix(parent._consent.id), system=SourceSystem.MANUAL):
                raise ValueError("original review already consumed")
            from zacai.backup_artifacts import _assert_personal_custody_append_capacity

            _assert_personal_custody_append_capacity(session, 3)
            before = _review_current(session, self)
            packet, association = load_fragment_publication_output_association(
                session,
                authorization=parent,
                reference=output.association_reference,
                expected=output.association,
            )
            _same(session, entry)
            if packet != output.retained.packet or association != output.association:
                raise ValueError("actual output origin changed")
            consumed = parent._clock()
            if not parent._consent.approved_at <= consumed < parent._consent.expires_at:
                raise ValueError("original processing expiry")
            m = descriptor.mechanical
            claim = FragmentPublicationReviewClaimV1(
                generation_id=parent._consent.id,
                run_id=self._profile.run_id,
                reviewer_id=self._profile.reviewer_id,
                attempt_id=descriptor.attempt_id,
                task_id=prepared.task_id,
                builder_id=prepared.builder_id,
                association_reference=output.association_reference,
                association_digest=output.association_reference.content_hash,
                packet_reference=association.packet_reference,
                publication_reference=association.publication_reference,
                publication_digest=association.publication_digest,
                admission_reference=association.admission_reference,
                admission_digest=association.admission_digest,
                generation_claim_reference=association.claim_reference,
                generation_claim_digest=association.claim_digest,
                review_profile=self._profile,
                review_profile_digest=fragment_review_profile_digest(self._profile),
                prepared_request_digest=prepared.request_digest,
                prepared_body_digest=prepared.body_digest,
                wire_body_digest=m.body_digest,
                route_digest=m.route_digest,
                runtime_profile_digest=content_hash_of(canonical_bytes(asdict(m.profile))),
                authorization_graph_digest=self._authorization_graph_digest,
                model_metadata_digest=m.model_metadata_digest,
                mechanical_descriptor_digest=content_hash_of(canonical_bytes(asdict(m))),
                original_deadline_monotonic=m.deadline_monotonic,
                measured_input_tokens=m.measured_input_tokens,
                requested_output_tokens=m.requested_output_tokens,
                original_session_binding=parent._consent.original_session_binding,
                original_approved_at=parent._consent.approved_at,
                expires_at=parent._consent.expires_at,
                consumed_at=consumed,
                selected_references=_selected(self),
            )
            self._claim_binding(claim)
            raw = encode_fragment_publication_review_claim(claim)
            location = parent._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            _same(session, entry)
            returned = parent._artifacts.get_bounded(
                B.PERSONAL, location, max_bytes=MAX_REVIEW_RECORD_BYTES
            )
            _same(session, entry)
            self._descriptor(prepared, descriptor)
            if returned != raw or _review_current(session, self) != before:
                raise ValueError("review burn input changed")
            if not consumed <= parent._clock() < parent._consent.expires_at:
                raise ValueError("original review expiry before commit")
            self._require_phase("ENTERED")
            _assert_personal_custody_append_capacity(session, 3)
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
                raise ValueError("one child burn required")
            reference = EvidenceReference(
                source_id=source.id,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            _review_current(session, self, reference, pending_claim_reference=reference)
            _same(session, entry)
            _assert_personal_custody_append_capacity(session, 2)
            _same(session, entry)
            self._require_phase("ENTERED")
            from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

            if (self._deadline_monotonic is None
                or _AUTHENTICATED_MONOTONIC() >= self._deadline_monotonic):
                raise ValueError("original reviewer interval exhausted before burn commit")
            session.commit()
        return claim, reference

    def _reopen(self) -> None:
        if self._claim is None or self._claim_reference is None:
            raise ValueError("committed child burn required")
        with self._generation._factory() as session:
            session.begin()
            load_fragment_publication_review_claim(
                session,
                authorization=self,
                reference=self._claim_reference,
                expected=self._claim,
            )
        self._generation._owner()

    def _terminal(
        self,
        receipt: PersonalFragmentPublicationReviewReceiptV1,
        subject: EvidenceReference,
        kind: Literal["CLAIM", "ASSESSMENT"],
    ) -> None:
        from zacai.review_authorization import _lock

        parent, runtime = self._generation, self._runtime
        if runtime is None or self._claim_reference is None:
            raise ValueError("concrete runtime/committed claim required")
        if (
            content_hash_of(parent._protector._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest
        ):
            raise ValueError("actual live review journal changed")
        self._graph_check()
        if kind == "CLAIM":
            runtime._observe_authenticated_clock()
        else:
            from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

            if (
                self._deadline_monotonic is None
                or _AUTHENTICATED_MONOTONIC() >= self._deadline_monotonic
            ):
                raise ValueError("original reviewer interval exhausted")
        parent._owner()  # Original signed owner after all callable observations.
        with parent._factory() as session:
            session.begin()
            _lock(session, parent._consent.id)
            entry = _physical(session)
            if any(
                getattr(receipt, k) != v for k, v in _receipt_binding(self, subject, kind).items()
            ):
                raise ValueError("exact own reviewer receipt required")
            plan = prepare_personal_encrypted_custody_backup_plan(session)
            _same(session, entry)
            rows = json.loads(plan.rows)
            hashes = tuple(
                sorted(((UUID(r["id"]), r["content_hash"]) for r in rows), key=lambda x: str(x[0]))
            )
            fingerprints = tuple(
                sorted(
                    ((UUID(r["id"]), content_hash_of(canonical_bytes(r))) for r in rows),
                    key=lambda x: str(x[0]),
                )
            )
            if (
                content_hash_of(plan.rows) != receipt.full_plan_digest
                or hashes != receipt.full_boundary_source_hashes
                or fingerprints != receipt.full_boundary_source_fingerprints
            ):
                raise ValueError("complete current reviewer checkpoint changed")
            _review_current(session, self, self._claim_reference, subject)
            _same(session, entry)
        from zacai.intelligence.fragment_review_runtime import _AUTHENTICATED_MONOTONIC

        if self._deadline_monotonic is None or _AUTHENTICATED_MONOTONIC() >= self._deadline_monotonic:
            raise ValueError("original reviewer interval exhausted")
        # No owner/counter/model callbacks after this terminal canonical query.

    def recheck_review_dispatch(
        self,
        prepared: PreparedFragmentReviewRequest,
        descriptor: AuthenticatedFragmentReviewDispatchDescriptor,
    ) -> None:
        succeeded = False
        uncertain = False
        with self._lock:
            if self._phase in {"ENTERED", "RELEASING", "CAPTURING"}:
                self._phase = "HELD"
                raise FragmentPublicationReviewError("PERSONAL review attempt consumed")
            try:
                self._descriptor(prepared, descriptor)
                parent, output = self._generation, self._output
                if descriptor.phase == "PRE_DISPATCH":
                    self._require_phase("PREPARED")
                    self._phase = "ENTERED"
                    parent._owner()
                    packet, plan = _reopen_publication_output(
                        parent,
                        output.retained.source_id,
                        output.retained.packet_digest,
                        output.association_reference,
                        output.association,
                    )
                    original = parent._protector.recheck(
                        source_id=output.retained.source_id,
                        expected_digest=output.retained.packet_digest,
                        expected_request=parent._request,
                    )
                    if original != output.retained.recovery_receipt:
                        raise ValueError("original output checkpoint changed")
                    _terminal_publication_output(
                        parent,
                        original,
                        packet,
                        output.retained.source_id,
                        output.retained.packet_digest,
                        plan,
                        output.association_reference,
                        output.association,
                    )
                    self._descriptor(prepared, descriptor)
                    self._require_phase("ENTERED")
                    self._mechanical = descriptor.mechanical
                    self._claim, self._claim_reference = self._burn(descriptor)
                    self._reopen()
                    self._receipt = protect_publication_review_claim(
                        parent._protector,
                        authorization=self,
                        reference=self._claim_reference,
                        expected_claim=self._claim,
                    )
                    self._descriptor(prepared, descriptor)
                    self._terminal(self._receipt, self._claim_reference, "CLAIM")
                    self._require_phase("ENTERED")
                    self._phase = "DISPATCHED"
                else:
                    self._require_phase("DISPATCHED")
                    if self._claim is None or self._claim_reference is None:
                        raise ValueError("committed original child required")
                    self._phase = "RELEASING"
                    parent._owner()
                    receipt = recheck_publication_review_claim(
                        parent._protector,
                        authorization=self,
                        reference=self._claim_reference,
                        expected_claim=self._claim,
                    )
                    if receipt != self._receipt:
                        raise ValueError("original child checkpoint changed")
                    self._descriptor(prepared, descriptor)
                    self._terminal(receipt, self._claim_reference, "CLAIM")
                    self._require_phase("RELEASING")
                    self._released = descriptor
                    self._phase = "RELEASED"
                succeeded = True
            except PersonalFragmentCleanupUncertain:
                uncertain = True
            except Exception:  # noqa: BLE001,S110
                pass
            finally:
                if not succeeded:
                    self._phase = "HELD"
                    self._observed_result = None
        if not succeeded:
            if uncertain:
                raise PersonalFragmentCleanupUncertain(
                    "PERSONAL reviewer cleanup uncertain; operator review required"
                )
            raise FragmentPublicationReviewError("PERSONAL review attempt unavailable or consumed")


def _receipt_binding(
    gate: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    kind: Literal["CLAIM", "ASSESSMENT"],
) -> dict[str, object]:
    parent, output, claim = gate._generation, gate._output, gate._claim
    if claim is None or gate._claim_reference is None:
        raise ValueError("original consumed child required")
    consent = parent._consent
    return {
        "kind": kind,
        "subject_reference": reference,
        "subject_digest": reference.content_hash,
        "association_reference": output.association_reference,
        "packet_reference": output.association.packet_reference,
        "reviewer_id": claim.reviewer_id,
        "run_id": claim.run_id,
        "authorization_graph_digest": gate._authorization_graph_digest,
        "claim_reference": gate._claim_reference,
        "claim_digest": gate._claim_reference.content_hash,
        "attempt_id": claim.attempt_id,
        "consumed_at": claim.consumed_at,
        "admission_reference": parent._admission_reference,
        "admission_digest": parent._admission_reference.content_hash,
        "observed_action_at": parent._admission.observed_action_at,
        "publication_reference": parent._admission.publication_reference,
        "publication_digest": fragment_generation_review_declaration_digest(parent._publication),
        "request_digest": consent.request_digest,
        "review_profile_digest": parent._publication.review_profile_digest,
        "selected_references": _selected(gate, gate._claim_reference, reference),
        "task_id": consent.task_id,
        "builder_id": consent.builder_id,
        "original_observed_at": parent._request.observed_at,
        "declared_window_started_at": parent._publication.approved_at,
        "expires_at": parent._publication.expires_at,
        "original_session_binding": consent.original_session_binding,
        "original_session_issued_at": consent.original_session_issued_at,
        "original_session_expires_at": consent.original_session_expires_at,
    }


def _review_subject_load(
    session: Session,
    gate: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    kind: Literal["CLAIM", "ASSESSMENT"],
) -> None:
    if kind == "CLAIM":
        if gate._claim is None or reference != gate._claim_reference:
            raise ValueError("exact own committed review claim required")
        load_fragment_publication_review_claim(
            session,
            authorization=gate,
            reference=reference,
            expected=gate._claim,
        )
    else:
        if gate._assessment is None or reference != gate._assessment_reference:
            raise ValueError("exact own committed assessment required")
        load_fragment_publication_assessment(
            session,
            authorization=gate,
            reference=reference,
            expected=gate._assessment,
        )


def _review_checkpoint(
    protector: PersonalHistoryFragmentProtector,
    gate: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    kind: Literal["CLAIM", "ASSESSMENT"],
    read_existing: bool,
) -> PersonalFragmentPublicationReviewReceiptV1:
    from zacai.backup_artifacts import run_artifact_backup
    from zacai.claude_local_protection import _crypt, _read, _recover
    from zacai.review_protection import ReviewProtectionCleanupUncertain
    from zacai.state import ArtifactBackupRunStatus

    result = None
    uncertain = False
    try:
        if (
            type(protector) is not PersonalHistoryFragmentProtector
            or type(gate) is not CanonicalFragmentPublicationReviewAuthorization
            or protector is not gate._generation._protector
            or type(reference) is not EvidenceReference
        ):
            raise ValueError("actual exact original protection graph required")
        gate._graph_check()
        parent, claim_reference = gate._generation, gate._claim_reference
        if claim_reference is None:
            raise ValueError("committed review claim required")
        binding = _receipt_binding(gate, reference, kind)
        key = (
            f"PERSONAL/state/history-fragment-publication-review-{reference.source_id}/"
            f"receipt-{reference.content_hash}.age"
        )
        with protector._lock:
            access = protector._authority_access(parent._consent)
            plan = protector._plan()
            rows = json.loads(plan.rows)
            expected = {UUID(row["id"]): row["content_hash"] for row in rows}
            selected = _selected(gate, claim_reference, reference)
            if any(expected.get(r.source_id) != r.content_hash for r in selected):
                raise ValueError("whole plan missing own subject before any body")
            with parent._factory() as session:
                session.begin()
                _review_subject_load(session, gate, reference, kind)
            protector._authority_access(parent._consent, access)
            if protector._plan() != plan:
                raise ValueError("whole reviewer plan changed during load")
            complete = {
                **binding,
                "full_plan_digest": content_hash_of(plan.rows),
                "full_boundary_source_hashes": tuple(
                    sorted(expected.items(), key=lambda p: str(p[0]))
                ),
                "full_boundary_source_fingerprints": tuple(
                    sorted(
                        ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                        key=lambda p: str(p[0]),
                    )
                ),
            }
            if read_existing:
                cipher = _read(protector._reader, key, 2_100_000)
                protector._authority_access(parent._consent, access)
                raw = _recover(cipher, protector._identity, 2_000_000)
                protector._authority_access(parent._consent, access)
                receipt = decode_publication_review_receipt(raw)
                receipt_cipher_digest = content_hash_of(cipher)
            else:
                if protector._reader.exists(key) is not False:
                    raise ValueError("own checkpoint never overwritten")
                protector._authority_access(parent._consent, access)
                completed = run_artifact_backup(
                    parent._factory,
                    trust_boundary=B.PERSONAL,
                    artifact_store=parent._artifacts,
                    backup_store=protector._writer,
                    recipient=protector._recipient,
                    local_manifest_cache_path=protector._cache,
                    personal_plan=plan,
                )
                protector._authority_access(parent._consent, access)
                if (
                    completed.status is not ArtifactBackupRunStatus.SUCCEEDED
                    or protector._plan() != plan
                ):
                    raise ValueError("whole reviewer artifact backup incomplete")
                snapshot, journal = protector._snapshot(expected, completed.id)
                protector._authority_access(parent._consent, access)
                objects = []
                prefix = key.rsplit("/", 1)[0]
                for name, raw, maximum in (
                    ("state", snapshot, 64_000_000),
                    ("journal", journal, 4_000_000),
                ):
                    cipher = _crypt(raw, protector._recipient, maximum)
                    protector._authority_access(parent._consent, access)
                    digest = content_hash_of(cipher)
                    protector._writer.put_object(f"{prefix}/{name}-{digest}.age", cipher)
                    protector._authority_access(parent._consent, access)
                    objects.append((digest, content_hash_of(raw)))
                receipt = PersonalFragmentPublicationReviewReceiptV1.model_validate(
                    {
                        **complete,
                        "verified_at": protector._clock(),
                        "artifact_backup_run_id": completed.id,
                        "live_journal_digest": content_hash_of(protector._run_row(completed.id)),
                        "state_ciphertext_hash": objects[0][0],
                        "state_plaintext_hash": objects[0][1],
                        "journal_ciphertext_hash": objects[1][0],
                        "journal_plaintext_hash": objects[1][1],
                    }
                )
            if (
                any(getattr(receipt, n) != v for n, v in complete.items())
                or not parent._consent.approved_at
                <= receipt.verified_at
                < parent._consent.expires_at
                or receipt.verified_at > protector._clock()
            ):
                raise ValueError("original exact reviewer recovery observation required")
            observations = list(protector._artifacts_recover(plan, access))
            protector._authority_access(parent._consent, access)
            recovered = []
            for location, cipher_digest, plain_digest, maximum in (
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
                raw = _read(protector._reader, location, maximum + 1_000_000)
                protector._authority_access(parent._consent, access)
                if content_hash_of(raw) != cipher_digest:
                    raise ValueError("reviewer snapshot ciphertext changed")
                observations.append((location, cipher_digest, maximum + 1_000_000))
                restored = _recover(raw, protector._identity, maximum)
                protector._authority_access(parent._consent, access)
                if content_hash_of(restored) != plain_digest:
                    raise ValueError("reviewer snapshot plaintext changed")
                recovered.append(restored)
            protector._restoration.verify_personal(
                recovered[0],
                expected,
                current_selected_sources=protector._engine,
                operational_journal=recovered[1],
            )
            protector._authority_access(parent._consent, access)
            if (
                protector._plan() != plan
                or content_hash_of(protector._run_row(receipt.artifact_backup_run_id))
                != receipt.live_journal_digest
            ):
                raise ValueError("reviewer full plan/live journal changed")
            protector._reobserve_objects(tuple(observations), access)
            protector._authority_access(parent._consent, access)
            if not read_existing:
                receipt = PersonalFragmentPublicationReviewReceiptV1.model_validate(
                    {
                        **receipt.model_dump(),
                        "verified_at": protector._clock(),
                    }
                )
                cipher = _crypt(
                    encode_publication_review_receipt(receipt), protector._recipient, 2_000_000
                )
                protector._authority_access(parent._consent, access)
                if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                    raise ValueError("bounded complete receipt ciphertext required")
                protector._writer.put_object(key, cipher)
                protector._authority_access(parent._consent, access)
                returned = _read(protector._reader, key, 2_100_000)
                protector._authority_access(parent._consent, access)
                plain = _recover(returned, protector._identity, 2_000_000)
                protector._authority_access(parent._consent, access)
                if returned != cipher or decode_publication_review_receipt(plain) != receipt:
                    raise ValueError("reviewer receipt readback differs")
                receipt_cipher_digest = content_hash_of(returned)
            protector._reobserve_objects(
                (*observations, (key, receipt_cipher_digest, 2_100_000)), access
            )
            protector._authority_access(parent._consent, access)
            if (
                protector._plan() != plan
                or content_hash_of(protector._run_row(receipt.artifact_backup_run_id))
                != receipt.live_journal_digest
            ):
                raise ValueError("terminal full reviewer plan/journal changed")
            with parent._factory() as session:
                session.begin()
                entry = _physical(session)
                _review_current(session, gate, claim_reference, reference)
                _same(session, entry)
            result = receipt
    except ReviewProtectionCleanupUncertain:
        uncertain = True
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        if uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL reviewer cleanup uncertain; operator review required"
            )
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return result


def protect_publication_review_claim(
    protector: PersonalHistoryFragmentProtector,
    *,
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    expected_claim: FragmentPublicationReviewClaimV1,
) -> PersonalFragmentPublicationReviewReceiptV1:
    if type(authorization) is not CanonicalFragmentPublicationReviewAuthorization:
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    if (
        type(expected_claim) is not FragmentPublicationReviewClaimV1
        or expected_claim != authorization._claim
        or reference != authorization._claim_reference
    ):
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return _review_checkpoint(protector, authorization, reference, "CLAIM", False)


def recheck_publication_review_claim(
    protector: PersonalHistoryFragmentProtector,
    *,
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    expected_claim: FragmentPublicationReviewClaimV1,
) -> PersonalFragmentPublicationReviewReceiptV1:
    if type(authorization) is not CanonicalFragmentPublicationReviewAuthorization:
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    if (
        type(expected_claim) is not FragmentPublicationReviewClaimV1
        or expected_claim != authorization._claim
        or reference != authorization._claim_reference
    ):
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return _review_checkpoint(protector, authorization, reference, "CLAIM", True)


def protect_publication_assessment(
    protector: PersonalHistoryFragmentProtector,
    *,
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    expected_assessment: FragmentPublicationAssessmentV1,
) -> PersonalFragmentPublicationReviewReceiptV1:
    if (
        type(authorization) is not CanonicalFragmentPublicationReviewAuthorization
        or type(expected_assessment) is not FragmentPublicationAssessmentV1
        or expected_assessment != authorization._assessment
        or reference != authorization._assessment_reference
    ):
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return _review_checkpoint(protector, authorization, reference, "ASSESSMENT", False)


def recheck_publication_assessment(
    protector: PersonalHistoryFragmentProtector,
    *,
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    reference: EvidenceReference,
    expected_assessment: FragmentPublicationAssessmentV1,
) -> PersonalFragmentPublicationReviewReceiptV1:
    if (
        type(authorization) is not CanonicalFragmentPublicationReviewAuthorization
        or type(expected_assessment) is not FragmentPublicationAssessmentV1
        or expected_assessment != authorization._assessment
        or reference != authorization._assessment_reference
    ):
        raise FragmentPublicationReviewError("PERSONAL reviewer checkpoint unavailable")
    return _review_checkpoint(protector, authorization, reference, "ASSESSMENT", True)


def invoke_personal_fragment_publication_review(
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    *,
    runtime: _LocalFragmentReviewRuntime,
) -> _MechanicalReviewResult:
    """Owned once-only real invocation. No active host calls this source-only seam."""
    from zacai.intelligence.fragment_review_runtime import _LocalFragmentReviewRuntime

    result = None
    uncertain = False
    if type(authorization) is not CanonicalFragmentPublicationReviewAuthorization:
        raise FragmentPublicationReviewError("PERSONAL reviewer invocation unavailable")
    gate = authorization
    with gate._lock:
        try:
            if (
                type(runtime) is not _LocalFragmentReviewRuntime
                or gate._runtime is not runtime
                or gate._phase != "PREPARED"
                or gate._invoked
                or gate._prepared is None
                or gate._packet_raw is None
                or gate._deadline_monotonic is None
            ):
                raise ValueError("actual unused owned reviewer invocation required")
            gate._invoked = True  # Includes preflight and every failure/interruption.
            runtime.preflight(
                gate._prepared,
                packet_raw=gate._packet_raw,
                rubric_utf8=gate._rubric,
                template_utf8=gate._template,
                deadline_monotonic=gate._deadline_monotonic,
            )
            gate._require_phase("PREPARED")
            produced = runtime._attempt_authenticated(
                gate._prepared,
                packet_raw=gate._packet_raw,
                rubric_utf8=gate._rubric,
                template_utf8=gate._template,
                authorization=gate,
            )
            if (
                gate._phase != "RELEASED"
                or gate._released is None
                or produced is not runtime._authenticated_result
                or not runtime.did_transport_attempt
                or produced.descriptor != gate._released.mechanical
                or produced.judgments_digest != gate._released.judgments_digest
                or produced.usage_digest != gate._released.usage_digest
            ):
                raise ValueError("actual completed concrete reviewer RELEASE required")
            gate._graph_check()
            gate._observed_result = produced
            result = produced
        except PersonalFragmentCleanupUncertain:
            uncertain = True
        except Exception:  # noqa: BLE001,S110
            pass
        finally:
            if result is None:
                gate._phase = "HELD"
                gate._observed_result = None
    if result is None:
        if uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL reviewer cleanup uncertain; operator review required"
            )
        raise FragmentPublicationReviewError("PERSONAL reviewer invocation unavailable")
    return result


@dataclass(frozen=True, slots=True, repr=False)
class PersonalFragmentRetainedAssessment:
    reference: EvidenceReference
    assessment: FragmentPublicationAssessmentV1
    recovery_receipt: PersonalFragmentPublicationReviewReceiptV1
    # Interpretation remains the existing ten-criterion checker; no delivered flag.


def capture_fragment_publication_assessment(
    authorization: CanonicalFragmentPublicationReviewAuthorization,
    *,
    runtime: _LocalFragmentReviewRuntime,
    result: _MechanicalReviewResult,
) -> PersonalFragmentRetainedAssessment:
    """Consume exact observed RELEASE once; canonical assessment plus whole proof.

    No caller-created ContextualEvaluation is accepted as authenticated output.
    Failed capture cannot be retried, even if committed/orphan bytes remain.
    """
    from zacai.intelligence.fragment_review_runtime import (
        _AUTHENTICATED_MONOTONIC,
        _LocalFragmentReviewRuntime,
        _MechanicalReviewResult,
    )
    from zacai.review_authorization import _lock
    from zacai.state_repository import record_source

    returned = None
    uncertain = False
    if type(authorization) is not CanonicalFragmentPublicationReviewAuthorization:
        raise FragmentPublicationReviewError("PERSONAL assessment retention unavailable")
    gate = authorization
    with gate._lock:
        if gate._phase != "RELEASED":
            if gate._phase == "CAPTURING":
                gate._phase = "HELD"
            raise FragmentPublicationReviewError("PERSONAL assessment retention consumed")
        gate._phase = "CAPTURING"
        try:
            parent, released = gate._generation, gate._released
            if (
                type(runtime) is not _LocalFragmentReviewRuntime
                or gate._runtime is not runtime
                or type(result) is not _MechanicalReviewResult
                or result is not gate._observed_result
                or result is not runtime._authenticated_result
                or released is None
                or gate._claim is None
                or gate._claim_reference is None
                or gate._deadline_monotonic is None
                or result.descriptor != released.mechanical
                or result.judgments_digest != released.judgments_digest
                or result.usage_digest != released.usage_digest
            ):
                raise ValueError("actual original observed reviewer result required")
            gate._graph_check()
            judgments = FragmentReviewJudgments.model_validate(result.judgments)
            usage = UsageObservation.model_validate(result.usage)
            if (
                content_hash_of(canonical_bytes(judgments.model_dump(mode="json")))
                != released.judgments_digest
                or content_hash_of(canonical_bytes(usage.model_dump(mode="json")))
                != released.usage_digest
            ):
                raise ValueError("actual released judgments/usage changed")
            captured = parent._clock()
            parent._owner()
            if (
                not gate._claim.consumed_at <= captured < parent._consent.expires_at
                or _AUTHENTICATED_MONOTONIC() >= gate._deadline_monotonic
            ):
                raise ValueError("original reviewer interval exhausted")
            evaluation = ContextualEvaluation(
                format="zac-contextual-evaluation-v1",
                evaluation_id=gate._profile.run_id,
                task_id=gate._claim.task_id,
                reviewer_id=gate._profile.reviewer_id,
                builder_id=gate._claim.builder_id,
                evaluated_at=captured,
                packet_digest=gate._claim.packet_reference.content_hash,
                assessments=judgments.assessments,
            )
            if gate._packet_raw is None:
                raise ValueError("original complete packet required")
            check_history_fragment_contextual_evaluation(evaluation, gate._packet_raw)
            assessment = FragmentPublicationAssessmentV1(
                evaluation=evaluation,
                review_claim_reference=gate._claim_reference,
                review_claim=gate._claim,
                released_judgments_digest=result.judgments_digest,
                released_usage_digest=result.usage_digest,
                usage=usage,
                captured_at=captured,
            )
            raw = encode_fragment_publication_assessment(assessment)
            with parent._factory() as session:
                session.begin()
                _lock(session, parent._consent.id)
                entry = _physical(session)
                if _ids(
                    session, _assessment_prefix(parent._consent.id), system=SourceSystem.MANUAL
                ):
                    raise ValueError("original assessment already retained")
                before = _review_current(session, gate, gate._claim_reference)
                load_fragment_publication_review_claim(
                    session,
                    authorization=gate,
                    reference=gate._claim_reference,
                    expected=gate._claim,
                )
                _same(session, entry)
                from zacai.backup_artifacts import _assert_personal_custody_append_capacity

                _assert_personal_custody_append_capacity(session, 2)
                location = parent._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
                _same(session, entry)
                fetched = parent._artifacts.get_bounded(
                    B.PERSONAL, location, max_bytes=MAX_REVIEW_RECORD_BYTES
                )
                _same(session, entry)
                if (
                    fetched != raw
                    or _review_current(session, gate, gate._claim_reference) != before
                ):
                    raise ValueError("assessment current input changed")
                if not captured <= parent._clock() < parent._consent.expires_at:
                    raise ValueError("original expiry before assessment commit")
                gate._require_phase("CAPTURING")
                _assert_personal_custody_append_capacity(session, 2)
                source, new = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=_assessment_namespace(assessment),
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    captured_at=captured,
                )
                if not new or source.supersedes_source_id is not None:
                    raise ValueError("one immutable actual assessment required")
                reference = EvidenceReference(
                    source_id=source.id,
                    content_hash=content_hash_of(raw),
                    trust_boundary=B.PERSONAL,
                    effective_classification=C.HIGHLY_RESTRICTED,
                )
                _review_current(
                    session,
                    gate,
                    gate._claim_reference,
                    reference,
                    pending_assessment_reference=reference,
                )
                _same(session, entry)
                _assert_personal_custody_append_capacity(session, 1)
                _same(session, entry)
                gate._require_phase("CAPTURING")
                if _AUTHENTICATED_MONOTONIC() >= gate._deadline_monotonic:
                    raise ValueError("original reviewer interval exhausted before assessment commit")
                session.commit()
            gate._assessment, gate._assessment_reference = assessment, reference
            with parent._factory() as session:
                session.begin()
                load_fragment_publication_assessment(
                    session,
                    authorization=gate,
                    reference=reference,
                    expected=assessment,
                )
            receipt = protect_publication_assessment(
                parent._protector,
                authorization=gate,
                reference=reference,
                expected_assessment=assessment,
            )
            gate._terminal(receipt, reference, "ASSESSMENT")
            if _AUTHENTICATED_MONOTONIC() >= gate._deadline_monotonic:
                raise ValueError("original reviewer interval exhausted at retention")
            gate._require_phase("CAPTURING")
            gate._phase = "ASSESSMENT_RETAINED"
            gate._observed_result = None
            returned = PersonalFragmentRetainedAssessment(reference, assessment, receipt)
        except PersonalFragmentCleanupUncertain:
            uncertain = True
        except Exception:  # noqa: BLE001,S110
            pass
        finally:
            if returned is None:
                gate._phase = "HELD"
                gate._observed_result = None
    if returned is None:
        if uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL reviewer cleanup uncertain; operator review required"
            )
        raise FragmentPublicationReviewError("PERSONAL assessment retention unavailable")
    return returned


# Fixed actual local import closure. File identity, not permission.
_AUTHENTICATED_GRAPH_FILES = (
    "zacai/__init__.py",
    "zacai/backup.py",
    "zacai/backup_artifacts.py",
    "zacai/backup_artifacts_s3.py",
    "zacai/backup_safety.py",
    "zacai/brainstorm_identity_recovery.py",
    "zacai/claude_custody_selection.py",
    "zacai/claude_historical_fragment.py",
    "zacai/claude_history_index.py",
    "zacai/claude_large_original_message.py",
    "zacai/claude_literal_presentation.py",
    "zacai/claude_local_custody.py",
    "zacai/claude_local_protection.py",
    "zacai/claude_message_projection.py",
    "zacai/claude_original_capture.py",
    "zacai/claude_original_read.py",
    "zacai/config.py",
    "zacai/connectors/account_preflight.py",
    "zacai/connectors/approved_communications.py",
    "zacai/connectors/communication_transport.py",
    "zacai/connectors/connector_authority.py",
    "zacai/connectors/gmail_client_secret.py",
    "zacai/connectors/gmail_held_diagnostic.py",
    "zacai/connectors/gmail_held_payload.py",
    "zacai/connectors/gmail_held_reconciliation.py",
    "zacai/connectors/gmail_held_staging.py",
    "zacai/connectors/gmail_held_tokeninfo.py",
    "zacai/connectors/gmail_installation.py",
    "zacai/connectors/gmail_installed_authority.py",
    "zacai/connectors/gmail_installed_load.py",
    "zacai/connectors/gmail_native_reader.py",
    "zacai/connectors/gmail_native_staging.py",
    "zacai/connectors/gmail_quarantine_journal.py",
    "zacai/connectors/gmail_quarantine_record.py",
    "zacai/connectors/gmail_recovery_authorization.py",
    "zacai/connectors/gmail_recovery_consumer.py",
    "zacai/connectors/gmail_registration.py",
    "zacai/connectors/gmail_transport.py",
    "zacai/connectors/gmail_wire.py",
    "zacai/connectors/oauth_callback_diagnostic.py",
    "zacai/connectors/oauth_configuration.py",
    "zacai/connectors/oauth_exchange.py",
    "zacai/connectors/oauth_host_guard.py",
    "zacai/connectors/oauth_transactions.py",
    "zacai/connectors/provider_oauth_evidence.py",
    "zacai/connectors/slack_transport.py",
    "zacai/connectors/slack_wire.py",
    "zacai/contextual_authorization.py",
    "zacai/contextual_protection.py",
    "zacai/contextual_recovery_record.py",
    "zacai/gateway.py",
    "zacai/history_manifest.py",
    "zacai/ingestion/__init__.py",
    "zacai/ingestion/artifact_store.py",
    "zacai/ingestion/native_batch_envelope.py",
    "zacai/ingestion/native_batch_inventory.py",
    "zacai/ingestion/native_proposal_retention.py",
    "zacai/ingestion/native_source_capture.py",
    "zacai/ingestion/native_source_preparation.py",
    "zacai/intelligence/__init__.py",
    "zacai/intelligence/briefing_delivery.py",
    "zacai/intelligence/contextual_diagnostics.py",
    "zacai/intelligence/contextual_evaluation.py",
    "zacai/intelligence/contextual_generation.py",
    "zacai/intelligence/contextual_host.py",
    "zacai/intelligence/contextual_review.py",
    "zacai/intelligence/contextual_storage.py",
    "zacai/intelligence/contracts.py",
    "zacai/intelligence/decision_cards.py",
    "zacai/intelligence/eligibility.py",
    "zacai/intelligence/evidence.py",
    "zacai/intelligence/followup_generation.py",
    "zacai/intelligence/followup_prompt_counter.py",
    "zacai/intelligence/followup_transport.py",
    "zacai/intelligence/fragment_publication_admission.py",
    "zacai/intelligence/fragment_publication_generation.py",
    "zacai/intelligence/fragment_publication_review.py",
    "zacai/intelligence/fragment_review_declaration.py",
    "zacai/intelligence/fragment_review_preparation.py",
    "zacai/intelligence/fragment_review_prompt_counter.py",
    "zacai/intelligence/fragment_review_retention.py",
    "zacai/intelligence/fragment_review_runtime.py",
    "zacai/intelligence/fragment_review_wire.py",
    "zacai/intelligence/fragment_review_withdrawal.py",
    "zacai/intelligence/history_context_metadata.py",
    "zacai/intelligence/history_contextual_codec.py",
    "zacai/intelligence/history_fragment_contextual_codec.py",
    "zacai/intelligence/local_contextual_runtime.py",
    "zacai/intelligence/local_followup_runtime.py",
    "zacai/intelligence/local_review_runtime.py",
    "zacai/intelligence/meeting_review.py",
    "zacai/intelligence/native_context_metadata.py",
    "zacai/intelligence/native_evidence_context.py",
    "zacai/intelligence/native_prompt_counter.py",
    "zacai/intelligence/ollama_token_counter.py",
    "zacai/intelligence/personal_fragment_output.py",
    "zacai/intelligence/project_review_context.py",
    "zacai/intelligence/research_context.py",
    "zacai/intelligence/review_audit.py",
    "zacai/intelligence/review_context.py",
    "zacai/intelligence/review_evaluation.py",
    "zacai/intelligence/review_freshness.py",
    "zacai/intelligence/review_generation.py",
    "zacai/intelligence/review_host.py",
    "zacai/intelligence/runtime_diagnostics.py",
    "zacai/intelligence/selected_briefing.py",
    "zacai/intelligence/text_followup.py",
    "zacai/intelligence/work_briefing.py",
    "zacai/intelligence/work_proposals.py",
    "zacai/intelligence/work_tracking.py",
    "zacai/interfaces/checkpoint_lease.py",
    "zacai/interfaces/followup_authorization.py",
    "zacai/interfaces/fragment_publication_web.py",
    "zacai/interfaces/fragment_preparation_web.py",
    "zacai/interfaces/personal_fragment_factory.py",
    "zacai/interfaces/gmail_connection_web.py",
    "zacai/interfaces/gmail_diagnostic_host.py",
    "zacai/interfaces/gmail_installed_web.py",
    "zacai/interfaces/gmail_recovery_host.py",
    "zacai/interfaces/gmail_recovery_web.py",
    "zacai/interfaces/host_clock.py",
    "zacai/interfaces/named_admission_store.py",
    "zacai/interfaces/named_browser_pointer.py",
    "zacai/interfaces/named_candidate_rows.py",
    "zacai/interfaces/named_decision_admission.py",
    "zacai/interfaces/named_decision_binding.py",
    "zacai/interfaces/named_decision_capture.py",
    "zacai/interfaces/named_decision_inventory.py",
    "zacai/interfaces/named_followup_decision.py",
    "zacai/interfaces/named_followup_web.py",
    "zacai/interfaces/named_published_display.py",
    "zacai/interfaces/named_runtime_binding.py",
    "zacai/interfaces/named_session_binding.py",
    "zacai/interfaces/named_worker_lifecycle.py",
    "zacai/interfaces/oidc_identity.py",
    "zacai/interfaces/owner_enrollment.py",
    "zacai/interfaces/owner_store.py",
    "zacai/interfaces/presentation.py",
    "zacai/interfaces/private_host.py",
    "zacai/interfaces/private_https_ingress.py",
    "zacai/interfaces/private_operator.py",
    "zacai/interfaces/private_server_lifecycle.py",
    "zacai/interfaces/private_startup.py",
    "zacai/interfaces/private_web.py",
    "zacai/interfaces/reply_final_snapshot.py",
    "zacai/interfaces/session_store.py",
    "zacai/interfaces/sqlite_sessions.py",
    "zacai/interfaces/text_followup_context.py",
    "zacai/interfaces/text_reply_capture.py",
    "zacai/interfaces/text_turn_capture.py",
    "zacai/interfaces/text_turn_protection.py",
    "zacai/interfaces/work_choice_capture.py",
    "zacai/interfaces/work_choice_web.py",
    "zacai/policy.py",
    "zacai/research_intake.py",
    "zacai/review_authorization.py",
    "zacai/review_protection.py",
    "zacai/review_recovery.py",
    "zacai/state.py",
    "zacai/state_repository.py",
)


def fragment_publication_review_graph_digest() -> str:
    root = Path(__file__).resolve().parents[2]
    return content_hash_of(
        b"zac-personal-fragment-authenticated-review-graph-v1\x00"
        + canonical_bytes(
            {
                "files": [
                    (name, content_hash_of((root / name).read_bytes()))
                    for name in _AUTHENTICATED_GRAPH_FILES
                ]
            }
        )
    )
