"""Concrete complete reviewer child claim and whole-answer assessment custody.

No loader/model JSON issues admission. Dispatch requires original successful
complete producer graph plus the exact canonical full-purpose approval.
"""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from time import monotonic as _NATIVE_MONOTONIC
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.orm import Session

from zacai.backup_artifacts import _assert_personal_custody_append_capacity
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence import history_publication_generation as generation
from zacai.intelligence.contextual_evaluation import (
    ContextualEvaluation,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, UsageObservation
from zacai.intelligence.fragment_publication_generation import (
    _same_output_commit_transaction as _same_commit,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_contextual_runtime import _route_digest
from zacai.intelligence.history_generation_review_declaration import (
    HistoryClaimV1,
    HistoryGenerationReviewDeclarationV1,
    HistoryReviewPurposeProfileV1,
    history_review_profile_digest,
)
from zacai.intelligence.history_publication_admission import HistoryPublicationAdmissionV1
from zacai.intelligence.history_publication_generation import (
    CanonicalPersonalHistoryPublicationAuthorization,
    PersonalHistoryAssociatedOutput,
)
from zacai.intelligence.history_review_preparation import (
    HistoryReviewJudgments,
    PreparedHistoryReviewRequest,
    prepare_history_review_request,
    verify_history_review_request,
)
from zacai.intelligence.history_review_retention import HistoryDeclarationContext, _parts
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import SourceSystem
from zacai.state_repository import record_source

if TYPE_CHECKING:
    from zacai.intelligence.history_publication_protection import PersonalHistoryReviewReceiptV1
    from zacai.intelligence.history_review_runtime import (
        HistoryReviewDispatchDescriptor,
        LocalHistoryReviewRuntime,
        ObservedHistoryReview,
    )
MAX_REVIEW_RECORD_BYTES = 16000
_BOUNDARIES = frozenset({B.PERSONAL})
_LABELS = frozenset({C.HIGHLY_RESTRICTED})


class HistoryPublicationReviewError(ValueError):
    """Fixed complete reviewer HOLD; no source bodies in diagnostics."""


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


class HistoryPublicationReviewClaimV1(Contract):
    """A canonical one-attempt burn; construction is not admission."""

    format: Literal["zac-personal-complete-publication-review-claim-v1"] = (
        "zac-personal-complete-publication-review-claim-v1"
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
    review_profile: HistoryReviewPurposeProfileV1 = Field(repr=False)
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
            or self.review_profile_digest != history_review_profile_digest(self.review_profile)
            or self.review_profile.run_id != self.run_id
            or self.review_profile.reviewer_id != self.reviewer_id
            or self.requested_output_tokens != self.review_profile.max_output_tokens
            or self.measured_input_tokens + self.requested_output_tokens
            > self.review_profile.context_window_tokens
            or not self.original_approved_at <= self.consumed_at < self.expires_at
        ):
            raise ValueError("exact original review claim bindings required")
        return self


class HistoryPublicationAssessmentV1(Contract):
    """Closed retained invocation evidence, never model-authored host provenance."""

    format: Literal["zac-personal-complete-publication-assessment-v1"] = (
        "zac-personal-complete-publication-assessment-v1"
    )
    evaluation: ContextualEvaluation = Field(repr=False)
    review_claim_reference: EvidenceReference
    review_claim: HistoryPublicationReviewClaimV1 = Field(repr=False)
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
            != content_hash_of(encode_history_publication_review_claim(claim))
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
                    HistoryReviewJudgments(
                        format="zac-history-complete-review-judgments-v1",
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


def encode_history_publication_review_claim(value: HistoryPublicationReviewClaimV1) -> bytes:
    result = None
    try:
        if type(value) is not HistoryPublicationReviewClaimV1:
            raise ValueError("exact claim required")
        checked = HistoryPublicationReviewClaimV1.model_validate(value.model_dump())
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
        raise HistoryPublicationReviewError("PERSONAL review claim unavailable")
    return result


def decode_history_publication_review_claim(raw: bytes) -> HistoryPublicationReviewClaimV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REVIEW_RECORD_BYTES:
            raise ValueError("bounded claim required")
        value = HistoryPublicationReviewClaimV1.model_validate_json(raw)
        if encode_history_publication_review_claim(value) != raw:
            raise ValueError("canonical claim required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationReviewError("PERSONAL review claim unavailable")
    return result


def encode_history_publication_assessment(value: HistoryPublicationAssessmentV1) -> bytes:
    result = None
    try:
        if type(value) is not HistoryPublicationAssessmentV1:
            raise ValueError("exact assessment required")
        checked = HistoryPublicationAssessmentV1.model_validate(value.model_dump())
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
        raise HistoryPublicationReviewError("PERSONAL review assessment unavailable")
    return result


def decode_history_publication_assessment(raw: bytes) -> HistoryPublicationAssessmentV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REVIEW_RECORD_BYTES:
            raise ValueError("bounded assessment required")
        value = HistoryPublicationAssessmentV1.model_validate_json(raw)
        if encode_history_publication_assessment(value) != raw:
            raise ValueError("canonical assessment required")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationReviewError("PERSONAL review assessment unavailable")
    return result


def _review_prefix(generation_id: UUID) -> str:
    # Same durable child namespace as existing history-fragment review.
    return f"personal-history-fragment-publication-review-claim/{generation_id}/"


def _assessment_prefix(generation_id: UUID) -> str:
    return f"personal-history-fragment-publication-assessment/{generation_id}/"


def _claim_namespace(value: HistoryPublicationReviewClaimV1) -> str:
    return _review_prefix(value.generation_id) + str(value.run_id)


def _assessment_namespace(value: HistoryPublicationAssessmentV1) -> str:
    return _assessment_prefix(value.review_claim.generation_id) + str(
        value.evaluation.evaluation_id
    )


def history_publication_review_graph_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    paths = (
        "intelligence/history_publication_review.py",
        "intelligence/history_review_runtime.py",
        "intelligence/history_publication_generation.py",
        "intelligence/history_contextual_runtime.py",
        "intelligence/history_publication_protection.py",
        "intelligence/history_publication_admission.py",
        "interfaces/history_publication_action.py",
        "intelligence/history_review_preparation.py",
        "intelligence/history_review_wire.py",
        "intelligence/history_review_prompt_counter.py",
        "intelligence/history_generation_review_declaration.py",
        "intelligence/history_review_retention.py",
        "intelligence/history_declaration_protection.py",
        "__init__.py",
        "claude_historical_fragment.py",
        "ingestion/__init__.py",
        "intelligence/__init__.py",
        "intelligence/eligibility.py",
        "intelligence/evidence.py",
        "intelligence/history_fragment_contextual_codec.py",
        "intelligence/project_review_context.py",
        "intelligence/review_audit.py",
        "intelligence/review_freshness.py",
        "intelligence/review_host.py",
        "intelligence/runtime_diagnostics.py",
        "intelligence/history_contextual_codec.py",
        "claude_large_original_message.py",
        "claude_history_index.py",
        "claude_custody_selection.py",
        "history_manifest.py",
        "intelligence/contextual_storage.py",
        "intelligence/fragment_review_runtime.py",
        "intelligence/review_evaluation.py",
        "ingestion/artifact_store.py",
        "intelligence/contextual_generation.py",
        "intelligence/contextual_evaluation.py",
        "intelligence/local_contextual_runtime.py",
        "intelligence/local_review_runtime.py",
        "intelligence/ollama_token_counter.py",
        "state_repository.py",
        "state.py",
        "contextual_protection.py",
        "backup.py",
        "backup_artifacts.py",
        "review_protection.py",
        "interfaces/named_session_binding.py",
        "host_clock.py",
        "interfaces/host_clock.py",
        "policy.py",
        "gateway.py",
        "review_authorization.py",
        "claude_local_protection.py",
        "intelligence/fragment_review_retention.py",
        "intelligence/fragment_publication_generation.py",
        "intelligence/review_context.py",
        "intelligence/contracts.py",
        "intelligence/contextual_review.py",
        "intelligence/contextual_diagnostics.py",
        "intelligence/meeting_review.py",
        "intelligence/review_generation.py",
        "intelligence/history_context_metadata.py",
        "intelligence/native_context_metadata.py",
        "claude_message_projection.py",
        "claude_original_capture.py",
        "claude_original_read.py",
    )
    return content_hash_of(
        b"zac-complete-review-authenticated-graph-v1\0"
        + canonical_bytes(
            {"files": [(name, content_hash_of((root / name).read_bytes())) for name in paths]}
        )
    )


def _claim_binding(
    declaration: HistoryGenerationReviewDeclarationV1,
    admission: HistoryPublicationAdmissionV1,
    admission_reference: EvidenceReference,
    claim: HistoryClaimV1,
    claim_reference: EvidenceReference,
    association: generation.HistoryPublicationOutputAssociationV1,
    association_reference: EvidenceReference,
    child: HistoryPublicationReviewClaimV1,
) -> None:
    generation._association_binding(
        association,
        declaration=declaration,
        admission_reference=admission_reference,
        admission=admission,
        claim_reference=claim_reference,
        claim=claim,
    )
    _, g, _ = _parts(declaration)
    selected = tuple(
        sorted(
            (
                *g.provenance,
                admission.publication_reference,
                admission_reference,
                claim_reference,
                association.packet_reference,
                association_reference,
            ),
            key=lambda r: str(r.source_id),
        )
    )
    if (
        type(child) is not HistoryPublicationReviewClaimV1
        or declaration.review is None
        or child.generation_id != g.id
        or child.task_id != g.task_id
        or child.builder_id != g.builder_id
        or child.association_reference != association_reference
        or child.association_digest != association_reference.content_hash
        or child.packet_reference != association.packet_reference
        or child.publication_reference != admission.publication_reference
        or child.publication_digest != admission.publication_digest
        or child.admission_reference != admission_reference
        or child.generation_claim_reference != claim_reference
        or child.review_profile != declaration.review
        or child.review_profile_digest != declaration.review_profile_digest
        or child.selected_references != selected
        or child.original_session_binding != g.original_session_binding
        or child.original_approved_at != g.approved_at
        or child.expires_at != g.expires_at
        or child.consumed_at < association.packet_created_at
    ):
        raise ValueError("exact original complete reviewer parent required")


def _subject_current(
    session: Session,
    *,
    declaration: HistoryGenerationReviewDeclarationV1,
    admission: HistoryPublicationAdmissionV1,
    admission_reference: EvidenceReference,
    generation_claim: HistoryClaimV1,
    generation_claim_reference: EvidenceReference,
    association: generation.HistoryPublicationOutputAssociationV1,
    association_reference: EvidenceReference,
    review_claim: HistoryPublicationReviewClaimV1,
    review_claim_reference: EvidenceReference,
    assessment: HistoryPublicationAssessmentV1 | None = None,
    assessment_reference: EvidenceReference | None = None,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    _claim_binding(
        declaration,
        admission,
        admission_reference,
        generation_claim,
        generation_claim_reference,
        association,
        association_reference,
        review_claim,
    )
    parent = generation._output_current(
        session,
        reference=association_reference,
        value=association,
        declaration=declaration,
        admission_reference=admission_reference,
        admission=admission,
        claim_reference=generation_claim_reference,
        claim=generation_claim,
    )
    raw = encode_history_publication_review_claim(review_claim)
    if review_claim_reference.content_hash != content_hash_of(raw):
        raise ValueError("exact canonical child hash required")
    own = [review_claim_reference]
    if (assessment is None) != (assessment_reference is None):
        raise ValueError("closed assessment family required")
    if assessment is not None:
        assert assessment_reference is not None
        if (
            type(assessment) is not HistoryPublicationAssessmentV1
            or assessment.review_claim_reference != review_claim_reference
            or assessment.review_claim != review_claim
            or assessment_reference.content_hash
            != content_hash_of(encode_history_publication_assessment(assessment))
        ):
            raise ValueError("exact complete assessment parent required")
        own.append(assessment_reference)
    selected = tuple(
        sorted((*review_claim.selected_references, *own), key=lambda r: str(r.source_id))
    )
    if len(selected) > 95 or len({r.source_id for r in selected}) != len(selected):
        raise ValueError("full selected complete review union exceeds bound")
    if generation._ids(session, _review_prefix(review_claim.generation_id)) != (
        review_claim_reference.source_id,
    ) or generation._ids(session, _assessment_prefix(review_claim.generation_id)) != (
        () if assessment_reference is None else (assessment_reference.source_id,)
    ):
        raise ValueError("exact child and assessment namespace required")
    rows = _fragment_rows(session, selected, _BOUNDARIES, _LABELS)
    for ref, external, at in [
        (review_claim_reference, _claim_namespace(review_claim), review_claim.consumed_at),
        *(
            [(assessment_reference, _assessment_namespace(assessment), assessment.captured_at)]
            if assessment is not None
            else []
        ),
    ]:
        assert ref is not None
        row = next(dict(r) for r in rows if dict(r)["id"] == ref.source_id)
        if (
            row["system"] is not SourceSystem.MANUAL
            or row["external_ref"] != external
            or row["captured_at"] != at
            or row["lineage_id"] != ref.source_id
            or row["supersedes_source_id"] is not None
        ):
            raise ValueError("immutable own complete reviewer Source required")
    if not parent:
        raise ValueError("actual complete parent current required")
    return rows


def load_history_publication_review_subject(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    declaration: HistoryGenerationReviewDeclarationV1,
    admission: HistoryPublicationAdmissionV1,
    admission_reference: EvidenceReference,
    generation_claim: HistoryClaimV1,
    generation_claim_reference: EvidenceReference,
    association: generation.HistoryPublicationOutputAssociationV1,
    association_reference: EvidenceReference,
    review_claim: HistoryPublicationReviewClaimV1,
    review_claim_reference: EvidenceReference,
    assessment: HistoryPublicationAssessmentV1 | None = None,
    assessment_reference: EvidenceReference | None = None,
) -> HistoryPublicationReviewClaimV1 | HistoryPublicationAssessmentV1:
    result = None
    try:

        def current() -> tuple[tuple[tuple[str, object], ...], ...]:
            return _subject_current(
                session,
                declaration=declaration,
                admission=admission,
                admission_reference=admission_reference,
                generation_claim=generation_claim,
                generation_claim_reference=generation_claim_reference,
                association=association,
                association_reference=association_reference,
                review_claim=review_claim,
                review_claim_reference=review_claim_reference,
                assessment=assessment,
                assessment_reference=assessment_reference,
            )

        entry = _physical(session)
        before = current()
        generation.load_history_publication_output_association(
            session,
            artifacts=artifacts,
            context=context,
            reference=association_reference,
            expected_association=association,
            expected_declaration=declaration,
            admission_reference=admission_reference,
            expected_admission=admission,
            claim_reference=generation_claim_reference,
            expected_claim=generation_claim,
        )
        _same(session, entry)
        if current() != before:
            raise ValueError("complete child changed during parent body")
        subjects = [(review_claim_reference, encode_history_publication_review_claim(review_claim))]
        if assessment is not None:
            assert assessment_reference is not None
            subjects.append(
                (assessment_reference, encode_history_publication_assessment(assessment))
            )
        for ref, raw in subjects:
            row = next(dict(r) for r in before if dict(r)["id"] == ref.source_id)
            location = row["content_location"]
            if type(location) is not str:
                raise ValueError("bounded own body required")
            if (
                artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_REVIEW_RECORD_BYTES)
                != raw
            ):
                raise ValueError("exact complete child body required")
            _same(session, entry)
            if current() != before:
                raise ValueError("complete child changed after body")
        result = review_claim if assessment is None else assessment
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationReviewError("complete reviewer subject unavailable")
    return result


class CanonicalPersonalHistoryReviewAuthorization:
    """One independent child, anchored to the original successful complete producer."""

    def __init__(
        self,
        *,
        generation_authorization: CanonicalPersonalHistoryPublicationAuthorization,
        output: PersonalHistoryAssociatedOutput,
        runtime: LocalHistoryReviewRuntime,
        rubric_utf8: bytes,
        template_utf8: bytes,
    ) -> None:
        from zacai.intelligence.history_review_runtime import LocalHistoryReviewRuntime

        started = _NATIVE_MONOTONIC()
        parent = generation_authorization
        if (
            type(parent) is not CanonicalPersonalHistoryPublicationAuthorization
            or type(output) is not PersonalHistoryAssociatedOutput
            or parent._phase != "OUTPUT_RETAINED"
            or parent._result is not output
            or parent._released is None
            or parent._runtime is None
            or parent._runtime._authorization is not parent
            or parent._runtime._result is None
            or parent._runtime._released is not parent._released
            or parent._claim is None
            or parent._claim_reference is None
            or parent._declaration.review is None
            or type(runtime) is not LocalHistoryReviewRuntime
            or runtime._authorization is not None
            or type(rubric_utf8) is not bytes
            or type(template_utf8) is not bytes
        ):
            raise HistoryPublicationReviewError("actual original complete producer/result required")
        with parent._lock:
            if parent._phase != "OUTPUT_RETAINED" or parent._result is not output:
                raise HistoryPublicationReviewError("original complete review already entered")
            parent._phase = "REVIEW_ENTERED"
        self._generation, self._output, self._runtime = parent, output, runtime
        self._rubric, self._template = rubric_utf8, template_utf8
        self._started = started
        self._deadline = started
        self._original_interval = (started, started)
        self._profile = parent._declaration.review
        self._configuration: tuple[str, ...] = ()
        self._graph = (
            parent,
            output,
            runtime,
            parent._operation,
            parent._clock,
            parent._protector,
            parent._factory,
            parent._artifacts,
            parent._context,
        )
        self._phase = "PREPARING"
        self._lock = RLock()
        self._prepared: PreparedHistoryReviewRequest | None = None
        self._packet_raw = b""
        self._claim: HistoryPublicationReviewClaimV1 | None = None
        self._claim_reference: EvidenceReference | None = None
        self._assessment: HistoryPublicationAssessmentV1 | None = None
        self._assessment_reference: EvidenceReference | None = None
        self._released: HistoryReviewDispatchDescriptor | None = None
        self._observed: ObservedHistoryReview | None = None
        self._claim_proof: PersonalHistoryReviewReceiptV1 | None = None
        self._result: PersonalHistoryRetainedAssessment | None = None
        self._invoked = False
        failed = False
        uncertain = False
        interrupted = None
        try:
            self._deadline = min(
                parent._deadline_monotonic, started + parent._declaration.review.max_latency_ms / 1000
            )
            self._original_interval = (started, self._deadline)
            self._configuration = runtime.configuration()
            self._graph_check()
            parent._owner()
            with parent._factory() as session:
                session.begin()
                packet, association = generation.load_history_publication_output_association(
                    session,
                    artifacts=parent._artifacts,
                    context=parent._context,
                    reference=output.association_reference,
                    expected_association=output.association,
                    expected_declaration=parent._declaration,
                    admission_reference=parent._admission_reference,
                    expected_admission=parent._admission,
                    claim_reference=parent._claim_reference,
                    expected_claim=parent._claim,
                )
                if packet != output.packet or association != output.association:
                    raise ValueError("canonical complete producer packet changed")
                # Own packet identity and ACL already validated by actual paired loader.
                rows = generation._output_current(
                    session,
                    reference=output.association_reference,
                    value=output.association,
                    declaration=parent._declaration,
                    admission_reference=parent._admission_reference,
                    admission=parent._admission,
                    claim_reference=parent._claim_reference,
                    claim=parent._claim,
                )
                row = next(
                    dict(v)
                    for v in rows
                    if dict(v)["id"] == output.association.packet_reference.source_id
                )
                location = row["content_location"]
                if type(location) is not str:
                    raise ValueError("exact complete packet location required")
                raw = parent._artifacts.get_bounded(B.PERSONAL, location, max_bytes=512000)
                if content_hash_of(raw) != output.association.packet_reference.content_hash:
                    raise ValueError("original complete packet changed")
                if (
                    generation._output_current(
                        session,
                        reference=output.association_reference,
                        value=output.association,
                        declaration=parent._declaration,
                        admission_reference=parent._admission_reference,
                        admission=parent._admission,
                        claim_reference=parent._claim_reference,
                        claim=parent._claim,
                    )
                    != rows
                ):
                    raise ValueError("complete parent changed after body")
            parent._owner()
            self._packet_raw = raw
            self._prepared = prepare_history_review_request(
                packet_raw=raw,
                expected_packet_digest=output.association.packet_reference.content_hash,
                expected_task_id=parent._consent.task_id,
                expected_builder_id=parent._consent.builder_id,
                expected_request=parent._request,
                review=self._profile,
                rubric_utf8=rubric_utf8,
                template_utf8=template_utf8,
            )
            if self._configuration != (
                self._profile.model_digest,
                self._profile.tokenizer_digest,
                runtime._counter.template_digest,
                self._profile.renderer_digest,
                self._profile.runtime_digest,
            ):
                raise ValueError("actual declared complete reviewer runtime required")
            from zacai.intelligence.history_review_runtime import (
                history_review_derivation_digest,
                history_review_wire_digest,
            )

            if (
                self._profile.reviewer_wire_digest != history_review_wire_digest()
                or self._profile.body_derivation_digest != history_review_derivation_digest()
            ):
                raise ValueError("actual complete reviewer wire and derivation pins required")
            parent._owner()
            self._graph_check()
            if _NATIVE_MONOTONIC() >= self._deadline:
                raise ValueError("original reviewer interval exhausted during preparation")
            runtime._authorization = self
            self._phase = "PREPARED"
        except PersonalFragmentCleanupUncertain:
            uncertain = True
            failed = True
        except (KeyboardInterrupt, SystemExit) as error:
            interrupted = error
            failed = True
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            self._hold()
        if uncertain:
            raise PersonalFragmentCleanupUncertain("PERSONAL complete reviewer preparation cleanup uncertain")
        if interrupted is not None:
            raise type(interrupted)() from None
        if failed:
            raise HistoryPublicationReviewError("complete reviewer preparation held")

    def _hold(self) -> None:
        self._phase = "HELD"
        self._released = None
        self._observed = None
        self._result = None

    def _require(self, phase: str) -> None:
        if self._phase != phase:
            raise ValueError("original complete review phase changed")

    def _graph_check(self) -> None:
        p = self._generation
        if (
            self._graph
            != (
                p,
                self._output,
                self._runtime,
                p._operation,
                p._clock,
                p._protector,
                p._factory,
                p._artifacts,
                p._context,
            )
            or p._phase != "REVIEW_ENTERED"
            or p._result is not self._output
            or p._runtime is None
            or p._runtime._authorization is not p
            or p._runtime._result is None
            or p._runtime._released is not p._released
            or p._declaration.review != self._profile
            or self._runtime.configuration() != self._configuration
            or (self._started, self._deadline) != self._original_interval
        ):
            raise ValueError("original complete reviewer graph changed")
        p._graph_check()

    def _current(
        self,
        session: Session,
        *,
        assessment: HistoryPublicationAssessmentV1 | None = None,
        reference: EvidenceReference | None = None,
    ) -> tuple[tuple[tuple[str, object], ...], ...]:
        p = self._generation
        assert p._claim is not None and p._claim_reference is not None
        assert self._claim is not None and self._claim_reference is not None
        return _subject_current(
            session,
            declaration=p._declaration,
            admission=p._admission,
            admission_reference=p._admission_reference,
            generation_claim=p._claim,
            generation_claim_reference=p._claim_reference,
            association=self._output.association,
            association_reference=self._output.association_reference,
            review_claim=self._claim,
            review_claim_reference=self._claim_reference,
            assessment=assessment,
            assessment_reference=reference,
        )

    def _terminal(self, proof: PersonalHistoryReviewReceiptV1, phase: str) -> None:
        p = self._generation
        if (
            content_hash_of(p._protector._run_row(proof.artifact_backup_run_id))
            != proof.live_journal_digest
        ):
            raise ValueError("complete review recovery journal changed")
        with p._factory() as session:
            session.begin()
            _lock(session, p._consent.id)
            entry = _physical(session)
            self._current(
                session, assessment=self._assessment, reference=self._assessment_reference
            )
            p._receipt_current(session, proof)
            _same(session, entry)
            self._require(phase)
        self._graph_check()
        if _NATIVE_MONOTONIC() >= self._deadline:
            raise ValueError("original complete reviewer interval exhausted")

    def _burn(self, d: HistoryReviewDispatchDescriptor) -> None:
        p = self._generation
        assert (
            self._prepared is not None and p._claim is not None and p._claim_reference is not None
        )
        prepared = self._prepared
        consumed = p._owner()
        selected = tuple(
            sorted(
                (
                    *p._consent.provenance,
                    p._admission.publication_reference,
                    p._admission_reference,
                    p._claim_reference,
                    self._output.association.packet_reference,
                    self._output.association_reference,
                ),
                key=lambda r: str(r.source_id),
            )
        )
        from zacai.intelligence.history_review_runtime import descriptor_digest

        self._claim = HistoryPublicationReviewClaimV1(
            generation_id=p._consent.id,
            run_id=prepared.run_id,
            reviewer_id=prepared.reviewer_id,
            attempt_id=d.attempt_id,
            task_id=prepared.task_id,
            builder_id=prepared.builder_id,
            association_reference=self._output.association_reference,
            association_digest=self._output.association_reference.content_hash,
            packet_reference=self._output.association.packet_reference,
            publication_reference=p._admission.publication_reference,
            publication_digest=p._admission.publication_digest,
            admission_reference=p._admission_reference,
            admission_digest=p._admission_reference.content_hash,
            generation_claim_reference=p._claim_reference,
            generation_claim_digest=p._claim_reference.content_hash,
            review_profile=self._profile,
            review_profile_digest=prepared.purpose_digest,
            prepared_request_digest=prepared.request_digest,
            prepared_body_digest=prepared.body_digest,
            wire_body_digest=d.wire_body_digest,
            route_digest=_route_digest(prepared.route),
            runtime_profile_digest=content_hash_of(
                canonical_bytes({"configuration": d.configuration})
            ),
            authorization_graph_digest=history_publication_review_graph_digest(),
            model_metadata_digest=d.model_metadata_digest,
            mechanical_descriptor_digest=descriptor_digest(d),
            original_deadline_monotonic=self._deadline,
            measured_input_tokens=d.measured_input_tokens,
            requested_output_tokens=d.requested_output_tokens,
            original_session_binding=p._consent.original_session_binding,
            original_approved_at=p._consent.approved_at,
            expires_at=p._consent.expires_at,
            consumed_at=consumed,
            selected_references=selected,
        )
        raw = encode_history_publication_review_claim(self._claim)
        sid = uuid4()
        self._claim_reference = EvidenceReference(
            source_id=sid,
            content_hash=content_hash_of(raw),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        location = p._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
        if p._artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_REVIEW_RECORD_BYTES) != raw:
            raise ValueError("complete reviewer claim artifact changed")
        p._owner()
        self._graph_check()
        self._require("ENTERED")
        with p._factory() as session:
            session.begin()
            _lock(session, p._consent.id)
            entry = _physical(session)
            generation._output_current(
                session,
                reference=self._output.association_reference,
                value=self._output.association,
                declaration=p._declaration,
                admission_reference=p._admission_reference,
                admission=p._admission,
                claim_reference=p._claim_reference,
                claim=p._claim,
            )
            if generation._ids(session, _review_prefix(p._consent.id)) or generation._ids(
                session, _assessment_prefix(p._consent.id)
            ):
                raise ValueError("original independent reviewer attempt already consumed")
            _assert_personal_custody_append_capacity(session, 3)
            row, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=_claim_namespace(self._claim),
                content_hash=content_hash_of(raw),
                content_location=location,
                captured_at=consumed,
                preallocated_source_id=sid,
            )
            if not new or row.id != sid or row.supersedes_source_id is not None:
                raise ValueError("first exact complete reviewer claim required")
            self._current(session)
            _assert_personal_custody_append_capacity(session, 2)
            _same(session, entry)
            self._require("ENTERED")
            if _NATIVE_MONOTONIC() >= self._deadline:
                raise ValueError("original review interval expired before burn commit")
            _same_commit(session, entry)
            session.commit()

    def recheck_review_dispatch(
        self, prepared: PreparedHistoryReviewRequest, d: HistoryReviewDispatchDescriptor
    ) -> None:
        from zacai.intelligence.history_publication_protection import protect_history_review_claim
        from zacai.intelligence.history_review_runtime import (
            HistoryReviewDispatchDescriptor,
        )

        failed = False
        uncertain = False
        interrupted = None
        try:
            with self._lock:
                if type(d) is not HistoryReviewDispatchDescriptor or d.phase not in (
                    "PRE_DISPATCH",
                    "RELEASE",
                ):
                    raise ValueError("closed complete reviewer dispatch phase required")
                self._graph_check()
                if (
                    prepared is not self._prepared
                    or type(d) is not HistoryReviewDispatchDescriptor
                    or self._runtime._prepared is not prepared
                    or self._runtime._body is None
                    or d.request_digest != prepared.request_digest
                    or d.packet_digest != prepared.packet_digest
                    or d.wire_body_digest != content_hash_of(self._runtime._body)
                    or d.configuration != self._configuration
                    or d.deadline_monotonic != self._deadline
                    or d.requested_output_tokens != self._profile.max_output_tokens
                ):
                    raise ValueError("actual whole complete review dispatch required")
                verify_history_review_request(
                    prepared,
                    packet_raw=self._packet_raw,
                    expected_request=self._generation._request,
                    rubric_utf8=self._rubric,
                    template_utf8=self._template,
                )
                if d.phase == "PRE_DISPATCH":
                    self._require("PREPARED")
                    if d.judgments_digest is not None or d.usage_digest is not None:
                        raise ValueError("PRE has no generated judgment")
                    self._phase = "ENTERED"
                    self._burn(d)
                    self._claim_proof = protect_history_review_claim(self, read_existing=False)
                    self._terminal(self._claim_proof, "ENTERED")
                    self._phase = "CLAIMED"
                else:
                    self._require("CLAIMED")
                    assert self._claim is not None
                    if (
                        d.attempt_id != self._claim.attempt_id
                        or d.model_metadata_digest != self._claim.model_metadata_digest
                        or d.measured_input_tokens != self._claim.measured_input_tokens
                        or d.judgments_digest is None
                        or d.usage_digest is None
                    ):
                        raise ValueError("actual original independent review RELEASE required")
                    self._phase = "RELEASE_ENTERED"
                    proof = protect_history_review_claim(self, read_existing=True)
                    if proof != self._claim_proof:
                        raise ValueError("original complete review proof changed")
                    self._terminal(proof, "RELEASE_ENTERED")
                    self._released = d
                    self._phase = "RELEASED"
        except PersonalFragmentCleanupUncertain:
            uncertain = True
            failed = True
        except (KeyboardInterrupt, SystemExit) as error:
            interrupted = error
            failed = True
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            self._hold()
        if uncertain:
            raise PersonalFragmentCleanupUncertain("PERSONAL complete review cleanup uncertain")
        if interrupted is not None:
            raise type(interrupted)() from None
        if failed:
            raise HistoryPublicationReviewError("complete review dispatch held")

    def invoke(self) -> ObservedHistoryReview:
        result = None
        uncertain = False
        interrupted = None
        try:
            with self._lock:
                if self._phase != "PREPARED" or self._invoked:
                    raise ValueError("original reviewer invocation already entered")
                self._invoked = True
                produced = self._runtime.invoke(self)
                if (
                    self._phase != "RELEASED"
                    or produced is not self._runtime._result
                    or produced.descriptor is not self._released
                    or not self._runtime._did_transport
                ):
                    raise ValueError("original complete reviewer observation required")
                self._graph_check()
                self._observed = produced
                result = produced
        except PersonalFragmentCleanupUncertain:
            uncertain = True
        except (KeyboardInterrupt, SystemExit) as error:
            interrupted = error
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            self._hold()
        if uncertain:
            raise PersonalFragmentCleanupUncertain("PERSONAL complete reviewer invocation cleanup uncertain")
        if interrupted is not None:
            raise type(interrupted)() from None
        if result is None:
            raise HistoryPublicationReviewError("complete reviewer invocation held")
        return result


from dataclasses import dataclass

from zacai.intelligence.contextual_evaluation import (
    ContextualOutcome,
    check_history_contextual_evaluation,
)


@dataclass(frozen=True, slots=True, repr=False)
class PersonalHistoryRetainedAssessment:
    reference: EvidenceReference
    assessment: HistoryPublicationAssessmentV1
    recovery_receipt: PersonalHistoryReviewReceiptV1
    outcome: ContextualOutcome

    @property
    def ready_to_deliver(self) -> bool:
        # An observation at successful original release, never a renewed grant.
        return self.outcome is ContextualOutcome.REVIEWED_PASS


def capture_history_publication_assessment(
    gate: CanonicalPersonalHistoryReviewAuthorization, *, observed: ObservedHistoryReview
) -> PersonalHistoryRetainedAssessment:
    from zacai.intelligence.history_publication_protection import protect_history_assessment
    from zacai.intelligence.history_review_runtime import ObservedHistoryReview

    result = None
    uncertain = False
    interrupted = None
    try:
        if type(gate) is not CanonicalPersonalHistoryReviewAuthorization:
            raise ValueError("actual complete reviewer gate required")
        with gate._lock:
            gate._require("RELEASED")
            gate._phase = "ASSESSMENT_ENTERED"
            if (
                type(observed) is not ObservedHistoryReview
                or observed is not gate._observed
                or observed is not gate._runtime._result
                or observed.descriptor is not gate._released
                or gate._claim is None
                or gate._claim_reference is None
            ):
                raise ValueError("only actual independent invocation result may be retained")
            gate._graph_check()
            p = gate._generation
            at = p._owner()
            assert gate._prepared is not None and gate._released is not None
            evaluation = ContextualEvaluation(
                format="zac-contextual-evaluation-v1",
                evaluation_id=gate._prepared.run_id,
                task_id=gate._prepared.task_id,
                reviewer_id=gate._prepared.reviewer_id,
                builder_id=gate._prepared.builder_id,
                evaluated_at=at,
                packet_digest=gate._prepared.packet_digest,
                assessments=observed.judgments.assessments,
            )
            outcome = check_history_contextual_evaluation(evaluation, gate._packet_raw)
            assessment = HistoryPublicationAssessmentV1(
                evaluation=evaluation,
                review_claim_reference=gate._claim_reference,
                review_claim=gate._claim,
                released_judgments_digest=gate._released.judgments_digest,
                released_usage_digest=gate._released.usage_digest,
                usage=observed.usage,
                captured_at=at,
            )
            raw = encode_history_publication_assessment(assessment)
            sid = uuid4()
            reference = EvidenceReference(
                source_id=sid,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            with p._factory() as session:
                session.begin()
                _lock(session, p._consent.id)
                entry = _physical(session)
                before = gate._current(session)
                assert p._claim is not None and p._claim_reference is not None
                load_history_publication_review_subject(
                    session,
                    artifacts=p._artifacts,
                    context=p._context,
                    declaration=p._declaration,
                    admission=p._admission,
                    admission_reference=p._admission_reference,
                    generation_claim=p._claim,
                    generation_claim_reference=p._claim_reference,
                    association=gate._output.association,
                    association_reference=gate._output.association_reference,
                    review_claim=gate._claim,
                    review_claim_reference=gate._claim_reference,
                )
                if gate._current(session) != before:
                    raise ValueError("review subject changed during assessment preparation")
                _assert_personal_custody_append_capacity(session, 2)
                _same(session, entry)
            location = p._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            if (
                p._artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_REVIEW_RECORD_BYTES)
                != raw
            ):
                raise ValueError("actual assessment artifact changed")
            p._owner()
            gate._graph_check()
            gate._require("ASSESSMENT_ENTERED")
            if gate._runtime._result is not observed or gate._observed is not observed:
                raise ValueError("original whole answer judgments changed")
            with p._factory() as session:
                session.begin()
                _lock(session, p._consent.id)
                entry = _physical(session)
                if gate._current(session) != before:
                    raise ValueError("original reviewer union changed before assessment write")
                _assert_personal_custody_append_capacity(session, 2)
                row, new = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=_assessment_namespace(assessment),
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    captured_at=at,
                    preallocated_source_id=sid,
                )
                if not new or row.id != sid or row.supersedes_source_id is not None:
                    raise ValueError("first exact complete assessment required")
                gate._current(session, assessment=assessment, reference=reference)
                _assert_personal_custody_append_capacity(session, 1)
                _same(session, entry)
                gate._require("ASSESSMENT_ENTERED")
                if _NATIVE_MONOTONIC() >= gate._deadline:
                    raise ValueError("original review interval expired before assessment commit")
                _same_commit(session, entry)
                session.commit()
            gate._assessment, gate._assessment_reference = assessment, reference
            p._owner()
            with p._factory() as session:
                session.begin()
                load_history_publication_review_subject(
                    session,
                    artifacts=p._artifacts,
                    context=p._context,
                    declaration=p._declaration,
                    admission=p._admission,
                    admission_reference=p._admission_reference,
                    generation_claim=p._claim,
                    generation_claim_reference=p._claim_reference,
                    association=gate._output.association,
                    association_reference=gate._output.association_reference,
                    review_claim=gate._claim,
                    review_claim_reference=gate._claim_reference,
                    assessment=assessment,
                    assessment_reference=reference,
                )
            proof = protect_history_assessment(gate, read_existing=False)
            gate._terminal(proof, "ASSESSMENT_ENTERED")
            if observed is not gate._observed or observed is not gate._runtime._result:
                raise ValueError("original complete assessment origin changed")
            result = PersonalHistoryRetainedAssessment(reference, assessment, proof, outcome)
            gate._result = result
            gate._phase = "ASSESSMENT_RETAINED"
    except PersonalFragmentCleanupUncertain:
        uncertain = True
    except (KeyboardInterrupt, SystemExit) as error:
        interrupted = error
    except Exception:  # noqa: BLE001,S110
        pass
    finally:
        if result is None and type(gate) is CanonicalPersonalHistoryReviewAuthorization:
            gate._hold()
    if uncertain:
        raise PersonalFragmentCleanupUncertain("PERSONAL complete assessment cleanup uncertain")
    if interrupted is not None:
        raise type(interrupted)() from None
    if result is None:
        raise HistoryPublicationReviewError("complete assessment retention held")
    return result


def release_history_reviewed_text(
    gate: CanonicalPersonalHistoryReviewAuthorization,
    *,
    expected: PersonalHistoryRetainedAssessment,
) -> str | None:
    """Current one-use original response release; constructed PASS is no grant."""
    from zacai.intelligence.history_contextual_codec import (
        decode_history_contextual_packet,
        render_history_packet_preview,
    )
    from zacai.intelligence.history_publication_protection import protect_history_assessment

    result = None
    entered = False
    uncertain = False
    interrupted = None
    try:
        if type(gate) is not CanonicalPersonalHistoryReviewAuthorization:
            raise ValueError("actual original complete review gate required")
        with gate._lock:
            gate._require("ASSESSMENT_RETAINED")
            gate._phase = "DELIVERY_ENTERED"
            entered = True
            if (
                type(expected) is not PersonalHistoryRetainedAssessment
                or expected is not gate._result
            ):
                raise ValueError("actual retained independent assessment required")
            gate._graph_check()
            proof = protect_history_assessment(gate, read_existing=True)
            if proof != expected.recovery_receipt:
                raise ValueError("original whole assessment proof stale")
            gate._terminal(proof, "DELIVERY_ENTERED")
            actual = check_history_contextual_evaluation(
                expected.assessment.evaluation, gate._packet_raw
            )
            if actual is not expected.outcome:
                raise ValueError("original complete assessment outcome changed")
            # Derive visible text from the exact retained bytes that were reviewed.
            packet = decode_history_contextual_packet(gate._packet_raw)
            candidate = (
                render_history_packet_preview(packet.review, gate._generation._request)
                if actual is ContextualOutcome.REVIEWED_PASS
                else None
            )
            before_owner_native = _NATIVE_MONOTONIC()
            at = gate._generation._owner()
            original_wall_end = min(
                expected.assessment.review_claim.expires_at,
                gate._generation._consent.original_session_expires_at,
            )
            remaining_original_wall = (original_wall_end - at).total_seconds()
            if remaining_original_wall <= 0:
                raise ValueError("original complete publication wall interval expired")
            delivery_deadline = min(
                gate._deadline, before_owner_native + remaining_original_wall
            )
            # No configurable runtime/artifact/owner adapter after final owner.
            # Repeat exact scalar canonical currency under the original lock.
            p = gate._generation
            with p._factory() as session:
                session.begin()
                _lock(session, p._consent.id)
                entry = _physical(session)
                gate._current(
                    session,
                    assessment=gate._assessment,
                    reference=gate._assessment_reference,
                )
                p._receipt_current(session, proof)
                _same(session, entry)
                gate._require("DELIVERY_ENTERED")
            if _NATIVE_MONOTONIC() >= delivery_deadline:
                raise ValueError("original reviewer interval expired before plaintext return")
            if expected is not gate._result:
                raise ValueError("original retained assessment changed during owner observation")
            result = candidate
            gate._phase = "DELIVERY_RELEASED"
            return result
    except PersonalFragmentCleanupUncertain:
        uncertain = True
    except (KeyboardInterrupt, SystemExit) as error:
        interrupted = error
    except Exception:  # noqa: BLE001,S110
        pass
    finally:
        if (
            entered
            and result is None
            and type(gate) is CanonicalPersonalHistoryReviewAuthorization
            and gate._phase != "DELIVERY_RELEASED"
        ):
            gate._hold()
    if uncertain:
        raise PersonalFragmentCleanupUncertain("PERSONAL complete delivery cleanup uncertain")
    if interrupted is not None:
        raise type(interrupted)() from None
    raise HistoryPublicationReviewError("complete reviewed response withheld")


def _assert_complete_review_record_fit(
    publication: object,
    *,
    rubric_utf8: bytes = b"",
    template_utf8: bytes = b"",
) -> tuple[int, int]:
    """Conservative existing-schema record fit only, never canonical identities.

    Future Source IDs/digests below are distinct fixed-width sizing values. None
    is returned, stored, authorized or used as provenance. Actual canonical
    identities, complete prompt fit, rights and one-use checks remain mandatory.
    """
    from datetime import UTC, timedelta

    from zacai.intelligence.contextual_evaluation import ContextualAssessment, ContextualCriterion
    from zacai.intelligence.history_generation_review_declaration import (
        HistoryGenerationReviewDeclarationV1,
    )
    from zacai.intelligence.history_review_retention import _parts
    from zacai.intelligence.review_evaluation import ReviewJudgment

    if type(publication) is not HistoryGenerationReviewDeclarationV1:
        raise ValueError("exact prospective declaration required")
    _, consent, _ = _parts(publication)
    if len(consent.provenance) > 88:
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
        return EvidenceReference(
            source_id=sid,
            content_hash="f" * 64,
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )

    association, packet, declaration, admission, generation_claim = (
        future_reference() for _ in range(5)
    )
    at = (consent.approved_at + (consent.expires_at - consent.approved_at) / 2).astimezone(UTC)
    if at.microsecond == 0:
        at += timedelta(microseconds=1)
    maximum_float = 1.7976931348623157e308
    selected = tuple(
        sorted(
            (*consent.provenance, association, packet, declaration, admission, generation_claim),
            key=lambda ref: str(ref.source_id),
        )
    )
    claim = HistoryPublicationReviewClaimV1(
        generation_id=consent.id,
        run_id=profile.run_id,
        reviewer_id=profile.reviewer_id,
        attempt_id=UUID(int=1),
        task_id=consent.task_id,
        builder_id=consent.builder_id,
        association_reference=association,
        association_digest=association.content_hash,
        packet_reference=packet,
        publication_reference=declaration,
        publication_digest="f" * 64,
        admission_reference=admission,
        admission_digest=admission.content_hash,
        generation_claim_reference=generation_claim,
        generation_claim_digest=generation_claim.content_hash,
        review_profile=profile,
        review_profile_digest=history_review_profile_digest(profile),
        prepared_request_digest="f" * 64,
        prepared_body_digest="f" * 64,
        wire_body_digest="f" * 64,
        route_digest="f" * 64,
        runtime_profile_digest="f" * 64,
        authorization_graph_digest="f" * 64,
        model_metadata_digest="f" * 64,
        mechanical_descriptor_digest="f" * 64,
        original_deadline_monotonic=maximum_float,
        measured_input_tokens=profile.context_window_tokens - profile.max_output_tokens,
        requested_output_tokens=profile.max_output_tokens,
        original_session_binding=consent.original_session_binding,
        original_approved_at=consent.approved_at,
        expires_at=consent.expires_at,
        consumed_at=at,
        selected_references=selected,
    )
    claim_raw = encode_history_publication_review_claim(claim)
    judgments = tuple(
        ContextualAssessment(criterion=criterion, judgment=ReviewJudgment.UNREVIEWED)
        for criterion in ContextualCriterion
    )
    evaluation = ContextualEvaluation(
        format="zac-contextual-evaluation-v1",
        evaluation_id=profile.run_id,
        task_id=consent.task_id,
        reviewer_id=profile.reviewer_id,
        builder_id=consent.builder_id,
        evaluated_at=at,
        packet_digest=packet.content_hash,
        assessments=judgments,
    )
    usage = UsageObservation(
        input_tokens=claim.measured_input_tokens,
        output_tokens=profile.max_output_tokens,
        latency_ms=maximum_float,
        cost_usd=maximum_float,
    )
    own = future_reference().model_copy(update={"content_hash": content_hash_of(claim_raw)})
    assessment = HistoryPublicationAssessmentV1(
        evaluation=evaluation,
        review_claim_reference=own,
        review_claim=claim,
        released_judgments_digest=content_hash_of(
            canonical_bytes(
                HistoryReviewJudgments(
                    format="zac-history-complete-review-judgments-v1", assessments=judgments
                ).model_dump(mode="json")
            )
        ),
        released_usage_digest=content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
        usage=usage,
        captured_at=at,
    )
    assessment_raw = encode_history_publication_assessment(assessment)
    if type(rubric_utf8) is not bytes or type(template_utf8) is not bytes:
        raise ValueError("exact optional declared review text bytes required")
    from zacai.intelligence.history_review_preparation import _text

    # The packet retains request_json as an exact JSON string. The actual
    # preparer includes that packet and this schema/rubric/template as distinct
    # values. This is a necessary lower bound, never a full prompt/token fit.
    minimum = (
        len(canonical_bytes({"v": publication.generation_request_json}))
        - 6
        + len(canonical_bytes(HistoryReviewJudgments.model_json_schema()))
    )
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
