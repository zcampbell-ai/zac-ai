"""Trusted dormant source-to-declaration factory; no browser approval minted."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai import contextual_authorization as auth
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
from zacai.claude_historical_fragment import prepare_claude_historical_fragment
from zacai.claude_original_capture import ClaudeArtifactRootIdentity
from zacai.claude_original_read import load_claude_original
from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import _fragment_request_provenance
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask, ModelRoute
from zacai.intelligence.fragment_review_declaration import (
    FragmentReviewPurposeProfileV1,
    prepare_fragment_generation_review_declaration,
)
from zacai.intelligence.fragment_review_prompt_counter import OllamaQwenFragmentReviewTokenCounter
from zacai.intelligence.fragment_review_retention import (
    _physical,
    _same,
    capture_fragment_review_declaration,
    load_fragment_review_declaration,
)
from zacai.intelligence.fragment_review_runtime import FragmentReviewRuntimeProfile
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
    prepare_history_fragment_contextual_request,
)
from zacai.intelligence.local_contextual_runtime import (
    _context_tokens,
    fragment_contextual_counter_pins,
    fragment_contextual_runtime_digest,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.fragment_preparation_web import _instruction
from zacai.interfaces.fragment_publication_web import (
    FragmentPublicationWeb,
    _assert_fragment_publication_configuration,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, assert_local_review_state_engine


class PersonalFragmentFactoryError(ValueError):
    """Hold without retry; prospective canonical publication may be committed."""


@dataclass(frozen=True, repr=False)
class PersonalFragmentTaskConfiguration:
    """Reviewed explicit host inputs, not credentials, consent or a receipt."""

    factory: sessionmaker[Session]
    engine: Engine
    artifacts: LocalFilesystemArtifactStore
    expected_root: ClaudeArtifactRootIdentity
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    expected_account_ref: str
    expected_exported_at: datetime | None
    message_id: UUID
    character_start: int
    character_end: int
    original_context: ReviewContext
    route: ModelRoute
    generation_id: UUID
    builder_id: UUID
    expires_at: datetime
    generation_counter: OllamaQwenContextualTokenCounter
    review_counter: OllamaQwenFragmentReviewTokenCounter
    review_profile: FragmentReviewPurposeProfileV1
    review_runtime_profile: FragmentReviewRuntimeProfile
    rubric_utf8: bytes
    template_utf8: bytes
    cold_artifacts: LocalFilesystemArtifactStore
    objects: LocalDirectoryBackupStore | S3CompatibleBackupObjectStore
    verification_objects: LocalDirectoryBackupStore | S3CompatibleBackupObjectStore
    recipient: str
    identity_path: Path
    manifest_cache: Path
    restoration: DisposableStateRestoreVerifier


def _owner(
    inputs: NamedOwnerHostInputs, operation: NamedSessionOperation, binding: str | None = None
) -> VerifiedNamedSession:
    inputs.clock()
    owner = operation.establish() if binding is None else operation.recheck(binding)
    if (
        operation._source._sessions is not inputs.sessions
        or operation._source._owner is not inputs.owner
        or operation.host_clock is not inputs.clock
        or owner.principal.scopes != auth._FRAGMENT_OWNER_SCOPE
    ):
        raise ValueError("actual original PERSONAL owner required")
    return owner


def prepare_personal_fragment_task(
    configuration: PersonalFragmentTaskConfiguration,
    *,
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    instruction: str,
) -> FragmentPublicationWeb:
    """Capture/reopen/protect prospective full declaration, never approve it.

    Invoke only through reviewed request preparation. Actual source custody/read
    and recovery credential geography are separate owner-approved prerequisites.
    The existing later original-browser APPROVE is the sole processing action.
    """
    result = None
    cleanup_uncertain = False
    try:
        instruction = _instruction(instruction)
        c = configuration
        if (
            type(c) is not PersonalFragmentTaskConfiguration
            or type(inputs) is not NamedOwnerHostInputs
            or type(operation) is not NamedSessionOperation
            or type(c.original_context) is not ReviewContext
            or c.original_context.task.event.trust_boundary is not B.PERSONAL
            or c.original_context.task.event.data_classification is not C.HIGHLY_RESTRICTED
            or type(c.route) is not ModelRoute
            or c.route.destination is not Destination.LOCAL
            or type(c.generation_counter) is not OllamaQwenContextualTokenCounter
            or type(c.review_counter) is not OllamaQwenFragmentReviewTokenCounter
            or type(c.review_profile) is not FragmentReviewPurposeProfileV1
            or c.factory.kw.get("bind") is not c.engine
            or c.factory.kw.get("binds")
            or type(c.expires_at) is not datetime
            or c.expires_at.utcoffset() is None
            or any(
                type(ref) is not EvidenceReference
                or ref.trust_boundary is not B.PERSONAL
                or ref.effective_classification is not C.HIGHLY_RESTRICTED
                for ref in (
                    c.original_reference,
                    c.companion_reference,
                    *c.original_context.task.event.provenance,
                    *(item.reference for item in c.original_context.task.context),
                )
            )
        ):
            raise ValueError("reviewed concrete PERSONAL configuration required")
        original_task = IntelligenceTask.model_validate({
            **c.original_context.task.model_dump(), "instruction": instruction,
        })
        if original_task.instruction != instruction:
            raise ValueError("exact untrimmed owner instruction required")
        original_context = ReviewContext(original_task,
            c.original_context.meeting_source_id, c.original_context.related_source_ids)
        assert_local_review_state_engine(c.engine)
        current = _owner(inputs, operation)
        with inputs.clock._lock:
            prepared_at = inputs.clock._last
        if (
            prepared_at is None
            or not prepared_at < c.expires_at <= current.effective_expires_at
            or c.expires_at - prepared_at > timedelta(minutes=15)
        ):
            raise ValueError("fixed original preparation window required")
        protector = PersonalHistoryFragmentProtector(
            factory=c.factory,
            engine=c.engine,
            artifacts=c.artifacts,
            cold_artifacts=c.cold_artifacts,
            objects=c.objects,
            verification_objects=c.verification_objects,
            recipient=c.recipient,
            identity_path=c.identity_path,
            manifest_cache=c.manifest_cache,
            operation=operation,
            clock=inputs.clock,
            restoration=c.restoration,
        )
        with c.factory() as session:
            session.begin()
            entry = _physical(session)
            read = load_claude_original(
                session,
                artifacts=c.artifacts,
                expected_root=c.expected_root,
                original_reference=c.original_reference,
                companion_reference=c.companion_reference,
                expected_account_ref=c.expected_account_ref,
                expected_exported_at=c.expected_exported_at,
                requestor_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
            )
            _same(session, entry)
        _owner(inputs, operation, current.binding_digest)
        fragment = prepare_claude_historical_fragment(
            read,
            message_id=c.message_id,
            character_start=c.character_start,
            character_end=c.character_end,
        )
        request = prepare_history_fragment_contextual_request(
            original_context,
            fragment,
            observed_at=prepared_at,
            route=c.route,
        )
        provenance = _fragment_request_provenance(request)
        if len(provenance) > 89:
            raise ValueError("full publication review provenance capacity exceeded")
        prompt = request.prompt_body.encode("utf-8")
        count = c.generation_counter.count_prompt_tokens(prompt)
        if (
            type(count) is not int
            or count <= 0
            or (count + request.task.max_output_tokens > _context_tokens(request.route))
        ):
            raise ValueError("exact complete generation body does not fit")
        tokenizer, template, renderer = fragment_contextual_counter_pins(c.generation_counter)
        generation = auth.HistoryFragmentConsentV1(
            id=c.generation_id,
            builder_id=c.builder_id,
            task_id=request.task.task_id,
            request_digest=content_hash_of(encode_history_fragment_contextual_request(request)),
            provenance=provenance,
            owner_issuer=current.principal.identity.issuer,
            owner_subject=current.principal.identity.subject,
            original_session_binding=current.binding_digest,
            original_session_issued_at=current.issued_at,
            original_session_expires_at=current.effective_expires_at,
            approved_at=prepared_at,
            expires_at=c.expires_at,
            human_reference="Prospective task preparation; full browser approval pending",
            route=request.route,
            model_digest=c.generation_counter.model_digest,
            tokenizer_digest=tokenizer,
            runtime_digest=fragment_contextual_runtime_digest(),
            template_digest=template,
            renderer_digest=renderer,
            body_digest=content_hash_of(prompt),
            prompt_tokens=count,
            max_output_tokens=request.task.max_output_tokens,
        )
        declaration = prepare_fragment_generation_review_declaration(
            generation,
            request,
            review=c.review_profile,
        )
        _owner(inputs, operation, current.binding_digest)
        with inputs.clock._lock:
            observed = inputs.clock._last
        review = declaration.review
        if (
            observed is None
            or review is None
            or (c.expires_at - observed).total_seconds() * 1000
            < request.task.max_latency_ms + review.max_latency_ms
        ):
            raise ValueError("original processing window cannot fit")
        _assert_fragment_publication_configuration(declaration,
            generation_counter=c.generation_counter, review_counter=c.review_counter,
            review_runtime_profile=c.review_runtime_profile,
            rubric_utf8=c.rubric_utf8, template_utf8=c.template_utf8)
        retained = capture_fragment_review_declaration(
            factory=c.factory,
            artifacts=c.artifacts,
            declaration=declaration,
            operation=operation,
            clock=inputs.clock,
        )
        # Capture owns outer commit/close. Reopen independently before recovery.
        with c.factory() as session:
            session.begin()
            entry = _physical(session)
            reopened = load_fragment_review_declaration(
                session,
                artifacts=c.artifacts,
                reference=retained.reference,
                expected_declaration=declaration,
            )
            _same(session, entry)
            if reopened != retained:
                raise ValueError("exact committed declaration required")
        _owner(inputs, operation, current.binding_digest)
        receipt = protector.protect_declaration(
            reference=retained.reference,
            expected_declaration=declaration,
        )
        controller = FragmentPublicationWeb(
            continuity=operation._source,
            publication=declaration,
            reference=retained.reference,
            protector=protector,
            generation_counter=c.generation_counter,
            review_counter=c.review_counter,
            review_runtime_profile=c.review_runtime_profile,
            rubric_utf8=c.rubric_utf8,
            template_utf8=c.template_utf8,
            run_approved_task=True,
        )
        _owner(inputs, operation, current.binding_digest)
        with inputs.clock._lock:
            final_observed = inputs.clock._last
        if final_observed is None or not prepared_at <= final_observed < c.expires_at:
            raise ValueError("original declaration expired")
        controller.scalar_release(receipt)
        result = controller
    except PersonalFragmentCleanupUncertain:
        cleanup_uncertain = True
    except BaseException:  # noqa: BLE001 - committed failures require manual reconciliation
        result = None
    if result is None:
        if cleanup_uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL recovery cleanup uncertain; operator review required"
            )
        raise PersonalFragmentFactoryError("local task declaration preparation held")
    return result
