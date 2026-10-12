"""Dormant complete USER source-to-declaration preparation, no APPROVE UI."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
from zacai.claude_original_capture import ClaudeArtifactRootIdentity, observe_claude_artifact_root
from zacai.claude_original_read import load_claude_original
from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import _history_request_provenance
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask, ModelRoute
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_context_metadata import (
    ClaudeMessageMetadata,
    HistoryMessageSpan,
    prepare_claude_history_context_preview,
)
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualRequestV1,
    encode_history_contextual_request,
    prepare_history_contextual_request,
)
from zacai.intelligence.history_declaration_protection import (
    PersonalHistoryDeclarationReceiptV1,
    protect_history_declaration,
)
from zacai.intelligence.history_generation_review_declaration import (
    GENERATION_WIRE_V2,
    HistoryConsentV1,
    HistoryReviewPurposeProfileV1,
    prepare_history_generation_review_declaration,
    prepare_history_generation_wire,
)
from zacai.intelligence.history_review_retention import (
    HistoryDeclarationContext,
    RetainedHistoryDeclarationV1,
    capture_history_review_declaration,
    history_declaration_owner,
    load_history_review_declaration,
)
from zacai.intelligence.local_contextual_runtime import (
    _context_tokens,
    fragment_contextual_counter_pins,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.fragment_preparation_web import _instruction
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.personal_fragment_factory import _owner
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, assert_local_review_state_engine


class PersonalHistoryFactoryError(ValueError):
    """Fixed HOLD; retained declaration may already be committed, never retry."""


@dataclass(frozen=True, repr=False)
class PersonalHistoryTaskConfiguration:
    factory: sessionmaker[Session]
    engine: Engine
    artifacts: LocalFilesystemArtifactStore
    expected_root: ClaudeArtifactRootIdentity
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    expected_account_ref: str
    expected_exported_at: datetime | None
    selections: tuple[HistoryMessageSpan, ...]
    original_context: ReviewContext
    route: ModelRoute
    generation_id: UUID
    builder_id: UUID
    expires_at: datetime
    generation_counter: OllamaQwenContextualTokenCounter
    generation_runtime_digest: str  # declared prospective implementation pin, not readiness
    review_profile: HistoryReviewPurposeProfileV1
    cold_artifacts: LocalFilesystemArtifactStore
    objects: LocalDirectoryBackupStore | S3CompatibleBackupObjectStore
    verification_objects: LocalDirectoryBackupStore | S3CompatibleBackupObjectStore
    recipient: str
    identity_path: Path
    manifest_cache: Path
    restoration: DisposableStateRestoreVerifier


@dataclass(frozen=True, repr=False)
class PreparedPersonalHistoryDeclaration:
    retained: RetainedHistoryDeclarationV1
    request: HistoryContextualRequestV1
    generation_wire: bytes
    receipt: PersonalHistoryDeclarationReceiptV1
    protector: PersonalHistoryFragmentProtector

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def prepare_personal_history_task(
    configuration: PersonalHistoryTaskConfiguration,
    *,
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    instruction: str,
) -> PreparedPersonalHistoryDeclaration:
    """Actual reader/count/commit/reopen/whole recovery, no processing action.

    Selections are separately reviewed host configuration, not a relevance proof.
    No model/network call is made, no browser controller or APPROVE is returned.
    Required runtime pin/review profile remain prospective until concrete joined
    consumers exist; a mechanical checkpoint cannot admit unavailable review.
    """
    result = None
    uncertain = False
    try:
        instruction = _instruction(instruction)
        c = configuration
        if (
            type(c) is not PersonalHistoryTaskConfiguration
            or type(inputs) is not NamedOwnerHostInputs
            or type(operation) is not NamedSessionOperation
            or type(c.original_context) is not ReviewContext
            or c.original_context.task.event.trust_boundary is not B.PERSONAL
            or c.original_context.task.event.data_classification is not C.HIGHLY_RESTRICTED
            or type(c.route) is not ModelRoute
            or c.route.destination is not Destination.LOCAL
            or type(c.generation_counter) is not OllamaQwenContextualTokenCounter
            or type(c.review_profile) is not HistoryReviewPurposeProfileV1
            or type(c.generation_runtime_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", c.generation_runtime_digest) is None
            or c.factory.kw.get("bind") is not c.engine
            or c.factory.kw.get("binds")
            or type(c.selections) is not tuple
            or not 1 <= len(c.selections) <= 64
            or any(type(selection) is not HistoryMessageSpan for selection in c.selections)
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
            raise ValueError("explicit reviewed complete PERSONAL configuration required")
        task = IntelligenceTask.model_validate(
            {**c.original_context.task.model_dump(), "instruction": instruction}
        )
        if task.instruction != instruction:
            raise ValueError("exact original instruction required")
        original = ReviewContext(
            task, c.original_context.meeting_source_id, c.original_context.related_source_ids
        )
        assert_local_review_state_engine(c.engine)
        current = _owner(inputs, operation)
        with inputs.clock._lock:
            prepared_at = inputs.clock._last
        if (
            prepared_at is None
            or not prepared_at < c.expires_at <= current.effective_expires_at
            or c.expires_at - prepared_at > timedelta(minutes=15)
            or observe_claude_artifact_root(c.artifacts) != c.expected_root
        ):
            raise ValueError("original fixed preparation window/root required")
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
        preview = prepare_claude_history_context_preview(
            original, read, selections=c.selections, observed_at=prepared_at, route=c.route
        )
        if any(
            type(entry) is not ClaudeMessageMetadata or entry.historical_role != "USER"
            for entry in preview.sidecar.entries
        ):
            raise ValueError("complete USER selection required for first writing preparation")
        request = prepare_history_contextual_request(
            preview, original_context=original, route=c.route
        )
        provenance = _history_request_provenance(request)
        if len(provenance) > 89:
            raise ValueError("complete later review inventory capacity exceeded")
        wire = prepare_history_generation_wire(request, generation_wire_format=GENERATION_WIRE_V2)
        count = c.generation_counter.count_prompt_tokens(wire)
        _owner(inputs, operation, current.binding_digest)
        if (
            type(count) is not int
            or count <= 0
            or count + request.task.max_output_tokens > _context_tokens(request.route)
        ):
            raise ValueError("actual complete generation wire does not fit")
        tokenizer, template, renderer = fragment_contextual_counter_pins(c.generation_counter)
        _owner(inputs, operation, current.binding_digest)
        generation = HistoryConsentV1(
            id=c.generation_id,
            builder_id=c.builder_id,
            task_id=request.task.task_id,
            request_digest=content_hash_of(encode_history_contextual_request(request)),
            provenance=provenance,
            owner_issuer=current.principal.identity.issuer,
            owner_subject=current.principal.identity.subject,
            original_session_binding=current.binding_digest,
            original_session_issued_at=current.issued_at,
            original_session_expires_at=current.effective_expires_at,
            approved_at=prepared_at,
            expires_at=c.expires_at,
            human_reference="Prospective complete task preparation; full browser approval pending",
            route=c.route,
            model_digest=c.generation_counter.model_digest,
            tokenizer_digest=tokenizer,
            runtime_digest=c.generation_runtime_digest,
            template_digest=template,
            renderer_digest=renderer,
            body_digest=content_hash_of(request.prompt_body.encode()),
            generation_wire_format=GENERATION_WIRE_V2,
            generation_wire_digest=content_hash_of(wire),
            prompt_tokens=count,
            max_output_tokens=request.task.max_output_tokens,
        )
        declaration = prepare_history_generation_review_declaration(
            generation, request, review=c.review_profile
        )
        history_declaration_owner(operation, inputs.clock, generation)
        with inputs.clock._lock:
            observed = inputs.clock._last
        if (
            observed is None
            or (c.expires_at - observed).total_seconds() * 1000
            < request.task.max_latency_ms + c.review_profile.max_latency_ms
        ):
            raise ValueError("unchanged original processing interval cannot fit")
        context = HistoryDeclarationContext(
            c.expected_root, c.expected_account_ref, c.expected_exported_at
        )
        retained = capture_history_review_declaration(
            factory=c.factory,
            artifacts=c.artifacts,
            context=context,
            declaration=declaration,
            operation=operation,
            clock=inputs.clock,
        )
        history_declaration_owner(operation, inputs.clock, generation)
        with c.factory() as session:
            session.begin()
            entry = _physical(session)
            reopened = load_history_review_declaration(
                session,
                artifacts=c.artifacts,
                context=context,
                reference=retained.reference,
                expected_declaration=declaration,
            )
            _same(session, entry)
            if reopened != retained:
                raise ValueError("actual committed complete declaration differs")
        history_declaration_owner(operation, inputs.clock, generation)
        receipt = protect_history_declaration(
            protector,
            reference=retained.reference,
            expected_declaration=declaration,
            context=context,
        )
        history_declaration_owner(operation, inputs.clock, generation)
        plan = protector._plan()
        if (
            receipt.publication_reference != retained.reference
            or receipt.publication_digest != retained.publication_digest
            or receipt.generation_wire_digest != content_hash_of(wire)
            or content_hash_of(plan.rows) != receipt.full_plan_digest
            or content_hash_of(protector._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest
        ):
            raise ValueError("terminal complete checkpoint changed")
        result = PreparedPersonalHistoryDeclaration(retained, request, wire, receipt, protector)
    except PersonalFragmentCleanupUncertain:
        uncertain = True
    except Exception:  # noqa: BLE001
        result = None
    if uncertain:
        raise PersonalFragmentCleanupUncertain(
            "PERSONAL complete preparation cleanup uncertain; operator review required"
        )
    if result is None:
        raise PersonalHistoryFactoryError(
            "PERSONAL complete preparation unavailable; reconcile before retry"
        )
    return result
