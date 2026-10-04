"""Read-only trusted preparation of exact trial metadata; never creates consent.

Preparation needs independently authorized BRAINSTORM source reads. No arbitrary
user input parser, credentials, issuer, generation, canonical writes or upload.
The result contains private metadata only, not transcript or model output.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.contextual_authorization import (
    BrainstormContextualRecoveryGate,
    ContextualConsent,
    prepared_contextual_digest,
)
from zacai.ingestion.artifact_store import ArtifactStore
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.contextual_host import assemble_contextual_context
from zacai.intelligence.contracts import Contract, Digest, ModelRoute
from zacai.intelligence.eligibility import ApprovedRoute, ApprovedRouteRegistry, assess_routes
from zacai.intelligence.local_contextual_runtime import LocalContextualRuntime, prepare_payload
from zacai.intelligence.local_review_runtime import LocalPromptTokenCounter
from zacai.intelligence.review_freshness import review_evidence_digest
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_recovery import BrainstormReviewRecoveryGate, ReviewRecoveryCheckpoint

_BOUNDARIES = frozenset({B.BRAINSTORM})
_LABELS = frozenset({C.CONFIDENTIAL})


class ContextualTrialProposal(Contract):
    builder_id: UUID
    selection: ReviewSelection
    route: ModelRoute
    model_digest: Digest
    prepared_digest: Digest
    evidence_digest: Digest
    source_hashes: tuple[tuple[UUID, Digest], ...] = Field(min_length=1, max_length=11)
    prepared_at: AwareDatetime
    prompt_tokens: int = Field(gt=0, le=8192, strict=True)
    reserved_output_tokens: int = Field(gt=0, le=8192, strict=True)
    context_limit: Literal[8192] = 8192
    serialized_bytes: int = Field(gt=0, le=64000, strict=True)
    max_generation_latency_ms: int = Field(gt=0, strict=True)
    state_recovery_reference: str
    artifact_recovery_reference: str
    credential_recovery_reference: str

    @model_validator(mode="after")
    def capacity(self) -> Self:
        if self.prompt_tokens + self.reserved_output_tokens > self.context_limit:
            raise ValueError("proposal outside current context capacity")
        return self

    # Fresh namespace IDs can slightly change tokenization at actual execution.
    # These measured counts are preparation evidence, not permission or a guarantee.


class ContextualTrialPreparationError(RuntimeError):
    """Fixed diagnostics; omit traceback locals in error reporting."""


def prepare_contextual_trial(
    *,
    factory: sessionmaker[Session],
    engine: Engine,
    artifacts: ArtifactStore,
    selection: ReviewSelection,
    builder_id: UUID,
    route: ModelRoute,
    model_digest: str,
    token_counter: LocalPromptTokenCounter,
    checkpoint: ReviewRecoveryCheckpoint,
    recovery: BrainstormReviewRecoveryGate,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ContextualTrialProposal:
    """Validate target/recovery, assemble exact evidence, metadata-only preflight.

    The consent-shaped recovery view below is NEVER recorded or passed to an
    authority ledger. It grants nothing; it adapts the existing recovery verifier's
    selected-source interface. Human approval must be separately authenticated,
    recorded after revalidation, and consumed by the concrete operator.
    """
    try:
        url = engine.url
        if (
            url.drivername != "postgresql+psycopg"
            or url.host != "127.0.0.1"
            or url.port != 5432
            or url.database not in ("zacai_dev", "zacai_test")
            or url.password
            or url.query
            or factory.kw.get("bind") is not engine
            or not isinstance(recovery, BrainstormReviewRecoveryGate)
            or recovery._engine is not engine
            or recovery._factory is not factory
            or route.destination != Destination.LOCAL
            or "contextual_meeting_review" not in route.capabilities
            or "compact_meeting_review" in route.capabilities
            or token_counter.model_digest != model_digest
            or checkpoint != recovery._checkpoint
        ):
            raise ValueError("controlled preparation required")
        now = clock()
        recovery_view = ContextualConsent(
            id=uuid4(),
            builder_id=builder_id,
            selection=selection,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
            route=route,
            model_digest=model_digest,
            prepared_digest="0" * 64,
            approved_at=now,
            expires_at=now + timedelta(minutes=15),
            human_reference="read-only preparation recovery view; NOT human consent",
            state_recovery_reference=checkpoint.state_reference,
            artifact_recovery_reference=checkpoint.artifact_reference,
            credential_recovery_reference=checkpoint.credential_reference,
        )
        BrainstormContextualRecoveryGate(recovery).preflight(recovery_view)
        context = assemble_contextual_context(
            factory,
            artifacts=artifacts,
            selection=selection,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
            now=clock(),
        )
        registry = ApprovedRouteRegistry((ApprovedRoute(route, _BOUNDARIES, _LABELS),))
        if (
            route.identity
            not in assess_routes(
                context.task, authorized_boundaries=_BOUNDARIES, registry=registry
            ).eligible_routes
        ):
            raise ValueError("route unavailable")
        request = prepare_contextual_request(context)
        runtime = LocalContextualRuntime(
            route=route, model_digest=model_digest, token_counter=token_counter
        )
        runtime.preflight(request)  # names/metadata only; never /api/chat
        body = prepare_payload(request, route, model_digest)
        count = runtime._token_count(body, request)
        current = assemble_contextual_context(
            factory,
            artifacts=artifacts,
            selection=selection,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
            now=clock(),
        )
        if review_evidence_digest(current) != review_evidence_digest(context):
            raise ValueError("evidence changed during preparation")
        return ContextualTrialProposal(
            builder_id=builder_id,
            selection=selection,
            route=route,
            model_digest=model_digest,
            prepared_digest=prepared_contextual_digest(request),
            evidence_digest=review_evidence_digest(context),
            source_hashes=tuple(
                (i.reference.source_id, i.reference.content_hash) for i in context.task.context
            ),
            prepared_at=clock(),
            prompt_tokens=count,
            reserved_output_tokens=context.task.max_output_tokens,
            serialized_bytes=len(body),
            max_generation_latency_ms=context.task.max_latency_ms,
            state_recovery_reference=checkpoint.state_reference,
            artifact_recovery_reference=checkpoint.artifact_reference,
            credential_recovery_reference=checkpoint.credential_reference,
        )
    except Exception:  # noqa: BLE001, S110 - no source/backend diagnostics
        pass
    raise ContextualTrialPreparationError(
        "contextual trial preparation unavailable; no approval or dispatch"
    )
