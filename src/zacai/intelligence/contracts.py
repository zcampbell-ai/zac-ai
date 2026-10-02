"""Validated D032 declarations, not permissions or canonical-state writes.

Only the trusted host may resolve evidence, label data, register routes, supply
authorization, or dispatch work. These declarations cannot prove a caller's
claims about provenance or runtime locality. Model output remains a proposal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Final, Literal, Protocol, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from zacai.gateway import ActionType
from zacai.policy import DataClassification, Destination, TrustBoundary

Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100_000)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Confidence = Annotated[float, Field(ge=0, le=1, strict=True)]
NonNegative = Annotated[float, Field(ge=0, strict=True)]
PositiveInt = Annotated[int, Field(gt=0, strict=True)]
EVENT_CONTRACT_VERSION: Final = 1
TASK_CONTRACT_VERSION: Final = 1
RESULT_CONTRACT_VERSION: Final = 1

_CLASSIFICATION_RANK = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.HIGHLY_RESTRICTED: 3,
}


def classification_covers(label: DataClassification, evidence: DataClassification) -> bool:
    """Ordering only; access decisions remain exclusively in zacai.policy."""
    return _CLASSIFICATION_RANK[label] >= _CLASSIFICATION_RANK[evidence]


class Contract(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", allow_inf_nan=False, revalidate_instances="always"
    )

    @field_validator("contract_version", mode="before", check_fields=False)
    @classmethod
    def exact_version(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("unsupported contract version; expected integer 1")
        return value


class EvidenceReference(Contract):
    """Host-resolved snapshot; not proof of access or current classification."""

    source_id: UUID
    content_hash: Digest
    trust_boundary: TrustBoundary
    effective_classification: DataClassification


class EntityReference(Contract):
    """An unresolved declaration; host must verify existence/boundary/version.

    D032 checks shape and event-boundary consistency, not canonical resolution.
    This must never be treated as proof of a real entity or access permission.
    """

    entity_type: Identifier
    entity_id: UUID
    trust_boundary: TrustBoundary
    version: PositiveInt | None = None


class Importance(str, Enum):
    URGENT = "URGENT"
    IMPORTANT = "IMPORTANT"
    FYI = "FYI"
    NOISE = "NOISE"


class ProcessingStatus(str, Enum):
    NEW = "NEW"
    PROCESSED = "PROCESSED"
    FAILED = "FAILED"


class ZacEvent(Contract):
    """One canonical envelope, distinct from a persisted Event entity.

    v1 covers source-backed events. It has no arbitrary payload, commands,
    credential fields or authority fields. Processing status describes this
    snapshot; constructing a later snapshot never updates a stored state row.
    """

    contract_version: Literal[1] = EVENT_CONTRACT_VERSION
    event_id: UUID
    event_type: Identifier
    producer: Identifier
    occurred_at: AwareDatetime
    observed_at: AwareDatetime
    trust_boundary: TrustBoundary
    data_classification: DataClassification
    provenance: tuple[EvidenceReference, ...] = Field(min_length=1)
    related_entities: tuple[EntityReference, ...] = ()
    correlation_id: UUID
    causation_id: UUID | None = None
    importance: Importance
    confidence: Confidence
    processing_status: ProcessingStatus = ProcessingStatus.NEW

    @field_validator("occurred_at", "observed_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def valid_provenance(self) -> Self:
        source_ids = [ref.source_id for ref in self.provenance]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("duplicate source IDs in event provenance")
        for ref in self.provenance:
            if ref.trust_boundary != self.trust_boundary:
                raise ValueError("event provenance must retain the exact event boundary")
            if not classification_covers(self.data_classification, ref.effective_classification):
                raise ValueError("event classification is weaker than its evidence")
        if any(ref.trust_boundary != self.trust_boundary for ref in self.related_entities):
            raise ValueError("related entities must retain the exact event boundary")
        return self


class ContextItem(Contract):
    reference: EvidenceReference
    untrusted_text: Text


class IntelligenceTask(Contract):
    contract_version: Literal[1] = TASK_CONTRACT_VERSION
    task_id: UUID
    event: ZacEvent
    required_capabilities: frozenset[Identifier] = Field(min_length=1)
    instruction: Text
    context: tuple[ContextItem, ...] = Field(min_length=1)
    max_latency_ms: PositiveInt
    max_estimated_cost_usd: NonNegative
    max_output_tokens: PositiveInt

    @model_validator(mode="after")
    def context_matches_event(self) -> Self:
        provenance = {ref.source_id: ref for ref in self.event.provenance}
        seen: set[UUID] = set()
        for item in self.context:
            ref = item.reference
            if ref.source_id in seen:
                raise ValueError("duplicate context source ID")
            seen.add(ref.source_id)
            if provenance.get(ref.source_id) != ref:
                raise ValueError("context reference must exactly match event provenance")
        return self


class RouteIdentity(Contract):
    provider_id: Identifier
    model_id: Identifier
    runtime_id: Identifier


class ModelRoute(Contract):
    """Trusted host registration; estimated figures are never measurements.

    Runtime destination must be supplied by trusted configuration, never inferred
    from the provider's name or asserted by task content. No credentials here.
    Character capacity is deliberately an explicit v1 unit, not a token estimate.
    """

    identity: RouteIdentity
    destination: Destination
    capabilities: frozenset[Identifier] = Field(min_length=1)
    max_input_characters: PositiveInt
    max_output_tokens: PositiveInt
    estimated_latency_ms: NonNegative
    estimated_cost_usd: NonNegative
    available: bool = Field(strict=True)


class FindingKind(str, Enum):
    SUMMARY = "SUMMARY"
    DECISION_CANDIDATE = "DECISION_CANDIDATE"
    COMMITMENT_CANDIDATE = "COMMITMENT_CANDIDATE"


class Finding(Contract):
    kind: FindingKind
    text: Text
    source_ids: tuple[UUID, ...] = Field(min_length=1)
    confidence: Confidence
    data_classification: DataClassification

    @field_validator("source_ids")
    @classmethod
    def distinct_sources(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate finding evidence")
        return value


class ExecutionProposal(Contract):
    """A recommendation only: no execution method, approval or credential."""

    action_type: ActionType
    target_reference: Identifier
    description: Text
    source_ids: tuple[UUID, ...] = Field(min_length=1)
    data_classification: DataClassification

    @field_validator("source_ids")
    @classmethod
    def distinct_sources(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate execution proposal evidence")
        return value


class UsageObservation(Contract):
    input_tokens: Annotated[int, Field(ge=0, strict=True)]
    output_tokens: Annotated[int, Field(ge=0, strict=True)]
    latency_ms: NonNegative
    cost_usd: NonNegative | None = None


class ResultStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class FailureCode(str, Enum):
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"


class IntelligenceResult(Contract):
    contract_version: Literal[1] = RESULT_CONTRACT_VERSION
    task_id: UUID
    route: RouteIdentity
    status: ResultStatus
    findings: tuple[Finding, ...] = ()
    execution_proposals: tuple[ExecutionProposal, ...] = ()
    usage: UsageObservation | None = None
    failure_code: FailureCode | None = None

    @model_validator(mode="after")
    def consistent_status(self) -> Self:
        if self.status == ResultStatus.FAILED:
            if self.failure_code is None or self.findings or self.execution_proposals:
                raise ValueError("failure requires a code and must not carry partial proposals")
        elif self.failure_code is not None:
            raise ValueError("success must not carry a failure code")
        return self


class IntelligenceProvider(Protocol):
    """Replaceable adapter; host owns dispatch, credentials and authorization.

    Implementations are trusted code, not sandboxed by this Protocol. D032 ships
    no live implementation. Returning a result never promotes or executes it.
    """

    def infer(self, task: IntelligenceTask, /) -> IntelligenceResult: ...


def validate_result_for_task(
    result: IntelligenceResult, task: IntelligenceTask, route: ModelRoute
) -> IntelligenceResult:
    """Validate linkage and claimed evidence; host still verifies source support.

    Call at the adapter boundary before accepting output. No state writes, action
    execution, retry or privacy-changing fallback happens here.
    Passing linkage validation does not authorize the route: a future dispatcher
    must only dispatch/accept routes in its current EligibilityReport.eligible_routes.
    """
    result = IntelligenceResult.model_validate(result)
    task = IntelligenceTask.model_validate(task)
    route = ModelRoute.model_validate(route)
    if result.task_id != task.task_id or result.route != route.identity:
        raise ValueError("result task/route identity does not match the dispatched request")
    references = {item.reference.source_id: item.reference for item in task.context}
    proposals: tuple[Finding | ExecutionProposal, ...] = (
        *result.findings,
        *result.execution_proposals,
    )
    for proposal in proposals:
        if not classification_covers(proposal.data_classification, task.event.data_classification):
            raise ValueError("result classification is weaker than the task event")
        for source_id in proposal.source_ids:
            if source_id not in references:
                raise ValueError("result cites evidence outside the supplied context")
            if not classification_covers(
                proposal.data_classification, references[source_id].effective_classification
            ):
                raise ValueError("result classification is weaker than cited evidence")
    if result.usage is not None and result.usage.output_tokens > task.max_output_tokens:
        raise ValueError("reported output exceeds the task output limit")
    return result
