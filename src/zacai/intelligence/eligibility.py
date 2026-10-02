"""D032 deterministic eligibility, not production ranking or dispatch.

The host supplies authorization and its approved route registry separately from
untrusted task content. No registry values are learned from a transcript/model.
The host must resolve current effective classification before each dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from zacai.intelligence.contracts import IntelligenceTask, ModelRoute, RouteIdentity
from zacai.policy import AccessRequest, DataClassification, TrustBoundary, evaluate_access


class ExclusionReason(str, Enum):
    POLICY_DENIED = "POLICY_DENIED"
    ROUTE_BOUNDARY_NOT_APPROVED = "ROUTE_BOUNDARY_NOT_APPROVED"
    ROUTE_CLASSIFICATION_NOT_APPROVED = "ROUTE_CLASSIFICATION_NOT_APPROVED"
    UNAVAILABLE = "UNAVAILABLE"
    MISSING_CAPABILITY = "MISSING_CAPABILITY"
    INPUT_LIMIT = "INPUT_LIMIT"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    COST_LIMIT = "COST_LIMIT"
    LATENCY_LIMIT = "LATENCY_LIMIT"


@dataclass(frozen=True)
class ApprovedRoute:
    """Host-approved runtime descriptor and its explicitly permitted boundaries."""

    route: ModelRoute
    allowed_boundaries: frozenset[TrustBoundary]
    allowed_classifications: frozenset[DataClassification]

    def __post_init__(self) -> None:
        object.__setattr__(self, "route", ModelRoute.model_validate(self.route))
        if not isinstance(self.allowed_boundaries, frozenset) or any(
            not isinstance(boundary, TrustBoundary) for boundary in self.allowed_boundaries
        ):
            raise ValueError("route approvals require a frozenset of TrustBoundary values")
        if not isinstance(self.allowed_classifications, frozenset) or any(
            not isinstance(label, DataClassification) for label in self.allowed_classifications
        ):
            raise ValueError("route approvals require a frozenset of DataClassification values")


@dataclass(frozen=True)
class ApprovedRouteRegistry:
    """Host-only configuration, deliberately outside the JSON task contracts.

    Construct only from trusted configuration; no JSON loader or task-derived
    registration exists. This object is not a sandbox against hostile Python
    code. Runtime approval includes the descriptor's declared destination.
    """

    routes: tuple[ApprovedRoute, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.routes, tuple) or any(
            not isinstance(item, ApprovedRoute) for item in self.routes
        ):
            raise ValueError("registry requires a tuple of host-approved route registrations")
        identities = [item.route.identity for item in self.routes]
        if len(identities) != len(set(identities)):
            raise ValueError("approved route registry contains duplicate route identities")


@dataclass(frozen=True)
class RouteAssessment:
    identity: RouteIdentity
    reasons: tuple[ExclusionReason, ...]

    @property
    def eligible(self) -> bool:
        return not self.reasons


@dataclass(frozen=True)
class EligibilityReport:
    assessments: tuple[RouteAssessment, ...]

    @property
    def eligible_routes(self) -> tuple[RouteIdentity, ...]:
        return tuple(item.identity for item in self.assessments if item.eligible)


def assess_routes(
    task: IntelligenceTask,
    *,
    authorized_boundaries: frozenset[TrustBoundary],
    registry: ApprovedRouteRegistry,
) -> EligibilityReport:
    """Assess every host-approved route; never pick a fallback or execute work.

    Cost and latency are estimates used for eligibility only, not an enforceable
    spending cap or timeout. Input limits count all supplied instruction/context
    text in characters; an adapter's full serialized/tokenized request still needs
    its own capacity check. No eligible route is a terminal report, not permission
    to use an unregistered provider or relax any constraint.
    """
    task = IntelligenceTask.model_validate(task)
    text_size = len(task.instruction) + sum(len(item.untrusted_text) for item in task.context)
    assessments: list[RouteAssessment] = []
    for registration in registry.routes:
        route = registration.route
        reasons: list[ExclusionReason] = []
        if task.event.trust_boundary not in registration.allowed_boundaries:
            reasons.append(ExclusionReason.ROUTE_BOUNDARY_NOT_APPROVED)
        if task.event.data_classification not in registration.allowed_classifications:
            reasons.append(ExclusionReason.ROUTE_CLASSIFICATION_NOT_APPROVED)
        checks = [(task.event.trust_boundary, task.event.data_classification)]
        checks.extend(
            (item.reference.trust_boundary, item.reference.effective_classification)
            for item in task.context
        )
        if any(
            not evaluate_access(
                AccessRequest(
                    data_boundary=boundary,
                    data_classification=classification,
                    requestor_boundaries=authorized_boundaries,
                    destination=route.destination,
                )
            ).allowed
            for boundary, classification in checks
        ):
            reasons.append(ExclusionReason.POLICY_DENIED)
        if not route.available:
            reasons.append(ExclusionReason.UNAVAILABLE)
        if not task.required_capabilities.issubset(route.capabilities):
            reasons.append(ExclusionReason.MISSING_CAPABILITY)
        if text_size > route.max_input_characters:
            reasons.append(ExclusionReason.INPUT_LIMIT)
        if task.max_output_tokens > route.max_output_tokens:
            reasons.append(ExclusionReason.OUTPUT_LIMIT)
        if route.estimated_cost_usd > task.max_estimated_cost_usd:
            reasons.append(ExclusionReason.COST_LIMIT)
        if route.estimated_latency_ms > task.max_latency_ms:
            reasons.append(ExclusionReason.LATENCY_LIMIT)
        assessments.append(RouteAssessment(identity=route.identity, reasons=tuple(reasons)))
    return EligibilityReport(assessments=tuple(assessments))
