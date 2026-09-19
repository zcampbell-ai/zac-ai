"""Deterministic Action/Approval Gateway (D024).

See ARCHITECTURE.md Section 10 ("Approval and Action Gateway"), SECURITY.md
("Agent Permissions", "Human Control"), and DECISIONS.md D007/D023/D024.

This module sits downstream of `zacai.policy.evaluate_access` (D023) and
decides whether an otherwise-permitted operation may execute now, needs
human approval, or is denied outright in v1. It never overrides a policy
denial - see `evaluate_gateway`'s docstring and the D023 "no override"
architecture principle it must satisfy.

Model/provider/orchestration-independent: no connector, database, LLM, or
framework dependency. Deterministic - the same `ActionRequest` always
produces the same `GatewayDecision`.

REQUIRE_APPROVAL is a terminal result in this module: it means execution
must stop and no action may occur until a future, separately designed
approval mechanism (not built by this decision) satisfies the requirement.
That future mechanism must respect these invariants without exception:
- An approval must never override a D023 policy DENY.
- An approval must never override a D024 hard DENY (see `_DENY_ACTIONS`).
- Approval must eventually be bound to the specific action being
  authorized, not represented as a caller-controlled boolean.
- Approval must be auditable.
- Replay/stale-approval risks must be addressed when that system is
  designed.
This module does not define an `ApprovalRecord`, token, persistence, lookup
interface, expiry, or replay protection - that architecture is
intentionally deferred until it is actually designed.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from zacai.policy import AccessRequest, evaluate_access


class ActionType(str, Enum):
    """The kind of operation being attempted.

    Every member here is classified into exactly one of `_ALLOW_ACTIONS`,
    `_REQUIRE_APPROVAL_ACTIONS`, or `_DENY_ACTIONS` below - enforced by
    `test_all_action_types_are_classified`.
    """

    # Read / analyze / recommend - non-executing, informational.
    READ_DATA = "READ_DATA"
    ANALYZE_DATA = "ANALYZE_DATA"
    SUMMARIZE_CONTENT = "SUMMARIZE_CONTENT"
    RECOMMEND_ACTION = "RECOMMEND_ACTION"

    # Draft - non-executing. Structurally separate from the SEND_*/
    # PUBLISH_CONTENT action types it might precede, so no single field
    # anywhere can turn a draft into an executing send.
    DRAFT_CONTENT = "DRAFT_CONTENT"

    # External communication / publishing writes.
    SEND_EMAIL = "SEND_EMAIL"
    SEND_SLACK_MESSAGE = "SEND_SLACK_MESSAGE"
    PUBLISH_CONTENT = "PUBLISH_CONTENT"

    # CRM / task / calendar state changes.
    CREATE_CRM_RECORD = "CREATE_CRM_RECORD"
    UPDATE_CRM_RECORD = "UPDATE_CRM_RECORD"
    DELETE_CRM_RECORD = "DELETE_CRM_RECORD"
    CREATE_TASK = "CREATE_TASK"
    UPDATE_TASK = "UPDATE_TASK"
    DELETE_TASK = "DELETE_TASK"
    CREATE_CALENDAR_EVENT = "CREATE_CALENDAR_EVENT"
    UPDATE_CALENDAR_EVENT = "UPDATE_CALENDAR_EVENT"
    DELETE_CALENDAR_EVENT = "DELETE_CALENDAR_EVENT"

    # Scoped destructive - a single, addressable record.
    DELETE_FILE = "DELETE_FILE"

    # Bulk/unscoped destructive - hard-denied in v1, see _DENY_ACTIONS.
    DELETE_DATA = "DELETE_DATA"

    # Financial - hard-denied in v1.
    SPEND_MONEY = "SPEND_MONEY"

    # Security / production - hard-denied in v1.
    MODIFY_CREDENTIAL = "MODIFY_CREDENTIAL"
    CHANGE_PERMISSION = "CHANGE_PERMISSION"
    MODIFY_PRODUCTION_CONFIG = "MODIFY_PRODUCTION_CONFIG"


class ActionRisk(str, Enum):
    """Risk tier (ARCHITECTURE.md Section 10). Derived internally by
    `evaluate_gateway` - never settable by a caller, so a caller cannot
    self-declare a lower risk to influence the outcome."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class GatewayOutcome(str, Enum):
    """Tri-state gateway outcome. Deliberately not a boolean like
    `PolicyDecision.allowed`: ALLOW and REQUIRE_APPROVAL are both "not
    denied" but must never be conflated, and REQUIRE_APPROVAL and DENY are
    both "does not execute now" but must never be conflated either."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class ActionRequest(BaseModel):
    """A single attempted action, ready for gateway evaluation.

    Immutable by construction, matching `AccessRequest`/`PolicyDecision`.
    Deliberately has no approval/override field of any kind - see the
    module docstring's REQUIRE_APPROVAL invariants and
    `test_action_request_has_no_approval_or_override_field`.
    """

    model_config = ConfigDict(frozen=True)

    action_type: ActionType
    access: AccessRequest
    description: str


class GatewayDecision(BaseModel):
    """The outcome of `evaluate_gateway`. `reason` is always populated, like
    `PolicyDecision.reason`, so every decision is self-explanatory in a log
    line on its own."""

    model_config = ConfigDict(frozen=True)

    outcome: GatewayOutcome
    reason: str
    risk: ActionRisk


_ALLOW_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.READ_DATA,
        ActionType.ANALYZE_DATA,
        ActionType.SUMMARIZE_CONTENT,
        ActionType.RECOMMEND_ACTION,
        ActionType.DRAFT_CONTENT,
    }
)

_REQUIRE_APPROVAL_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.SEND_EMAIL,
        ActionType.SEND_SLACK_MESSAGE,
        ActionType.PUBLISH_CONTENT,
        ActionType.CREATE_CRM_RECORD,
        ActionType.UPDATE_CRM_RECORD,
        ActionType.DELETE_CRM_RECORD,
        ActionType.CREATE_TASK,
        ActionType.UPDATE_TASK,
        ActionType.DELETE_TASK,
        ActionType.CREATE_CALENDAR_EVENT,
        ActionType.UPDATE_CALENDAR_EVENT,
        ActionType.DELETE_CALENDAR_EVENT,
        ActionType.DELETE_FILE,
    }
)

_DENY_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.DELETE_DATA,
        ActionType.SPEND_MONEY,
        ActionType.MODIFY_CREDENTIAL,
        ActionType.CHANGE_PERMISSION,
        ActionType.MODIFY_PRODUCTION_CONFIG,
    }
)

_DEFAULT_RISK_BY_OUTCOME: dict[GatewayOutcome, ActionRisk] = {
    GatewayOutcome.ALLOW: ActionRisk.LOW,
    GatewayOutcome.REQUIRE_APPROVAL: ActionRisk.MEDIUM,
    GatewayOutcome.DENY: ActionRisk.HIGH,
}

# Overrides where an action's risk tier differs from its outcome's default.
# DELETE_FILE is scoped to a single addressable file (unlike the unscoped
# DELETE_DATA, which is a hard DENY), so it remains REQUIRE_APPROVAL - but
# SECURITY.md's "high-risk deletions" language still marks it HIGH risk.
_ACTION_RISK_OVERRIDES: dict[ActionType, ActionRisk] = {
    ActionType.DELETE_FILE: ActionRisk.HIGH,
}


def _decide(
    outcome: GatewayOutcome, reason: str, action_type: ActionType
) -> GatewayDecision:
    risk = _ACTION_RISK_OVERRIDES.get(action_type, _DEFAULT_RISK_BY_OUTCOME[outcome])
    return GatewayDecision(outcome=outcome, reason=reason, risk=risk)


def evaluate_gateway(request: ActionRequest) -> GatewayDecision:
    """Decide whether `request` may execute now, needs human approval, or
    is denied.

    Step 1 (mandatory, first, unconditional): evaluate D023 policy via
    `evaluate_access(request.access)`. If it denies, this function returns
    DENY immediately and stops - action-type classification below is never
    consulted. There is no parameter, flag, or code path anywhere in this
    module that skips or overrides that check.

    Step 2: only once policy allows, classify `request.action_type` into
    exactly one of `_ALLOW_ACTIONS`, `_REQUIRE_APPROVAL_ACTIONS`, or
    `_DENY_ACTIONS` and return the corresponding outcome. An action type
    absent from all three (should be unreachable - see
    `test_all_action_types_are_classified`) fails closed to DENY.
    """
    policy_decision = evaluate_access(request.access)
    if not policy_decision.allowed:
        return _decide(
            GatewayOutcome.DENY,
            f"policy denied: {policy_decision.reason}",
            request.action_type,
        )

    if request.action_type in _DENY_ACTIONS:
        return _decide(
            GatewayOutcome.DENY,
            f"{request.action_type.value} is hard-denied in v1 regardless of approval",
            request.action_type,
        )

    if request.action_type in _REQUIRE_APPROVAL_ACTIONS:
        return _decide(
            GatewayOutcome.REQUIRE_APPROVAL,
            f"{request.action_type.value} requires explicit human approval before it may execute",
            request.action_type,
        )

    if request.action_type in _ALLOW_ACTIONS:
        return _decide(
            GatewayOutcome.ALLOW,
            f"{request.action_type.value} is permitted to execute",
            request.action_type,
        )

    # Unreachable if _ALLOW_ACTIONS | _REQUIRE_APPROVAL_ACTIONS | _DENY_ACTIONS
    # covers every ActionType member - test_all_action_types_are_classified
    # guards this. Fail closed rather than silently allow an unclassified
    # action type.
    return _decide(
        GatewayOutcome.DENY,
        f"{request.action_type.value} is not classified by this gateway; failing closed",
        request.action_type,
    )
