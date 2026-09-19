"""Tests for the deterministic Action/Approval Gateway (D024).

Uses synthetic ActionRequest/AccessRequest fixtures only. No real Personal,
Brainstorm, or connector data is created or read by these tests.
"""

import pytest
from pydantic import ValidationError

from zacai.gateway import (
    _ALLOW_ACTIONS,
    _DENY_ACTIONS,
    _REQUIRE_APPROVAL_ACTIONS,
    ActionRequest,
    ActionRisk,
    ActionType,
    GatewayDecision,
    GatewayOutcome,
    evaluate_gateway,
)
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary


def _allowed_access() -> AccessRequest:
    return AccessRequest(
        data_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
        destination=Destination.LOCAL,
    )


def _denied_access() -> AccessRequest:
    return AccessRequest(
        data_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        requestor_boundaries=frozenset(),
        destination=Destination.LOCAL,
    )


def _hard_denied_policy_access() -> AccessRequest:
    """HIGHLY_RESTRICTED + EXTERNAL - the D023 hard deny, distinct from a
    plain missing-boundary denial, used to prove the gateway defers to
    whatever reason `evaluate_access` gives without inspecting it."""
    return AccessRequest(
        data_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.HIGHLY_RESTRICTED,
        requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
        destination=Destination.EXTERNAL,
    )


def _action(
    action_type: ActionType,
    *,
    access: AccessRequest | None = None,
    description: str = "synthetic test action",
) -> ActionRequest:
    return ActionRequest(
        action_type=action_type,
        access=access if access is not None else _allowed_access(),
        description=description,
    )


# --- policy-deny precedence cannot be overridden ----------------------------


@pytest.mark.parametrize("action_type", list(ActionType))
def test_policy_denied_access_always_denies_regardless_of_action_type(
    action_type: ActionType,
) -> None:
    decision = evaluate_gateway(_action(action_type, access=_denied_access()))

    assert decision.outcome is GatewayOutcome.DENY
    assert decision.reason


def test_highly_restricted_external_denied_even_for_low_risk_action_type() -> None:
    decision = evaluate_gateway(
        _action(ActionType.READ_DATA, access=_hard_denied_policy_access())
    )

    assert decision.outcome is GatewayOutcome.DENY
    assert "HIGHLY_RESTRICTED" in decision.reason


def test_hard_deny_action_with_allowed_policy_is_deny_not_require_approval() -> None:
    decision = evaluate_gateway(_action(ActionType.MODIFY_CREDENTIAL))

    assert decision.outcome is GatewayOutcome.DENY


# --- drafts are non-executing ------------------------------------------------


def test_draft_content_allows_when_policy_allows() -> None:
    decision = evaluate_gateway(_action(ActionType.DRAFT_CONTENT))

    assert decision.outcome is GatewayOutcome.ALLOW
    assert decision.reason


def test_draft_and_send_are_independent_action_types() -> None:
    shared_description = "quarterly renewal follow-up"

    draft = evaluate_gateway(_action(ActionType.DRAFT_CONTENT, description=shared_description))
    send = evaluate_gateway(_action(ActionType.SEND_EMAIL, description=shared_description))

    assert draft.outcome is GatewayOutcome.ALLOW
    assert send.outcome is GatewayOutcome.REQUIRE_APPROVAL


def test_action_request_has_no_approval_or_override_field() -> None:
    assert set(ActionRequest.model_fields) == {"action_type", "access", "description"}


# --- writes require approval by default -------------------------------------


@pytest.mark.parametrize(
    "action_type", sorted(_REQUIRE_APPROVAL_ACTIONS, key=lambda a: a.value)
)
def test_require_approval_actions_need_approval_when_policy_allows(
    action_type: ActionType,
) -> None:
    decision = evaluate_gateway(_action(action_type))

    assert decision.outcome is GatewayOutcome.REQUIRE_APPROVAL
    assert decision.reason


# --- dangerous/unsupported actions denied even hypothetically approved -----


@pytest.mark.parametrize("action_type", sorted(_DENY_ACTIONS, key=lambda a: a.value))
def test_hard_denied_actions_are_denied_when_policy_allows(
    action_type: ActionType,
) -> None:
    decision = evaluate_gateway(_action(action_type))

    assert decision.outcome is GatewayOutcome.DENY
    assert decision.reason


def test_scoped_delete_is_require_approval_but_bulk_delete_is_deny() -> None:
    for scoped_delete in (
        ActionType.DELETE_CRM_RECORD,
        ActionType.DELETE_TASK,
        ActionType.DELETE_FILE,
    ):
        decision = evaluate_gateway(_action(scoped_delete))
        assert decision.outcome is GatewayOutcome.REQUIRE_APPROVAL

    bulk_delete = evaluate_gateway(_action(ActionType.DELETE_DATA))
    assert bulk_delete.outcome is GatewayOutcome.DENY


def test_delete_file_is_high_risk_despite_requiring_only_approval() -> None:
    decision = evaluate_gateway(_action(ActionType.DELETE_FILE))

    assert decision.outcome is GatewayOutcome.REQUIRE_APPROVAL
    assert decision.risk is ActionRisk.HIGH


# --- reason strings are always populated ------------------------------------


@pytest.mark.parametrize("action_type", list(ActionType))
@pytest.mark.parametrize(
    "access", [_allowed_access(), _denied_access()], ids=["allowed", "denied"]
)
def test_all_decisions_have_a_nonempty_reason(
    action_type: ActionType, access: AccessRequest
) -> None:
    decision = evaluate_gateway(_action(action_type, access=access))

    assert decision.reason


def test_all_action_types_are_classified() -> None:
    classified = _ALLOW_ACTIONS | _REQUIRE_APPROVAL_ACTIONS | _DENY_ACTIONS

    assert classified == set(ActionType)
    assert _ALLOW_ACTIONS.isdisjoint(_REQUIRE_APPROVAL_ACTIONS)
    assert _ALLOW_ACTIONS.isdisjoint(_DENY_ACTIONS)
    assert _REQUIRE_APPROVAL_ACTIONS.isdisjoint(_DENY_ACTIONS)


# --- fail-closed construction / immutability --------------------------------


def test_action_request_is_frozen() -> None:
    request = _action(ActionType.READ_DATA)

    with pytest.raises(ValidationError):
        request.action_type = ActionType.SEND_EMAIL  # type: ignore[misc]


def test_gateway_decision_is_frozen() -> None:
    decision = GatewayDecision(outcome=GatewayOutcome.ALLOW, reason="test", risk=ActionRisk.LOW)

    with pytest.raises(ValidationError):
        decision.outcome = GatewayOutcome.DENY  # type: ignore[misc]


def test_action_request_rejects_invalid_action_type_string() -> None:
    with pytest.raises(ValidationError):
        ActionRequest(
            action_type="NOT_AN_ACTION_TYPE",  # type: ignore[arg-type]
            access=_allowed_access(),
            description="synthetic test action",
        )
