"""Tests for the trust-boundary/data-classification policy layer (D023).

Uses synthetic Personal/Brainstorm/Shared fixtures only. No real Personal
or Brainstorm data is created or read by these tests.
"""

import pytest
from pydantic import ValidationError

import zacai.config as config_module
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    PolicyDecision,
    TrustBoundary,
    evaluate_access,
)


def _request(
    data_boundary: TrustBoundary,
    requestor_boundaries: frozenset[TrustBoundary],
    *,
    classification: DataClassification = DataClassification.INTERNAL,
    destination: Destination = Destination.LOCAL,
) -> AccessRequest:
    return AccessRequest(
        data_boundary=data_boundary,
        data_classification=classification,
        requestor_boundaries=requestor_boundaries,
        destination=destination,
    )


# --- config.py re-export identity -------------------------------------------


def test_config_reexports_the_same_trust_boundary_type() -> None:
    assert config_module.TrustBoundary is TrustBoundary


# --- same-boundary access ----------------------------------------------------


@pytest.mark.parametrize("boundary", list(TrustBoundary))
def test_same_boundary_access_is_allowed(boundary: TrustBoundary) -> None:
    decision = evaluate_access(_request(boundary, frozenset({boundary})))

    assert decision.allowed is True
    assert decision.reason


# --- missing/empty authorization --------------------------------------------


@pytest.mark.parametrize("boundary", list(TrustBoundary))
def test_empty_requestor_boundaries_is_denied(boundary: TrustBoundary) -> None:
    decision = evaluate_access(_request(boundary, frozenset()))

    assert decision.allowed is False
    assert decision.reason


# --- SHARED policy invariants (D023) ----------------------------------------
#
# SHARED is an independently authorized boundary. It must never behave as a
# combination of, or a bridge between, PERSONAL and BRAINSTORM.


def test_personal_authorization_does_not_imply_shared() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.SHARED, frozenset({TrustBoundary.PERSONAL}))
    )

    assert decision.allowed is False


def test_brainstorm_authorization_does_not_imply_shared() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.SHARED, frozenset({TrustBoundary.BRAINSTORM}))
    )

    assert decision.allowed is False


def test_personal_plus_brainstorm_authorization_does_not_imply_shared() -> None:
    decision = evaluate_access(
        _request(
            TrustBoundary.SHARED,
            frozenset({TrustBoundary.PERSONAL, TrustBoundary.BRAINSTORM}),
        )
    )

    assert decision.allowed is False


def test_shared_authorization_grants_no_personal_access() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.PERSONAL, frozenset({TrustBoundary.SHARED}))
    )

    assert decision.allowed is False


def test_shared_authorization_grants_no_brainstorm_access() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.BRAINSTORM, frozenset({TrustBoundary.SHARED}))
    )

    assert decision.allowed is False


def test_shared_access_requires_its_own_explicit_grant() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.SHARED, frozenset({TrustBoundary.SHARED}))
    )

    assert decision.allowed is True


# --- cross-boundary access is denied, never silently merged ----------------


def test_personal_requestor_denied_brainstorm_data() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.BRAINSTORM, frozenset({TrustBoundary.PERSONAL}))
    )

    assert decision.allowed is False
    assert "BRAINSTORM" in decision.reason


def test_brainstorm_requestor_denied_personal_data() -> None:
    decision = evaluate_access(
        _request(TrustBoundary.PERSONAL, frozenset({TrustBoundary.BRAINSTORM}))
    )

    assert decision.allowed is False
    assert "PERSONAL" in decision.reason


def test_explicit_multi_boundary_grant_allows_both() -> None:
    both = frozenset({TrustBoundary.PERSONAL, TrustBoundary.BRAINSTORM})

    assert evaluate_access(_request(TrustBoundary.PERSONAL, both)).allowed is True
    assert evaluate_access(_request(TrustBoundary.BRAINSTORM, both)).allowed is True
    # Still no implicit SHARED, even with both explicit grants.
    assert evaluate_access(_request(TrustBoundary.SHARED, both)).allowed is False


# --- HIGHLY_RESTRICTED + EXTERNAL is a hard deny (D023) ---------------------


def test_highly_restricted_external_denied_even_for_authorized_same_boundary() -> None:
    decision = evaluate_access(
        _request(
            TrustBoundary.PERSONAL,
            frozenset({TrustBoundary.PERSONAL}),
            classification=DataClassification.HIGHLY_RESTRICTED,
            destination=Destination.EXTERNAL,
        )
    )

    assert decision.allowed is False
    assert "HIGHLY_RESTRICTED" in decision.reason


def test_highly_restricted_local_same_boundary_is_allowed() -> None:
    decision = evaluate_access(
        _request(
            TrustBoundary.PERSONAL,
            frozenset({TrustBoundary.PERSONAL}),
            classification=DataClassification.HIGHLY_RESTRICTED,
            destination=Destination.LOCAL,
        )
    )

    assert decision.allowed is True


def test_confidential_external_same_boundary_is_allowed() -> None:
    decision = evaluate_access(
        _request(
            TrustBoundary.BRAINSTORM,
            frozenset({TrustBoundary.BRAINSTORM}),
            classification=DataClassification.CONFIDENTIAL,
            destination=Destination.EXTERNAL,
        )
    )

    assert decision.allowed is True


# --- fail-closed construction -------------------------------------------


def test_access_request_rejects_invalid_boundary_string() -> None:
    with pytest.raises(ValidationError):
        AccessRequest(
            data_boundary="NOT_A_BOUNDARY",
            data_classification=DataClassification.INTERNAL,
            requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
            destination=Destination.LOCAL,
        )


def test_access_request_rejects_invalid_classification_string() -> None:
    with pytest.raises(ValidationError):
        AccessRequest(
            data_boundary=TrustBoundary.PERSONAL,
            data_classification="NOT_A_CLASSIFICATION",
            requestor_boundaries=frozenset({TrustBoundary.PERSONAL}),
            destination=Destination.LOCAL,
        )


def test_access_request_is_frozen() -> None:
    request = _request(TrustBoundary.PERSONAL, frozenset({TrustBoundary.PERSONAL}))

    with pytest.raises(ValidationError):
        request.data_boundary = TrustBoundary.BRAINSTORM  # type: ignore[misc]


def test_policy_decision_is_frozen() -> None:
    decision = PolicyDecision(allowed=True, reason="test")

    with pytest.raises(ValidationError):
        decision.allowed = False  # type: ignore[misc]
