"""Tests for the boundary-checked secrets accessor (SECRETS.md, D017).

Uses fake, obviously-not-real values only. No real credential, Keychain
entry, or production secret is created or read by these tests.
"""

import pytest

from zacai.config import BoundaryError, TrustBoundary, get_secret

FAKE_ENV = {
    "PERSONAL_TEST_TOKEN": "fake-personal-value-123",
    "BRAINSTORM_TEST_TOKEN": "fake-brainstorm-value-456",
    "SHARED_TEST_TOKEN": "fake-shared-value-789",
}


def test_get_secret_returns_value_for_matching_boundary() -> None:
    assert (
        get_secret("PERSONAL_TEST_TOKEN", TrustBoundary.PERSONAL, env=FAKE_ENV)
        == "fake-personal-value-123"
    )


def test_get_secret_returns_none_when_absent() -> None:
    assert get_secret("PERSONAL_MISSING", TrustBoundary.PERSONAL, env=FAKE_ENV) is None


@pytest.mark.parametrize(
    ("name", "boundary"),
    [
        ("BRAINSTORM_TEST_TOKEN", TrustBoundary.PERSONAL),
        ("PERSONAL_TEST_TOKEN", TrustBoundary.BRAINSTORM),
        ("SHARED_TEST_TOKEN", TrustBoundary.PERSONAL),
    ],
)
def test_get_secret_rejects_cross_boundary_prefix(
    name: str, boundary: TrustBoundary
) -> None:
    with pytest.raises(BoundaryError):
        get_secret(name, boundary, env=FAKE_ENV)


def test_get_secret_rejects_name_with_no_boundary_prefix() -> None:
    with pytest.raises(BoundaryError):
        get_secret("UNPREFIXED_TOKEN", TrustBoundary.SHARED, env=FAKE_ENV)
