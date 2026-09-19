"""Tests for Tier-0 settings, environment resolution, and the boundary-
checked secrets accessor (SECRETS.md, D017, D021).

Uses fake, obviously-not-real values only. No real credential, Keychain
entry, or production secret is created or read by these tests.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from zacai.config import (
    BoundaryError,
    Environment,
    Settings,
    TrustBoundary,
    _select_env_file,
    get_secret,
    get_settings,
)

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


# --- Environment enum and Settings validation (D021) -----------------------


def test_settings_accepts_valid_development_environment() -> None:
    assert Settings(environment="development").environment is Environment.DEVELOPMENT


def test_settings_accepts_valid_production_environment() -> None:
    assert Settings(environment="production").environment is Environment.PRODUCTION


def test_settings_rejects_invalid_environment_value() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="staging")


# --- _select_env_file: the single dotenv-selection code path (D021) --------


def test_select_env_file_for_development() -> None:
    assert _select_env_file("development") == ".env.development"


def test_select_env_file_for_production() -> None:
    assert _select_env_file("production") is None


def test_select_env_file_for_invalid_value_loads_nothing() -> None:
    assert _select_env_file("bogus-typo") is None


# --- get_settings(): environment resolution end-to-end (D021) --------------


def test_get_settings_defaults_to_development_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ZACAI_ENVIRONMENT", raising=False)

    assert get_settings().environment is Environment.DEVELOPMENT


def test_get_settings_resolves_explicit_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZACAI_ENVIRONMENT", "production")

    assert get_settings().environment is Environment.PRODUCTION


def test_get_settings_rejects_invalid_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZACAI_ENVIRONMENT", "staging")

    with pytest.raises(ValidationError):
        get_settings()


def test_production_never_reads_env_development_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env.development").write_text("ZACAI_PORT=9999\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZACAI_ENVIRONMENT", "production")

    settings = get_settings()

    assert settings.environment is Environment.PRODUCTION
    assert settings.port == 8000


def test_development_reads_env_development_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env.development").write_text("ZACAI_PORT=9999\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZACAI_ENVIRONMENT", "development")

    settings = get_settings()

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.port == 9999
