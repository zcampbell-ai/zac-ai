"""Tier-0 configuration and the boundary-checked secrets accessor.

See SECRETS.md and DECISIONS.md D017 for the full policy this implements:
- Tier 0: versioned, non-secret configuration (this module's `Settings`).
- Every secret name must carry a PERSONAL_/BRAINSTORM_/SHARED_ trust-boundary
  prefix, enforced here in code rather than by naming convention alone.

No real secret values exist yet. `get_secret` only establishes the
enforcement mechanism so it is in place before any real credential is
introduced (Tier 1 `.env.development` or Tier 2 macOS Keychain).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Tier-0, non-secret configuration only. Never add a secret value here."""

    model_config = SettingsConfigDict(
        env_prefix="ZACAI_",
        env_file=".env.development",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    environment: str = "development"


def get_settings() -> Settings:
    return Settings()


class TrustBoundary(str, Enum):
    """Trust boundaries a secret name must declare (SECURITY.md, D003)."""

    PERSONAL = "PERSONAL"
    BRAINSTORM = "BRAINSTORM"
    SHARED = "SHARED"


class BoundaryError(ValueError):
    """Raised when a secret name's prefix does not match its declared boundary."""


def get_secret(
    name: str,
    boundary: TrustBoundary,
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Look up a secret by name, enforcing its trust-boundary prefix in code.

    Per SECRETS.md and D017, a caller must declare which trust boundary it is
    entitled to read from, and the secret's name must carry the matching
    PERSONAL_/BRAINSTORM_/SHARED_ prefix. A mismatched or missing prefix is
    rejected before any lookup happens, regardless of whether a value exists.
    """
    expected_prefix = f"{boundary.value}_"
    if not name.startswith(expected_prefix):
        raise BoundaryError(
            f"secret {name!r} does not carry the {expected_prefix!r} prefix "
            f"required for the {boundary.value} trust boundary"
        )
    source = env if env is not None else os.environ
    return source.get(name)
