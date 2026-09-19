"""Tier-0 configuration and the boundary-checked secrets accessor.

See SECRETS.md and DECISIONS.md D017/D021/D023 for the full policy this
implements:
- Tier 0: versioned, non-secret configuration (this module's `Settings`).
- Every secret name must carry a PERSONAL_/BRAINSTORM_/SHARED_ trust-boundary
  prefix, enforced here in code rather than by naming convention alone.
  `TrustBoundary` itself is defined in `zacai.policy` (D023), which is the
  broader, data-access policy layer this secret-name check is one narrow
  consumer of - re-exported here so existing imports keep working.
- The runtime `Environment` is explicit and fails safely on an invalid value;
  only development mode ever reads `.env.development` (D021).

No real secret values exist yet. `get_secret` only establishes the
enforcement mechanism so it is in place before any real credential is
introduced (Tier 1 `.env.development` or Tier 2 macOS Keychain). Wiring
`get_secret` to actually read `.env.development` remains separate,
not-yet-done work (D021) - see DECISIONS.md.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict

from zacai.policy import TrustBoundary

__all__ = [
    "BoundaryError",
    "Environment",
    "Settings",
    "TrustBoundary",
    "get_secret",
    "get_settings",
]


class Environment(str, Enum):
    """Runtime modes Zac AI can start in (SECRETS.md, D017, D021).

    Exactly two values. Any other value must fail Settings validation at
    startup rather than being silently accepted or coerced.
    """

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Tier-0, non-secret configuration only. Never add a secret value here."""

    model_config = SettingsConfigDict(
        env_prefix="ZACAI_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    environment: Environment = Environment.DEVELOPMENT


def _select_env_file(raw_environment: str) -> str | None:
    """The one code path deciding whether a dotenv file is loaded.

    Only an exact "development" match loads `.env.development`. Anything
    else - "production", a typo, an empty value - loads nothing, so an
    invalid value falls through to Settings validation and fails startup
    instead of silently falling back, and a production run can never pick
    up a dev-only file (DECISIONS.md D021).
    """
    return ".env.development" if raw_environment == Environment.DEVELOPMENT.value else None


def get_settings() -> Settings:
    raw_environment = os.environ.get("ZACAI_ENVIRONMENT", Environment.DEVELOPMENT.value)
    return Settings(_env_file=_select_env_file(raw_environment))


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
