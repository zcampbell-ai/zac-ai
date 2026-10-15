"""Existing owner identity and boundary contracts, independent of transport.

These values do not authenticate a caller or grant model, source or execution
permission. Google-only owner enrollment policy is preserved by this relocation.
"""

from __future__ import annotations

from dataclasses import dataclass

from zacai.policy import DataClassification, TrustBoundary

GOOGLE_ISSUER = "https://accounts.google.com"


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str


@dataclass(frozen=True)
class BoundaryScope:
    boundary: TrustBoundary
    classifications: frozenset[DataClassification]


@dataclass(frozen=True)
class OwnerGrant:
    identity: Identity
    scopes: tuple[BoundaryScope, ...]

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not Identity
            or self.identity.issuer != GOOGLE_ISSUER
            or not isinstance(self.identity.subject, str)
            or not self.identity.subject
            or type(self.scopes) is not tuple
            or not self.scopes
            or any(type(scope) is not BoundaryScope for scope in self.scopes)
            or len({s.boundary for s in self.scopes}) != len(self.scopes)
            or any(type(s.classifications) is not frozenset for s in self.scopes)
            or any(
                not s.classifications
                or any(not isinstance(c, DataClassification) for c in s.classifications)
                for s in self.scopes
            )
            or any(not isinstance(s.boundary, TrustBoundary) for s in self.scopes)
        ):
            raise ValueError("owner enrollment unavailable")


@dataclass(frozen=True)
class InterfacePrincipal:
    identity: Identity
    scopes: tuple[BoundaryScope, ...]
