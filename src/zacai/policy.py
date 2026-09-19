"""Personal/Brainstorm/Shared trust-boundary and data-classification policy.

See ARCHITECTURE.md Section 16 ("Security and Trust Boundaries"),
SECURITY.md ("Data Classification", "Trust Boundaries"), and DECISIONS.md
D003/D017/D023.

This module is the single source of truth for two independent questions:
- `TrustBoundary`: whose data/context this is, and which boundary or
  boundaries a requestor (a future agent, model-router call, or action) is
  authorized to operate within.
- `DataClassification` + `Destination`: how sensitive the data is, and
  whether handling it would send it outside the local system - independent
  of whose data it is.

`evaluate_access` is the single decision point a future model router
(Phase 5) and a future Action/Approval Gateway (Phase 6) are both meant to
call. It has no knowledge of, and takes no dependency on, any specific
model, connector, database, or orchestration framework.

SHARED policy invariant (D023):
SHARED means data that genuinely belongs to neither Personal nor Brainstorm
exclusively (e.g. Zac AI's own operational data). It is its own,
independently authorized boundary, never a combination of the other two:
- PERSONAL authorization does not imply SHARED.
- BRAINSTORM authorization does not imply SHARED.
- PERSONAL + BRAINSTORM authorization does not imply SHARED.
- SHARED authorization grants no PERSONAL or BRAINSTORM access.
SHARED must never be used as a bridge between Personal and Brainstorm data,
and mixed or provenance-bearing data must keep its actual source boundary
rather than being relabeled SHARED to sidestep this check. This module only
enforces access once data is already labeled; deciding whether a given
entity genuinely deserves the SHARED label is a data-classification/
entity-tagging decision made elsewhere, not something `evaluate_access` can
verify on its own.

HIGHLY_RESTRICTED + EXTERNAL policy invariant (D023):
This is a hard deny inside this module, not a default some later layer may
override. Policy decides whether an operation is permitted at all; a future
Action/Approval Gateway (Phase 6, ARCHITECTURE.md Section 10) may impose
further restrictions or require human approval on top of an
otherwise-permitted operation, but it does not, and must not, override a
policy denial produced here. Changing this specific rule would require its
own future, explicit security/architecture decision - not an ordinary
runtime approval.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class TrustBoundary(str, Enum):
    """Trust boundaries data and requestors are scoped to (SECURITY.md, D003).

    PERSONAL, BRAINSTORM, and SHARED are independently authorized boundaries.
    None of them implies any other - see the SHARED policy invariant above.
    """

    PERSONAL = "PERSONAL"
    BRAINSTORM = "BRAINSTORM"
    SHARED = "SHARED"


class DataClassification(str, Enum):
    """Data sensitivity levels (SECURITY.md, "Data Classification")."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    HIGHLY_RESTRICTED = "HIGHLY_RESTRICTED"


class Destination(str, Enum):
    """Whether handling a request would keep data local or send it out."""

    LOCAL = "LOCAL"
    EXTERNAL = "EXTERNAL"


class AccessRequest(BaseModel):
    """A single access question: may `requestor_boundaries` touch this data?

    Immutable by construction. An invalid boundary, classification, or
    destination value fails Pydantic validation here, at construction,
    rather than reaching `evaluate_access` in an ambiguous state.
    """

    model_config = ConfigDict(frozen=True)

    data_boundary: TrustBoundary
    data_classification: DataClassification
    requestor_boundaries: frozenset[TrustBoundary]
    destination: Destination


class PolicyDecision(BaseModel):
    """The outcome of `evaluate_access`. `reason` is always populated so
    every decision is self-explanatory in a log line on its own."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str


def evaluate_access(request: AccessRequest) -> PolicyDecision:
    """Decide whether `request.requestor_boundaries` may access this data.

    Both checks below must pass for an allow; there is no override for
    either inside this function - see the module-level policy invariants.
    """
    if (
        request.data_classification is DataClassification.HIGHLY_RESTRICTED
        and request.destination is Destination.EXTERNAL
    ):
        return PolicyDecision(
            allowed=False,
            reason="HIGHLY_RESTRICTED data may not be sent to an external destination",
        )

    if request.data_boundary not in request.requestor_boundaries:
        return PolicyDecision(
            allowed=False,
            reason=f"requestor is not authorized for the {request.data_boundary.value} boundary",
        )

    return PolicyDecision(
        allowed=True,
        reason=f"requestor is authorized for the {request.data_boundary.value} boundary",
    )
