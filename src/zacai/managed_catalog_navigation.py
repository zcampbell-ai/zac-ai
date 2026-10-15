"""Pure literal navigation lookup over one already reopened observation.

No I/O or authority: a trusted host must perform the actual fresh authenticated
reopen before release. ReopenedCatalog is a value, not an unforgeable permission.
JSON pointers identify original values, not native/provider identity or confirmed
customers/projects. Returned strings remain untrusted data, including URL hints.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationScopeV1,
    prepare_managed_app_catalog_observation,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.managed_catalog_recovery import CatalogRecoveryReceiptV1, ReopenedCatalog
from zacai.policy import TrustBoundary as B

_NAMES = frozenset(
    {"name", "title", "display_name", "account_name", "project_name", "channel_name"}
)
_HINTS = _NAMES | {"id", "url"}


class CatalogNavigationError(ValueError):
    """Fixed failure; never report private decoder inputs or exception locals."""


@dataclass(frozen=True, repr=False)
class CatalogNavigationCandidate:
    object_pointer: str
    matching_fields: tuple[str, ...]
    observed_scalar_hints: tuple[tuple[str, str], ...] = field(repr=False)


@dataclass(frozen=True, repr=False)
class CatalogNavigationLookup:
    exact_name: str = field(repr=False)
    candidates: tuple[CatalogNavigationCandidate, ...] = field(repr=False)
    status: Literal["ONE_OBSERVED_OBJECT", "AMBIGUOUS_OBSERVED_OBJECTS", "NOT_FOUND_IN_OBSERVATION"]
    observation: ManagedAppCatalogObservationScopeV1 = field(repr=False)
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference] = field(repr=False)
    receipt: CatalogRecoveryReceiptV1 = field(repr=False)
    # These dates have distinct meanings, never freshness/complete-history proof.
    checked_at: datetime
    current_facts_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    execution_authorized: Literal[False] = field(default=False, init=False)
    complete_history_verified: Literal[False] = field(default=False, init=False)
    absence_means: Literal["NO_EXACT_NAME_FIELD_MATCH_IN_THIS_BOUNDED_DATED_OBSERVATION_ONLY"] = (
        field(
            default="NO_EXACT_NAME_FIELD_MATCH_IN_THIS_BOUNDED_DATED_OBSERVATION_ONLY", init=False
        )
    )


def _pointer(parent: str, key: str) -> str:
    result = parent + "/" + key.replace("~", "~0").replace("/", "~1")
    if len(result) > 2000:
        raise ValueError("bounded exact pointer required")
    return result


def lookup_catalog_navigation(
    *, reopened: ReopenedCatalog, exact_name: str
) -> CatalogNavigationLookup:
    """Case/whitespace-sensitive literal matching, no aliases/fuzzy/entity inference.

    Reject an over-capacity lookup rather than silently returning a partial set.
    No embedded text can change the match fields or authorize a subsequent read.
    """
    result = None
    try:
        if (
            type(reopened) is not ReopenedCatalog
            or type(exact_name) is not str
            or not 0 < len(exact_name) <= 200
            or exact_name != exact_name.strip()
            or len(exact_name.encode("utf-8")) > 800
            or any(ord(c) < 32 or ord(c) == 127 for c in exact_name)
        ):
            raise ValueError("bounded exact name and reopened value required")
        p, refs, receipt = reopened.preparation, reopened.references, reopened.receipt
        rebuilt = prepare_managed_app_catalog_observation(
            raw=p.artifacts[0].original_bytes,
            scope=p.companion.scope,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({p.companion.scope.classification}),
        )
        if (
            rebuilt != p
            or type(receipt) is not CatalogRecoveryReceiptV1
            or CatalogRecoveryReceiptV1.model_validate(receipt) != receipt
            or receipt.references != refs
            or any(
                ref.trust_boundary is not B.BRAINSTORM
                or ref.effective_classification is not p.companion.scope.classification
                for ref in refs
            )
            or any(
                ref.content_hash != artifact.content_hash
                for ref, artifact in zip(refs[:2], p.artifacts, strict=True)
            )
            or not p.companion.scope.inspected_at
            <= receipt.captured_at
            <= receipt.verified_at
            <= reopened.checked_at
        ):
            raise ValueError("exact reopened observation binding required")
        data = json.loads(p.artifacts[0].original_bytes)
        pending = [(data, "", 0)]
        candidates = []
        visited = 0
        output_bytes = 0
        while pending:
            node, pointer, depth = pending.pop()
            visited += 1
            if visited > 10000 or depth > 32:
                raise ValueError("bounded complete navigation traversal required")
            if type(node) is dict:
                matches = tuple(sorted(key for key in _NAMES if node.get(key) == exact_name))
                if matches:
                    hints = tuple(
                        sorted(
                            (key, value)
                            for key, value in node.items()
                            if key in _HINTS and type(value) is str
                        )
                    )
                    if any(len(value.encode("utf-8")) > 2000 for _, value in hints):
                        raise ValueError("bounded exact navigation hints required")
                    output_bytes += len(pointer.encode("utf-8")) + sum(
                        len(key.encode("utf-8")) + len(value.encode("utf-8"))
                        for key, value in hints
                    )
                    if output_bytes > 32000:
                        raise ValueError("bounded complete navigation result required")
                    candidates.append(CatalogNavigationCandidate(pointer, matches, hints))
                    if len(candidates) > 16:
                        raise ValueError("ambiguous navigation exceeds disclosed capacity")
                for key, value in reversed(tuple(node.items())):
                    pending.append((value, _pointer(pointer, key), depth + 1))
            elif type(node) is list:
                for index in range(len(node) - 1, -1, -1):
                    pending.append((node[index], _pointer(pointer, str(index)), depth + 1))
        status: Literal[
            "ONE_OBSERVED_OBJECT", "AMBIGUOUS_OBSERVED_OBJECTS", "NOT_FOUND_IN_OBSERVATION"
        ]
        status = (
            "ONE_OBSERVED_OBJECT"
            if len(candidates) == 1
            else ("AMBIGUOUS_OBSERVED_OBJECTS" if candidates else "NOT_FOUND_IN_OBSERVATION")
        )
        result = CatalogNavigationLookup(
            exact_name,
            tuple(candidates),
            status,
            p.companion.scope,
            refs,
            receipt,
            reopened.checked_at,
        )
    except Exception:  # noqa: BLE001,S110 - fixed diagnostics without private values
        pass
    if result is None:
        raise CatalogNavigationError("catalog navigation lookup unavailable")
    return result
