"""Offline managed-app navigation observations, never native provider evidence.

Exact supplied JSON bytes are preserved, including unknown fields. The declared
representation describes what the host supplies, not an authenticated tool call.
This preparer performs no I/O, capture, entity promotion, recovery or processing.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest
from zacai.policy import AccessRequest, Destination, evaluate_access
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

MAX_OBSERVATION_BYTES = 256_000
MAX_COMPANION_BYTES = 24_000
Provider = Literal["CLICKUP", "SLACK"]
Representation = Literal["ASSEMBLED_NAVIGATION_CATALOG", "AS_RETURNED_TOOL_RESPONSE"]


class ManagedAppCatalogObservationError(ValueError):
    """Fixed public hold; hosts must suppress private traceback locals."""


class ManagedAppToolDeclarationV1(Contract):
    provider: Provider
    reported_tool_name: str = Field(
        strict=True, min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:/-]+$"
    )
    declared_account_label: str = Field(strict=True, min_length=1, max_length=200, repr=False)

    @field_validator("declared_account_label")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("exact nonblank declared label required")
        value.encode("utf-8", errors="strict")
        return value


class ManagedAppCatalogObservationScopeV1(Contract):
    format: Literal["zac-managed-app-catalog-observation-scope-v1"] = (
        "zac-managed-app-catalog-observation-scope-v1"
    )
    reported_tool_origin: Literal["CHATGPT_MANAGED_APPS"] = "CHATGPT_MANAGED_APPS"
    observation_id: UUID
    representation: Representation
    tools: tuple[ManagedAppToolDeclarationV1, ...] = Field(min_length=1, max_length=8)
    declared_navigation_selection: str = Field(
        strict=True, min_length=1, max_length=1000, repr=False
    )
    reported_acquired_at: AwareDatetime | None
    inspected_at: AwareDatetime
    reported_entry_count: int | None = Field(strict=True, ge=0, le=5000)
    reported_pagination: Literal[
        "NOT_REPORTED", "MORE_PAGES_REPORTED", "RETURNED_PAGE_EXHAUSTED_NOT_FULL_HISTORY"
    ]
    coverage_notes: str = Field(strict=True, min_length=1, max_length=2000, repr=False)
    declared_input_hashes: tuple[Digest, ...] = Field(max_length=16)
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL, C.HIGHLY_RESTRICTED]

    @model_validator(mode="after")
    def bounded_declarations(self) -> Self:
        if (
            self.observation_id.int == 0
            or len(set(self.tools)) != len(self.tools)
            or len(set(self.declared_input_hashes)) != len(self.declared_input_hashes)
            or self.reported_acquired_at is not None
            and self.reported_acquired_at > self.inspected_at
            or self.representation == "AS_RETURNED_TOOL_RESPONSE"
            and (len(self.tools) != 1 or self.declared_input_hashes)
        ):
            raise ValueError("closed observation declarations required")
        for text in (self.declared_navigation_selection, self.coverage_notes):
            if not text.strip() or text != text.strip():
                raise ValueError("exact nonblank navigation and coverage required")
            text.encode("utf-8", errors="strict")
        return self

    def scope_digest(self) -> str:
        return content_hash_of(canonical_bytes(self.model_dump(mode="json")))

    def raw_namespace(self) -> str:
        return f"managed-app-catalog-observation/{self.observation_id}/{self.scope_digest()}"


class ManagedAppCatalogObservationCompanionV1(Contract):
    format: Literal["zac-managed-app-catalog-observation-companion-v1"] = (
        "zac-managed-app-catalog-observation-companion-v1"
    )
    evidence_kind: Literal["DECLARED_MANAGED_APP_NAVIGATION_OBSERVATION"] = (
        "DECLARED_MANAGED_APP_NAVIGATION_OBSERVATION"
    )
    scope: ManagedAppCatalogObservationScopeV1 = Field(repr=False)
    raw_namespace: str = Field(strict=True, min_length=1, max_length=500)
    raw_digest: Digest
    raw_bytes: int = Field(strict=True, ge=1, le=MAX_OBSERVATION_BYTES)
    json_root_kind: Literal["OBJECT", "ARRAY"]
    unknown_fields: Literal["PRESERVED_EXACTLY_IN_SUPPLIED_JSON"] = (
        "PRESERVED_EXACTLY_IN_SUPPLIED_JSON"
    )
    coverage: Literal["ONE_BOUNDED_NAVIGATION_OBSERVATION_ONLY"] = (
        "ONE_BOUNDED_NAVIGATION_OBSERVATION_ONLY"
    )
    declared_inputs: Literal["HASH_DECLARATIONS_ONLY_NOT_RETRIEVED_OR_VERIFIED"] = (
        "HASH_DECLARATIONS_ONLY_NOT_RETRIEVED_OR_VERIFIED"
    )
    acquisition_account_verified: Literal[False] = False
    acquisition_time_verified: Literal[False] = False
    tool_origin_verified: Literal[False] = False
    representation_verified: Literal[False] = False
    entry_count_verified: Literal[False] = False
    provider_raw_available: Literal[False] = False
    complete_history_verified: Literal[False] = False
    canonical_entities_confirmed: Literal[False] = False
    current_facts_verified: Literal[False] = False
    capture_authorized: Literal[False] = False
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False

    @field_validator(
        "acquisition_account_verified",
        "acquisition_time_verified",
        "tool_origin_verified",
        "representation_verified",
        "entry_count_verified",
        "provider_raw_available",
        "complete_history_verified",
        "canonical_entities_confirmed",
        "current_facts_verified",
        "capture_authorized",
        "processing_authorized",
        "recovery_verified",
        mode="before",
    )
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("unverified observation only")
        return value

    @model_validator(mode="after")
    def exact_namespace(self) -> Self:
        if self.raw_namespace != self.scope.raw_namespace():
            raise ValueError("exact declared observation namespace required")
        return self

    def companion_namespace(self) -> str:
        return (
            self.raw_namespace.replace(
                "managed-app-catalog-observation/", "managed-app-catalog-observation-companion/", 1
            )
            + f"/raw/{self.raw_digest}"
        )


@dataclass(frozen=True, repr=False)
class ManagedAppCatalogArtifactPlanV1:
    """Observation-only append plan; never a native SourceArtifactPlan.

    The host must rebuild the complete preparation before append. Dataclass
    construction alone does not validate classification or authorize capture.
    """

    external_ref: str
    original_bytes: bytes
    content_hash: str
    classification: Literal[C.CONFIDENTIAL, C.HIGHLY_RESTRICTED]
    artifact_kind: Literal["app-observation-json", "app-observation-companion-json"]
    system: Literal[SourceSystem.MANUAL] = field(default=SourceSystem.MANUAL, init=False)
    boundary: Literal[B.BRAINSTORM] = field(default=B.BRAINSTORM, init=False)
    source_occurred_at: None = field(default=None, init=False)
    derives_from: None = field(default=None, init=False)


@dataclass(frozen=True, repr=False)
class ManagedAppCatalogObservationPreparationV1:
    artifacts: tuple[ManagedAppCatalogArtifactPlanV1, ManagedAppCatalogArtifactPlanV1]
    companion: ManagedAppCatalogObservationCompanionV1
    capture_authorized: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate observation key")
        result[key] = value
    return result


def _float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("nonfinite observation number")
    return value


def _constant(raw: str) -> None:
    raise ValueError("nonfinite observation number")


def prepare_managed_app_catalog_observation(
    *,
    raw: bytes,
    scope: ManagedAppCatalogObservationScopeV1,
    requestor_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> ManagedAppCatalogObservationPreparationV1:
    """Prepare exact untrusted bytes and comparison metadata, never record them.

    The host still owns current identity/source-scope authorization, exact capture
    approval, immutable canonical append/reopen and complete recovery. No task
    context, citation, customer/project/person identity or processing grant results.
    """
    result = None
    try:
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= MAX_OBSERVATION_BYTES
            or type(scope) is not ManagedAppCatalogObservationScopeV1
            or type(requestor_boundaries) is not frozenset
            or type(allowed_classifications) is not frozenset
            or any(type(b) is not B for b in requestor_boundaries)
            or any(type(c) is not C for c in allowed_classifications)
            or scope.classification not in allowed_classifications
            or not evaluate_access(
                AccessRequest(
                    data_boundary=B.BRAINSTORM,
                    data_classification=scope.classification,
                    requestor_boundaries=requestor_boundaries,
                    destination=Destination.LOCAL,
                )
            ).allowed
        ):
            raise ValueError("bounded business observation declarations required")
        scope = ManagedAppCatalogObservationScopeV1.model_validate(scope)
        data = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=_float,
            parse_constant=_constant,
        )
        if type(data) not in (dict, list):
            raise ValueError("navigation observation JSON object or array required")
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")
        companion = ManagedAppCatalogObservationCompanionV1(
            scope=scope,
            raw_namespace=scope.raw_namespace(),
            raw_digest=content_hash_of(raw),
            raw_bytes=len(raw),
            json_root_kind="OBJECT" if type(data) is dict else "ARRAY",
        )
        encoded = canonical_bytes(companion.model_dump(mode="json"))
        if len(encoded) > MAX_COMPANION_BYTES:
            raise ValueError("bounded complete companion required")
        result = ManagedAppCatalogObservationPreparationV1(
            (
                ManagedAppCatalogArtifactPlanV1(
                    companion.raw_namespace,
                    raw,
                    companion.raw_digest,
                    scope.classification,
                    "app-observation-json",
                ),
                ManagedAppCatalogArtifactPlanV1(
                    companion.companion_namespace(),
                    encoded,
                    content_hash_of(encoded),
                    scope.classification,
                    "app-observation-companion-json",
                ),
            ),
            companion,
        )
    except Exception:  # noqa: BLE001,S110 - no private input/parser diagnostics
        pass
    if result is None:
        raise ManagedAppCatalogObservationError("managed-app catalog observation preparation held")
    return result
