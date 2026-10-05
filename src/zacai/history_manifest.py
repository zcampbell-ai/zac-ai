"""Offline history-selection inspection, never capture or import authorization.

A trusted host supplies original bytes and its explicit metadata selection. This
module binds exact byte spans; it does not parse vendor exports, verify account
ownership, determine privacy labels, prove completeness or promote history into
current facts/preferences. Original instructions remain untrusted source data.
No filesystem, DB, credential, model or network access occurs here. Future capture
must preserve the whole labeled export plus span provenance through existing
Source/artifact/revision/recovery paths, after separate host approval and checks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StringConstraints, field_validator

from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import Contract, Digest
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)

MAX_EXPORT_BYTES = 8_000_000
MAX_MANIFEST_BYTES = 64_000
MAX_RECORD_BYTES = 128_000
MAX_RECORDS = 64
OpaqueId = Annotated[
    str, StringConstraints(min_length=1, max_length=200, pattern=r"^[\x21-\x7e]+$")
]
Offset = Annotated[int, Field(ge=0, strict=True)]


class HistoryProvider(str, Enum):
    CLAUDE = "CLAUDE"
    CHATGPT = "CHATGPT"
    FIREFLIES = "FIREFLIES"


class _HistoryMetadata(Contract):
    @field_validator("reported_at", "exported_at", mode="before", check_fields=False)
    @classmethod
    def explicit_datetime(cls, value: object) -> object:
        if value is None or isinstance(value, datetime):
            return value
        # Require an explicit date/time separator, not Pydantic's lax numeric
        # timestamp coercion (whose units may otherwise be guessed).
        if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}[Tt ]", value):
            return value
        raise ValueError("explicit ISO datetime required")


class HistorySelection(_HistoryMetadata):
    """Host-declared identity/role/time; exact spans do not verify these claims."""

    original_id: OpaqueId
    start: Offset
    end: Offset
    content_hash: Digest
    reported_at: AwareDatetime | None
    role: Literal["USER", "ASSISTANT", "CONVERSATION", "TRANSCRIPT"]


class HistoryManifest(_HistoryMetadata):
    format: Literal["zac-history-selection-manifest-v1"]
    provider: HistoryProvider
    account_ref: OpaqueId
    export_hash: Digest
    export_bytes: Annotated[int, Field(gt=0, le=MAX_EXPORT_BYTES, strict=True)]
    # A whole original export must be assigned one boundary before inspection.
    # A mixed archive needs a separate approved partition/retention workflow.
    boundary: TrustBoundary
    classification: DataClassification
    boundary_scope: Literal["ONE_REVIEWED_BOUNDARY"]
    coverage: Literal["SELECTED_RECORDS_ONLY"]
    attachment_coverage: Literal["NOT_ASSESSED"]
    deletion_coverage: Literal["NOT_ASSESSED"]
    exported_at: AwareDatetime | None
    selections: tuple[HistorySelection, ...] = Field(min_length=1, max_length=MAX_RECORDS)


class PriorHistoryVersion(Contract):
    """Host-supplied inventory only; no live/current-state verification."""

    provider: HistoryProvider
    account_ref: OpaqueId
    boundary: TrustBoundary
    original_id: OpaqueId
    content_hash: Digest


class HistoryDisposition(str, Enum):
    NEW_CANDIDATE = "NEW_UNCONFIRMED_HISTORY"
    EXISTING_VERSION = "EXISTING_BYTE_VERSION"
    CHANGED_VERSION = "CHANGED_ID_REQUIRES_REVISION_REVIEW"


@dataclass(frozen=True)
class InspectedHistoryRecord:
    original_id: str
    start: int
    end: int
    content_hash: str
    disposition: HistoryDisposition


@dataclass(frozen=True)
class HistoryInspection:
    manifest: HistoryManifest
    manifest_hash: str
    records: tuple[InspectedHistoryRecord, ...]

    # Shape/integrity inspection can never establish these separate gates.
    @property
    def account_ownership_verified(self) -> Literal[False]:
        return False

    @property
    def source_visibility_verified(self) -> Literal[False]:
        return False

    @property
    def completeness_verified(self) -> Literal[False]:
        return False

    @property
    def capture_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False

    @property
    def fact_promotion_authorized(self) -> Literal[False]:
        return False


class HistoryManifestError(RuntimeError):
    """Fixed diagnostics only; no source text, IDs or validation input leaked."""


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("duplicate key")
        values[key] = value
    return values


def _reject_constant(value: str) -> None:
    raise ValueError("nonfinite number")


def inspect_history_selection(
    manifest_raw: bytes,
    export_raw: bytes,
    *,
    expected_manifest_hash: str,
    requestor_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    prior_versions: tuple[PriorHistoryVersion, ...] = (),
) -> HistoryInspection:
    """Validate an exact host-selected scope without interpreting source prose.

    Hash binding is integrity, not consent. Supplied metadata/previous versions
    remain host declarations. This intentionally cannot read mixed-boundary or
    oversized archives, follow attachment paths/URLs, or silently split batches.
    It returns no source prose. Private raw bytes must not be passed to cloud
    models/logged merely because this offline inspection succeeds.
    """
    try:
        if (
            type(manifest_raw) is not bytes
            or type(export_raw) is not bytes
            or not 0 < len(manifest_raw) <= MAX_MANIFEST_BYTES
            or not 0 < len(export_raw) <= MAX_EXPORT_BYTES
            or type(expected_manifest_hash) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_manifest_hash) is None
            or content_hash_of(manifest_raw) != expected_manifest_hash
            or len(prior_versions) > 4096
        ):
            raise ValueError("scope")
        manifest = HistoryManifest.model_validate(
            json.loads(
                manifest_raw.decode("utf-8"),
                object_pairs_hook=_unique_pairs,
                parse_constant=_reject_constant,
            )
        )
        if (
            manifest.classification not in allowed_classifications
            or not evaluate_access(
                AccessRequest(
                    data_boundary=manifest.boundary,
                    data_classification=manifest.classification,
                    requestor_boundaries=requestor_boundaries,
                    destination=Destination.LOCAL,
                )
            ).allowed
            or manifest.boundary == TrustBoundary.SHARED
            or manifest.export_bytes != len(export_raw)
            or manifest.export_hash != content_hash_of(export_raw)
        ):
            raise ValueError("export scope")
        versions: dict[str, set[str]] = {}
        for raw_prior in prior_versions:
            prior = PriorHistoryVersion.model_validate(raw_prior)
            # Reject rather than inspect or leak cross-boundary prior inventory.
            if prior.boundary != manifest.boundary:
                raise ValueError("prior boundary")
            if prior.provider == manifest.provider and prior.account_ref == manifest.account_ref:
                versions.setdefault(prior.original_id, set()).add(prior.content_hash)
        seen: set[str] = set()
        intervals: list[tuple[int, int]] = []
        records: list[InspectedHistoryRecord] = []
        for selection in manifest.selections:
            if (
                selection.original_id in seen
                or selection.end <= selection.start
                or selection.end > len(export_raw)
                or selection.end - selection.start > MAX_RECORD_BYTES
                or any(selection.start < end and selection.end > start for start, end in intervals)
                or (
                    selection.reported_at is not None
                    and manifest.exported_at is not None
                    and selection.reported_at > manifest.exported_at
                )
            ):
                raise ValueError("selection scope")
            span = export_raw[selection.start : selection.end]
            if content_hash_of(span) != selection.content_hash:
                raise ValueError("span integrity")
            previous = versions.get(selection.original_id, set())
            disposition = (
                HistoryDisposition.EXISTING_VERSION
                if selection.content_hash in previous
                else HistoryDisposition.CHANGED_VERSION
                if previous
                else HistoryDisposition.NEW_CANDIDATE
            )
            records.append(
                InspectedHistoryRecord(
                    selection.original_id,
                    selection.start,
                    selection.end,
                    selection.content_hash,
                    disposition,
                )
            )
            intervals.append((selection.start, selection.end))
            seen.add(selection.original_id)
        return HistoryInspection(manifest, content_hash_of(manifest_raw), tuple(records))
    except Exception:  # noqa: BLE001, S110 - strip private validation/error context
        pass
    raise HistoryManifestError("history selection inspection rejected")
