"""Closed whole-original Claude selection metadata; no custody or permission.

Caller-supplied original/reference/provenance are declarations, not Source ACL,
account ownership, encrypted protection or authenticated human approval. Private
metadata includes hashes/IDs/offset lengths; never log it or traceback locals.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from zacai.claude_history_index import (
    MAX_INPUT_BYTES,
    ClaudeConversationSpan,
    ClaudeHistoryIndex,
    ClaudeMessageSpan,
    index_claude_member_history,
)
from zacai.history_manifest import (
    MAX_EXPORT_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    HistorySelection,
    OpaqueId,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.policy import DataClassification, TrustBoundary


class ClaudeCustodySelectionError(ValueError):
    """Fixed public error; never return private validation or parser exceptions."""


class ClaudeCustodySelection(Contract):
    format: Literal["zac-claude-whole-original-selection-v1"] = Field(repr=False)
    provider: Literal["CLAUDE"] = Field(repr=False)
    original_reference: EvidenceReference = Field(repr=False)
    original_file_hash: Digest = Field(repr=False)
    original_file_bytes: Annotated[int, Field(gt=0, le=MAX_INPUT_BYTES, strict=True)] = Field(
        repr=False
    )
    account_ref: OpaqueId = Field(repr=False)
    exported_at: AwareDatetime | None = Field(repr=False)
    boundary: TrustBoundary = Field(repr=False)
    classification: DataClassification = Field(repr=False)
    boundary_scope: Literal["ONE_REVIEWED_BOUNDARY"] = Field(repr=False)
    coverage: Literal["SELECTED_RECORDS_ONLY"] = Field(repr=False)
    selections: tuple[HistorySelection, ...] = Field(
        min_length=1, max_length=MAX_RECORDS, repr=False
    )

    @field_validator("exported_at", mode="before")
    @classmethod
    def explicit_date(cls, value: object) -> object:
        if value is None or type(value) is datetime:
            return value
        if type(value) is str and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
            value,
        ):
            return value
        raise ValueError("explicit reported date required")

    @field_validator("exported_at")
    @classmethod
    def utc_date(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def original_matches_scope(self) -> Self:
        ref = self.original_reference
        if (
            self.boundary == TrustBoundary.SHARED
            or ref.source_id.int == 0
            or ref.content_hash != self.original_file_hash
            or ref.trust_boundary != self.boundary
            or ref.effective_classification != self.classification
        ):
            raise ValueError("original declaration differs")
        ids: set[str] = set()
        ranges: list[tuple[int, int]] = []
        for selected in self.selections:
            identity = UUID(selected.original_id)
            if (
                str(identity) != selected.original_id
                or identity.int == 0
                or selected.original_id in ids
                or selected.end <= selected.start
                or selected.end > self.original_file_bytes
                or selected.end - selected.start > MAX_RECORD_BYTES
                or any(selected.start < end and selected.end > start for start, end in ranges)
            ):
                raise ValueError("bounded exact original spans required")
            ids.add(selected.original_id)
            ranges.append((selected.start, selected.end))
        return self


@dataclass(frozen=True, repr=False)
class ClaudeCheckedSelection:
    selection: HistorySelection
    record_kind: Literal["MESSAGE", "CONVERSATION"]
    lineage_complete: bool
    parent_id: UUID | None
    parent_status: Literal["EXPLICIT_ZERO_ROOT", "RESOLVED_EARLIER", "UNRESOLVED_MISSING"] | None
    held_by_byte_or_lineage_gate: bool


@dataclass(frozen=True, repr=False)
class ClaudeCustodyInspection:
    companion: ClaudeCustodySelection
    companion_hash: str
    records: tuple[ClaudeCheckedSelection, ...]
    original_within_legacy_byte_limit: bool
    account_ownership_verified: Literal[False] = field(default=False, init=False)
    original_source_verified: Literal[False] = field(default=False, init=False)
    current_acl_verified: Literal[False] = field(default=False, init=False)
    original_custody_verified: Literal[False] = field(default=False, init=False)
    capture_authorized: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    completeness_verified: Literal[False] = field(default=False, init=False)
    fact_promotion_authorized: Literal[False] = field(default=False, init=False)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("unsupported metadata number")


def _integer(value: str) -> int:
    if len(value) > 20:
        raise ValueError("bounded metadata integer required")
    return int(value)


def _selected(
    index: ClaudeHistoryIndex, choices: tuple[HistorySelection, ...]
) -> dict[str, ClaudeConversationSpan | ClaudeMessageSpan]:
    ids = {item.original_id for item in choices}
    result: dict[str, ClaudeConversationSpan | ClaudeMessageSpan] = {}
    for conversation in index.conversations:
        cid = str(conversation.original_id)
        if cid in ids:
            result[cid] = conversation
        for message in conversation.messages:
            mid = str(message.original_id)
            if mid in ids:
                result[mid] = message
    if result.keys() != ids:
        raise ValueError("selected original identity absent")
    return result


def _inspect(
    companion_raw: bytes,
    original_raw: bytes,
    *,
    expected_companion_hash: str,
    expected_original_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
) -> ClaudeCustodyInspection:
    if (
        type(companion_raw) is not bytes
        or not 0 < len(companion_raw) <= MAX_MANIFEST_BYTES
        or type(original_raw) is not bytes
        or not 0 < len(original_raw) <= MAX_INPUT_BYTES
        or type(expected_companion_hash) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_companion_hash) is None
        or content_hash_of(companion_raw) != expected_companion_hash
        or type(expected_original_reference) is not EvidenceReference
        or type(expected_account_ref) is not str
        or (
            expected_exported_at is not None
            and (
                type(expected_exported_at) is not datetime
                or expected_exported_at.utcoffset() is None
            )
        )
    ):
        raise ValueError("bounded exact declarations required")
    expected_ref = EvidenceReference.model_validate(expected_original_reference)
    companion = ClaudeCustodySelection.model_validate(
        json.loads(
            companion_raw,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_int=_integer,
            parse_float=_constant,
        )
    )
    if (
        canonical_bytes(companion.model_dump(mode="json")) != companion_raw
        or companion.original_reference != expected_ref
        or companion.account_ref != expected_account_ref
        or companion.exported_at != expected_exported_at
        or companion.original_file_bytes != len(original_raw)
    ):
        raise ValueError("claimed original/provenance differs")
    index = index_claude_member_history(
        original_raw, expected_file_hash=companion.original_file_hash
    )
    selected = _selected(index, companion.selections)
    records = []
    for choice in companion.selections:
        record = selected[choice.original_id]
        span = record.record
        if (choice.start, choice.end) != (
            span.start,
            span.end,
        ) or choice.reported_at != record.reported_created_at:
            raise ValueError("exact original record/date differs")
        if companion.exported_at is not None and (
            record.reported_created_at > companion.exported_at
            or record.reported_updated_at > companion.exported_at
        ):
            raise ValueError("selected reported date after claimed export")
        original = original_raw[choice.start : choice.end]
        original.decode("utf-8", errors="strict")
        if content_hash_of(original) != choice.content_hash:
            raise ValueError("exact original record hash differs")
        if type(record) is ClaudeMessageSpan:
            if choice.role != record.historical_role:
                raise ValueError("reported historical role differs")
            records.append(
                ClaudeCheckedSelection(
                    choice,
                    "MESSAGE",
                    record.lineage_complete,
                    record.parent_id,
                    record.parent_status,
                    record.held_by_byte_or_lineage_gate,
                )
            )
        else:
            if choice.role != "CONVERSATION":
                raise ValueError("reported conversation role differs")
            records.append(
                ClaudeCheckedSelection(
                    choice,
                    "CONVERSATION",
                    record.lineage_complete,
                    None,
                    None,
                    record.held_by_byte_or_lineage_gate,
                )
            )
    return ClaudeCustodyInspection(
        companion, expected_companion_hash, tuple(records), len(original_raw) <= MAX_EXPORT_BYTES
    )


def inspect_claude_custody_selection(
    companion_raw: bytes,
    original_raw: bytes,
    *,
    expected_companion_hash: str,
    expected_original_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
) -> ClaudeCustodyInspection:
    """Exact structural join only; no filesystem, SQL, source grant or protection.

    Account/exported date are exact host declarations, not fields authenticated
    from export bytes. Record role/date/spans are checked against the indexer.
    Legacy byte/lineage gates remain visible; no selection is made context-ready.
    """
    result = None
    try:
        result = _inspect(
            companion_raw,
            original_raw,
            expected_companion_hash=expected_companion_hash,
            expected_original_reference=expected_original_reference,
            expected_account_ref=expected_account_ref,
            expected_exported_at=expected_exported_at,
        )
    except Exception:  # noqa: BLE001,S110 - private declared input never enters diagnostics
        pass
    if result is None:
        raise ClaudeCustodySelectionError("Claude original selection unavailable")
    return result
