"""Closed historical fragment preparation; canonical read metadata is not protection.

Legacy indexer/companion/projector byte gates remain unchanged. Hosts must verify
complete original AND companion recovery/current owner and ACL before active use,
and obtain exact changed-request processing approval. No callback/boolean can
supply that proof here. Hosts must suppress private traceback locals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.claude_custody_selection import inspect_claude_custody_selection
from zacai.claude_history_index import (
    MAX_INPUT_BYTES,
    OriginalByteRange,
    index_claude_member_history,
)
from zacai.claude_message_projection import (
    MAX_SELECTED_CHARACTERS,
    MAX_SELECTED_UTF8_BYTES,
)
from zacai.claude_original_capture import ClaudeCustodyProposal, _envelope, _validated
from zacai.claude_original_read import ReadClaudeCustody
from zacai.history_manifest import (
    MAX_EXPORT_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    HistorySelection,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, classification_covers
from zacai.policy import DataClassification, TrustBoundary


class ClaudeHistoricalFragmentError(ValueError):
    """Fixed public hold; caller exception contexts are not a privacy sandbox."""


class ClaudeHistoricalFragmentProfileV1(Contract):
    format: Literal["zac-claude-historical-literal-fragment-profile-v1"] = Field(repr=False)
    original_binding_reference: EvidenceReference = Field(repr=False)
    companion_binding_reference: EvidenceReference = Field(repr=False)
    current_original_reference: EvidenceReference = Field(repr=False)
    current_companion_reference: EvidenceReference = Field(repr=False)
    joint_output_classification: DataClassification = Field(repr=False)
    projection_reference_semantics: Literal["IMMUTABLE_CAPTURE_BINDING_ONLY"] = Field(repr=False)
    declared_acquired_at: AwareDatetime = Field(repr=False)
    declared_exported_at: AwareDatetime | None = Field(repr=False)
    declared_captured_at: AwareDatetime = Field(repr=False)
    date_semantics: Literal["HOST_DECLARED_AND_EXPORT_REPORTED"] = Field(repr=False)
    selected_dates_after_acquired_at: bool = Field(strict=True, repr=False)
    custody_selected_dates_after_acquired_at: bool = Field(strict=True, repr=False)
    original_tip_id: UUID = Field(repr=False)
    superseded_at_read: bool = Field(strict=True, repr=False)
    original_within_legacy_byte_limit: bool = Field(strict=True, repr=False)
    custody_selected_record_count: int = Field(gt=0, le=MAX_RECORDS, strict=True, repr=False)
    custody_id: UUID = Field(repr=False)
    proposal_hash: Digest = Field(repr=False)
    original_file_hash: Digest = Field(repr=False)
    original_file_bytes: int = Field(gt=0, le=MAX_INPUT_BYTES, strict=True, repr=False)
    original_capacity_bytes: Literal[100_000_000] = Field(repr=False)
    message_capacity_bytes: Literal[128_000] = Field(repr=False)
    custody_selection_capacity: Literal[64] = Field(repr=False)
    selected_character_capacity: Literal[8_000] = Field(repr=False)
    selected_utf8_capacity_bytes: Literal[12_000] = Field(repr=False)
    selected_line_capacity: Literal[250] = Field(repr=False)
    selected_line_character_capacity: Literal[1_500] = Field(repr=False)
    required_protection: Literal["COMPLETE_ORIGINAL_AND_COMPANION"] = Field(repr=False)
    coverage: Literal["SELECTED_LITERAL_FRAGMENT_ONLY"] = Field(repr=False)
    thread_context_complete: Literal[False] = Field(repr=False)
    lineage_complete: Literal[False] = Field(repr=False)
    lineage_gap: Literal["DIRECT_MISSING_PARENT", "INHERITED_MISSING_ANCESTOR"] = Field(repr=False)
    reported_role_and_dates_are_export_claims: Literal[True] = Field(repr=False)
    other_content_assessed: Literal[False] = Field(repr=False)
    selection: HistorySelection = Field(repr=False)
    conversation_id: UUID = Field(repr=False)
    parent_id: UUID = Field(repr=False)
    parent_status: Literal["UNRESOLVED_MISSING", "RESOLVED_EARLIER"] = Field(repr=False)
    reported_updated_at: datetime = Field(repr=False)
    character_start: int = Field(ge=0, strict=True, repr=False)
    character_end: int = Field(gt=0, strict=True, repr=False)
    selected_text_hash: Digest = Field(repr=False)

    @model_validator(mode="after")
    def consistent_fragment_observations(self) -> Self:
        """Closed profile consistency only; original bytes remain a separate check."""
        selected_id = UUID(self.selection.original_id)
        if (
            str(selected_id) != self.selection.original_id
            or selected_id.int == 0
            or self.parent_id.int == 0
            or self.parent_id == selected_id
            or self.conversation_id.int == 0
            or self.custody_id.int == 0
            or self.original_tip_id.int == 0
            or (self.lineage_gap, self.parent_status)
            not in {
                ("DIRECT_MISSING_PARENT", "UNRESOLVED_MISSING"),
                ("INHERITED_MISSING_ANCESTOR", "RESOLVED_EARLIER"),
            }
            or self.selection.role not in {"USER", "ASSISTANT"}
            or self.selection.reported_at is None
            or self.reported_updated_at.utcoffset() is None
            or self.selection.reported_at > self.reported_updated_at
            or self.declared_acquired_at > self.declared_captured_at
            or (
                self.declared_exported_at is not None
                and self.declared_exported_at > self.declared_acquired_at
            )
            or self.selected_dates_after_acquired_at
            != (
                self.selection.reported_at > self.declared_acquired_at
                or self.reported_updated_at > self.declared_acquired_at
            )
            or (
                self.selected_dates_after_acquired_at
                and not self.custody_selected_dates_after_acquired_at
            )
            or not 0 <= self.character_start < self.character_end
            or self.character_end - self.character_start > MAX_SELECTED_CHARACTERS
            or not 0 <= self.selection.start < self.selection.end <= self.original_file_bytes
            or self.selection.end - self.selection.start > MAX_RECORD_BYTES
            or self.original_within_legacy_byte_limit
            != (self.original_file_bytes <= MAX_EXPORT_BYTES)
        ):
            raise ValueError("inconsistent bounded fragment observations")
        original, companion = self.original_binding_reference, self.companion_binding_reference
        if (
            original.source_id.int == 0
            or companion.source_id.int == 0
            or original.source_id == companion.source_id
            or original.trust_boundary != companion.trust_boundary
            or original.trust_boundary == TrustBoundary.SHARED
            or original.effective_classification != companion.effective_classification
            or self.original_file_hash != original.content_hash
            or self.superseded_at_read != (self.original_tip_id != original.source_id)
        ):
            raise ValueError("inconsistent original companion bindings")
        for current, binding in (
            (self.current_original_reference, original),
            (self.current_companion_reference, companion),
        ):
            if (
                current.source_id != binding.source_id
                or current.content_hash != binding.content_hash
                or current.trust_boundary != binding.trust_boundary
                or not classification_covers(
                    current.effective_classification, binding.effective_classification
                )
            ):
                raise ValueError("inconsistent current immutable references")
        expected_joint = (
            self.current_original_reference.effective_classification
            if classification_covers(
                self.current_original_reference.effective_classification,
                self.current_companion_reference.effective_classification,
            )
            else self.current_companion_reference.effective_classification
        )
        if self.joint_output_classification != expected_joint:
            raise ValueError("inconsistent current joint classification")
        return self


@dataclass(frozen=True, repr=False)
class ClaudeHistoricalLiteralFragment:
    reference: EvidenceReference
    companion_hash: str
    message_id: UUID
    conversation_id: UUID
    record_bytes: OriginalByteRange
    record_hash: str
    text_json_bytes: OriginalByteRange
    full_decoded_text_hash: str
    full_decoded_characters: int
    selected_character_start: int
    selected_character_end: int
    selected_decoded_utf8_start: int
    selected_decoded_utf8_end: int
    selected_text: str
    selected_text_hash: str
    reported_created_at: datetime
    reported_updated_at: datetime
    historical_role: Literal["USER", "ASSISTANT"]
    parent_id: UUID
    parent_status: Literal["UNRESOLVED_MISSING", "RESOLVED_EARLIER"]
    omitted_prefix_characters: int
    omitted_suffix_characters: int
    lineage_gap: Literal["DIRECT_MISSING_PARENT", "INHERITED_MISSING_ANCESTOR"]
    lineage_complete: Literal[False] = field(default=False, init=False)
    thread_context_complete: Literal[False] = field(default=False, init=False)
    owner_authenticated: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, repr=False)
class ClaudeHistoricalFragmentPreparation:
    profile: ClaudeHistoricalFragmentProfileV1
    profile_raw: bytes
    profile_hash: str
    fragment: ClaudeHistoricalLiteralFragment
    requires_verified_whole_original_and_companion_recovery: Literal[True] = field(
        default=True, init=False
    )
    owner_authenticated: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def prepare_claude_historical_fragment(
    read: ReadClaudeCustody,
    *,
    message_id: UUID,
    character_start: int,
    character_end: int,
) -> ClaudeHistoricalFragmentPreparation:
    """Prepare one exact dated literal with explicitly incomplete thread coverage.

    Complete messages continue the separate v2 profile. Missing ancestry is not
    inferred as a root, authorship, current fact or processing permission. Exact
    supplied canonical-read metadata is consistency, not proof of its origin.
    """
    result = None
    try:
        if (
            (
                MAX_INPUT_BYTES,
                MAX_RECORD_BYTES,
                MAX_RECORDS,
                MAX_SELECTED_CHARACTERS,
                MAX_SELECTED_UTF8_BYTES,
            )
            != (100_000_000, 128_000, 64, 8_000, 12_000)
            or type(read) is not ReadClaudeCustody
            or type(read.original_raw) is not bytes
            or not 0 < len(read.original_raw) <= MAX_INPUT_BYTES
            or type(read.companion_raw) is not bytes
            or not 0 < len(read.companion_raw) <= MAX_MANIFEST_BYTES
            or type(read.envelope_raw) is not bytes
            or not 0 < len(read.envelope_raw) <= MAX_MANIFEST_BYTES
            or type(read.proposal) is not ClaudeCustodyProposal
            or type(read.original_tip_id) is not UUID
            or read.original_tip_id.int == 0
            or type(read.superseded_at_read) is not bool
            or type(read.original_within_legacy_byte_limit) is not bool
            or type(read.reported_dates_after_acquired_at) is not bool
            or read.date_semantics != "HOST_DECLARED_AND_EXPORT_REPORTED"
            or type(message_id) is not UUID
            or message_id.int == 0
            or type(character_start) is not int
            or type(character_end) is not int
            or not 0 <= character_start < character_end
            or character_end - character_start > MAX_SELECTED_CHARACTERS
        ):
            raise ValueError("closed bounded preparation inputs required")
        for reference in (
            read.original_binding_reference,
            read.companion_binding_reference,
            read.original_reference,
            read.companion_reference,
        ):
            if (
                type(reference) is not EvidenceReference
                or type(reference.source_id) is not UUID
                or type(reference.content_hash) is not str
                or type(reference.trust_boundary) is not TrustBoundary
                or type(reference.effective_classification) is not DataClassification
            ):
                raise ValueError("exact typed reader references required")
        original = EvidenceReference.model_validate(read.original_binding_reference)
        companion = EvidenceReference.model_validate(read.companion_binding_reference)
        current_original = EvidenceReference.model_validate(read.original_reference)
        current_companion = EvidenceReference.model_validate(read.companion_reference)
        if (
            original.source_id.int == 0
            or companion.source_id.int == 0
            or original.source_id == companion.source_id
        ):
            raise ValueError("distinct nonzero original and companion required")
        for current, binding in ((current_original, original), (current_companion, companion)):
            if (
                current.source_id != binding.source_id
                or current.content_hash != binding.content_hash
                or current.trust_boundary != binding.trust_boundary
                or not classification_covers(
                    current.effective_classification, binding.effective_classification
                )
            ):
                raise ValueError("exact binding and current Source relationship required")
        joint = (
            current_original.effective_classification
            if classification_covers(
                current_original.effective_classification,
                current_companion.effective_classification,
            )
            else current_companion.effective_classification
        )
        if read.joint_output_classification != joint:
            raise ValueError("exact current joint sensitivity required")
        proposal_raw = canonical_bytes(read.proposal.model_dump(mode="json"))
        proposal = _validated(proposal_raw, read.original_raw)
        envelope_raw = _envelope(proposal, str(original.source_id))
        if (
            envelope_raw != read.envelope_raw
            or content_hash_of(proposal_raw) != read.proposal_hash
            or content_hash_of(envelope_raw) != companion.content_hash
            or canonical_bytes(json.loads(envelope_raw)["companion"]) != read.companion_raw
            or read.captured_at != proposal.captured_at
            or original.content_hash != proposal.original_hash
            or original.trust_boundary != proposal.boundary
            or original.effective_classification != proposal.classification
            or companion.trust_boundary != proposal.boundary
            or companion.effective_classification != proposal.classification
            or read.original_within_legacy_byte_limit
            != (len(read.original_raw) <= MAX_EXPORT_BYTES)
            or read.superseded_at_read != (read.original_tip_id != original.source_id)
            or companion.trust_boundary != original.trust_boundary
            or companion.effective_classification != original.effective_classification
        ):
            raise ValueError("exact retained custody relationship required")
        inspection = inspect_claude_custody_selection(
            read.companion_raw,
            read.original_raw,
            expected_companion_hash=content_hash_of(read.companion_raw),
            expected_original_reference=original,
            expected_account_ref=proposal.account_ref,
            expected_exported_at=proposal.exported_at,
        )
        if not 1 <= len(inspection.records) <= MAX_RECORDS:
            raise ValueError("bounded retained selection required")
        chosen = [x for x in inspection.records if x.selection.original_id == str(message_id)]
        if len(chosen) != 1 or chosen[0].record_kind != "MESSAGE":
            raise ValueError("exact retained MESSAGE selection required")
        index = index_claude_member_history(
            read.original_raw, expected_file_hash=original.content_hash
        )
        selected_ids = {choice.original_id for choice in proposal.selections}
        selected_dates = [choice.reported_at for choice in proposal.selections]
        selected_dates.extend(
            c.reported_updated_at for c in index.conversations if str(c.original_id) in selected_ids
        )
        selected_dates.extend(
            m.reported_updated_at
            for c in index.conversations
            for m in c.messages
            if str(m.original_id) in selected_ids
        )
        custody_date_conflict = any(
            value is not None and value > proposal.acquired_at for value in selected_dates
        )
        if read.reported_dates_after_acquired_at != custody_date_conflict:
            raise ValueError("exact custody date-conflict observation required")
        messages = [
            m for c in index.conversations for m in c.messages if m.original_id == message_id
        ]
        if len(messages) != 1:
            raise ValueError("unique original message required")
        message = messages[0]
        if (
            message.lineage_complete
            or message.parent_status not in {"UNRESOLVED_MISSING", "RESOLVED_EARLIER"}
            or message.parent_id is None
            or not message.record_within_existing_byte_limit
            or message.record.end - message.record.start > MAX_RECORD_BYTES
        ):
            raise ValueError("own MESSAGE record and lineage gates required")
        gap: Literal["DIRECT_MISSING_PARENT", "INHERITED_MISSING_ANCESTOR"]
        parent_status: Literal["UNRESOLVED_MISSING", "RESOLVED_EARLIER"]
        if message.parent_status == "UNRESOLVED_MISSING":
            gap = "DIRECT_MISSING_PARENT"
            parent_status = "UNRESOLVED_MISSING"
        elif message.parent_status == "RESOLVED_EARLIER":
            gap = "INHERITED_MISSING_ANCESTOR"
            parent_status = "RESOLVED_EARLIER"
        else:
            raise ValueError("incomplete literal ancestry required")
        decoded = json.loads(
            read.original_raw[message.text_json_value.start : message.text_json_value.end]
        )
        if type(decoded) is not str or character_end > len(decoded):
            raise ValueError("exact decoded text range required")
        selected = decoded[character_start:character_end]
        selected_utf8 = selected.encode("utf-8", errors="strict")
        lines = selected.splitlines(keepends=True)
        if (
            not selected.strip()
            or selected != selected.strip()
            or len(selected_utf8) > MAX_SELECTED_UTF8_BYTES
            or len(lines) > 250
            or any(len(line.rstrip("\r\n")) > 1_500 for line in lines)
        ):
            raise ValueError("existing model-text preparation bounds required")
        byte_start = len(decoded[:character_start].encode("utf-8", errors="strict"))
        projection = ClaudeHistoricalLiteralFragment(
            original,
            content_hash_of(read.companion_raw),
            message.original_id,
            message.conversation_id,
            message.record,
            chosen[0].selection.content_hash,
            message.text_json_value,
            content_hash_of(decoded.encode("utf-8", errors="strict")),
            len(decoded),
            character_start,
            character_end,
            byte_start,
            byte_start + len(selected_utf8),
            selected,
            content_hash_of(selected_utf8),
            message.reported_created_at,
            message.reported_updated_at,
            message.historical_role,
            message.parent_id,
            parent_status,
            character_start,
            len(decoded) - character_end,
            gap,
        )
        profile = ClaudeHistoricalFragmentProfileV1(
            format="zac-claude-historical-literal-fragment-profile-v1",
            original_binding_reference=original,
            companion_binding_reference=companion,
            current_original_reference=current_original,
            current_companion_reference=current_companion,
            joint_output_classification=joint,
            projection_reference_semantics="IMMUTABLE_CAPTURE_BINDING_ONLY",
            declared_acquired_at=proposal.acquired_at,
            declared_exported_at=proposal.exported_at,
            declared_captured_at=proposal.captured_at,
            date_semantics=read.date_semantics,
            selected_dates_after_acquired_at=(
                message.reported_created_at > proposal.acquired_at
                or message.reported_updated_at > proposal.acquired_at
            ),
            custody_selected_dates_after_acquired_at=custody_date_conflict,
            original_tip_id=read.original_tip_id,
            superseded_at_read=read.superseded_at_read,
            original_within_legacy_byte_limit=read.original_within_legacy_byte_limit,
            custody_selected_record_count=len(inspection.records),
            custody_id=proposal.custody_id,
            proposal_hash=read.proposal_hash,
            original_file_hash=original.content_hash,
            original_file_bytes=len(read.original_raw),
            original_capacity_bytes=100_000_000,
            message_capacity_bytes=128_000,
            custody_selection_capacity=64,
            selected_character_capacity=8_000,
            selected_utf8_capacity_bytes=12_000,
            selected_line_capacity=250,
            selected_line_character_capacity=1_500,
            required_protection="COMPLETE_ORIGINAL_AND_COMPANION",
            coverage="SELECTED_LITERAL_FRAGMENT_ONLY",
            thread_context_complete=False,
            lineage_complete=False,
            lineage_gap=gap,
            reported_role_and_dates_are_export_claims=True,
            other_content_assessed=False,
            selection=chosen[0].selection,
            conversation_id=message.conversation_id,
            parent_id=message.parent_id,
            parent_status=parent_status,
            reported_updated_at=message.reported_updated_at,
            character_start=character_start,
            character_end=character_end,
            selected_text_hash=projection.selected_text_hash,
        )
        profile_raw = canonical_bytes(profile.model_dump(mode="json"))
        if len(profile_raw) > MAX_MANIFEST_BYTES:
            raise ValueError("bounded canonical profile required")
        result = ClaudeHistoricalFragmentPreparation(
            profile, profile_raw, content_hash_of(profile_raw), projection
        )
    except Exception:  # noqa: BLE001,S110 - private bytes never enter public diagnostics
        pass
    if result is None:
        raise ClaudeHistoricalFragmentError("Claude historical fragment preparation held")
    return result
