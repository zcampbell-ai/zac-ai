"""Offline exact Claude message text extraction; no custody, retrieval or authority.

Original JSON byte ranges and decoded Unicode codepoint offsets are distinct.
Dataclass type is not proof. Hosts must suppress traceback locals.
Structured content is not interpreted. Reported role/date are export claims.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from zacai.claude_custody_selection import inspect_claude_custody_selection
from zacai.claude_history_index import OriginalByteRange, index_claude_member_history
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import EvidenceReference

MAX_SELECTED_CHARACTERS = 8_000
MAX_SELECTED_UTF8_BYTES = 12_000


class ClaudeMessageProjectionError(ValueError):
    """Fixed cause-free public hold; never expose private parser diagnostics."""


@dataclass(frozen=True, repr=False)
class ClaudeMessageProjection:
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
    parent_id: UUID | None
    parent_status: Literal["EXPLICIT_ZERO_ROOT", "RESOLVED_EARLIER", "UNRESOLVED_MISSING"]
    omitted_prefix_characters: int
    omitted_suffix_characters: int
    dates_are_export_claims: Literal[True] = field(default=True, init=False)
    structured_content_assessed: Literal[False] = field(default=False, init=False)
    current_fact_verified: Literal[False] = field(default=False, init=False)
    original_custody_verified: Literal[False] = field(default=False, init=False)
    current_acl_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    sender_authenticated: Literal[False] = field(default=False, init=False)


def extract_claude_selected_message(
    companion_raw: bytes,
    original_raw: bytes,
    *,
    expected_companion_hash: str,
    expected_original_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
    character_start: int,
    character_end: int,
) -> ClaudeMessageProjection:
    """One inspected MESSAGE per original Source, no new Source identity.

    Inputs remain caller declarations. The host must verify canonical original
    AND companion custody/recovery/current access before calling with private
    bytes, and refresh that complete union after callbacks before later use.
    Text is the explicit JSON text field, not inferred from content/attachments.
    Bounded lines support existing quote packing; no token-fit claim follows.
    """
    result = None
    try:
        if (
            type(character_start) is not int
            or type(character_end) is not int
            or not 0 <= character_start < character_end
            or character_end - character_start > MAX_SELECTED_CHARACTERS
        ):
            raise ValueError("bounded decoded character span required")
        inspection = inspect_claude_custody_selection(
            companion_raw,
            original_raw,
            expected_companion_hash=expected_companion_hash,
            expected_original_reference=expected_original_reference,
            expected_account_ref=expected_account_ref,
            expected_exported_at=expected_exported_at,
        )
        if len(inspection.records) != 1:
            raise ValueError("one explicit message per Source required")
        checked = inspection.records[0]
        if checked.record_kind != "MESSAGE" or checked.held_by_byte_or_lineage_gate:
            raise ValueError("message byte and lineage gates required")
        index = index_claude_member_history(
            original_raw, expected_file_hash=inspection.companion.original_file_hash
        )
        matches = [
            message
            for conversation in index.conversations
            for message in conversation.messages
            if str(message.original_id) == checked.selection.original_id
        ]
        if len(matches) != 1:
            raise ValueError("exact selected message required")
        message = matches[0]
        raw_text = original_raw[message.text_json_value.start : message.text_json_value.end]
        decoded = json.loads(raw_text.decode("utf-8", errors="strict"))
        if type(decoded) is not str or character_end > len(decoded):
            raise ValueError("exact decoded text span required")
        full_utf8 = decoded.encode("utf-8", errors="strict")
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
            raise ValueError("explicit bounded nonblank text required")
        byte_start = len(decoded[:character_start].encode("utf-8"))
        result = ClaudeMessageProjection(
            inspection.companion.original_reference,
            inspection.companion_hash,
            message.original_id,
            message.conversation_id,
            message.record,
            checked.selection.content_hash,
            message.text_json_value,
            content_hash_of(full_utf8),
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
            message.parent_status,
            character_start,
            len(decoded) - character_end,
        )
    except Exception:  # noqa: BLE001,S110 - private text/parser errors never enter diagnostics
        pass
    if result is None:
        raise ClaudeMessageProjectionError("Claude selected message unavailable")
    return result
