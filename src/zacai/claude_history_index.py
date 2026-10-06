"""Offline Claude member-export span preparation; no retention or authority.

Unknown structured content remains unassessed in its exact original record span.
The 100MB input-byte ceiling is not a peak-RAM bound and never changes the
existing history selection limits. Decoded text/tree can use several times that RAM.
Bounds are conjunctive ceilings; structure can hit 500,000 nodes before the
100,000 message or 200,000 content ceilings. Those counts are not capacity promises.
Inputs/identifiers are private; hosts must disable traceback-local collection.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from zacai.history_manifest import MAX_EXPORT_BYTES, MAX_RECORD_BYTES
from zacai.ingestion.artifact_store import content_hash_of

MAX_INPUT_BYTES = 100_000_000
MAX_NODES = 500_000
MAX_DEPTH = 32
MAX_CONVERSATIONS = 4096
MAX_MESSAGES = 100_000
MAX_CONTENT_COMPONENTS = 200_000
MAX_NUMERIC_TOKEN_CHARS = 1024
ZERO_ID = UUID(int=0)
_WHITESPACE = re.compile(r"[ \t\r\n]*")


class ClaudeHistoryIndexError(ValueError):
    """Fixed error; private inputs never enter diagnostics or chained exceptions."""


@dataclass(frozen=True, repr=False)
class OriginalByteRange:
    start: int
    end: int


@dataclass(frozen=True, repr=False)
class ClaudeMessageSpan:
    original_id: UUID
    conversation_id: UUID
    parent_id: UUID | None
    parent_status: Literal["EXPLICIT_ZERO_ROOT", "RESOLVED_EARLIER", "UNRESOLVED_MISSING"]
    lineage_complete: bool
    original_sender: Literal["human", "assistant"]
    historical_role: Literal["USER", "ASSISTANT"]
    reported_created_at: datetime
    reported_updated_at: datetime
    record: OriginalByteRange
    text_json_value: OriginalByteRange
    structured_content: OriginalByteRange
    record_within_existing_byte_limit: bool
    held_by_byte_or_lineage_gate: bool


@dataclass(frozen=True, repr=False)
class ClaudeConversationSpan:
    original_id: UUID
    reported_created_at: datetime
    reported_updated_at: datetime
    record: OriginalByteRange
    messages: tuple[ClaudeMessageSpan, ...]
    lineage_complete: bool
    record_within_existing_byte_limit: bool
    held_by_byte_or_lineage_gate: bool


@dataclass(frozen=True, repr=False)
class ClaudeHistoryIndex:
    original_file_hash: str
    original_file_bytes: int
    conversations: tuple[ClaudeConversationSpan, ...]
    message_count: int
    whole_file_within_existing_byte_limit: bool
    lineage_complete: bool
    source_specific_selection_implemented: Literal[False] = False
    dates_are_export_claims: Literal[True] = True
    structured_content_assessed: Literal[False] = False
    account_ownership_verified: Literal[False] = False
    completeness_verified: Literal[False] = False
    capture_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False
    fact_promotion_authorized: Literal[False] = False


@dataclass(repr=False, slots=True)
class _Node:
    start: int
    end: int
    value: object


def _bounded_int(token: str) -> int:
    if len(token) > MAX_NUMERIC_TOKEN_CHARS:
        raise ValueError("numeric token ceiling")
    # Small chunks avoid process-global int-string limits; JSON validates grammar.
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    value = 0
    for start in range(0, len(digits), 256):
        chunk = digits[start : start + 256]
        value = value * (10 ** len(chunk)) + int(chunk)
    return -value if negative else value


def _bounded_float(token: str) -> float:
    if len(token) > MAX_NUMERIC_TOKEN_CHARS:
        raise ValueError("numeric token ceiling")
    return float(token)


class _Walker:
    """Bounded delimiter walk; stdlib decoder validates every scalar token.

    Positions advance through original Unicode text while counting original UTF8
    bytes. No normalization, reserialization, substring search or char offset is
    used as a claimed source byte position.
    """

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.byte = 0
        self.nodes = 0
        self.decoder = json.JSONDecoder(
            parse_constant=self._constant, parse_int=_bounded_int, parse_float=_bounded_float
        )

    @staticmethod
    def _constant(value: str) -> None:
        raise ValueError("nonfinite token")

    def advance(self, end: int) -> None:
        self.byte += len(self.text[self.pos : end].encode("utf-8"))
        self.pos = end

    def space(self) -> None:
        match = _WHITESPACE.match(self.text, self.pos)
        assert match is not None
        self.advance(match.end())

    def scalar(self) -> object:
        value, end = self.decoder.raw_decode(self.text, self.pos)
        if isinstance(value, (list, dict)):
            raise TypeError("scalar required")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite scalar")
        if isinstance(value, str):
            value.encode("utf-8", errors="strict")
        self.advance(end)
        return value

    def node(self, depth: int = 0) -> _Node:
        self.space()
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH or self.pos >= len(self.text):
            raise ValueError("bounded structure required")
        start = self.byte
        marker = self.text[self.pos]
        if marker not in "[{":
            value = self.scalar()
            return _Node(start, self.byte, value)
        self.advance(self.pos + 1)
        self.space()
        closing = "]" if marker == "[" else "}"
        values: list[_Node] = []
        members: dict[str, _Node] = {}
        if self.pos < len(self.text) and self.text[self.pos] == closing:
            self.advance(self.pos + 1)
            return _Node(start, self.byte, values if marker == "[" else members)
        while True:
            if marker == "{":
                self.space()
                if self.pos >= len(self.text) or self.text[self.pos] != '"':
                    raise ValueError("string key required")
                key = self.scalar()
                if type(key) is not str or len(key.encode()) > 1024 or key in members:
                    raise ValueError("bounded unique key required")
                self.space()
                if self.pos >= len(self.text) or self.text[self.pos] != ":":
                    raise ValueError("colon required")
                self.advance(self.pos + 1)
                members[key] = self.node(depth + 1)
            else:
                values.append(self.node(depth + 1))
            self.space()
            if self.pos >= len(self.text):
                raise ValueError("closing delimiter required")
            delimiter = self.text[self.pos]
            self.advance(self.pos + 1)
            if delimiter == closing:
                return _Node(start, self.byte, values if marker == "[" else members)
            if delimiter != ",":
                raise ValueError("separator required")


def _object(node: _Node) -> dict[str, _Node]:
    if not isinstance(node.value, dict):
        raise TypeError("object required")
    return node.value


def _array(node: _Node) -> list[_Node]:
    if not isinstance(node.value, list):
        raise TypeError("array required")
    return node.value


def _uuid(node: _Node) -> UUID:
    value = node.value
    if type(value) is not str:
        raise ValueError("UUID string required")
    result = UUID(value)
    if str(result) != value:
        raise ValueError("canonical UUID required")
    return result


def _date(node: _Node) -> datetime:
    value = node.value
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
        value,
        flags=re.ASCII,
    ):
        raise ValueError("explicit date required")
    result = datetime.fromisoformat(value)
    if result.utcoffset() is None:
        raise ValueError("aware date required")
    return result.astimezone(UTC)


def _span(node: _Node) -> OriginalByteRange:
    return OriginalByteRange(node.start, node.end)


def _message_conversations(records: list[_Node]) -> tuple[dict[UUID, UUID], frozenset[UUID]]:
    """Bounded conversation/message cross-kind IDs; no guessed missing roots.

    Account IDs and nested structured IDs are outside this closed namespace.
    """
    result: dict[UUID, UUID] = {}
    seen_conversations: set[UUID] = set()
    for record in records:
        conv = _object(record)
        cid = _uuid(conv["uuid"])
        if cid == ZERO_ID or cid in seen_conversations:
            raise ValueError("conversation identity conflict")
        seen_conversations.add(cid)
    for record in records:
        conv = _object(record)
        cid = _uuid(conv["uuid"])
        for row in _array(conv["chat_messages"]):
            mid = _uuid(_object(row)["uuid"])
            if (
                mid == ZERO_ID
                or mid in seen_conversations
                or mid in result
                or len(result) >= MAX_MESSAGES
            ):
                raise ValueError("bounded unique message identity required")
            result[mid] = cid
    return result, frozenset(seen_conversations)


def _build(raw: bytes, *, expected_file_hash: str) -> ClaudeHistoryIndex:
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_INPUT_BYTES
        or type(expected_file_hash) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_file_hash) is None
        or content_hash_of(raw) != expected_file_hash
    ):
        raise ValueError("exact bounded original required")
    walker = _Walker(raw.decode("utf-8", errors="strict"))
    root = walker.node()
    walker.space()
    if walker.pos != len(walker.text):
        raise ValueError("trailing input")
    records = _array(root)
    if not 1 <= len(records) <= MAX_CONVERSATIONS:
        raise ValueError("bounded conversations required")
    message_conversations, conversation_ids = _message_conversations(records)
    seen_conversations: set[UUID] = set()
    seen_messages: set[UUID] = set()
    conversations = []
    total = 0
    components = 0
    for record in records:
        conv = _object(record)
        cid = _uuid(conv["uuid"])
        created, updated = _date(conv["created_at"]), _date(conv["updated_at"])
        if cid == ZERO_ID or cid in seen_conversations or created > updated:
            raise ValueError("conversation identity/date conflict")
        seen_conversations.add(cid)
        _object(conv["account"])
        rows = _array(conv["chat_messages"])
        total += len(rows)
        if total > MAX_MESSAGES:
            raise ValueError("bounded messages required")
        messages = []
        local: dict[UUID, ClaudeMessageSpan] = {}
        for row in rows:
            obj = _object(row)
            mid = _uuid(obj["uuid"])
            parent = _uuid(obj["parent_message_uuid"])
            mcreated, mupdated = _date(obj["created_at"]), _date(obj["updated_at"])
            sender = obj["sender"].value
            if (
                mid == ZERO_ID
                or mid in seen_messages
                or mcreated > mupdated
                or mcreated < created
                or mcreated > updated
                or sender not in ("human", "assistant")
                or type(obj["text"].value) is not str
            ):
                raise ValueError("message identity/role/date conflict")
            seen_messages.add(mid)
            content = _array(obj["content"])
            components += len(content)
            if components > MAX_CONTENT_COMPONENTS:
                raise ValueError("bounded content inventory required")
            for component in content:
                _object(component)
            parent_status: Literal["EXPLICIT_ZERO_ROOT", "RESOLVED_EARLIER", "UNRESOLVED_MISSING"]
            if parent == ZERO_ID:
                parent_status = "EXPLICIT_ZERO_ROOT"
                lineage_complete = True
            elif parent not in message_conversations and parent not in conversation_ids:
                parent_status = "UNRESOLVED_MISSING"
                lineage_complete = False
            else:
                if (
                    message_conversations.get(parent) != cid
                    or parent not in local
                    or local[parent].reported_created_at > mcreated
                ):
                    raise ValueError("present parent must be earlier in same conversation")
                parent_status = "RESOLVED_EARLIER"
                lineage_complete = local[parent].lineage_complete
            span = _span(row)
            message = ClaudeMessageSpan(
                mid,
                cid,
                None if parent == ZERO_ID else parent,
                parent_status,
                lineage_complete,
                "human" if sender == "human" else "assistant",
                "USER" if sender == "human" else "ASSISTANT",
                mcreated,
                mupdated,
                span,
                OriginalByteRange(obj["text"].start, obj["text"].end),
                OriginalByteRange(obj["content"].start, obj["content"].end),
                span.end - span.start <= MAX_RECORD_BYTES,
                not lineage_complete
                or len(raw) > MAX_EXPORT_BYTES
                or span.end - span.start > MAX_RECORD_BYTES,
            )
            messages.append(message)
            local[mid] = message
        span = _span(record)
        conversation_lineage_complete = all(message.lineage_complete for message in messages)
        conversation_unavailable = (
            not conversation_lineage_complete
            or len(raw) > MAX_EXPORT_BYTES
            or span.end - span.start > MAX_RECORD_BYTES
        )
        # No source-specific message/conversation selection adapter exists yet.
        # Conservatively preserve the whole conversation gate for every message.
        messages = [
            replace(message, held_by_byte_or_lineage_gate=True)
            if conversation_unavailable
            else message
            for message in messages
        ]
        conversations.append(
            ClaudeConversationSpan(
                cid,
                created,
                updated,
                span,
                tuple(messages),
                conversation_lineage_complete,
                span.end - span.start <= MAX_RECORD_BYTES,
                conversation_unavailable,
            )
        )
    return ClaudeHistoryIndex(
        expected_file_hash,
        len(raw),
        tuple(conversations),
        total,
        len(raw) <= MAX_EXPORT_BYTES,
        all(conv.lineage_complete for conv in conversations),
    )


def index_claude_member_history(raw: bytes, *, expected_file_hash: str) -> ClaudeHistoryIndex:
    """Metadata only; exact file hash is integrity, never approval or retention.

    The entire original is caller-held. Returned record spans preserve unknown
    structured fields without returning their values. Root parent sentinel is
    only canonical all-zero UUID. A globally absent nonzero parent remains an
    unresolved original ID with incomplete lineage, never an inferred root.
    """
    result = None
    try:
        result = _build(raw, expected_file_hash=expected_file_hash)
    except Exception:  # noqa: BLE001,S110 - private export never enters diagnostics
        pass
    if result is None:
        raise ClaudeHistoryIndexError("Claude history metadata unavailable")
    return result
